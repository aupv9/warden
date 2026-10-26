package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/rbac"
	"github.com/aupv9/warden/backend/internal/ids"
	"github.com/aupv9/warden/backend/internal/scan/orchestrator"
	"github.com/aupv9/warden/backend/internal/worker"
)

var sha256Hex = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

const oneHour = time.Hour

type CreateScanInput struct {
	FileName string    `json:"file_name"`
	FileSize int64     `json:"file_size"`
	SHA256   string    `json:"sha256"`
	Tools    *[]string `json:"tools"`
}

// ObjectKey is where a scan's upload lives in object storage.
func ObjectKey(orgID, scanID uuid.UUID) string {
	return fmt.Sprintf("scans/%s/%s.zip", orgID, scanID)
}

func (s *Service) validateScanInput(in CreateScanInput) fieldErrors {
	fe := fieldErrors{}
	n := in.FileName
	if !strings.HasSuffix(strings.ToLower(n), ".zip") || len(n) <= len(".zip") || utf8.RuneCountInString(n) > 255 ||
		strings.ContainsAny(n, `/\`) || !validText(n) || strings.ContainsFunc(n, isControl) {
		fe.add("file_name", "must be a .zip file name of at most 255 characters, without / or \\")
	}
	if in.FileSize < 1 || in.FileSize > s.cfg.UploadMaxBytes {
		fe.add("file_size", fmt.Sprintf("must be between 1 and %d bytes", s.cfg.UploadMaxBytes))
	}
	if !sha256Hex.MatchString(in.SHA256) {
		fe.add("sha256", "must be 64 hexadecimal characters")
	}
	if in.Tools != nil && !validTools(*in.Tools) {
		fe.add("tools", "must be a non-empty list of distinct tools: gitleaks, opengrep, trivy, checkov")
	}
	return fe
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f }

// CreateScan records a scan in pending_upload and returns a presigned PUT URL
// for the archive. The API never receives the archive itself.
func (s *Service) CreateScan(ctx context.Context, a *Actor, projectID uuid.UUID, in CreateScanInput) (CreatedScan, error) {
	fe := s.validateScanInput(in)
	var out CreatedScan
	err := s.inOrg(ctx, a, func(r Repo) error {
		role, err := projectAccess(ctx, r, a, projectID)
		if err != nil {
			return err
		}
		if !rbac.Can(rbac.RunScan, a.OrgRole, role, false) {
			return errForbidden()
		}
		if err := fe.err(); err != nil {
			return err
		}
		project, err := r.Project(ctx, a.vis(), projectID, s.now())
		if err != nil {
			return notFound(err)
		}
		if project.ArchivedAt != nil {
			return errProjectArchived()
		}
		tools := project.DefaultTools
		if in.Tools != nil {
			tools = *in.Tools
		}
		if s.cfg.RateLimitPerHour > 0 {
			if err := r.LockScanRate(ctx, a.UserID); err != nil {
				return err
			}
			now := s.now()
			n, oldest, err := r.ScansSince(ctx, a.UserID, now.Add(-oneHour))
			if err != nil {
				return err
			}
			if n >= s.cfg.RateLimitPerHour {
				return errRateLimited(oldest.Add(oneHour).Sub(now))
			}
		}
		id := ids.New()
		key := ObjectKey(a.OrgID, id)
		sum := strings.ToLower(in.SHA256)
		if err := r.InsertScan(ctx, NewScan{
			ID: id, OrgID: a.OrgID, ProjectID: projectID, CreatedBy: a.UserID,
			FileName: in.FileName, FileSize: in.FileSize, SHA256: sum, ObjectKey: key, Tools: tools,
		}); err != nil {
			return err
		}
		scan, err := r.Scan(ctx, id, false)
		if err != nil {
			return err
		}
		if err := s.audit(ctx, r, a, "scan.created", "scan", id.String(), map[string]any{
			"project_id": projectID.String(), "file_name": in.FileName, "file_size": in.FileSize, "sha256": sum,
		}); err != nil {
			return err
		}
		// Presigning is a local computation; doing it inside the transaction
		// means a failure leaves no orphan scan behind.
		expires := s.now().Add(s.cfg.UploadURLTTL)
		url, headers, err := s.objects.PresignPut(ctx, key, in.FileSize, sum, s.cfg.UploadURLTTL)
		if err != nil {
			return fmt.Errorf("presign upload: %w", err)
		}
		if headers == nil {
			headers = map[string]string{}
		}
		out = CreatedScan{Scan: scan, Upload: Upload{Method: "PUT", URL: url, Headers: headers, ExpiresAt: Time(expires)}}
		return nil
	})
	return out, err
}

// scanAccess loads a scan the caller can see and returns their project role.
func scanAccess(ctx context.Context, r Repo, a *Actor, scanID uuid.UUID, forUpdate bool) (Scan, rbac.Role, error) {
	sc, err := r.Scan(ctx, scanID, forUpdate)
	if err != nil {
		return Scan{}, "", notFound(err)
	}
	role, err := projectAccess(ctx, r, a, sc.ProjectID)
	if err != nil {
		return Scan{}, "", err
	}
	return sc, role, nil
}

// StartScan checks the uploaded object and queues the scan. The River job is
// inserted in the same transaction as the status change, so a scan is never
// queued without a job (or the reverse).
func (s *Service) StartScan(ctx context.Context, a *Actor, scanID uuid.UUID) (Scan, error) {
	// First pass, read-only: authorize and find the object, so the HEAD request
	// to object storage doesn't run while holding row locks.
	var pre Scan
	err := s.inOrg(ctx, a, func(r Repo) error {
		sc, role, err := scanAccess(ctx, r, a, scanID, false)
		if err != nil {
			return err
		}
		if !rbac.Can(rbac.RunScan, a.OrgRole, role, false) {
			return errForbidden()
		}
		if err := requireNotArchived(ctx, r, sc.ProjectID); err != nil {
			return err
		}
		pre = sc
		return nil
	})
	if err != nil {
		return Scan{}, err
	}
	if pre.Status == "queued" || pre.Status == "running" {
		return pre, nil // idempotent
	}
	if pre.Status != "pending_upload" {
		return Scan{}, errConflict("the scan has already finished")
	}
	size, err := s.objects.Head(ctx, pre.ObjectKey)
	if errors.Is(err, ErrObjectNotFound) {
		return Scan{}, errUploadMismatch()
	}
	if err != nil {
		return Scan{}, fmt.Errorf("head upload: %w", err)
	}
	if size != pre.FileSize {
		s.log.InfoContext(ctx, "upload size mismatch", slog.String("scan_id", scanID.String()),
			slog.Int64("want", pre.FileSize), slog.Int64("got", size))
		return Scan{}, errUploadMismatch()
	}

	var out Scan
	err = s.inOrg(ctx, a, func(r Repo) error {
		sc, role, err := scanAccess(ctx, r, a, scanID, true)
		if err != nil {
			return err
		}
		if !rbac.Can(rbac.RunScan, a.OrgRole, role, false) {
			return errForbidden()
		}
		switch sc.Status {
		case "queued", "running":
			out = sc
			return nil // started concurrently: idempotent
		case "pending_upload":
		default:
			return errConflict("the scan has already finished")
		}
		if err := requireNotArchived(ctx, r, sc.ProjectID); err != nil {
			return err // archived meanwhile
		}
		if err := r.MarkScanQueued(ctx, scanID); err != nil {
			return err
		}
		if err := r.EnqueueScan(ctx, worker.ScanArgs{Job: orchestrator.Job{
			ScanID: sc.ID.String(), OrgID: sc.OrgID.String(), ProjectID: sc.ProjectID.String(),
			ObjectKey: sc.ObjectKey, SHA256: sc.SHA256, Tools: sc.Tools,
		}}); err != nil {
			return err
		}
		if out, err = r.Scan(ctx, scanID, false); err != nil {
			return err
		}
		return s.audit(ctx, r, a, "scan.started", "scan", scanID.String(), nil)
	})
	return out, err
}

// CancelScan cancels a scan that hasn't finished. A running scan is marked
// cancelled; the worker notices and stops it.
func (s *Service) CancelScan(ctx context.Context, a *Actor, scanID uuid.UUID) (Scan, error) {
	var out Scan
	err := s.inOrg(ctx, a, func(r Repo) error {
		sc, role, err := scanAccess(ctx, r, a, scanID, true)
		if err != nil {
			return err
		}
		if !rbac.Can(rbac.RunScan, a.OrgRole, role, false) {
			return errForbidden()
		}
		switch sc.Status {
		case "pending_upload", "queued", "running":
		default:
			return errConflict("the scan has already finished")
		}
		if err := r.MarkScanCancelled(ctx, scanID); err != nil {
			return err
		}
		if out, err = r.Scan(ctx, scanID, false); err != nil {
			return err
		}
		return s.audit(ctx, r, a, "scan.cancelled", "scan", scanID.String(), map[string]any{"from": sc.Status})
	})
	return out, err
}

func (s *Service) Scans(ctx context.Context, a *Actor, projectID uuid.UUID, pp PageParams) (Page[Scan], error) {
	limit, err := pp.limit()
	if err != nil {
		return Page[Scan]{}, err
	}
	var after *ScanCursor
	if pp.Cursor != "" {
		after = &ScanCursor{}
		if err := decodeCursor(pp.Cursor, after); err != nil {
			return Page[Scan]{}, err
		}
	}
	var out Page[Scan]
	err = s.inOrg(ctx, a, func(r Repo) error {
		role, err := projectAccess(ctx, r, a, projectID)
		if err != nil {
			return err
		}
		if !rbac.Can(rbac.ViewResults, a.OrgRole, role, false) {
			return errForbidden()
		}
		rows, err := r.Scans(ctx, projectID, after, limit+1)
		if err != nil {
			return err
		}
		out.Items, out.NextCursor = page(rows, limit, func(sc Scan) any {
			return ScanCursor{CreatedAt: sc.CreatedAt.T(), ID: sc.ID}
		})
		return nil
	})
	return out, err
}

func (s *Service) Scan(ctx context.Context, a *Actor, scanID uuid.UUID) (Scan, error) {
	var out Scan
	err := s.inOrg(ctx, a, func(r Repo) error {
		sc, role, err := scanAccess(ctx, r, a, scanID, false)
		if err != nil {
			return err
		}
		if !rbac.Can(rbac.ViewResults, a.OrgRole, role, false) {
			return errForbidden()
		}
		runs, err := r.ToolRuns(ctx, scanID)
		if err != nil {
			return err
		}
		if runs == nil {
			runs = []ToolRun{}
		}
		sc.ToolRuns = &runs
		out = sc
		return nil
	})
	return out, err
}
