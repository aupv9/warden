package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/rbac"
	"github.com/aupv9/warden/backend/internal/domain/registry"
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
	// Kind is source (default: a .zip of code), image (a docker save .tar)
	// or history (a git bundle, .bundle).
	Kind     string  `json:"kind"`
	Target   *string `json:"target"`
	ImageRef *string `json:"image_ref"`
}

// Scan kinds.
const (
	KindSource  = orchestrator.KindSource
	KindImage   = orchestrator.KindImage
	KindHistory = orchestrator.KindHistory
)

// HistoryTarget is the target of every history scan and its issues.
const HistoryTarget = orchestrator.HistoryTarget

// ImageTarget is an image repository without tag or digest (the OpenAPI
// CreateScanRequest.target pattern): lower-case path components, an optional
// registry host and port. Image issues are tracked per target.
var ImageTarget = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]{1,5})?(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$`)

const (
	maxTarget   = 255
	maxImageRef = 512
)

// ObjectKey is where a source scan's upload lives in object storage.
func ObjectKey(orgID, scanID uuid.UUID) string {
	return fmt.Sprintf("scans/%s/%s.zip", orgID, scanID)
}

// ImageObjectKey is where an image scan's tarball lives in object storage.
func ImageObjectKey(orgID, scanID uuid.UUID) string {
	return fmt.Sprintf("scans/%s/%s.tar", orgID, scanID)
}

// HistoryObjectKey is where a history scan's git bundle lives in object storage.
func HistoryObjectKey(orgID, scanID uuid.UUID) string {
	return fmt.Sprintf("scans/%s/%s.bundle", orgID, scanID)
}

func (s *Service) validateScanInput(in CreateScanInput) fieldErrors {
	fe := fieldErrors{}
	image, history := in.Kind == KindImage, in.Kind == KindHistory
	if in.Kind != "" && in.Kind != KindSource && !image && !history {
		fe.add("kind", "must be source, image or history (imports: POST …/scans/import)")
	}
	ext, maxBytes := ".zip", s.cfg.UploadMaxBytes
	switch {
	case image:
		ext, maxBytes = ".tar", s.cfg.ImageUploadMaxBytes
	case history:
		ext, maxBytes = ".bundle", s.cfg.HistoryUploadMaxBytes
	}
	n := in.FileName
	if !strings.HasSuffix(strings.ToLower(n), ext) || len(n) <= len(ext) || utf8.RuneCountInString(n) > 255 ||
		strings.ContainsAny(n, `/\`) || !validText(n) || strings.ContainsFunc(n, isControl) {
		fe.add("file_name", "must be a "+ext+" file name of at most 255 characters, without / or \\")
	}
	if in.FileSize < 1 || in.FileSize > maxBytes {
		fe.add("file_size", fmt.Sprintf("must be between 1 and %d bytes", maxBytes))
	}
	if !sha256Hex.MatchString(in.SHA256) {
		fe.add("sha256", "must be 64 hexadecimal characters")
	}
	if in.Tools != nil && !validTools(*in.Tools) {
		fe.add("tools", "must be a non-empty list of distinct tools: gitleaks, opengrep, trivy, checkov")
	}
	if history {
		// Only Gitleaks reads a git bundle (in git mode); the other scanners
		// read a source tree, and only Gitleaks output is redacted.
		if in.Tools != nil && (len(*in.Tools) != 1 || (*in.Tools)[0] != "gitleaks") {
			fe.add("tools", "history scans run gitleaks only")
		}
	}
	if !image {
		if in.Target != nil {
			fe.add("target", "is only for image scans")
		}
		if in.ImageRef != nil {
			fe.add("image_ref", "is only for image scans")
		}
		return fe
	}
	if in.Tools != nil && !validImageTools(*in.Tools) {
		fe.add("tools", imageToolsMsg)
	}
	if in.Target == nil || len(*in.Target) > maxTarget || !ImageTarget.MatchString(*in.Target) {
		fe.add("target", "must be an image repository without tag or digest, such as ghcr.io/acme/api")
	}
	if r := in.ImageRef; r != nil && (*r == "" || utf8.RuneCountInString(*r) > maxImageRef || !validText(*r) || strings.ContainsFunc(*r, isControl)) {
		fe.add("image_ref", fmt.Sprintf("must be an image reference of at most %d characters", maxImageRef))
	}
	return fe
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f }

// Image scans run Trivy (packages) and Gitleaks (secrets in the layers, read
// inside its sandbox); the other scanners read source code.
const imageToolsMsg = "image scans run trivy and/or gitleaks"

var defaultImageTools = []string{"trivy", "gitleaks"}

func validImageTools(tools []string) bool {
	return validTools(tools) && !slices.ContainsFunc(tools, func(t string) bool { return !slices.Contains(defaultImageTools, t) })
}

// imageTools is the tools asked for, else both.
func imageTools(tools *[]string) []string {
	if tools == nil {
		return slices.Clone(defaultImageTools)
	}
	return *tools
}

// checkScanRate holds the per-user hourly scan limit (uploads and pulls alike).
func (s *Service) checkScanRate(ctx context.Context, r Repo, a *Actor) error {
	if s.cfg.RateLimitPerHour <= 0 {
		return nil
	}
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
	return nil
}

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
		kind, target := KindSource, ""
		switch in.Kind {
		case KindImage:
			kind, target, tools = KindImage, *in.Target, imageTools(in.Tools)
		case KindHistory:
			kind, target, tools = KindHistory, HistoryTarget, []string{"gitleaks"}
		}
		if err := s.checkScanRate(ctx, r, a); err != nil {
			return err
		}
		id := ids.New()
		key := ObjectKey(a.OrgID, id)
		switch kind {
		case KindImage:
			key = ImageObjectKey(a.OrgID, id)
		case KindHistory:
			key = HistoryObjectKey(a.OrgID, id)
		}
		sum := strings.ToLower(in.SHA256)
		ns := NewScan{
			ID: id, OrgID: a.OrgID, ProjectID: projectID, CreatedBy: a.UserID,
			FileName: in.FileName, FileSize: in.FileSize, SHA256: sum, ObjectKey: key, Tools: tools,
			Kind: kind, Target: target, ImageRef: in.ImageRef,
		}
		if a.Token != nil {
			ns.ViaToken = &a.Token.ID
		}
		if err := r.InsertScan(ctx, ns); err != nil {
			return err
		}
		scan, err := r.Scan(ctx, id, false)
		if err != nil {
			return err
		}
		if err := s.audit(ctx, r, a, "scan.created", "scan", id.String(), map[string]any{
			"project_id": projectID.String(), "file_name": in.FileName, "file_size": in.FileSize, "sha256": sum,
			"kind": kind, "target": target,
		}); err != nil {
			return err
		}
		up, err := s.presignUpload(ctx, key, in.FileSize, sum)
		if err != nil {
			return err
		}
		out = CreatedScan{Scan: scan, Upload: up}
		return nil
	})
	return out, err
}

// presignUpload is the PUT a client uploads a scan's file with. Presigning is
// a local computation; callers do it inside the transaction that records the
// scan, so a failure leaves no orphan scan behind.
func (s *Service) presignUpload(ctx context.Context, key string, size int64, sum string) (Upload, error) {
	expires := s.now().Add(s.cfg.UploadURLTTL)
	url, headers, err := s.objects.PresignPut(ctx, key, size, sum, s.cfg.UploadURLTTL)
	if err != nil {
		return Upload{}, fmt.Errorf("presign upload: %w", err)
	}
	if headers == nil {
		headers = map[string]string{}
	}
	return Upload{Method: "PUT", URL: url, Headers: headers, ExpiresAt: Time(expires)}, nil
}

// PullScanInput is POST …/scans/pull: an image Warden pulls itself.
type PullScanInput struct {
	ImageRef string    `json:"image_ref"`
	Tools    *[]string `json:"tools"`
}

// CreatePullScan queues an image scan with no upload: the worker pulls
// image_ref (pinned by digest) with the org's credentials for its host, else
// anonymously, and scans it like an uploaded tarball (it branches on
// scan.pulled). The scan's target is the repository. It counts against the
// hourly scan limit, and the River job is inserted in the same transaction as
// the scan, which is queued at once.
func (s *Service) CreatePullScan(ctx context.Context, a *Actor, projectID uuid.UUID, in PullScanInput) (Scan, error) {
	fe := fieldErrors{}
	ref, err := registry.ParseRef(in.ImageRef, s.pullHostAllowed)
	if err != nil {
		fe.add("image_ref", err.Error())
	} else if !ImageTarget.MatchString(ref.Name()) {
		fe.add("image_ref", registry.ErrRefFormat.Error())
	}
	if in.Tools != nil && !validImageTools(*in.Tools) {
		fe.add("tools", imageToolsMsg)
	}
	var out Scan
	err = s.inOrg(ctx, a, func(r Repo) error {
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
		if err := requireNotArchived(ctx, r, projectID); err != nil {
			return err
		}
		if err := s.checkScanRate(ctx, r, a); err != nil {
			return err
		}
		id, tools, target, imageRef := ids.New(), imageTools(in.Tools), ref.Name(), ref.String()
		// The worker stores the tarball it builds where an upload would be,
		// so it is cleaned up like one.
		ns := NewScan{
			ID: id, OrgID: a.OrgID, ProjectID: projectID, CreatedBy: a.UserID,
			FileName: path.Base(ref.Repository) + ".tar", ObjectKey: ImageObjectKey(a.OrgID, id), Tools: tools,
			Kind: KindImage, Target: target, ImageRef: &imageRef, Pulled: true,
		}
		if a.Token != nil {
			ns.ViaToken = &a.Token.ID
		}
		if err := r.InsertScan(ctx, ns); err != nil {
			return err
		}
		if err := r.MarkScanQueued(ctx, id); err != nil {
			return err
		}
		if err := r.EnqueueScan(ctx, worker.ScanArgs{Job: orchestrator.Job{
			ScanID: id.String(), OrgID: a.OrgID.String(), ProjectID: projectID.String(),
			ObjectKey: ns.ObjectKey, Tools: tools,
		}}); err != nil {
			return err
		}
		if out, err = r.Scan(ctx, id, false); err != nil {
			return err
		}
		return s.audit(ctx, r, a, "scan.created", "scan", id.String(), map[string]any{
			"project_id": projectID.String(), "kind": KindImage, "target": target, "image_ref": imageRef, "pulled": true,
		})
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
