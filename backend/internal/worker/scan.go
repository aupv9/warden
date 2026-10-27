package worker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/aupv9/warden/backend/internal/ids"
	"github.com/aupv9/warden/backend/internal/notify"
	"github.com/aupv9/warden/backend/internal/scan/orchestrator"
	"github.com/aupv9/warden/backend/internal/scan/results"
	"github.com/aupv9/warden/backend/internal/scan/sbom"
	"github.com/aupv9/warden/backend/internal/scan/zipcheck"
	"github.com/aupv9/warden/backend/internal/storage"
)

// Error codes the worker sets on scan.error_code (zipcheck adds its own, e.g.
// ZIP_PATH_TRAVERSAL, CHECKSUM_MISMATCH; the orchestrator ALL_SCANNERS_FAILED).
const (
	CodeTimeout           = "TIMEOUT"
	CodeSourceNotFound    = "SOURCE_NOT_FOUND"
	CodeSourceUnavailable = "SOURCE_UNAVAILABLE" // a previous attempt already deleted it
	CodeTooLarge          = "ZIP_TOO_LARGE"
	CodeInternal          = "INTERNAL_ERROR"
	CodeUploadAbandoned   = "UPLOAD_ABANDONED"
)

// finalizeTimeout bounds the writes after Execute; they use a context detached
// from the job's, which may already be past its deadline.
const finalizeTimeout = 5 * time.Minute

type scanRow struct {
	Status        string
	ProjectID     uuid.UUID
	ObjectKey     *string
	SHA256        *string
	Tools         []string
	SourceDeleted bool
	ProjectKey    string
}

func loadScan(ctx context.Context, db DB, id uuid.UUID) (scanRow, error) {
	var r scanRow
	err := db.QueryRow(ctx, `SELECT status, project_id, object_key, sha256, tools, source_deleted_at IS NOT NULL,
		(SELECT key FROM project WHERE id = scan.project_id)
		FROM scan WHERE id = $1`, id).Scan(&r.Status, &r.ProjectID, &r.ObjectKey, &r.SHA256, &r.Tools, &r.SourceDeleted, &r.ProjectKey)
	return r, err
}

// SBOMKey is where a scan's SBOM lives in object storage.
func SBOMKey(orgID, scanID uuid.UUID) string {
	return fmt.Sprintf("sboms/%s/%s.cdx.json", orgID, scanID)
}

// storeSBOM uploads the scan's SBOM. A failure is logged and costs only the
// SBOM (nil): the scan's results don't depend on it.
func (e *Env) storeSBOM(ctx context.Context, org, scanID uuid.UUID, s *sbom.Stamped, log *slog.Logger) *results.SBOM {
	if s == nil {
		return nil
	}
	key := SBOMKey(org, scanID)
	if err := e.Store.Put(ctx, key, s.Data, s.SHA256, sbom.MediaType); err != nil {
		log.Warn("SBOM not stored; the scan has none", "err", err)
		return nil
	}
	return &results.SBOM{Key: key, Size: int64(len(s.Data)), SHA256: s.SHA256, Components: s.Components,
		ExpiresAt: e.Now().UTC().Add(e.SBOMRetention)}
}

// RunScan executes one run_scan job. It returns an error only when River should
// retry; every outcome it can decide is written to the scan row instead. A
// retried attempt is idempotent: a finished scan is left alone, results are
// applied in one transaction with the final status, and a scan whose source is
// already gone fails cleanly.
func (e *Env) RunScan(ctx context.Context, job orchestrator.Job, attempt int) error {
	org, err1 := uuid.Parse(job.OrgID)
	scanID, err2 := uuid.Parse(job.ScanID)
	if err := errors.Join(err1, err2); err != nil {
		return river.JobCancel(fmt.Errorf("bad job ids: %w", err))
	}
	var sc scanRow
	err := e.Tx(ctx, org, func(db DB) error {
		var err error
		sc, err = loadScan(ctx, db, scanID)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return river.JobCancel(fmt.Errorf("scan %s not found", scanID))
	}
	if err != nil {
		return err // database unavailable: retry
	}
	log := e.Log.With("scan_id", scanID, "org_id", org, "attempt", attempt)

	switch orchestrator.ScanStatus(sc.Status) {
	case orchestrator.Cancelled:
		return e.finishCancelled(ctx, org, scanID, sc)
	case orchestrator.Completed, orchestrator.Partial, orchestrator.Failed:
		return nil
	case orchestrator.PendingUpload:
		return river.JobCancel(errors.New("scan was never started"))
	}
	if sc.SourceDeleted || sc.ObjectKey == nil || sc.SHA256 == nil {
		return e.finishFailed(ctx, org, scanID, sc.Tools, CodeSourceUnavailable)
	}

	// The database is the source of truth; the job only points at the scan.
	job.ProjectID, job.ObjectKey, job.SHA256, job.Tools, job.Attempt = sc.ProjectID.String(), *sc.ObjectKey, *sc.SHA256, sc.Tools, attempt
	job.ProjectKey = sc.ProjectKey
	// A crashed attempt may have left its scratch directory behind.
	if err := zipcheck.RemoveAll(filepath.Join(e.ScratchDir, scanID.String())); err != nil {
		return err
	}

	execCtx, cancel := context.WithTimeout(ctx, e.ScanTimeout)
	out, err := orchestrator.Execute(execCtx, job, &liveDeps{env: e, org: org, scan: scanID, attempt: attempt})
	timedOut := errors.Is(execCtx.Err(), context.DeadlineExceeded)
	cancel()

	fin, cancelFin := context.WithTimeout(context.WithoutCancel(ctx), finalizeTimeout)
	defer cancelFin()
	switch {
	case errors.Is(err, errNotRunnable) || (err == nil && out.Status == orchestrator.Cancelled):
		return e.finishCancelled(fin, org, scanID, sc)
	case err != nil:
		code := errorCode(err, timedOut)
		log.Error("scan failed", "code", code, "err", err)
		return e.finishFailed(fin, org, scanID, sc.Tools, code)
	case out.Status == orchestrator.Failed:
		code := out.ErrorCode
		if timedOut {
			code = CodeTimeout
		}
		return e.finishFailed(fin, org, scanID, sc.Tools, code)
	}

	// The SBOM columns are set with the results, so they are never half set;
	// if the results aren't recorded, the stored object goes too.
	stored := e.storeSBOM(fin, org, scanID, out.SBOM, log)
	var plan results.Plan
	err = e.Tx(fin, org, func(db DB) error {
		var err error
		plan, err = results.Process(fin, db, results.Input{
			OrgID: org, ProjectID: sc.ProjectID, ScanID: scanID, Status: string(out.Status),
			Runs: out.Runs, Findings: out.Findings, Licenses: out.Licenses, GuardRatio: e.GuardRatio, Now: e.Now().UTC(),
			SBOM: stored,
		})
		if err != nil {
			return err
		}
		return skipUnfinishedTools(fin, db, org, scanID, sc.Tools, e.Images)
	})
	if err != nil && stored != nil {
		if derr := e.Store.Delete(fin, stored.Key); derr != nil {
			log.Error("failed to delete the SBOM of an unrecorded scan", "object_key", stored.Key, "err", derr)
		}
	}
	if errors.Is(err, results.ErrScanNotRunning) {
		return e.finishCancelled(fin, org, scanID, sc)
	}
	if err != nil {
		// The source is gone, so a retry couldn't rescan; fail the scan now.
		log.Error("result processing failed", "err", err)
		return e.finishFailed(fin, org, scanID, sc.Tools, CodeInternal)
	}
	log.Info("scan finished", "status", out.Status, "new", plan.Stats.New, "fixed", plan.Stats.Fixed,
		"reopened", plan.Stats.Reopened, "total", plan.Stats.Total, "needs_confirmation", plan.NeedsConfirmation)
	return nil
}

func errorCode(err error, timedOut bool) string {
	switch {
	case timedOut:
		return CodeTimeout
	case errors.Is(err, storage.ErrNotFound):
		return CodeSourceNotFound
	case errors.Is(err, storage.ErrTooLarge):
		return CodeTooLarge
	}
	return CodeInternal
}

// skipUnfinishedTools records tools that never ran (or never reported) as
// skipped, so every selected tool has a terminal status.
func skipUnfinishedTools(ctx context.Context, db DB, org, scanID uuid.UUID, tools []string, images map[string]string) error {
	for _, t := range tools {
		version, digest := imageInfo(images[t])
		if _, err := db.Exec(ctx, `INSERT INTO scan_tool_run (id, org_id, scan_id, tool, tool_version, image_digest, status)
			VALUES ($1, $2, $3, $4, $5, $6, 'skipped')
			ON CONFLICT (scan_id, tool) DO UPDATE SET status = 'skipped'
			WHERE scan_tool_run.status IN ('queued', 'running')`, ids.New(), org, scanID, t, version, digest); err != nil {
			return fmt.Errorf("skip tool %s: %w", t, err)
		}
	}
	return nil
}

func (e *Env) finishFailed(ctx context.Context, org, scanID uuid.UUID, tools []string, code string) error {
	return e.Tx(ctx, org, func(db DB) error {
		// A scan cancelled meanwhile stays cancelled.
		tag, err := db.Exec(ctx, `UPDATE scan SET status = 'failed', error_code = $2, finished_at = now()
			WHERE id = $1 AND status IN ('queued', 'running')`, scanID, code)
		if err != nil {
			return err
		}
		if tag.RowsAffected() > 0 {
			if err := notify.Insert(ctx, db, notify.Event{OrgID: org, Type: notify.ScanFinished,
				Payload: notify.Payload{ScanID: notify.ID(scanID)}}); err != nil {
				return err
			}
		}
		return skipUnfinishedTools(ctx, db, org, scanID, tools, e.Images)
	})
}

// finishCancelled stamps a cancelled scan and makes sure its upload is gone. It
// changes no issue.
func (e *Env) finishCancelled(ctx context.Context, org, scanID uuid.UUID, sc scanRow) error {
	if !sc.SourceDeleted && sc.ObjectKey != nil {
		if err := e.Store.Delete(ctx, *sc.ObjectKey); err != nil {
			e.Log.Error("failed to delete upload of cancelled scan; retention sweep will retry", "scan_id", scanID, "err", err)
		} else {
			sc.SourceDeleted = true
		}
	}
	return e.Tx(ctx, org, func(db DB) error {
		if _, err := db.Exec(ctx, `UPDATE scan SET finished_at = coalesce(finished_at, now()),
			source_deleted_at = CASE WHEN $2 THEN coalesce(source_deleted_at, now()) ELSE source_deleted_at END
			WHERE id = $1 AND status = 'cancelled'`, scanID, sc.SourceDeleted); err != nil {
			return err
		}
		return skipUnfinishedTools(ctx, db, org, scanID, sc.Tools, e.Images)
	})
}
