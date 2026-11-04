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
	"github.com/aupv9/warden/backend/internal/metrics"
	"github.com/aupv9/warden/backend/internal/notify"
	"github.com/aupv9/warden/backend/internal/registry"
	"github.com/aupv9/warden/backend/internal/scan/importer"
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
	Kind, Target  string
}

func loadScan(ctx context.Context, db DB, id uuid.UUID) (scanRow, error) {
	var r scanRow
	err := db.QueryRow(ctx, `SELECT status, project_id, object_key, sha256, tools, source_deleted_at IS NOT NULL,
		(SELECT key FROM project WHERE id = scan.project_id), kind, target
		FROM scan WHERE id = $1`, id).Scan(&r.Status, &r.ProjectID, &r.ObjectKey, &r.SHA256, &r.Tools, &r.SourceDeleted, &r.ProjectKey,
		&r.Kind, &r.Target)
	return r, err
}

// SBOMKey is where a scan's CycloneDX SBOM lives in object storage.
func SBOMKey(orgID, scanID uuid.UUID) string {
	return fmt.Sprintf("sboms/%s/%s.cdx.json", orgID, scanID)
}

// SPDXKey is where a scan's SPDX SBOM lives in object storage.
func SPDXKey(orgID, scanID uuid.UUID) string {
	return fmt.Sprintf("sboms/%s/%s.spdx.json", orgID, scanID)
}

// storeSBOM uploads the scan's SBOMs. A failure is logged and costs only that
// SBOM: the scan's results don't depend on them. The SPDX file is kept only
// with the CycloneDX one (the scan's sbom_* columns describe the pair, and
// share one expiry).
func (e *Env) storeSBOM(ctx context.Context, org, scanID uuid.UUID, cdx, spdx *sbom.Stamped, log *slog.Logger) *results.SBOM {
	if cdx == nil {
		return nil
	}
	key := SBOMKey(org, scanID)
	if err := e.Store.Put(ctx, key, cdx.Data, cdx.SHA256, sbom.MediaType); err != nil {
		log.Warn("SBOM not stored; the scan has none", "err", err)
		return nil
	}
	out := &results.SBOM{Key: key, Size: int64(len(cdx.Data)), SHA256: cdx.SHA256, Components: cdx.Components,
		ExpiresAt: e.Now().UTC().Add(e.SBOMRetention)}
	if spdx != nil {
		key := SPDXKey(org, scanID)
		if err := e.Store.Put(ctx, key, spdx.Data, spdx.SHA256, sbom.SPDXMediaType); err != nil {
			log.Warn("SPDX SBOM not stored; the scan has only CycloneDX", "err", err)
		} else {
			out.SPDXKey, out.SPDXSize, out.SPDXSHA256 = key, int64(len(spdx.Data)), spdx.SHA256
		}
	}
	return out
}

// RunScan executes one run_scan job. It returns an error only when River should
// retry; every outcome it can decide is written to the scan row instead. A
// retried attempt is idempotent: a finished scan is left alone, results are
// applied in one transaction with the final status, and a scan whose source is
// already gone fails cleanly.
func (e *Env) RunScan(ctx context.Context, job orchestrator.Job, attempt int) error {
	started := time.Now()
	org, err1 := uuid.Parse(job.OrgID)
	scanID, err2 := uuid.Parse(job.ScanID)
	if err := errors.Join(err1, err2); err != nil {
		return river.JobCancel(fmt.Errorf("bad job ids: %w", err))
	}
	var sc scanRow
	var orgRules scanOrgRules
	var pr *pullRow
	var imp *orchestrator.Import
	log := e.Log.With("scan_id", scanID, "org_id", org, "attempt", attempt)
	err := e.Tx(ctx, org, func(db DB) error {
		var err error
		if sc, err = loadScan(ctx, db, scanID); err != nil {
			return err
		}
		if sc.Status == string(orchestrator.Queued) || sc.Status == string(orchestrator.Running) {
			if orgRules, err = loadOrgRules(ctx, db, org, sc.ProjectID, ruleTools(sc), log); err != nil {
				return err
			}
			switch sc.Kind {
			case orchestrator.KindImage:
				pr, err = loadPull(ctx, db, org, scanID, e.registryClient().Allowed)
			case orchestrator.KindImport:
				imp, err = loadImport(ctx, db, scanID)
			}
		}
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return river.JobCancel(fmt.Errorf("scan %s not found", scanID))
	}
	if err != nil {
		return err // database unavailable: retry
	}

	done := func(st orchestrator.ScanStatus, err error) error { return scanDone(sc.Kind, st, started, err) }

	switch orchestrator.ScanStatus(sc.Status) {
	case orchestrator.Cancelled:
		return done(orchestrator.Cancelled, e.finishCancelled(ctx, org, scanID, sc))
	case orchestrator.Completed, orchestrator.Partial, orchestrator.Failed:
		return nil
	case orchestrator.PendingUpload:
		return river.JobCancel(errors.New("scan was never started"))
	}
	// A pulled image has no upload: the worker fetches it from its registry.
	var pull *pullSpec
	if pr != nil {
		if pull, err = pr.open(e.Registry.Keys, org); err != nil {
			logPullSetup(log, err)
			return done(orchestrator.Failed, e.finishFailed(ctx, org, scanID, sc.Tools, registry.CodeFailed))
		}
		job.ObjectKey, job.SHA256, job.Pulled = "", "", true
		if sc.ObjectKey != nil {
			// Where an upload would be (the API sets it): never written, but
			// deleted and stamped like one.
			job.ObjectKey = *sc.ObjectKey
		}
	} else if sc.SourceDeleted || sc.ObjectKey == nil || sc.SHA256 == nil {
		return done(orchestrator.Failed, e.finishFailed(ctx, org, scanID, sc.Tools, CodeSourceUnavailable))
	} else {
		job.ObjectKey, job.SHA256, job.Pulled = *sc.ObjectKey, *sc.SHA256, false
	}

	// The database is the source of truth; the job only points at the scan.
	job.ProjectID, job.Tools, job.Attempt = sc.ProjectID.String(), sc.Tools, attempt
	job.ProjectKey, job.Kind, job.Target = sc.ProjectKey, sc.Kind, sc.Target
	var ruleRefs []results.OrgRuleRef
	job.OrgRules, ruleRefs = orgRules.render(log)
	job.Import = imp
	if imp != nil {
		// The org's Gitleaks rules screen the import's strings; they find
		// nothing the import stores, so they aren't recorded as run and
		// fix no org rule's issue.
		ruleRefs = nil
	}
	// A crashed attempt may have left its scratch directory behind.
	if err := zipcheck.RemoveAll(filepath.Join(e.ScratchDir, scanID.String())); err != nil {
		return err
	}

	execCtx, cancel := context.WithTimeout(ctx, e.ScanTimeout)
	out, err := orchestrator.Execute(execCtx, job, &liveDeps{env: e, org: org, scan: scanID, attempt: attempt, kind: sc.Kind,
		orgRules: job.OrgRules, pull: pull})
	timedOut := errors.Is(execCtx.Err(), context.DeadlineExceeded)
	cancel()

	fin, cancelFin := context.WithTimeout(context.WithoutCancel(ctx), finalizeTimeout)
	defer cancelFin()
	switch {
	case errors.Is(err, errNotRunnable) || (err == nil && out.Status == orchestrator.Cancelled):
		return done(orchestrator.Cancelled, e.finishCancelled(fin, org, scanID, sc))
	case err != nil:
		code := errorCode(err, timedOut)
		if code == CodeTooLarge && sc.Kind == orchestrator.KindImport {
			code = importer.CodeTooLarge
		}
		log.Error("scan failed", "code", code, "err", err)
		return done(orchestrator.Failed, e.finishFailed(fin, org, scanID, sc.Tools, code))
	case out.Status == orchestrator.Failed:
		code := out.ErrorCode
		// An import whose screening ran out of time says so: nothing was stored.
		if timedOut && code != importer.CodeScreenFailed {
			code = CodeTimeout
		}
		return done(orchestrator.Failed, e.finishFailed(fin, org, scanID, sc.Tools, code))
	}

	// The SBOM columns are set with the results, so they are never half set;
	// if the results aren't recorded, the stored object goes too.
	stored := e.storeSBOM(fin, org, scanID, out.SBOM, out.SPDX, log)
	var plan results.Plan
	err = e.Tx(fin, org, func(db DB) error {
		var err error
		plan, err = results.Process(fin, db, results.Input{
			OrgID: org, ProjectID: sc.ProjectID, ScanID: scanID, Status: string(out.Status), Target: sc.Target,
			Runs: out.Runs, Findings: out.Findings, Licenses: out.Licenses, Packages: out.Packages, GuardRatio: e.GuardRatio, Now: e.Now().UTC(),
			SBOM: stored, History: history(out.History), OrgRules: loadedRules(ruleRefs, out.OrgRulesLoaded, log),
			Import: importResult(imp, out.Import),
		})
		if err != nil {
			return err
		}
		return skipUnfinishedTools(fin, db, org, scanID, sc.Tools, e.Images)
	})
	if err != nil && stored != nil {
		for _, key := range []string{stored.Key, stored.SPDXKey} {
			if key == "" {
				continue
			}
			if derr := e.Store.Delete(fin, key); derr != nil {
				log.Error("failed to delete the SBOM of an unrecorded scan", "object_key", key, "err", derr)
			}
		}
	}
	if errors.Is(err, results.ErrScanNotRunning) {
		return done(orchestrator.Cancelled, e.finishCancelled(fin, org, scanID, sc))
	}
	if err != nil {
		// The source is gone, so a retry couldn't rescan; fail the scan now.
		log.Error("result processing failed", "err", err)
		return done(orchestrator.Failed, e.finishFailed(fin, org, scanID, sc.Tools, CodeInternal))
	}
	metrics.ScanFinished(sc.Kind, string(out.Status), time.Since(started))
	log.Info("scan finished", "status", out.Status, "new", plan.Stats.New, "fixed", plan.Stats.Fixed,
		"reopened", plan.Stats.Reopened, "total", plan.Stats.Total, "needs_confirmation", plan.NeedsConfirmation)
	if c := plan.Components; c != nil {
		log.Info("component inventory replaced", "added", c.Added, "kept", c.Kept, "removed", c.Removed, "skipped", c.Skipped)
	}
	return nil
}

// scanDone records a scan's final status and its job's duration in the
// metrics once the worker has written that status (err == nil). A job that
// returns an error is retried and records when it ends.
func scanDone(kind string, st orchestrator.ScanStatus, started time.Time, err error) error {
	if err == nil {
		metrics.ScanFinished(kind, string(st), time.Since(started))
	}
	return err
}

// history maps the orchestrator's history report onto the processor's.
func history(h *orchestrator.History) *results.History {
	if h == nil {
		return nil
	}
	return &results.History{Commits: h.Commits, Truncated: h.Truncated}
}

// ruleTools are the tools whose org rules a scan loads: its own, or for an
// import Gitleaks, which screens the imported strings.
func ruleTools(sc scanRow) []string {
	if sc.Kind == orchestrator.KindImport {
		return []string{"gitleaks"}
	}
	return sc.Tools
}

// loadImport reads an import scan's settings (migration 00016).
func loadImport(ctx context.Context, db DB, id uuid.UUID) (*orchestrator.Import, error) {
	var tool, category, format *string
	if err := db.QueryRow(ctx, `SELECT import_tool, import_category, import_format FROM scan WHERE id = $1`, id).
		Scan(&tool, &category, &format); err != nil {
		return nil, err
	}
	if tool == nil || category == nil || format == nil {
		return nil, errors.New("import scan without its import settings")
	}
	return &orchestrator.Import{Tool: *tool, Category: *category, Format: *format}, nil
}

// importResult maps an import's settings and outcome onto the processor's.
func importResult(imp *orchestrator.Import, st *orchestrator.ImportStats) *results.Import {
	if imp == nil {
		return nil
	}
	out := &results.Import{Tool: imp.Tool}
	if st != nil {
		out.ToolVersion, out.Results, out.Dropped, out.Screened = st.ToolVersion, st.Results, st.Dropped, st.Screened
	}
	return out
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
