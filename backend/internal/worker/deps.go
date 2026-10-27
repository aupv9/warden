package worker

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aupv9/warden/backend/internal/ids"
	"github.com/aupv9/warden/backend/internal/scan/orchestrator"
	"github.com/aupv9/warden/backend/internal/scan/sandbox"
	"github.com/aupv9/warden/backend/internal/scan/sarif"
)

// errNotRunnable: the scan left queued/running (cancelled) before it started.
var errNotRunnable = errors.New("scan is no longer runnable")

// liveDeps implements orchestrator.Deps for one scan.
type liveDeps struct {
	env     *Env
	org     uuid.UUID
	scan    uuid.UUID
	attempt int
}

var _ orchestrator.Deps = (*liveDeps)(nil)

func (d *liveDeps) ScratchRoot() string { return d.env.ScratchDir }

func (d *liveDeps) Limits() orchestrator.Limits { return d.env.Limits }

func (d *liveDeps) Download(ctx context.Context, key, dest string) error {
	return d.env.Store.Download(ctx, key, dest)
}

// DeleteObject deletes the upload and records it; if deletion fails the
// retention sweep retries (source_deleted_at stays NULL).
func (d *liveDeps) DeleteObject(ctx context.Context, key string) error {
	if err := d.env.Store.Delete(ctx, key); err != nil {
		return err
	}
	return d.env.Tx(ctx, d.org, func(db DB) error {
		_, err := db.Exec(ctx, `UPDATE scan SET source_deleted_at = now() WHERE id = $1 AND source_deleted_at IS NULL`, d.scan)
		return err
	})
}

func (d *liveDeps) SetStatus(ctx context.Context, _ string, st orchestrator.ScanStatus) error {
	if st != orchestrator.Running {
		// Final statuses are written by the worker (and the result processor).
		return fmt.Errorf("unexpected status %q from orchestrator", st)
	}
	return d.env.Tx(ctx, d.org, func(db DB) error {
		tag, err := db.Exec(ctx, `UPDATE scan SET status = 'running', started_at = coalesce(started_at, now())
			WHERE id = $1 AND status IN ('queued', 'running')`, d.scan)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return errNotRunnable
		}
		return nil
	})
}

// toolError is what the API shows for a failed tool. Scanner stderr can quote
// the scanned source (parse errors print code), so it is never stored; only
// Warden's own messages are.
func toolError(r sandbox.ToolRun) *string {
	var msg string
	switch {
	case r.Status == sandbox.Timeout:
		msg = "timeout"
	case r.Status != sandbox.Failed:
		return nil
	case strings.HasPrefix(r.Error, sarif.ErrSARIF.Error()+":"):
		msg = r.Error
		if len(msg) > 300 {
			msg = msg[:300]
		}
	case r.Error == "cancelled":
		msg = "cancelled"
	case r.Error == errNoImage:
		msg = errNoImage
	default:
		msg = "scanner failed (details in worker logs)"
	}
	return &msg
}

const upsertToolRun = `INSERT INTO scan_tool_run (id, org_id, scan_id, tool, tool_version, image_digest, status, duration_ms, error)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	ON CONFLICT (scan_id, tool) DO UPDATE SET tool_version = EXCLUDED.tool_version, image_digest = EXCLUDED.image_digest,
	  status = EXCLUDED.status, duration_ms = EXCLUDED.duration_ms, error = EXCLUDED.error, findings_count = NULL`

func (d *liveDeps) SetToolStatus(ctx context.Context, _ string, r sandbox.ToolRun) error {
	version, digest := imageInfo(d.env.Images[r.Tool])
	var dur *int64
	if r.Status != sandbox.Running && r.Status != sandbox.Queued {
		dur = &r.DurationMS
	}
	return d.env.Tx(ctx, d.org, func(db DB) error {
		_, err := db.Exec(ctx, upsertToolRun, ids.New(), d.org, d.scan, r.Tool, version, digest, string(r.Status), dur, toolError(r))
		return err
	})
}

func (d *liveDeps) IsCancelled(ctx context.Context, _ string) (bool, error) {
	var st string
	err := d.env.Tx(ctx, d.org, func(db DB) error {
		return db.QueryRow(ctx, `SELECT status FROM scan WHERE id = $1`, d.scan).Scan(&st)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return true, nil // gone: stop
	}
	return st == string(orchestrator.Cancelled), err
}

func (d *liveDeps) HMACKey(_ context.Context, orgID string) ([]byte, error) {
	return OrgKey(d.env.HMACMaster, orgID)
}

const errNoImage = "no scanner image configured"

func (d *liveDeps) RunTool(ctx context.Context, tool, scanID, scanDir string) sandbox.ToolRun {
	image := d.env.Images[tool]
	if image == "" {
		return sandbox.ToolRun{Tool: tool, Status: sandbox.Failed, Error: errNoImage}
	}
	if d.attempt > 1 {
		// A crashed attempt may have left its container; names are per scan+tool.
		d.env.Sandbox.Kill(scanID, tool)
	}
	r := d.env.Sandbox.Run(ctx, sandbox.Tools[tool], sandbox.RunConfig{
		ScanID: scanID, ScanDir: scanDir, Image: image, Runtime: d.env.Runtime, MirrorDir: d.env.MirrorDir,
	})
	if r.Status != sandbox.Succeeded {
		attrs := []any{"scan_id", scanID, "tool", tool, "status", r.Status}
		// Gitleaks' stderr may echo what it detected; operators get the other tools' tail.
		if tool != "gitleaks" {
			attrs = append(attrs, "stderr_tail", r.Error)
		}
		d.env.Log.Warn("scanner did not succeed", attrs...)
	}
	return r
}

func (d *liveDeps) KillTool(scanID, tool string) { d.env.Sandbox.Kill(scanID, tool) }
