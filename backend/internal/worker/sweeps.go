package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aupv9/warden/backend/internal/domain/issuestate"
	"github.com/aupv9/warden/backend/internal/domain/severity"
	"github.com/aupv9/warden/backend/internal/notify"
	"github.com/aupv9/warden/backend/internal/scan/results"
)

const sweepBatch = 500

// forEachOrg runs fn once per organization. organization has no RLS (it is the
// tenant list); everything fn touches is scoped with e.Tx(ctx, org, …). One
// org's failure doesn't stop the others.
func (e *Env) forEachOrg(ctx context.Context, job string, fn func(org uuid.UUID) error) error {
	var orgs []uuid.UUID
	err := e.Tx(ctx, uuid.Nil, func(db DB) error {
		rows, err := db.Query(ctx, `SELECT id FROM organization ORDER BY id`)
		if err != nil {
			return err
		}
		orgs, err = pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		return err
	})
	if err != nil {
		return fmt.Errorf("%s: list organizations: %w", job, err)
	}
	var errs []error
	for _, org := range orgs {
		if err := fn(org); err != nil {
			e.Log.Error("periodic job failed for organization", "job", job, "org_id", org, "err", err)
			errs = append(errs, fmt.Errorf("org %s: %w", org, err))
		}
	}
	return errors.Join(errs...)
}

type sourceRow struct {
	ID        uuid.UUID
	ObjectKey *string
	Tools     []string
}

func collectSources(rows pgx.Rows) ([]sourceRow, error) {
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (sourceRow, error) {
		var s sourceRow
		return s, r.Scan(&s.ID, &s.ObjectKey, &s.Tools)
	})
}

// PurgeExpiredSources cancels abandoned uploads and deletes uploaded objects
// that outlived SourceRetention (a failed delete, a crashed worker).
func (e *Env) PurgeExpiredSources(ctx context.Context) error {
	now := e.Now()
	return e.forEachOrg(ctx, "purge_expired_sources", func(org uuid.UUID) error {
		var abandoned, expired []sourceRow
		err := e.Tx(ctx, org, func(db DB) error {
			rows, err := db.Query(ctx, `UPDATE scan SET status = 'cancelled', error_code = $2, finished_at = $3
				WHERE status = 'pending_upload' AND created_at < $1 RETURNING id, object_key, tools`,
				now.Add(-e.AbandonUploadAfter), CodeUploadAbandoned, now)
			if err != nil {
				return err
			}
			if abandoned, err = collectSources(rows); err != nil {
				return err
			}
			for _, s := range abandoned {
				if err := skipUnfinishedTools(ctx, db, org, s.ID, s.Tools, e.Images); err != nil {
					return err
				}
			}
			// pending_upload scans younger than the abandon cutoff keep their
			// object: the upload may still be in flight.
			rows, err = db.Query(ctx, `SELECT id, object_key, tools FROM scan WHERE source_deleted_at IS NULL AND (
				  (status IN ('completed', 'partial', 'failed', 'cancelled') AND created_at < $1)
				  OR (status IN ('queued', 'running') AND created_at < $2))
				ORDER BY created_at LIMIT $3`, now.Add(-e.SourceRetention), now.Add(-e.StuckAfter), sweepBatch)
			if err != nil {
				return err
			}
			expired, err = collectSources(rows)
			return err
		})
		if err != nil {
			return err
		}
		var errs []error
		for _, s := range append(abandoned, expired...) {
			if s.ObjectKey != nil {
				if err := e.Store.Delete(ctx, *s.ObjectKey); err != nil {
					errs = append(errs, err) // retried on the next run
					continue
				}
			}
			if err := e.Tx(ctx, org, func(db DB) error {
				_, err := db.Exec(ctx, `UPDATE scan SET source_deleted_at = $2 WHERE id = $1 AND source_deleted_at IS NULL`, s.ID, now)
				return err
			}); err != nil {
				errs = append(errs, err)
			}
		}
		if n := len(abandoned) + len(expired); n > 0 {
			e.Log.Info("purged uploaded sources", "org_id", org, "abandoned", len(abandoned), "expired", len(expired), "errors", len(errs))
		}
		return errors.Join(append(errs, e.purgeSBOMs(ctx, org, now))...)
	})
}

type sbomRow struct {
	ID  uuid.UUID
	Key string
}

// purgeSBOMs deletes SBOMs past scan.sbom_retention: the object first, then
// all the scan's sbom_* columns at once (a failed delete is retried on the
// next run, and the API already treats the SBOM as gone).
func (e *Env) purgeSBOMs(ctx context.Context, org uuid.UUID, now time.Time) error {
	var expired []sbomRow
	err := e.Tx(ctx, org, func(db DB) error {
		rows, err := db.Query(ctx, `SELECT id, sbom_key FROM scan WHERE sbom_key IS NOT NULL AND sbom_expires_at <= $1
			ORDER BY sbom_expires_at LIMIT $2`, now, sweepBatch)
		if err != nil {
			return err
		}
		expired, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (sbomRow, error) {
			var s sbomRow
			return s, r.Scan(&s.ID, &s.Key)
		})
		return err
	})
	if err != nil {
		return err
	}
	var errs []error
	for _, s := range expired {
		if err := e.Store.Delete(ctx, s.Key); err != nil {
			errs = append(errs, err)
			continue
		}
		if err := e.Tx(ctx, org, func(db DB) error {
			_, err := db.Exec(ctx, `UPDATE scan SET sbom_key = NULL, sbom_size = NULL, sbom_sha256 = NULL, sbom_components = NULL,
				sbom_expires_at = NULL WHERE id = $1 AND sbom_key = $2`, s.ID, s.Key)
			return err
		}); err != nil {
			errs = append(errs, err)
		}
	}
	if len(expired) > 0 {
		e.Log.Info("purged expired SBOMs", "org_id", org, "expired", len(expired), "errors", len(errs))
	}
	return errors.Join(errs...)
}

type expiredException struct {
	ID          uuid.UUID
	IssueID     uuid.UUID
	IssueStatus issuestate.Status
	Severity    severity.Severity
}

// ReopenExpiredRiskAccepted expires approved risk acceptances past expires_at
// and reopens their issues (System actor), with an issue_event each.
func (e *Env) ReopenExpiredRiskAccepted(ctx context.Context) error {
	now := e.Now().UTC()
	return e.forEachOrg(ctx, "reopen_expired_risk_accepted", func(org uuid.UUID) error {
		return e.Tx(ctx, org, func(db DB) error {
			rows, err := db.Query(ctx, `SELECT x.id, x.issue_id, i.status, i.severity
				FROM exception_request x JOIN issue i ON i.id = x.issue_id
				WHERE x.type = 'risk_accepted' AND x.status = 'approved' AND x.expires_at <= $1
				ORDER BY x.expires_at LIMIT $2 FOR UPDATE OF x, i`, now, sweepBatch)
			if err != nil {
				return err
			}
			list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (expiredException, error) {
				var x expiredException
				var st, sev string
				err := r.Scan(&x.ID, &x.IssueID, &st, &sev)
				x.IssueStatus, x.Severity = issuestate.Status(st), severity.Severity(sev)
				return x, err
			})
			if err != nil || len(list) == 0 {
				return err
			}
			var rawSLA []byte
			var sla results.SLA
			if err := db.QueryRow(ctx, `SELECT sla_days FROM organization WHERE id = $1`, org).Scan(&rawSLA); err != nil {
				return err
			}
			if err := json.Unmarshal(rawSLA, &sla); err != nil {
				return fmt.Errorf("organization.sla_days: %w", err)
			}
			for _, x := range list {
				if err := reopenExpired(ctx, db, org, x, sla, now); err != nil {
					return err
				}
			}
			e.Log.Info("expired risk acceptances", "org_id", org, "count", len(list))
			return nil
		})
	})
}

func reopenExpired(ctx context.Context, db DB, org uuid.UUID, x expiredException, sla results.SLA, now time.Time) error {
	if _, err := db.Exec(ctx, `UPDATE exception_request SET status = 'expired' WHERE id = $1`, x.ID); err != nil {
		return err
	}
	if x.IssueStatus != issuestate.RiskAccepted {
		return nil // the issue moved on (e.g. fixed); only the exception expires
	}
	if _, err := issuestate.Check(issuestate.RiskAccepted, issuestate.Reopened, issuestate.System); err != nil {
		return err
	}
	tag, err := db.Exec(ctx, `UPDATE issue SET status = 'reopened', version = version + 1, updated_at = $2, due_at = $3
		WHERE id = $1 AND status = 'risk_accepted'`, x.IssueID, now, sla.DueAt(x.Severity, now))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return nil
	}
	if _, err = db.Exec(ctx, `INSERT INTO issue_event (org_id, issue_id, actor_id, type, from_value, to_value, note)
		VALUES ($1, $2, NULL, $3, 'risk_accepted', 'reopened', 'risk acceptance expired')`, org, x.IssueID, results.EventStatusChanged); err != nil {
		return err
	}
	return notify.Insert(ctx, db, notify.Event{OrgID: org, Type: notify.IssueReopened, Payload: notify.Payload{IssueID: notify.ID(x.IssueID)}})
}
