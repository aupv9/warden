package worker

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/aupv9/warden/backend/internal/domain/ecosystem"
	"github.com/aupv9/warden/backend/internal/scan/results"
	"github.com/aupv9/warden/backend/internal/scan/trivyjson"
)

// Retro-match: when the OSV load (intel.go) adds or changes malicious-package
// advisories, match_malicious looks for the affected packages in every org's
// component inventory and calls results.Inject, which creates or reopens the
// Critical issues a scan would have created. It never fixes an issue.

// MatchMaliciousArgs names what changed: one ecosystem, and either the
// normalized names whose advisories changed or All (the first load).
type MatchMaliciousArgs struct {
	Ecosystem string   `json:"ecosystem"`
	Names     []string `json:"names,omitempty"`
	All       bool     `json:"all,omitempty"`
}

func (MatchMaliciousArgs) Kind() string { return "match_malicious" }

func (MatchMaliciousArgs) InsertOpts() river.InsertOpts { return river.InsertOpts{MaxAttempts: 5} }

// maxMatchNames: above this many changed names the job matches the whole
// ecosystem (the join is indexed either way; this keeps job arguments small).
const maxMatchNames = 5000

type MatchMaliciousWorker struct {
	river.WorkerDefaults[MatchMaliciousArgs]
	Env *Env
}

func (MatchMaliciousWorker) Timeout(*river.Job[MatchMaliciousArgs]) time.Duration {
	return 10 * time.Minute
}

func (w MatchMaliciousWorker) Work(ctx context.Context, job *river.Job[MatchMaliciousArgs]) error {
	if w.Env == nil {
		return errNoEnv
	}
	defer kickDispatch(ctx) // component.malicious and issue.reopened events
	return w.Env.MatchMalicious(ctx, job.Args)
}

// enqueueMatch inserts the job in the load transaction, so the changed names
// can't be lost between the commit and the insert (the next load would see an
// unchanged file and never send them). Tests replace it.
var enqueueMatch = func(ctx context.Context, db DB, args MatchMaliciousArgs) error {
	c, err := river.ClientFromContextSafely[pgx.Tx](ctx)
	if err != nil {
		return fmt.Errorf("enqueue match_malicious: %w", err)
	}
	tx, ok := db.(pgx.Tx)
	if !ok {
		return errors.New("enqueue match_malicious: not a pgx transaction")
	}
	_, err = c.InsertTx(ctx, tx, args, nil)
	return err
}

// componentMatch is a component row joined with an advisory naming it.
type componentMatch struct {
	project, scan                       uuid.UUID
	target, eco, name, match, ver, path string
	advisory, summary                   string
	all                                 bool
	versions                            []string
}

// MatchMalicious matches the changed advisories against each org's
// inventory. Each (project, target) is injected in its own transaction, so
// one failure doesn't hold back the others; the job is retried on error and
// Inject is idempotent.
func (e *Env) MatchMalicious(ctx context.Context, args MatchMaliciousArgs) error {
	if !ecosystem.IsOSV(args.Ecosystem) {
		return river.JobCancel(fmt.Errorf("match_malicious: unknown ecosystem %q", args.Ecosystem))
	}
	if !args.All && len(args.Names) == 0 {
		return nil
	}
	return e.forEachOrg(ctx, "match_malicious", func(org uuid.UUID) error {
		var found []componentMatch
		err := e.Tx(ctx, org, func(db DB) error {
			rows, err := db.Query(ctx, `SELECT c.project_id, c.scan_id, c.target, c.ecosystem, c.name, c.match_name, c.version, c.path,
					m.id, m.summary, m.all_versions, m.versions
				FROM component c
				JOIN project p ON p.id = c.project_id AND p.archived_at IS NULL
				JOIN malicious_package m ON m.ecosystem = c.ecosystem AND m.match_name = c.match_name
				WHERE c.ecosystem = $1 AND ($2 OR c.match_name = ANY($3))
					AND (m.all_versions OR `+ecosystem.MatchVersionSQL("c.ecosystem", "c.version")+` = ANY(m.versions))
				ORDER BY c.project_id, c.target, m.id, c.match_name, c.version, c.path`, args.Ecosystem, args.All, args.Names)
			if err != nil {
				return err
			}
			found, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (componentMatch, error) {
				var m componentMatch
				return m, r.Scan(&m.project, &m.scan, &m.target, &m.eco, &m.name, &m.match, &m.ver, &m.path,
					&m.advisory, &m.summary, &m.all, &m.versions)
			})
			return err
		})
		if err != nil {
			return err
		}
		groups := map[[2]string][]results.MaliciousMatch{}
		var order [][2]string
		projects := map[[2]string]uuid.UUID{}
		for _, m := range found {
			// component keeps the version as reported: the join above
			// normalizes it in SQL (ecosystem.MatchVersionSQL); the Go
			// function decides, as it does at scan time, and gives the
			// version the fingerprint uses.
			mv := ecosystem.MatchVersion(m.eco, m.ver)
			if !m.all && !slices.Contains(m.versions, mv) {
				continue
			}
			k := [2]string{m.project.String(), m.target}
			if _, ok := groups[k]; !ok {
				order = append(order, k)
				projects[k] = m.project
			}
			groups[k] = append(groups[k], results.MaliciousMatch{
				Package: trivyjson.Package{Ecosystem: m.eco, Name: m.name, MatchName: m.match, Version: m.ver,
					MatchVersion: mv, FilePath: m.path},
				ScanID:   m.scan,
				Advisory: results.Advisory{ID: m.advisory, Summary: m.summary},
			})
		}
		var errs []error
		for _, k := range order {
			var created, reopened int
			err := e.Tx(ctx, org, func(db DB) error {
				var err error
				created, reopened, err = results.Inject(ctx, db, results.InjectInput{OrgID: org, ProjectID: projects[k],
					Target: k[1], Matches: groups[k], Now: e.Now().UTC()})
				return err
			})
			if err != nil {
				errs = append(errs, fmt.Errorf("project %s: %w", k[0], err))
				continue
			}
			if created+reopened > 0 {
				e.Log.Warn("malicious packages found in the component inventory", "org_id", org, "project_id", k[0],
					"ecosystem", args.Ecosystem, "created", created, "reopened", reopened)
			}
		}
		return errors.Join(errs...)
	})
}
