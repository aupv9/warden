package store

import (
	"context"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aupv9/warden/backend/internal/domain/ecosystem"
	"github.com/aupv9/warden/backend/internal/service"
)

// maxTargets bounds GET /projects/{p}/targets, which has no pagination: a
// project has a handful of image repositories, not thousands.
const maxTargets = 1000

// prefixPattern escapes LIKE wildcards and matches s as a prefix.
func prefixPattern(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s) + "%"
}

// namesWhere matches c.match_name against any of the prefixes, at the start
// of the name or of a segment after ':' or '/': people search for log4j-core
// (Maven org.apache.logging.log4j:log4j-core) or logrus (Go
// github.com/sirupsen/logrus). Only the whole-name prefix can use the
// component_prefix index; the segment matches scan the org's rows.
func namesWhere(a *args, names []service.NamePrefix) string {
	var or []string
	for _, n := range names {
		p := a.add(prefixPattern(n.Prefix))
		cond := `(c.match_name LIKE ` + p + ` OR c.match_name LIKE '%:' || ` + p + ` OR c.match_name LIKE '%/' || ` + p + `)`
		if n.Ecosystem != "" {
			cond = `(c.ecosystem = ` + a.add(n.Ecosystem) + ` AND ` + cond + `)`
		}
		or = append(or, cond)
	}
	return `(` + strings.Join(or, ` OR `) + `)`
}

// maliciousFor: an OSV malicious-package advisory lists the component (alias
// c, or the given columns): all versions, or its version normalized as the
// advisory's are.
func maliciousFor(eco, matchName, version string) string {
	return `EXISTS (SELECT 1 FROM malicious_package m WHERE m.ecosystem = ` + eco + ` AND m.match_name = ` + matchName +
		` AND (m.all_versions OR ` + ecosystem.MatchVersionSQL(eco, version) + ` = ANY(m.versions)))`
}

// openIssuesOn: active Trivy issues on the component's package and version
// (issue.package_name is stored as reported, so it is normalized here).
func openIssuesOn(eco, matchName, version string) string {
	return `i.tool = 'trivy' AND i.status IN ` + activeStatuses + ` AND i.package_version = ` + version +
		` AND ` + ecosystem.MatchNameSQL(eco, `i.package_name`) + ` = ` + matchName
}

// componentScope restricts component rows (alias c, joined to project p) to
// the org's visible, unarchived projects, and to one project if asked.
func componentScope(a *args, v service.Visibility, projectID *uuid.UUID) string {
	w := `c.org_id = ` + a.add(v.OrgID) + ` AND p.archived_at IS NULL AND ` + visible(a, v)
	if projectID != nil {
		w += ` AND c.project_id = ` + a.add(*projectID)
	}
	return w
}

func buildComponents(q service.ComponentQuery) (string, args) {
	var a args
	scope := componentScope(&a, q.Vis, q.ProjectID)
	w := []string{scope}
	if q.Ecosystem != "" {
		w = append(w, `c.ecosystem = `+a.add(q.Ecosystem))
	}
	if len(q.Names) > 0 {
		w = append(w, namesWhere(&a, q.Names))
	}
	if q.Version != "" {
		w = append(w, `c.version = `+a.add(q.Version))
	}
	if q.Malicious {
		w = append(w, maliciousFor(`c.ecosystem`, `c.match_name`, `c.version`))
	}
	if c := q.After; c != nil {
		w = append(w, `(c.match_name, c.ecosystem, c.version) > (`+a.add(c.MatchName)+`, `+a.add(c.Ecosystem)+`, `+a.add(c.Version)+`)`)
	}
	// The page of groups is cut first; open issues and the malicious flag are
	// then computed for those rows only. The open-issue count repeats the
	// scope (c2 renamed to c so the scope's aliases apply).
	sql := `SELECT g.ecosystem, g.name, g.version, g.purl, g.licenses, g.projects, g.targets, g.match_name,
		(SELECT count(DISTINCT i.id) FROM component c JOIN project p ON p.id = c.project_id
			JOIN issue i ON i.project_id = c.project_id AND i.target = c.target
			WHERE ` + scope + ` AND c.ecosystem = g.ecosystem AND c.match_name = g.match_name AND c.version = g.version
			AND ` + openIssuesOn(`g.ecosystem`, `g.match_name`, `g.version`) + `),
		` + maliciousFor(`g.ecosystem`, `g.match_name`, `g.version`) + `
	FROM (SELECT c.ecosystem, c.match_name, c.version, min(c.name) AS name, min(c.purl) AS purl,
			coalesce(array_agg(DISTINCT l.id ORDER BY l.id) FILTER (WHERE l.id IS NOT NULL), '{}') AS licenses,
			count(DISTINCT c.project_id) AS projects, count(DISTINCT (c.project_id, c.target)) AS targets
		FROM component c JOIN project p ON p.id = c.project_id
		LEFT JOIN LATERAL unnest(c.licenses) AS l(id) ON true
		WHERE ` + strings.Join(w, " AND ") + `
		GROUP BY c.ecosystem, c.match_name, c.version
		ORDER BY c.match_name, c.ecosystem, c.version
		LIMIT ` + a.add(q.Limit) + `) g
	ORDER BY g.match_name, g.ecosystem, g.version`
	return sql, a
}

func (r *Repo) Components(ctx context.Context, q service.ComponentQuery) ([]service.ComponentSummary, error) {
	sql, a := buildComponents(q)
	rows, _ := r.tx.Query(ctx, sql, a...)
	return collect(rows, func(row pgx.CollectableRow) (service.ComponentSummary, error) {
		var c service.ComponentSummary
		err := row.Scan(&c.Ecosystem, &c.Name, &c.Version, &c.PURL, &c.Licenses, &c.Projects, &c.Targets, &c.MatchName,
			&c.OpenIssues, &c.Malicious)
		return c, err
	})
}

func (r *Repo) ComponentUsage(ctx context.Context, q service.ComponentUsageQuery) ([]service.ComponentUsage, error) {
	var a args
	w := []string{componentScope(&a, q.Vis, q.ProjectID),
		`c.ecosystem = ` + a.add(q.Ecosystem), `c.match_name = ` + a.add(q.MatchName), `c.version = ` + a.add(q.Version)}
	if c := q.After; c != nil {
		w = append(w, `(p.key, c.target, c.path) > (`+a.add(c.ProjectKey)+`, `+a.add(c.Target)+`, `+a.add(c.Path)+`)`)
	}
	sql := `SELECT p.id, p.key, p.name, c.target, c.path, c.scan_id, coalesce(s.finished_at, s.created_at), c.first_seen
		FROM component c JOIN project p ON p.id = c.project_id JOIN scan s ON s.id = c.scan_id
		WHERE ` + strings.Join(w, " AND ") + `
		ORDER BY p.key, c.target, c.path LIMIT ` + a.add(q.Limit)
	rows, _ := r.tx.Query(ctx, sql, a...)
	return collect(rows, func(row pgx.CollectableRow) (service.ComponentUsage, error) {
		var u service.ComponentUsage
		err := row.Scan(&u.ProjectID, &u.ProjectKey, &u.ProjectName, &u.Target, &u.Path, &u.ScanID, &u.ScannedAt, &u.FirstSeen)
		return u, err
	})
}

func buildProjectComponents(q service.ProjectComponentQuery) (string, args) {
	var a args
	w := []string{`c.project_id = ` + a.add(q.ProjectID)}
	if q.Target != nil {
		w = append(w, `c.target = `+a.add(*q.Target))
	}
	if q.Ecosystem != "" {
		w = append(w, `c.ecosystem = `+a.add(q.Ecosystem))
	}
	if len(q.Names) > 0 {
		w = append(w, namesWhere(&a, q.Names))
	}
	// Malicious components first: the flag is computed for the project's
	// rows (pc), then the keyset and the order use it; open issues are counted
	// for the page only. The order is the cursor's (service.ProjectComponentCursor),
	// ending in the table's unique key so every row has one position.
	var o []string
	if q.Malicious {
		o = append(o, `pc.malicious`)
	}
	if c := q.After; c != nil && c.Malicious != nil {
		o = append(o, `(NOT pc.malicious, pc.match_name, pc.version, pc.ecosystem, pc.target, pc.path) > (`+a.add(!*c.Malicious)+`, `+
			a.add(c.MatchName)+`, `+a.add(c.Version)+`, `+a.add(c.Ecosystem)+`, `+a.add(c.Target)+`, `+a.add(c.Path)+`)`)
	}
	outer := ""
	if len(o) > 0 {
		outer = ` WHERE ` + strings.Join(o, " AND ")
	}
	sql := `SELECT pc.ecosystem, pc.name, pc.version, pc.purl, pc.licenses, pc.target, pc.path, pc.first_seen, pc.match_name,
		(SELECT count(*) FROM issue i WHERE i.project_id = pc.project_id AND i.target = pc.target
			AND ` + openIssuesOn(`pc.ecosystem`, `pc.match_name`, `pc.version`) + `),
		pc.malicious
	FROM (SELECT c.project_id, c.ecosystem, c.name, c.version, c.purl, c.licenses, c.target, c.path, c.first_seen, c.match_name,
			` + maliciousFor(`c.ecosystem`, `c.match_name`, `c.version`) + ` AS malicious
		FROM component c WHERE ` + strings.Join(w, " AND ") + `) pc` + outer + `
	ORDER BY NOT pc.malicious, pc.match_name, pc.version, pc.ecosystem, pc.target, pc.path LIMIT ` + a.add(q.Limit)
	return sql, a
}

func (r *Repo) ProjectComponents(ctx context.Context, q service.ProjectComponentQuery) ([]service.ProjectComponent, error) {
	sql, a := buildProjectComponents(q)
	rows, _ := r.tx.Query(ctx, sql, a...)
	return collect(rows, func(row pgx.CollectableRow) (service.ProjectComponent, error) {
		var c service.ProjectComponent
		err := row.Scan(&c.Ecosystem, &c.Name, &c.Version, &c.PURL, &c.Licenses, &c.Target, &c.Path, &c.FirstSeen, &c.MatchName,
			&c.OpenIssues, &c.Malicious)
		return c, err
	})
}

// maxOrgTargets bounds GET /targets the same way, across an org's projects.
const maxOrgTargets = 5000

// buildTargets lists every (project, target) with a scan that got past upload,
// or an issue, for the projects that projects (SQL yielding id, key, name)
// selects, optionally of one kind; by project key, then target.
func buildTargets(a *args, projects, kind string, limit int) string {
	var w string
	switch kind {
	case service.KindSource:
		w = ` WHERE t.target = ''`
	case service.KindHistory:
		w = ` WHERE t.target = ` + a.add(service.HistoryTarget)
	case service.KindImage:
		w = ` WHERE t.target <> '' AND t.target <> ` + a.add(service.HistoryTarget) +
			` AND NOT starts_with(t.target, ` + a.add(service.ImportTargetPrefix) + `)`
	case service.KindImport:
		w = ` WHERE starts_with(t.target, ` + a.add(service.ImportTargetPrefix) + `)`
	}
	return `WITH vp AS (` + projects + `), t AS (
			SELECT s.project_id, s.target FROM scan s JOIN vp ON vp.id = s.project_id WHERE s.status <> 'pending_upload'
			UNION SELECT i.project_id, i.target FROM issue i JOIN vp ON vp.id = i.project_id)
		SELECT vp.id, vp.key, vp.name, t.target,
			(SELECT max(s.created_at) FROM scan s WHERE s.project_id = t.project_id AND s.target = t.target AND s.status <> 'pending_upload'),
			(SELECT count(*) FROM issue i WHERE i.project_id = t.project_id AND i.target = t.target AND i.status IN ` + activeStatuses + `)
		FROM t JOIN vp ON vp.id = t.project_id` + w + `
		ORDER BY vp.key, t.target LIMIT ` + a.add(limit)
}

func scanTarget(row pgx.CollectableRow) (service.OrgTarget, error) {
	var t service.OrgTarget
	err := row.Scan(&t.ProjectID, &t.ProjectKey, &t.ProjectName, &t.Target, &t.LastScanAt, &t.OpenIssues)
	switch t.Target {
	case "":
		t.Kind = service.KindSource
	case service.HistoryTarget:
		t.Kind = service.KindHistory
	default:
		t.Kind = service.KindImage
		if strings.HasPrefix(t.Target, service.ImportTargetPrefix) {
			t.Kind = service.KindImport
		}
	}
	return t, err
}

// ProjectTargets: every target with a scan that got past upload, or an issue.
func (r *Repo) ProjectTargets(ctx context.Context, projectID uuid.UUID) ([]service.ProjectTarget, error) {
	var a args
	sql := buildTargets(&a, `SELECT id, key, name FROM project WHERE id = `+a.add(projectID), "", maxTargets)
	rows, _ := r.tx.Query(ctx, sql, a...)
	return collect(rows, func(row pgx.CollectableRow) (service.ProjectTarget, error) {
		t, err := scanTarget(row)
		return t.ProjectTarget, err
	})
}

// OrgTargets: ProjectTargets over the visible, unarchived projects (the issue
// list's scope).
func (r *Repo) OrgTargets(ctx context.Context, q service.OrgTargetQuery) ([]service.OrgTarget, error) {
	var a args
	projects := `SELECT p.id, p.key, p.name FROM project p WHERE p.org_id = ` + a.add(q.Vis.OrgID) +
		` AND p.archived_at IS NULL AND ` + visible(&a, q.Vis)
	if q.ProjectID != nil {
		projects += ` AND p.id = ` + a.add(*q.ProjectID)
	}
	sql := buildTargets(&a, projects, q.Kind, maxOrgTargets)
	rows, _ := r.tx.Query(ctx, sql, a...)
	return collect(rows, scanTarget)
}

// ComponentEcosystems: distinct (match name, version) per ecosystem, the
// grouping of Components, most first.
func (r *Repo) ComponentEcosystems(ctx context.Context, v service.Visibility, projectID *uuid.UUID) ([]service.EcosystemCount, error) {
	var a args
	sql := `SELECT c.ecosystem, count(DISTINCT (c.match_name, c.version))
		FROM component c JOIN project p ON p.id = c.project_id
		WHERE ` + componentScope(&a, v, projectID) + `
		GROUP BY c.ecosystem ORDER BY 2 DESC, 1`
	rows, _ := r.tx.Query(ctx, sql, a...)
	return collect(rows, func(row pgx.CollectableRow) (service.EcosystemCount, error) {
		var e service.EcosystemCount
		return e, row.Scan(&e.Ecosystem, &e.Components)
	})
}
