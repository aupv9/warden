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
	if q.Malicious {
		w = append(w, maliciousFor(`c.ecosystem`, `c.match_name`, `c.version`))
	}
	if c := q.After; c != nil {
		w = append(w, `(c.target, c.match_name, c.ecosystem, c.version, c.path) > (`+a.add(c.Target)+`, `+a.add(c.MatchName)+`, `+
			a.add(c.Ecosystem)+`, `+a.add(c.Version)+`, `+a.add(c.Path)+`)`)
	}
	sql := `SELECT c.ecosystem, c.name, c.version, c.purl, c.licenses, c.target, c.path, c.first_seen, c.match_name,
		(SELECT count(*) FROM issue i WHERE i.project_id = c.project_id AND i.target = c.target
			AND ` + openIssuesOn(`c.ecosystem`, `c.match_name`, `c.version`) + `),
		` + maliciousFor(`c.ecosystem`, `c.match_name`, `c.version`) + `
		FROM component c WHERE ` + strings.Join(w, " AND ") + `
		ORDER BY c.target, c.match_name, c.ecosystem, c.version, c.path LIMIT ` + a.add(q.Limit)
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

// ProjectTargets: every target with a scan that got past upload, or an issue.
func (r *Repo) ProjectTargets(ctx context.Context, projectID uuid.UUID) ([]service.ProjectTarget, error) {
	rows, _ := r.tx.Query(ctx, `WITH t AS (
			SELECT target FROM scan WHERE project_id = $1 AND status <> 'pending_upload'
			UNION SELECT target FROM issue WHERE project_id = $1)
		SELECT t.target,
			(SELECT max(s.created_at) FROM scan s WHERE s.project_id = $1 AND s.target = t.target AND s.status <> 'pending_upload'),
			(SELECT count(*) FROM issue i WHERE i.project_id = $1 AND i.target = t.target AND i.status IN `+activeStatuses+`)
		FROM t ORDER BY t.target LIMIT $2`, projectID, maxTargets)
	return collect(rows, func(row pgx.CollectableRow) (service.ProjectTarget, error) {
		var t service.ProjectTarget
		err := row.Scan(&t.Target, &t.LastScanAt, &t.OpenIssues)
		t.Kind = service.KindSource
		if t.Target != "" {
			t.Kind = service.KindImage
		}
		return t, err
	})
}
