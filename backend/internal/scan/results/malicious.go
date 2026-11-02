package results

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aupv9/warden/backend/internal/domain/ecosystem"
	"github.com/aupv9/warden/backend/internal/domain/fingerprint"
	"github.com/aupv9/warden/backend/internal/domain/issuestate"
	"github.com/aupv9/warden/backend/internal/domain/severity"
	"github.com/aupv9/warden/backend/internal/notify"
	"github.com/aupv9/warden/backend/internal/scan/sarif"
	"github.com/aupv9/warden/backend/internal/scan/trivyjson"
)

// Malicious packages: a package that an OSV MAL- advisory (malicious_package,
// loaded by the worker) lists is a Critical Trivy issue with rule
// malicious:<id>. It is found two ways that must agree exactly:
//   - at scan time, MaliciousFindings adds the findings to Trivy's, so dedup,
//     reopening, per-target auto-fix, the gate, SLA and exceptions apply as
//     for any finding;
//   - when an advisory arrives, the match_malicious job calls Inject for the
//     components already in the inventory: it builds the same finding and
//     fingerprint, and only creates or reopens issues. It never fixes one;
//     the next scan that no longer has the package does.
// A feed never closes, hides or downgrades an issue.

// MaliciousRulePrefix starts the rule id of every malicious-package issue.
const MaliciousRulePrefix = "malicious:"

// IsMalicious reports whether f is a malicious-package finding.
func IsMalicious(f sarif.Finding) bool {
	return f.Tool == "trivy" && strings.HasPrefix(f.RuleID, MaliciousRulePrefix)
}

// Advisory is the part of a malicious_package row a finding shows.
type Advisory struct {
	ID      string
	Summary string
}

const maliciousRemediation = "Remove this version from the project and its lockfile, and rotate every credential the " +
	"builds, CI jobs and developer machines that installed it had access to: malicious packages usually steal secrets " +
	"when installed. Treat those machines as compromised."

// MaliciousFinding is the finding for pkg matching adv, the same at scan time
// and in Inject. The content key uses the normalized name and version
// (ecosystem.MatchName/MatchVersion), which both the scan's package list and
// the component inventory carry, so the fingerprint doesn't depend on which
// of them the finding was built from.
func MaliciousFinding(pkg trivyjson.Package, adv Advisory) sarif.Finding {
	ruleID := MaliciousRulePrefix + adv.ID
	label := pkg.Name
	if pkg.Version != "" {
		label += " " + pkg.Version
	}
	// Plain text: names come from the scanned code (capped and sanitized by
	// trivyjson), the summary from OSV (sanitized by the feed parser).
	desc := fmt.Sprintf("The %s package %s is listed as malicious by the OSV advisory %s.", pkg.Ecosystem, label, adv.ID)
	if adv.Summary != "" {
		desc += " Advisory summary: " + adv.Summary
	}
	return sarif.Finding{
		Tool:           "trivy",
		RuleID:         ruleID,
		Title:          truncate(fmt.Sprintf("%s is a malicious package (%s)", label, adv.ID), sarif.MaxTitle),
		Severity:       severity.Critical,
		FilePath:       pkg.FilePath,
		ContentKey:     fingerprint.SCAContentKey(adv.ID, pkg.MatchName, pkg.MatchVersion),
		Description:    truncate(desc, sarif.MaxText),
		Remediation:    maliciousRemediation,
		PackageName:    pkg.Name,
		PackageVersion: pkg.Version,
	}
}

type advisoryRow struct {
	Advisory
	ecosystem, matchName string
	allVersions          bool
	versions             []string
}

func (r advisoryRow) affects(matchVersion string) bool {
	return r.allVersions || slices.Contains(r.versions, matchVersion)
}

// MaliciousFindings matches the scan's packages against malicious_package
// (by ecosystem and normalized name; all versions or a listed one) in the
// results transaction. Only ecosystems with an OSV feed are looked up.
func MaliciousFindings(ctx context.Context, db DB, packages []trivyjson.Package) ([]sarif.Finding, error) {
	var ecos, names []string
	seen := map[[2]string]bool{}
	for _, p := range packages {
		k := [2]string{p.Ecosystem, p.MatchName}
		if !ecosystem.IsOSV(p.Ecosystem) || p.MatchName == "" || seen[k] {
			continue
		}
		seen[k] = true
		ecos, names = append(ecos, k[0]), append(names, k[1])
	}
	if len(ecos) == 0 {
		return nil, nil
	}
	rows, err := db.Query(ctx, `SELECT m.id, m.summary, m.ecosystem, m.match_name, m.all_versions, m.versions
		FROM malicious_package m JOIN unnest($1::text[], $2::text[]) AS k(ecosystem, match_name)
			ON m.ecosystem = k.ecosystem AND m.match_name = k.match_name
		ORDER BY m.id`, ecos, names)
	if err != nil {
		return nil, fmt.Errorf("match malicious packages: %w", err)
	}
	advs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (advisoryRow, error) {
		var a advisoryRow
		return a, r.Scan(&a.ID, &a.Summary, &a.ecosystem, &a.matchName, &a.allVersions, &a.versions)
	})
	if err != nil {
		return nil, fmt.Errorf("match malicious packages: %w", err)
	}
	if len(advs) == 0 {
		return nil, nil
	}
	byName := map[[2]string][]advisoryRow{}
	for _, a := range advs {
		k := [2]string{a.ecosystem, a.matchName}
		byName[k] = append(byName[k], a)
	}
	var out []sarif.Finding
	keys := map[fingerprint.Key]bool{}
	for _, p := range packages {
		for _, a := range byName[[2]string{p.Ecosystem, p.MatchName}] {
			if !a.affects(p.MatchVersion) {
				continue
			}
			f := MaliciousFinding(p, a.Advisory)
			// One finding per identity, so fingerprint.Assign always gives
			// k = 0 and Inject (which dedupes the same way) agrees.
			if keys[f.Key()] {
				continue
			}
			keys[f.Key()] = true
			out = append(out, f)
		}
	}
	return out, nil
}

// MaliciousMatch is a component of the inventory that an advisory lists.
type MaliciousMatch struct {
	// Package carries the component's Ecosystem, Name, MatchName, Version,
	// MatchVersion (ecosystem.MatchVersion of Version) and FilePath (its path).
	Package trivyjson.Package
	// ScanID is the scan that recorded the component (component.scan_id):
	// a new issue is first seen there.
	ScanID   uuid.UUID
	Advisory Advisory
}

// InjectInput is one (project, target)'s matches.
type InjectInput struct {
	OrgID, ProjectID uuid.UUID
	Target           string
	Matches          []MaliciousMatch
	Now              time.Time
}

// maliciousEvent writes component.malicious for a new or reopened issue. The
// dedupe key includes the issue version, so the same change is announced
// once while a later reopen is announced again.
func maliciousEvent(ctx context.Context, db DB, org, issue uuid.UUID, version int) error {
	return notify.Insert(ctx, db, notify.Event{OrgID: org, Type: notify.ComponentMalicious,
		Payload: notify.Payload{IssueID: notify.ID(issue)}, DedupeKey: fmt.Sprintf("mal:%s:%d", issue, version)})
}

// notifyMalicious announces the malicious-package issues a scan created or
// reopened (applier.apply, once the plan is written). A reopen counts only if it
// happened (a concurrent user change wins).
func notifyMalicious(ctx context.Context, db DB, in Input, p Plan) error {
	var fps []string
	created := map[string]bool{}
	for _, n := range p.New {
		if IsMalicious(n.Finding) {
			fps, created[n.Fingerprint] = append(fps, n.Fingerprint), true
		}
	}
	for _, s := range p.Seen {
		if s.Reopen && IsMalicious(s.Finding) {
			fps = append(fps, s.Issue.Fingerprint)
		}
	}
	if len(fps) == 0 {
		return nil
	}
	rows, err := db.Query(ctx, `SELECT id, fingerprint, status::text, version FROM issue
		WHERE project_id = $1 AND fingerprint = ANY($2) ORDER BY number`, in.ProjectID, fps)
	if err != nil {
		return fmt.Errorf("malicious issues: %w", err)
	}
	type issueRow struct {
		id         uuid.UUID
		fp, status string
		version    int
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (issueRow, error) {
		var x issueRow
		return x, r.Scan(&x.id, &x.fp, &x.status, &x.version)
	})
	if err != nil {
		return fmt.Errorf("malicious issues: %w", err)
	}
	for _, x := range list {
		if created[x.fp] || x.status == string(issuestate.Reopened) {
			if err := maliciousEvent(ctx, db, in.OrgID, x.id, x.version); err != nil {
				return err
			}
		}
	}
	return nil
}

// injectFinding is a match's finding with its fingerprint.
type injectFinding struct {
	fingerprint string
	finding     sarif.Finding
	match       MaliciousMatch
}

// injectFindings builds the matches' findings and fingerprints exactly as a
// scan would (MaliciousFinding, deduplicated by identity, then Fingerprints).
func injectFindings(matches []MaliciousMatch) []injectFinding {
	var findings []sarif.Finding
	byKey := map[fingerprint.Key]MaliciousMatch{}
	for _, m := range matches {
		f := MaliciousFinding(m.Package, m.Advisory)
		if _, dup := byKey[f.Key()]; dup {
			continue
		}
		byKey[f.Key()] = m
		findings = append(findings, f)
	}
	fps := Fingerprints(map[string][]sarif.Finding{"trivy": findings}, map[string]bool{"trivy": true})
	out := make([]injectFinding, len(fps))
	for i, fp := range fps {
		out[i] = injectFinding{fingerprint: fp.Fingerprint, finding: fp.Finding, match: byKey[fp.Finding.Key()]}
	}
	return out
}

// Inject creates or reopens the malicious-package issues of one (project,
// target) for components already in the inventory, without a scan. It runs
// in the caller's transaction with app.org_id set, and takes the project
// lock Process takes. Existing active issues and approved exceptions
// (false_positive, risk_accepted) are left alone; fixed and verified issues
// are reopened; nothing is ever fixed. Archived projects are skipped.
func Inject(ctx context.Context, db DB, in InjectInput) (created, reopened int, err error) {
	if len(in.Matches) == 0 {
		return 0, 0, nil
	}
	var seq int
	err = db.QueryRow(ctx, `SELECT issue_seq FROM project WHERE id = $1 AND archived_at IS NULL FOR UPDATE`, in.ProjectID).Scan(&seq)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, fmt.Errorf("lock project: %w", err)
	}
	var rawSLA []byte
	var sla SLA
	if err := db.QueryRow(ctx, `SELECT sla_days FROM organization WHERE id = $1`, in.OrgID).Scan(&rawSLA); err != nil {
		return 0, 0, fmt.Errorf("load org sla: %w", err)
	}
	if err := json.Unmarshal(rawSLA, &sla); err != nil {
		return 0, 0, fmt.Errorf("organization.sla_days: %w", err)
	}
	found := injectFindings(in.Matches)
	fps := make([]string, len(found))
	for i, f := range found {
		fps[i] = f.fingerprint
	}
	rows, err := db.Query(ctx, `SELECT id, fingerprint, tool, status, severity, severity_overridden, last_seen_scan_id, target, version
		FROM issue WHERE project_id = $1 AND fingerprint = ANY($2)`, in.ProjectID, fps)
	if err != nil {
		return 0, 0, fmt.Errorf("load issues: %w", err)
	}
	type existing struct {
		ExistingIssue
		target  string
		version int
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (existing, error) {
		var e existing
		var st, sev string
		err := r.Scan(&e.ID, &e.Fingerprint, &e.Tool, &st, &sev, &e.SeverityOverridden, &e.LastSeenScanID, &e.target, &e.version)
		e.Status, e.Severity = issuestate.Status(st), severity.Severity(sev)
		return e, err
	})
	if err != nil {
		return 0, 0, fmt.Errorf("load issues: %w", err)
	}
	byFP := make(map[string]existing, len(list))
	for _, e := range list {
		byFP[e.Fingerprint] = e
	}

	var fresh []injectFinding
	for _, f := range found {
		e, ok := byFP[f.fingerprint]
		if !ok {
			fresh = append(fresh, f)
			continue
		}
		if e.target != in.Target || (e.Status != issuestate.Fixed && e.Status != issuestate.Verified) {
			continue
		}
		a := applier{db: db, in: Input{OrgID: in.OrgID, ProjectID: in.ProjectID, ScanID: f.match.ScanID, Target: in.Target, Now: in.Now}, sla: sla}
		due := sla.DueAt(e.Severity, in.Now)
		changed, err := a.transition(ctx, e.ExistingIssue, issuestate.Reopened, due, injectNote(f.match.Advisory.ID))
		if err != nil {
			return created, reopened, err
		}
		if !changed {
			continue
		}
		reopened++
		if err := a.outbox(ctx, notify.IssueReopened, notify.Payload{IssueID: notify.ID(e.ID)}); err != nil {
			return created, reopened, err
		}
		if err := maliciousEvent(ctx, db, in.OrgID, e.ID, e.version+1); err != nil {
			return created, reopened, err
		}
	}
	if len(fresh) == 0 {
		return created, reopened, nil
	}

	rules, eligible, err := loadAssignRules(ctx, db, in.ProjectID)
	if err != nil {
		return created, reopened, err
	}
	var last int
	if err := db.QueryRow(ctx, `UPDATE project SET issue_seq = issue_seq + $2 WHERE id = $1 RETURNING issue_seq`,
		in.ProjectID, len(fresh)).Scan(&last); err != nil {
		return created, reopened, fmt.Errorf("allocate issue numbers: %w", err)
	}
	first := last - len(fresh) + 1
	for i, f := range fresh {
		a := applier{db: db, in: Input{OrgID: in.OrgID, ProjectID: in.ProjectID, ScanID: f.match.ScanID, Target: in.Target, Now: in.Now},
			sla: sla, rules: rules, eligible: eligible, createNote: injectNote(f.match.Advisory.ID)}
		if err := a.create(ctx, first+i, NewIssue{Fingerprint: f.fingerprint, Finding: f.finding}, in.Now); err != nil {
			return created, reopened, err
		}
		created++
		var id uuid.UUID
		var version int
		if err := db.QueryRow(ctx, `SELECT id, version FROM issue WHERE project_id = $1 AND fingerprint = $2`,
			in.ProjectID, f.fingerprint).Scan(&id, &version); err != nil {
			return created, reopened, fmt.Errorf("created issue: %w", err)
		}
		if err := maliciousEvent(ctx, db, in.OrgID, id, version); err != nil {
			return created, reopened, err
		}
	}
	return created, reopened, nil
}

func injectNote(id string) string {
	return "found by malicious-package advisory " + id + " (no scan)"
}
