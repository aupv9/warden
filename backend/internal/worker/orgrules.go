package worker

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aupv9/warden/backend/internal/domain/severity"
	"github.com/aupv9/warden/backend/internal/rules"
	"github.com/aupv9/warden/backend/internal/scan/orchestrator"
	"github.com/aupv9/warden/backend/internal/scan/results"
	"github.com/aupv9/warden/backend/internal/scan/sandbox"
)

// An org's own rules (scan_rule) run in every scan of the org's projects
// they apply to (project_ids NULL: all of them), in addition to Warden's.
// Each rule is checked again with rules.Parse before it runs: the stored body
// came through the API once, but a rule the current parser refuses (a newer
// Warden is stricter, or the row was changed behind the API's back) must not
// reach a scanner. Such a rule is skipped and logged, never fails the scan,
// and isn't recorded on the scan, so its issues are not auto-fixed.

// orgRuleTools are the tools that take org rules, in the order they are loaded.
var orgRuleTools = []rules.Tool{rules.Opengrep, rules.Gitleaks}

// parseRule and renderRules are rules.Parse and rules.Render; tests replace them.
var (
	parseRule   = rules.Parse
	renderRules = rules.Render
)

// orgRule is an enabled rule as it runs in one scan.
type orgRule struct {
	rule     rules.Rule
	severity severity.Severity
	version  int
	sha256   string
}

// scanOrgRules are a scan's org rules, by tool.
type scanOrgRules map[string][]orgRule

// loadOrgRules reads the org's enabled rules that apply to project, for the
// scan's tools that take org rules. It runs in the scan's org transaction.
func loadOrgRules(ctx context.Context, db DB, org, project uuid.UUID, tools []string, log *slog.Logger) (scanOrgRules, error) {
	var want []string
	for _, t := range orgRuleTools {
		if slices.Contains(tools, string(t)) {
			want = append(want, string(t))
		}
	}
	if len(want) == 0 {
		return nil, nil
	}
	rows, err := db.Query(ctx, `SELECT id, tool::text, key, body_canonical, severity::text, version, sha256 FROM scan_rule
		WHERE org_id = $1 AND enabled AND deleted_at IS NULL AND tool::text = ANY($2::text[])
		  AND (project_ids IS NULL OR $3::uuid = ANY(project_ids))
		ORDER BY tool, key`, org, want, project)
	if err != nil {
		return nil, fmt.Errorf("load org rules: %w", err)
	}
	type row struct {
		id                   uuid.UUID
		tool, key, sev, hash string
		body                 []byte
		version              int
	}
	rs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (row, error) {
		var x row
		err := r.Scan(&x.id, &x.tool, &x.key, &x.body, &x.sev, &x.version, &x.hash)
		return x, err
	})
	if err != nil {
		return nil, fmt.Errorf("load org rules: %w", err)
	}
	out := scanOrgRules{}
	for _, x := range rs {
		skip := func(why string) {
			log.Warn("org rule skipped: "+why, "scan_rule_id", x.id, "tool", x.tool, "key", x.key, "version", x.version)
		}
		r, problems := parseRule(rules.Tool(x.tool), x.body)
		switch {
		case len(problems) > 0:
			skip("it no longer validates")
			continue
		case r.Key != x.key || r.Tool != rules.Tool(x.tool):
			skip("its body doesn't match its row")
			continue
		}
		sev, err := severity.Parse(x.sev)
		if err != nil {
			skip("invalid severity")
			continue
		}
		out[x.tool] = append(out[x.tool], orgRule{rule: r, severity: sev, version: x.version, sha256: x.hash})
	}
	return out, nil
}

// render turns the rules into what the orchestrator writes for the sandbox,
// and the refs recorded on the scan if their tool succeeds. A tool whose
// rules can't be rendered runs Warden's rules only (logged): the org's rules
// then didn't run, so none of their issues is auto-fixed.
func (s scanOrgRules) render(log *slog.Logger) (map[string]orchestrator.OrgRules, []results.OrgRuleRef) {
	if len(s) == 0 {
		return nil, nil
	}
	jobRules := map[string]orchestrator.OrgRules{}
	var refs []results.OrgRuleRef
	for _, t := range orgRuleTools {
		rs := s[string(t)]
		if len(rs) == 0 {
			continue
		}
		parsed := make([]rules.Rule, len(rs))
		for i, r := range rs {
			parsed[i] = r.rule
		}
		config, err := renderRules(t, parsed)
		if err != nil || len(config) == 0 {
			log.Error("org rules not rendered; the tool runs Warden's rules only", "tool", t, "err", err)
			continue
		}
		sev := make(map[string]severity.Severity, len(rs))
		for _, r := range rs {
			sev[r.rule.ID()] = r.severity
			refs = append(refs, results.OrgRuleRef{RuleID: r.rule.ID(), Tool: string(t), Version: r.version, SHA256: r.sha256})
		}
		jobRules[string(t)] = orchestrator.OrgRules{Config: config, Severity: sev}
	}
	return jobRules, refs
}

// loadedRules keeps the refs of rules their tool loaded (listed in its
// SARIF). A rule the tool dropped (Opengrep runs the rest of a config when one
// rule doesn't load) didn't run: it isn't recorded and fixes nothing. Refs of
// tools that didn't succeed are dropped later, by the result processor.
func loadedRules(refs []results.OrgRuleRef, loaded map[string]map[string]bool, log *slog.Logger) []results.OrgRuleRef {
	var out []results.OrgRuleRef
	for _, r := range refs {
		l, reported := loaded[r.Tool]
		switch {
		case !reported: // the tool didn't succeed: nothing to check
			out = append(out, r)
		case l[r.RuleID]:
			out = append(out, r)
		default:
			log.Warn("org rule not loaded by its scanner; recorded as not run", "tool", r.Tool, "rule_id", r.RuleID, "version", r.Version)
		}
	}
	return out
}

// specFor returns the sandbox spec of tool, running the org's rules too when
// the scan has any for it.
func specFor(spec sandbox.ToolSpec, orgRules map[string]orchestrator.OrgRules) (sandbox.ToolSpec, error) {
	if len(orgRules[spec.Name].Config) == 0 {
		return spec, nil
	}
	return sandbox.WithOrgRules(spec)
}
