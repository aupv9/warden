package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	apperrors "github.com/aupv9/common-go/errors"
	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/rbac"
	"github.com/aupv9/warden/backend/internal/ids"
	"github.com/aupv9/warden/backend/internal/rules"
)

// An org's own scan rules (v0.6 wave 1): Opengrep and Gitleaks rules that
// every scan of the org runs (internal/rules parses and renders them).
//
// Writes, validation and tests need manage_rules (org admins, security
// leads): a rule decides what every scan looks for. Reads are for anyone who
// can see results somewhere in the org, scoped like the results themselves:
// org admins and security leads see every rule; a member sees the rules that
// apply to a project they belong to (project_ids null, or naming one of
// theirs), with project_ids cut down to those projects, and any other rule is
// 404. Rules aren't secrets (their findings are shown to the same people),
// but a body or a project list can name internal systems a member has no
// business knowing about. A member of no project gets 403, like a missing
// view_results. API tokens can't call any of these routes (internal/api's
// allow-list); the service refuses them too.
//
// Audit entries carry id, tool, key and sha256: never the body or the name.

// RuleParser is rules.Parse's signature (Config.ParseRule, for tests).
type RuleParser func(tool rules.Tool, body []byte) (rules.Rule, []rules.Problem)

const (
	maxRuleName     = 200
	maxRuleProjects = 200
	maxVersionLimit = 100
	// ruleTestsPerHour caps a user's rule tests (sandbox runs) per hour.
	ruleTestsPerHour = 20
	// RuleTestRetention is how long a test's result can be read; the worker
	// prunes older rows.
	RuleTestRetention = 24 * time.Hour
	maxTestFilename   = 255
	maxSnippetBytes   = rules.MaxBodyBytes
)

var (
	ruleKeyRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	ruleFilenameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,255}$`)
	ruleTools      = []string{string(rules.Opengrep), string(rules.Gitleaks)}
)

// ScanRule is a rule as the API shows it. ProjectIDs nil (JSON null) means
// every project of the org.
type ScanRule struct {
	ID         uuid.UUID   `json:"id"`
	Tool       string      `json:"tool"`
	Key        string      `json:"key"`
	RuleID     string      `json:"rule_id"`
	Name       string      `json:"name"`
	Body       string      `json:"body"`
	SHA256     string      `json:"sha256"`
	Version    int         `json:"version"`
	Enabled    bool        `json:"enabled"`
	Severity   string      `json:"severity"`
	ProjectIDs []uuid.UUID `json:"project_ids"`
	CreatedBy  *UserRef    `json:"created_by"`
	UpdatedBy  *UserRef    `json:"updated_by"`
	CreatedAt  Time        `json:"created_at"`
	UpdatedAt  Time        `json:"updated_at"`

	OrgID uuid.UUID `json:"-"`
}

// ScanRuleVersion is one entry of a rule's history.
type ScanRuleVersion struct {
	Version    int         `json:"version"`
	Body       string      `json:"body"`
	SHA256     string      `json:"sha256"`
	Name       string      `json:"name"`
	Enabled    bool        `json:"enabled"`
	ProjectIDs []uuid.UUID `json:"project_ids"`
	CreatedBy  *UserRef    `json:"created_by"`
	CreatedAt  Time        `json:"created_at"`
}

// RuleProblem is rules.Problem as the API shows it (null position when unknown).
type RuleProblem struct {
	Line    *int   `json:"line"`
	Column  *int   `json:"column"`
	Message string `json:"message"`
}

type RuleValidation struct {
	OK       bool          `json:"ok"`
	Key      *string       `json:"key"`
	Severity *string       `json:"severity"`
	Body     *string       `json:"body"`
	Problems []RuleProblem `json:"problems"`
}

// RuleTestFinding is one match of a rule test: lines and the rule's message,
// never the matched text.
type RuleTestFinding struct {
	Line    int    `json:"line"`
	EndLine *int   `json:"end_line"`
	Message string `json:"message"`
}

// RuleTest is a draft rule's run against a snippet (job test_rules).
type RuleTest struct {
	ID         uuid.UUID         `json:"id"`
	State      string            `json:"state"`
	Findings   []RuleTestFinding `json:"findings"`
	Error      *string           `json:"error"`
	CreatedAt  Time              `json:"created_at"`
	FinishedAt *Time             `json:"finished_at"`

	CreatedBy uuid.UUID `json:"-"`
}

// NewRuleTest is a scan_rule_test row to insert (state queued).
type NewRuleTest struct {
	ID        uuid.UUID
	OrgID     uuid.UUID
	CreatedBy uuid.UUID
	Tool      string
	Body      []byte // canonical
	Filename  string
	Snippet   string
	CreatedAt time.Time
}

// ScanRuleRef is one org rule a scan ran (scan.org_rules, written by the worker).
type ScanRuleRef struct {
	RuleID  string `json:"rule_id"`
	Tool    string `json:"tool"`
	Version int    `json:"version"`
	SHA256  string `json:"sha256"`
}

// ScanRuleRefs renders as [] when empty.
type ScanRuleRefs []ScanRuleRef

func (r ScanRuleRefs) MarshalJSON() ([]byte, error) {
	if r == nil {
		return []byte("[]"), nil
	}
	return json.Marshal([]ScanRuleRef(r))
}

// IssueOrgRule is set on issues from an org rule (rule_id org.<key>). Name and
// ScanRuleID are null when no rule with that key exists (any more); a deleted
// rule still gives its name.
type IssueOrgRule struct {
	RuleID     string     `json:"rule_id"`
	Name       *string    `json:"name"`
	ScanRuleID *uuid.UUID `json:"scan_rule_id"`
}

// RuleVersionCursor positions a newest-first version list.
type RuleVersionCursor struct {
	Version int `json:"v"`
}

// ScanRuleRepo is the scan-rule part of Repo. Every method runs under the
// org's app.org_id (the three tables have forced RLS). Deleted rules are
// invisible to every method except the issue lookup (Issue.OrgRule).
type ScanRuleRepo interface {
	// LockScanRules serializes rule writes per org, so the limits hold.
	LockScanRules(ctx context.Context, orgID uuid.UUID) error
	// ScanRules lists the org's rules of tool ("" for every tool) by tool and key.
	ScanRules(ctx context.Context, tool string) ([]ScanRule, error)
	// ScanRule returns one, locked when forUpdate; ErrNotFound if there is none.
	ScanRule(ctx context.Context, id uuid.UUID, forUpdate bool) (ScanRule, error)
	// ScanRuleUsage counts the org's rules of tool and sums the canonical
	// bytes of all its rules.
	ScanRuleUsage(ctx context.Context, tool string) (count int, bytes int64, err error)
	// InsertScanRule inserts the rule and its version 1 (ErrConflict for a
	// duplicate key).
	InsertScanRule(ctx context.Context, r ScanRule) error
	// UpdateScanRule writes every mutable column of r and appends version
	// r.Version, by r.UpdatedBy.
	UpdateScanRule(ctx context.Context, r ScanRule) error
	DeleteScanRule(ctx context.Context, id, by uuid.UUID, at time.Time) error
	// ScanRuleVersions lists a rule's versions below before (0: from the
	// newest), newest first.
	ScanRuleVersions(ctx context.Context, id uuid.UUID, before, limit int) ([]ScanRuleVersion, error)
	// UserProjectRoles returns the user's role in each project of the org
	// they are a member of (archived ones included).
	UserProjectRoles(ctx context.Context, userID uuid.UUID) (map[uuid.UUID]rbac.Role, error)
	// LockRuleTests serializes a user's rule tests, so the rate limit holds.
	LockRuleTests(ctx context.Context, userID uuid.UUID) error
	// RuleTestsSince counts the user's tests created after since and returns
	// the oldest one's time (zero if none).
	RuleTestsSince(ctx context.Context, userID uuid.UUID, since time.Time) (int, time.Time, error)
	// InsertRuleTest inserts a queued test and enqueues its test_rules job in
	// the same transaction.
	InsertRuleTest(ctx context.Context, t NewRuleTest) error
	RuleTest(ctx context.Context, id uuid.UUID) (RuleTest, error)
}

type CreateScanRuleInput struct {
	Tool       string   `json:"tool"`
	Name       string   `json:"name"`
	Body       string   `json:"body"`
	Enabled    *bool    `json:"enabled"`
	ProjectIDs []string `json:"project_ids"`
}

type UpdateScanRuleInput struct {
	Version    *int               `json:"version"`
	Name       *string            `json:"name"`
	Body       *string            `json:"body"`
	Enabled    *bool              `json:"enabled"`
	ProjectIDs Optional[[]string] `json:"project_ids"`
}

type ValidateScanRuleInput struct {
	Tool string `json:"tool"`
	Body string `json:"body"`
}

type RuleTestInput struct {
	Tool     string  `json:"tool"`
	Body     string  `json:"body"`
	Filename string  `json:"filename"`
	Snippet  *string `json:"snippet"`
}

// ScanRuleFilter is the raw query of GET /scan-rules.
type ScanRuleFilter struct {
	Tool string
}

func errRuleInvalid(problems []RuleProblem) error {
	list := make([]any, len(problems))
	for i, p := range problems {
		list[i] = p
	}
	return apperrors.Invalid("RULE_INVALID", "the rule is invalid").
		WithHTTPStatus(http.StatusUnprocessableEntity).WithMetadata("problems", list)
}

func errRuleVersionConflict() error {
	return apperrors.Conflict("VERSION_CONFLICT", "the rule was changed by someone else; reload it and try again")
}

func errRuleTestsRateLimited(retryAfter time.Duration) error {
	secs := max(int64((retryAfter+time.Second-1)/time.Second), 1)
	return apperrors.Invalid("RATE_LIMITED", "you've run "+strconv.Itoa(ruleTestsPerHour)+" rule tests in the last hour; try again later").
		WithHTTPStatus(http.StatusTooManyRequests).WithMetadata("retry_after", secs)
}

// manageRules checks manage_rules. API tokens never get here (no scan-rule
// route is in the API's allow-list); the check is repeated anyway.
func manageRules(a *Actor) error {
	if a.Token != nil || !rbac.Can(rbac.ManageRules, a.OrgRole, "", false) {
		return errForbidden()
	}
	return nil
}

// ruleScope is what a reader may see: every rule (all), or the rules of the
// projects in mine.
type ruleScope struct {
	all  bool
	mine []uuid.UUID
}

// readRules returns the caller's scope (see the comment at the top).
func readRules(ctx context.Context, r Repo, a *Actor) (ruleScope, error) {
	if a.Token != nil {
		return ruleScope{}, errForbidden()
	}
	if a.seesAllProjects() {
		return ruleScope{all: true}, nil
	}
	roles, err := r.UserProjectRoles(ctx, a.UserID)
	if err != nil {
		return ruleScope{}, err
	}
	var mine []uuid.UUID
	for id, role := range roles {
		if rbac.Can(rbac.ViewResults, a.OrgRole, role, false) {
			mine = append(mine, id)
		}
	}
	if len(mine) == 0 {
		return ruleScope{}, errForbidden()
	}
	return ruleScope{mine: mine}, nil
}

// cut returns the part of ids the scope sees and whether a rule with those
// project ids is visible at all.
func (sc ruleScope) cut(ids []uuid.UUID) ([]uuid.UUID, bool) {
	if sc.all || ids == nil {
		return ids, true
	}
	out := []uuid.UUID{}
	for _, id := range ids {
		if slices.Contains(sc.mine, id) {
			out = append(out, id)
		}
	}
	return out, len(out) > 0
}

func (s *Service) parseRule(tool rules.Tool, body []byte) (rules.Rule, []rules.Problem) {
	if s.cfg.ParseRule != nil {
		return s.cfg.ParseRule(tool, body)
	}
	return rules.Parse(tool, body)
}

// maxProblems caps the problems returned for one body.
const maxProblems = 50

func ruleProblems(ps []rules.Problem) []RuleProblem {
	ps = ps[:min(len(ps), maxProblems)]
	out := make([]RuleProblem, 0, len(ps))
	for _, p := range ps {
		rp := RuleProblem{Message: p.Message}
		if p.Line > 0 {
			rp.Line = ptr(p.Line)
		}
		if p.Column > 0 {
			rp.Column = ptr(p.Column)
		}
		out = append(out, rp)
	}
	return out
}

// parse runs the parser and checks what it returned against what the schema
// stores, so a parser bug is a refused rule rather than a 500 or a row the
// worker can't use.
func (s *Service) parse(tool string, body string) (rules.Rule, []RuleProblem) {
	rule, problems := s.parseRule(rules.Tool(tool), []byte(body))
	if len(problems) > 0 {
		return rules.Rule{}, ruleProblems(problems)
	}
	switch {
	case rule.Tool != rules.Tool(tool):
		return rules.Rule{}, []RuleProblem{{Message: "the rule is for another tool"}}
	case !ruleKeyRe.MatchString(rule.Key):
		return rules.Rule{}, []RuleProblem{{Message: "the rule id must be 1-64 characters: a-z, 0-9, '.', '_' or '-', starting with a letter or digit"}}
	case !slices.Contains(severities, rule.Severity):
		return rules.Rule{}, []RuleProblem{{Message: "the rule's severity must be critical, high, medium, low or info"}}
	case len(rule.Canonical) == 0 || len(rule.Canonical) > rules.MaxBodyBytes || !validText(string(rule.Canonical)):
		return rules.Rule{}, []RuleProblem{{Message: fmt.Sprintf("the rule must be at most %d bytes as Warden stores it", rules.MaxBodyBytes)}}
	}
	return rule, nil
}

func validRuleTool(fe fieldErrors, tool string) {
	if !slices.Contains(ruleTools, tool) {
		fe.add("tool", "must be opengrep or gitleaks")
	}
}

func validRuleBody(fe fieldErrors, body string) {
	if body == "" || len(body) > rules.MaxBodyBytes || !validText(body) {
		fe.add("body", fmt.Sprintf("must be 1-%d bytes of UTF-8 text", rules.MaxBodyBytes))
	}
}

func validRuleName(fe fieldErrors, name string) string {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > maxRuleName || !validText(name) || strings.ContainsFunc(name, isControl) {
		fe.add("name", "must be 1-200 characters")
	}
	return name
}

// validRuleProjects parses a non-null project list: 1-200 distinct ids of the
// org's projects (null, not [], means every project).
func validRuleProjects(ctx context.Context, r Repo, fe fieldErrors, raw []string) ([]uuid.UUID, error) {
	if len(raw) == 0 || len(raw) > maxRuleProjects {
		fe.add("project_ids", "must list 1-200 projects, or be null for every project")
		return nil, nil
	}
	out := make([]uuid.UUID, 0, len(raw))
	for _, s := range raw {
		id, err := uuid.Parse(s)
		if err != nil || slices.Contains(out, id) {
			fe.add("project_ids", "must be distinct project ids")
			return nil, nil
		}
		out = append(out, id)
	}
	return out, checkProjects(ctx, r, fe, out)
}

func ruleSum(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

func ruleAudit(rule ScanRule) map[string]any {
	return map[string]any{"id": rule.ID.String(), "tool": rule.Tool, "key": rule.Key, "sha256": rule.SHA256}
}

// checkRuleLimits: at most rules.MaxRulesPerTool rules per tool (adding is
// true for a new rule) and rules.MaxOrgBytes canonical bytes per org, delta
// being the change in bytes. The caller holds LockScanRules.
func checkRuleLimits(ctx context.Context, r Repo, tool string, adding bool, delta int64) error {
	n, total, err := r.ScanRuleUsage(ctx, tool)
	if err != nil {
		return err
	}
	if adding && n >= rules.MaxRulesPerTool {
		return errConflict(fmt.Sprintf("an organization can have at most %d %s rules", rules.MaxRulesPerTool, tool))
	}
	if delta > 0 && total+delta > rules.MaxOrgBytes {
		return errConflict(fmt.Sprintf("an organization's rules can take at most %d KiB together", rules.MaxOrgBytes>>10))
	}
	return nil
}

// ScanRules lists the org's rules the caller can see.
func (s *Service) ScanRules(ctx context.Context, a *Actor, f ScanRuleFilter) (Items[ScanRule], error) {
	out := Items[ScanRule]{Items: []ScanRule{}}
	if f.Tool != "" && !slices.Contains(ruleTools, f.Tool) {
		return out, errField("tool", "must be opengrep or gitleaks")
	}
	err := s.inOrg(ctx, a, func(r Repo) error {
		sc, err := readRules(ctx, r, a)
		if err != nil {
			return err
		}
		list, err := r.ScanRules(ctx, f.Tool)
		for _, rule := range list {
			var ok bool
			if rule.ProjectIDs, ok = sc.cut(rule.ProjectIDs); ok {
				out.Items = append(out.Items, rule)
			}
		}
		return err
	})
	return out, err
}

// ScanRule returns one rule the caller can see.
func (s *Service) ScanRule(ctx context.Context, a *Actor, id uuid.UUID) (ScanRule, error) {
	var out ScanRule
	err := s.inOrg(ctx, a, func(r Repo) error {
		sc, err := readRules(ctx, r, a)
		if err != nil {
			return err
		}
		rule, err := r.ScanRule(ctx, id, false)
		if err != nil {
			return notFound(err)
		}
		var ok bool
		if rule.ProjectIDs, ok = sc.cut(rule.ProjectIDs); !ok {
			return errNotFound()
		}
		out = rule
		return nil
	})
	return out, err
}

// ScanRuleVersions lists a rule's history, newest first. A member sees the
// history of a rule they can see now, with each version's projects cut to
// theirs.
func (s *Service) ScanRuleVersions(ctx context.Context, a *Actor, id uuid.UUID, p PageParams) (Page[ScanRuleVersion], error) {
	var out Page[ScanRuleVersion]
	limit := DefaultLimit
	if p.Limit != "" {
		n, err := strconv.Atoi(p.Limit)
		if err != nil || n < 1 || n > maxVersionLimit {
			return out, errField("limit", "must be an integer between 1 and 100")
		}
		limit = n
	}
	before := 0
	if p.Cursor != "" {
		var c RuleVersionCursor
		if err := decodeCursor(p.Cursor, &c); err != nil {
			return out, err
		}
		if c.Version < 2 {
			return out, errField("cursor", "invalid cursor")
		}
		before = c.Version
	}
	err := s.inOrg(ctx, a, func(r Repo) error {
		sc, err := readRules(ctx, r, a)
		if err != nil {
			return err
		}
		rule, err := r.ScanRule(ctx, id, false)
		if err != nil {
			return notFound(err)
		}
		if _, ok := sc.cut(rule.ProjectIDs); !ok {
			return errNotFound()
		}
		rows, err := r.ScanRuleVersions(ctx, id, before, limit+1)
		if err != nil {
			return err
		}
		for i := range rows {
			rows[i].ProjectIDs, _ = sc.cut(rows[i].ProjectIDs)
		}
		out.Items, out.NextCursor = page(rows, limit, func(v ScanRuleVersion) any { return RuleVersionCursor{Version: v.Version} })
		return nil
	})
	return out, err
}

// CreateScanRule adds a rule (version 1). The body is stored as Warden
// rendered it from the parsed rule.
func (s *Service) CreateScanRule(ctx context.Context, a *Actor, in CreateScanRuleInput) (ScanRule, error) {
	var out ScanRule
	err := s.inOrg(ctx, a, func(r Repo) error {
		if err := manageRules(a); err != nil {
			return err
		}
		fe := fieldErrors{}
		validRuleTool(fe, in.Tool)
		name := validRuleName(fe, in.Name)
		validRuleBody(fe, in.Body)
		var projects []uuid.UUID
		if in.ProjectIDs != nil {
			var err error
			if projects, err = validRuleProjects(ctx, r, fe, in.ProjectIDs); err != nil {
				return err
			}
		}
		if err := fe.err(); err != nil {
			return err
		}
		parsed, problems := s.parse(in.Tool, in.Body)
		if problems != nil {
			return errRuleInvalid(problems)
		}
		if err := r.LockScanRules(ctx, a.OrgID); err != nil {
			return err
		}
		if err := checkRuleLimits(ctx, r, in.Tool, true, int64(len(parsed.Canonical))); err != nil {
			return err
		}
		now := Time(s.now().UTC())
		rule := ScanRule{
			ID: ids.New(), OrgID: a.OrgID, Tool: in.Tool, Key: parsed.Key, RuleID: parsed.ID(), Name: name,
			Body: string(parsed.Canonical), SHA256: ruleSum(parsed.Canonical), Version: 1, Enabled: in.Enabled == nil || *in.Enabled,
			Severity: parsed.Severity, ProjectIDs: projects, CreatedBy: &UserRef{ID: a.UserID}, UpdatedBy: &UserRef{ID: a.UserID},
			CreatedAt: now, UpdatedAt: now,
		}
		if err := r.InsertScanRule(ctx, rule); errors.Is(err, ErrConflict) {
			return errConflict(fmt.Sprintf("the organization already has a %s rule %q", in.Tool, parsed.Key))
		} else if err != nil {
			return err
		}
		stored, err := r.ScanRule(ctx, rule.ID, false)
		if err != nil {
			return err
		}
		out = stored
		return s.audit(ctx, r, a, "scan_rule.created", "scan_rule", rule.ID.String(), ruleAudit(stored))
	})
	return out, err
}

// UpdateScanRule changes the fields sent, if version is the rule's current
// one. Any change makes a new version; the rule's id (key) and tool can't
// change. Disabling a rule leaves its issues as they are.
func (s *Service) UpdateScanRule(ctx context.Context, a *Actor, id uuid.UUID, in UpdateScanRuleInput) (ScanRule, error) {
	var out ScanRule
	if in.Version == nil || *in.Version < 1 {
		return out, errField("version", "is required: the version you read")
	}
	err := s.inOrg(ctx, a, func(r Repo) error {
		if err := manageRules(a); err != nil {
			return err
		}
		if err := r.LockScanRules(ctx, a.OrgID); err != nil {
			return err
		}
		rule, err := r.ScanRule(ctx, id, true)
		if err != nil {
			return notFound(err)
		}
		if *in.Version != rule.Version {
			return errRuleVersionConflict()
		}
		fe := fieldErrors{}
		if in.Name == nil && in.Body == nil && in.Enabled == nil && !in.ProjectIDs.Set {
			fe.add("request", "must change at least one field")
		}
		updated, enabled := false, false
		if in.Name != nil {
			if name := validRuleName(fe, *in.Name); name != rule.Name {
				rule.Name, updated = name, true
			}
		}
		if in.ProjectIDs.Set {
			var projects []uuid.UUID
			if in.ProjectIDs.Value != nil {
				if projects, err = validRuleProjects(ctx, r, fe, *in.ProjectIDs.Value); err != nil {
					return err
				}
			}
			if (projects == nil) != (rule.ProjectIDs == nil) || !slices.Equal(projects, rule.ProjectIDs) {
				rule.ProjectIDs, updated = projects, true
			}
		}
		if in.Body != nil {
			validRuleBody(fe, *in.Body)
		}
		if err := fe.err(); err != nil {
			return err
		}
		if in.Body != nil {
			parsed, problems := s.parse(rule.Tool, *in.Body)
			if problems != nil {
				return errRuleInvalid(problems)
			}
			if parsed.Key != rule.Key {
				// Its issues and past scans name org.<key>: a new id is a new rule.
				return errRuleInvalid([]RuleProblem{{Message: fmt.Sprintf("the rule id can't change (it is %q); add a new rule for a new id", rule.Key)}})
			}
			if sum := ruleSum(parsed.Canonical); sum != rule.SHA256 {
				if err := checkRuleLimits(ctx, r, rule.Tool, false, int64(len(parsed.Canonical)-len(rule.Body))); err != nil {
					return err
				}
				rule.Body, rule.SHA256, rule.Severity, updated = string(parsed.Canonical), sum, parsed.Severity, true
			}
		}
		if in.Enabled != nil && *in.Enabled != rule.Enabled {
			rule.Enabled, enabled = *in.Enabled, true
		}
		if !updated && !enabled {
			out = rule
			return nil
		}
		rule.Version++
		rule.UpdatedBy, rule.UpdatedAt = &UserRef{ID: a.UserID}, Time(s.now().UTC())
		if err := r.UpdateScanRule(ctx, rule); err != nil {
			return err
		}
		stored, err := r.ScanRule(ctx, id, false)
		if err != nil {
			return err
		}
		out = stored
		if updated {
			if err := s.audit(ctx, r, a, "scan_rule.updated", "scan_rule", id.String(), ruleAudit(stored)); err != nil {
				return err
			}
		}
		if enabled {
			action := "scan_rule.disabled"
			if stored.Enabled {
				action = "scan_rule.enabled"
			}
			return s.audit(ctx, r, a, action, "scan_rule", id.String(), ruleAudit(stored))
		}
		return nil
	})
	return out, err
}

// DeleteScanRule soft-deletes a rule at version (?version=). Its versions
// stay, and so do its issues; the key can be used again.
func (s *Service) DeleteScanRule(ctx context.Context, a *Actor, id uuid.UUID, version string) error {
	v, err := strconv.Atoi(version)
	if err != nil || v < 1 {
		return errField("version", "is required: the version you read")
	}
	return s.inOrg(ctx, a, func(r Repo) error {
		if err := manageRules(a); err != nil {
			return err
		}
		rule, err := r.ScanRule(ctx, id, true)
		if err != nil {
			return notFound(err)
		}
		if v != rule.Version {
			return errRuleVersionConflict()
		}
		if err := r.DeleteScanRule(ctx, id, a.UserID, s.now().UTC()); err != nil {
			return err
		}
		return s.audit(ctx, r, a, "scan_rule.deleted", "scan_rule", id.String(), ruleAudit(rule))
	})
}

// ValidateScanRule parses a body without storing anything; problems are a
// result here, not an error.
func (s *Service) ValidateScanRule(ctx context.Context, a *Actor, in ValidateScanRuleInput) (RuleValidation, error) {
	out := RuleValidation{Problems: []RuleProblem{}}
	err := s.inOrg(ctx, a, func(Repo) error {
		if err := manageRules(a); err != nil {
			return err
		}
		fe := fieldErrors{}
		validRuleTool(fe, in.Tool)
		validRuleBody(fe, in.Body)
		if err := fe.err(); err != nil {
			return err
		}
		parsed, problems := s.parse(in.Tool, in.Body)
		if problems != nil {
			out.Problems = problems
			return nil
		}
		body := string(parsed.Canonical)
		out.OK, out.Key, out.Severity, out.Body = true, &parsed.Key, &parsed.Severity, &body
		return nil
	})
	return out, err
}

// CreateRuleTest queues a draft rule's run against a snippet (job
// test_rules), at most ruleTestsPerHour per user per hour. The snippet is
// stored only until the run ends and never goes into the job's arguments.
func (s *Service) CreateRuleTest(ctx context.Context, a *Actor, in RuleTestInput) (RuleTest, error) {
	var out RuleTest
	err := s.inOrg(ctx, a, func(r Repo) error {
		if err := manageRules(a); err != nil {
			return err
		}
		fe := fieldErrors{}
		validRuleTool(fe, in.Tool)
		validRuleBody(fe, in.Body)
		// One plain file name in the sandbox's work directory: no path, and
		// not "." or "..".
		if !ruleFilenameRe.MatchString(in.Filename) || strings.Trim(in.Filename, ".") == "" {
			fe.add("filename", "must be a file name of 1-255 characters: A-Z, a-z, 0-9, '.', '_' or '-'")
		}
		if in.Snippet == nil || len(*in.Snippet) > maxSnippetBytes || !validText(*in.Snippet) {
			fe.add("snippet", fmt.Sprintf("must be at most %d bytes of UTF-8 text", maxSnippetBytes))
		}
		if err := fe.err(); err != nil {
			return err
		}
		parsed, problems := s.parse(in.Tool, in.Body)
		if problems != nil {
			return errRuleInvalid(problems)
		}
		// Counted from the table, so the limit holds across API instances;
		// like the scan limit it is per user within the org (RLS).
		if err := r.LockRuleTests(ctx, a.UserID); err != nil {
			return err
		}
		now := s.now().UTC()
		n, oldest, err := r.RuleTestsSince(ctx, a.UserID, now.Add(-oneHour))
		if err != nil {
			return err
		}
		if n >= ruleTestsPerHour {
			return errRuleTestsRateLimited(oldest.Add(oneHour).Sub(now))
		}
		t := NewRuleTest{ID: ids.New(), OrgID: a.OrgID, CreatedBy: a.UserID, Tool: in.Tool, Body: parsed.Canonical,
			Filename: in.Filename, Snippet: *in.Snippet, CreatedAt: now}
		if err := r.InsertRuleTest(ctx, t); err != nil {
			return err
		}
		out = RuleTest{ID: t.ID, State: "queued", Findings: []RuleTestFinding{}, CreatedAt: Time(now), CreatedBy: a.UserID}
		return nil
	})
	return out, err
}

// RuleTest returns a test to its creator, for RuleTestRetention; anyone else,
// and anyone later, gets 404.
func (s *Service) RuleTest(ctx context.Context, a *Actor, id uuid.UUID) (RuleTest, error) {
	var out RuleTest
	err := s.inOrg(ctx, a, func(r Repo) error {
		if err := manageRules(a); err != nil {
			return err
		}
		t, err := r.RuleTest(ctx, id)
		if err != nil {
			return notFound(err)
		}
		if t.CreatedBy != a.UserID || t.CreatedAt.T().Before(s.now().Add(-RuleTestRetention)) {
			return errNotFound()
		}
		if t.Findings == nil {
			t.Findings = []RuleTestFinding{}
		}
		out = t
		return nil
	})
	return out, err
}
