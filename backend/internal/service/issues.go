package service

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/issuestate"
	"github.com/aupv9/warden/backend/internal/domain/rbac"
	"github.com/aupv9/warden/backend/internal/ids"
	"github.com/aupv9/warden/backend/internal/notify"
)

const (
	maxQueryLen   = 200
	maxReasonLen  = 5000
	maxCommentLen = 10000
	maxEvents     = 500
	maxBulkAssign = 100
	minReasonLen  = 20
)

var issueKey = regexp.MustCompile(`^([A-Z][A-Z0-9]{1,9})-([1-9][0-9]{0,8})$`)

// IssueFilter is the raw query of GET /issues.
type IssueFilter struct {
	ProjectID string
	Status    []string
	Severity  []string
	Assignee  string
	Tool      string
	PastSLA   string
	Kind      string
	KEV       string
	EPSSMin   string
	Source    string
	Target    string
	Q         string
	Sort      string
	PageParams
}

func (s *Service) issueQuery(a *Actor, f IssueFilter) (IssueQuery, error) {
	q := IssueQuery{Vis: a.vis(), Now: s.now(), Sort: SortDueAt}
	fe := fieldErrors{}
	if f.ProjectID != "" {
		id, err := uuid.Parse(f.ProjectID)
		if err != nil {
			fe.add("project_id", "must be a UUID")
		} else {
			q.ProjectID = &id
		}
	}
	statuses := f.Status
	if len(statuses) == 0 {
		statuses = []string{"active"}
	}
	for _, st := range splitValues(statuses) {
		switch {
		case st == "active":
			for _, x := range issuestate.Active {
				q.Statuses = appendUnique(q.Statuses, string(x))
			}
		case slices.Contains(issuestate.AllStatuses, issuestate.Status(st)):
			q.Statuses = appendUnique(q.Statuses, st)
		default:
			fe.add("status", "unknown status "+strconv.Quote(st))
		}
	}
	for _, sv := range splitValues(f.Severity) {
		if !slices.Contains(severities, sv) {
			fe.add("severity", "unknown severity "+strconv.Quote(sv))
			continue
		}
		q.Severities = appendUnique(q.Severities, sv)
	}
	switch f.Assignee {
	case "":
	case "me":
		q.AssigneeID = &a.UserID
	case "none":
		q.AssigneeNone = true
	default:
		id, err := uuid.Parse(f.Assignee)
		if err != nil {
			fe.add("assignee", "must be me, none or a user id")
		} else {
			q.AssigneeID = &id
		}
	}
	if f.Tool != "" {
		if !slices.Contains(allTools, f.Tool) {
			fe.add("tool", "unknown tool")
		}
		q.Tool = f.Tool
	}
	switch f.PastSLA {
	case "", "false":
	case "true":
		q.PastSLA = true
	default:
		fe.add("past_sla", "must be true or false")
	}
	switch f.Kind {
	case "", KindVulnerability, KindLicense:
		q.Kind = f.Kind
	default:
		fe.add("kind", "must be vulnerability or license")
	}
	switch f.KEV {
	case "", "false":
	case "true":
		q.KEV = true
	default:
		fe.add("kev", "must be true or false")
	}
	if f.EPSSMin != "" {
		// ParseFloat also takes NaN, Inf and hex; the range check rejects
		// the first two, and a hex value in range is harmless.
		v, err := strconv.ParseFloat(f.EPSSMin, 64)
		if err != nil || len(f.EPSSMin) > 32 || !(v >= 0 && v <= 1) {
			fe.add("epss_min", "must be a number between 0 and 1")
		} else {
			q.EPSSMin = &v
		}
	}
	switch f.Source {
	case "", "code", "image":
		q.Source = f.Source
	default:
		fe.add("source", "must be code or image")
	}
	if f.Target != "" {
		if len(f.Target) > maxTarget || !ImageTarget.MatchString(f.Target) {
			fe.add("target", "must be an image repository without tag, e.g. ghcr.io/acme/api")
		} else {
			q.Target = f.Target
		}
	}
	if text := strings.TrimSpace(f.Q); text != "" {
		if utf8.RuneCountInString(text) > maxQueryLen || !validText(text) {
			fe.add("q", "must be at most 200 characters")
		} else if m := issueKey.FindStringSubmatch(strings.ToUpper(text)); m != nil {
			q.KeyProject = m[1]
			q.KeyNumber, _ = strconv.Atoi(m[2])
		} else {
			q.Text = text
		}
	}
	switch f.Sort {
	case "":
	case SortDueAt, SortSeverity, SortUpdatedAt, SortEPSS:
		q.Sort = f.Sort
	default:
		fe.add("sort", "must be due_at, -severity, -updated_at or -epss")
	}
	limit, err := f.limit()
	if err != nil {
		fe.add("limit", "must be an integer between 1 and 200")
	}
	q.Limit = limit
	if f.Cursor != "" {
		c := &IssueCursor{}
		if decodeCursor(f.Cursor, c) != nil || c.Sort != q.Sort || (c.Sort == SortSeverity && !slices.Contains(severities, c.Severity)) ||
			(c.EPSS != nil && !(*c.EPSS >= 0 && *c.EPSS <= 1)) {
			fe.add("cursor", "invalid cursor")
		} else {
			q.After = c
		}
	}
	return q, fe.err()
}

// splitValues accepts both ?status=a&status=b and ?status=a,b.
func splitValues(in []string) []string {
	var out []string
	for _, v := range in {
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

func appendUnique(s []string, v string) []string {
	if slices.Contains(s, v) {
		return s
	}
	return append(s, v)
}

func issueCursor(sort string) func(IssueSummary) any {
	return func(i IssueSummary) any {
		c := IssueCursor{Sort: sort, ID: i.ID}
		switch sort {
		case SortDueAt:
			if i.DueAt != nil {
				t := i.DueAt.T()
				c.DueAt = &t
			}
		case SortSeverity:
			c.Severity = i.Severity
		case SortUpdatedAt:
			c.UpdatedAt = i.UpdatedAt.T()
		case SortEPSS:
			c.EPSS = i.EPSS
		}
		return c
	}
}

// Issues lists issues in the projects the caller can see.
func (s *Service) Issues(ctx context.Context, a *Actor, f IssueFilter) (IssuePage, error) {
	var out IssuePage
	err := s.inOrg(ctx, a, func(r Repo) error {
		q, err := s.issueQuery(a, f)
		if err != nil {
			return err
		}
		if a.Token != nil { // an API token lists its own project only
			if q.ProjectID == nil {
				q.ProjectID = &a.Token.ProjectID
			}
			if _, err := projectAccess(ctx, r, a, *q.ProjectID); err != nil {
				return err
			}
		}
		rq := q
		rq.Limit = q.Limit + 1 // one extra row tells whether there is a next page
		rows, err := r.Issues(ctx, rq)
		if err != nil {
			return err
		}
		out.Items, out.NextCursor = page(rows, q.Limit, issueCursor(q.Sort))
		// The severity chips count the whole result set, ignoring the severity filter.
		cq := q
		cq.Severities, cq.After = nil, nil
		out.CountsBySeverity, err = r.IssueCounts(ctx, cq)
		return err
	})
	return out, err
}

// issueAccess loads an issue the caller can see, with their project role.
func issueAccess(ctx context.Context, r Repo, a *Actor, issueID uuid.UUID, forUpdate bool, s *Service) (Issue, rbac.Role, error) {
	iss, err := r.Issue(ctx, issueID, forUpdate, s.now())
	if err != nil {
		return Issue{}, "", notFound(err)
	}
	role, err := projectAccess(ctx, r, a, iss.ProjectID)
	if err != nil {
		return Issue{}, "", err
	}
	return iss, role, nil
}

func isAssignee(a *Actor, iss Issue) bool {
	return iss.AssigneeID != nil && *iss.AssigneeID == a.UserID
}

// workflowActors maps the caller to issuestate actors for this issue.
func workflowActors(a *Actor, role rbac.Role, iss Issue) []issuestate.Actor {
	var out []issuestate.Actor
	if isAssignee(a, iss) {
		out = append(out, issuestate.Assignee)
	}
	if role == rbac.Owner {
		out = append(out, issuestate.ProjectOwner)
	}
	if a.OrgRole == rbac.SecurityLead {
		out = append(out, issuestate.SecurityLead)
	}
	return out
}

// checkTransition decides whether the caller may move iss to `to` through the
// transitions endpoint: the state machine (issuestate.Check) and the permission
// matrix (developers only on issues assigned to them) must both allow it.
// false_positive and risk_accepted are only reachable by an approved exception.
func checkTransition(a *Actor, role rbac.Role, iss Issue, to issuestate.Status) (issuestate.Transition, error) {
	rule, err := issuestate.Check(issuestate.Status(iss.Status), to, workflowActors(a, role, iss)...)
	if errors.Is(err, issuestate.ErrInvalidTransition) {
		return rule, errInvalidTransition("the issue can't move from " + iss.Status + " to " + string(to))
	}
	if err != nil {
		return rule, errForbidden()
	}
	if rule.RequiresApprovedException {
		return rule, errInvalidTransition("false_positive and risk_accepted need an approved exception")
	}
	if !rbac.Can(rbac.UpdateIssue, a.OrgRole, role, isAssignee(a, iss)) {
		return rule, errForbidden()
	}
	if rule.RequiresMemberAssignee && !rbac.Can(rbac.AssignIssue, a.OrgRole, role, false) {
		return rule, errForbidden()
	}
	return rule, nil
}

// decorate fills in what this caller may do with the issue.
func decorate(ctx context.Context, r Repo, a *Actor, role rbac.Role, iss *Issue) error {
	iss.AllowedTransitions = []string{}
	for _, to := range issuestate.AllStatuses {
		if _, err := checkTransition(a, role, *iss, to); err == nil {
			iss.AllowedTransitions = append(iss.AllowedTransitions, string(to))
		}
	}
	active := slices.Contains(issuestate.Active, issuestate.Status(iss.Status))
	// Bulk assignment accepts exactly the active statuses.
	iss.CanAssign = active && rbac.Can(rbac.AssignIssue, a.OrgRole, role, false)
	pending, err := r.PendingExceptionID(ctx, iss.ID)
	if err != nil {
		return err
	}
	iss.PendingExceptionID = pending
	iss.CanRequestException = active && pending == nil &&
		rbac.Can(rbac.ProposeException, a.OrgRole, role, isAssignee(a, *iss))
	if iss.CWE == nil {
		iss.CWE = []string{}
	}
	if iss.CVE == nil {
		iss.CVE = []string{}
	}
	return nil
}

func (s *Service) Issue(ctx context.Context, a *Actor, issueID uuid.UUID) (Issue, error) {
	var out Issue
	err := s.inOrg(ctx, a, func(r Repo) error {
		iss, role, err := issueAccess(ctx, r, a, issueID, false, s)
		if err != nil {
			return err
		}
		if !rbac.Can(rbac.ViewResults, a.OrgRole, role, false) {
			return errForbidden()
		}
		if err := decorate(ctx, r, a, role, &iss); err != nil {
			return err
		}
		out = iss
		return nil
	})
	return out, err
}

type TransitionInput struct {
	To         string  `json:"to"`
	Version    *int    `json:"version"`
	AssigneeID *string `json:"assignee_id"`
	Reason     *string `json:"reason"`
}

func (s *Service) Transition(ctx context.Context, a *Actor, issueID uuid.UUID, in TransitionInput) (Issue, error) {
	fe := fieldErrors{}
	to := issuestate.Status(in.To)
	if !slices.Contains(issuestate.AllStatuses, to) {
		fe.add("to", "unknown status")
	}
	if in.Version == nil || *in.Version < 1 {
		fe.add("version", "is required")
	}
	var assignee *uuid.UUID
	if in.AssigneeID != nil {
		id, err := uuid.Parse(*in.AssigneeID)
		if err != nil {
			fe.add("assignee_id", "must be a user id")
		}
		assignee = &id
	}
	var reason *string
	if in.Reason != nil {
		rs := strings.TrimSpace(*in.Reason)
		if utf8.RuneCountInString(rs) > maxReasonLen || !validText(rs) {
			fe.add("reason", "must be at most 5000 characters")
		}
		if rs != "" {
			reason = &rs
		}
	}
	if err := fe.err(); err != nil {
		return Issue{}, err
	}
	if to == issuestate.FalsePositive || to == issuestate.RiskAccepted {
		return Issue{}, errInvalidTransition("false_positive and risk_accepted need an approved exception")
	}

	var out Issue
	err := s.inOrg(ctx, a, func(r Repo) error {
		iss, role, err := issueAccess(ctx, r, a, issueID, true, s)
		if err != nil {
			return err
		}
		if iss.Version != *in.Version {
			return errVersionConflict()
		}
		rule, err := checkTransition(a, role, iss, to)
		if err != nil {
			return err
		}
		newAssignee := iss.AssigneeID
		switch {
		case rule.RequiresMemberAssignee:
			if assignee == nil {
				return errField("assignee_id", "is required to assign the issue")
			}
			if err := requireProjectMember(ctx, r, iss.ProjectID, *assignee); err != nil {
				return err
			}
			newAssignee = assignee
		case assignee != nil:
			return errField("assignee_id", "is only allowed when moving the issue to assigned")
		case rule.ClearsAssignee:
			newAssignee = nil
		}
		if rule.RequiresReason && reason == nil {
			return errField("reason", "is required for this transition")
		}
		if err := r.UpdateIssueState(ctx, iss.ID, string(to), newAssignee); err != nil {
			return err
		}
		uid := a.UserID
		if err := r.InsertIssueEvent(ctx, NewEvent{OrgID: a.OrgID, IssueID: iss.ID, ActorID: &uid, Type: "status_changed",
			From: ptr(iss.Status), To: ptr(string(to)), Note: reason}); err != nil {
			return err
		}
		if !sameUser(iss.AssigneeID, newAssignee) {
			if err := r.InsertIssueEvent(ctx, NewEvent{OrgID: a.OrgID, IssueID: iss.ID, ActorID: &uid, Type: "assigned",
				From: idString(iss.AssigneeID), To: idString(newAssignee)}); err != nil {
				return err
			}
			if newAssignee != nil {
				if err := outbox(ctx, r, a, notify.IssueAssigned, notify.Payload{IssueID: notify.ID(iss.ID), UserID: newAssignee}); err != nil {
					return err
				}
			}
		}
		data := map[string]any{"from": iss.Status, "to": string(to)}
		if newAssignee != nil {
			data["assignee_id"] = newAssignee.String()
		}
		if reason != nil {
			data["reason"] = *reason
		}
		if err := s.audit(ctx, r, a, "issue.transitioned", "issue", iss.ID.String(), data); err != nil {
			return err
		}
		if out, err = r.Issue(ctx, iss.ID, false, s.now()); err != nil {
			return err
		}
		return decorate(ctx, r, a, role, &out)
	})
	return out, err
}

func requireProjectMember(ctx context.Context, r Repo, projectID, userID uuid.UUID) error {
	role, err := r.ProjectRole(ctx, projectID, userID)
	if err != nil {
		return err
	}
	if role == "" {
		return errField("assignee_id", "must be a member of the issue's project")
	}
	return nil
}

func sameUser(a, b *uuid.UUID) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func idString(id *uuid.UUID) *string {
	if id == nil {
		return nil
	}
	return ptr(id.String())
}

type BulkAssignInput struct {
	IssueIDs   []string `json:"issue_ids"`
	AssigneeID string   `json:"assignee_id"`
}

type BulkAssignResult struct {
	Updated int `json:"updated"`
}

// BulkAssign assigns many issues to one project member. Issues the caller can't
// see or assign, whose project the assignee isn't in, or whose status doesn't
// allow assignment are skipped.
func (s *Service) BulkAssign(ctx context.Context, a *Actor, in BulkAssignInput) (BulkAssignResult, error) {
	fe := fieldErrors{}
	var issueIDs []uuid.UUID
	if len(in.IssueIDs) < 1 || len(in.IssueIDs) > maxBulkAssign {
		fe.add("issue_ids", "must contain 1 to 100 issue ids")
	}
	for _, raw := range in.IssueIDs {
		id, err := uuid.Parse(raw)
		if err != nil {
			fe.add("issue_ids", "must contain issue ids")
			break
		}
		if !slices.Contains(issueIDs, id) {
			issueIDs = append(issueIDs, id)
		}
	}
	assignee, err := uuid.Parse(in.AssigneeID)
	if err != nil {
		fe.add("assignee_id", "must be a user id")
	}
	// Lock in a fixed order so concurrent bulk assignments can't deadlock.
	slices.SortFunc(issueIDs, func(x, y uuid.UUID) int { return strings.Compare(x.String(), y.String()) })

	var out BulkAssignResult
	err = s.inOrg(ctx, a, func(r Repo) error {
		if !rbac.Can(rbac.AssignIssue, a.OrgRole, "", false) {
			owner, err := r.OwnsAnyProject(ctx, a.UserID)
			if err != nil {
				return err
			}
			if !owner {
				return errForbidden()
			}
		}
		if err := fe.err(); err != nil {
			return err
		}
		type access struct {
			role             rbac.Role
			visible, canAsgn bool
		}
		cache := map[uuid.UUID]access{}
		var updated []string
		uid := a.UserID
		for _, id := range issueIDs {
			iss, err := r.Issue(ctx, id, true, s.now())
			if errors.Is(err, ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			acc, ok := cache[iss.ProjectID]
			if !ok {
				role, err := r.ProjectRole(ctx, iss.ProjectID, a.UserID)
				if err != nil && !errors.Is(err, ErrNotFound) {
					return err
				}
				target, err := r.ProjectRole(ctx, iss.ProjectID, assignee)
				if err != nil && !errors.Is(err, ErrNotFound) {
					return err
				}
				acc = access{role: role, visible: role != "" || a.seesAllProjects()}
				acc.canAsgn = acc.visible && target != "" && rbac.Can(rbac.AssignIssue, a.OrgRole, role, false)
				cache[iss.ProjectID] = acc
			}
			if !acc.canAsgn {
				continue
			}
			from := issuestate.Status(iss.Status)
			switch from {
			case issuestate.Open, issuestate.Reopened:
				if _, err := issuestate.Check(from, issuestate.Assigned, workflowActors(a, acc.role, iss)...); err != nil {
					continue
				}
				if err := r.UpdateIssueState(ctx, iss.ID, string(issuestate.Assigned), &assignee); err != nil {
					return err
				}
				if err := r.InsertIssueEvent(ctx, NewEvent{OrgID: a.OrgID, IssueID: iss.ID, ActorID: &uid, Type: "status_changed",
					From: ptr(iss.Status), To: ptr(string(issuestate.Assigned))}); err != nil {
					return err
				}
			case issuestate.Assigned, issuestate.InProgress:
				if sameUser(iss.AssigneeID, &assignee) {
					continue
				}
				if err := r.UpdateIssueState(ctx, iss.ID, iss.Status, &assignee); err != nil {
					return err
				}
			default:
				continue
			}
			if err := r.InsertIssueEvent(ctx, NewEvent{OrgID: a.OrgID, IssueID: iss.ID, ActorID: &uid, Type: "assigned",
				From: idString(iss.AssigneeID), To: ptr(assignee.String())}); err != nil {
				return err
			}
			if err := outbox(ctx, r, a, notify.IssueAssigned, notify.Payload{IssueID: notify.ID(iss.ID), UserID: notify.ID(assignee)}); err != nil {
				return err
			}
			updated = append(updated, iss.ID.String())
		}
		out.Updated = len(updated)
		if len(updated) == 0 {
			return nil
		}
		return s.audit(ctx, r, a, "issue.assigned", "user", assignee.String(),
			map[string]any{"assignee_id": assignee.String(), "issue_ids": updated})
	})
	return out, err
}

func (s *Service) IssueEvents(ctx context.Context, a *Actor, issueID uuid.UUID) (Items[Event], error) {
	out := Items[Event]{Items: []Event{}}
	err := s.inOrg(ctx, a, func(r Repo) error {
		_, role, err := issueAccess(ctx, r, a, issueID, false, s)
		if err != nil {
			return err
		}
		if !rbac.Can(rbac.ViewResults, a.OrgRole, role, false) {
			return errForbidden()
		}
		ev, err := r.IssueEvents(ctx, issueID, maxEvents)
		if err != nil {
			return err
		}
		if ev != nil {
			out.Items = ev
		}
		return nil
	})
	return out, err
}

func (s *Service) Comments(ctx context.Context, a *Actor, issueID uuid.UUID) (Items[Comment], error) {
	out := Items[Comment]{Items: []Comment{}}
	err := s.inOrg(ctx, a, func(r Repo) error {
		_, role, err := issueAccess(ctx, r, a, issueID, false, s)
		if err != nil {
			return err
		}
		if !rbac.Can(rbac.ViewResults, a.OrgRole, role, false) {
			return errForbidden()
		}
		c, err := r.Comments(ctx, issueID)
		if err != nil {
			return err
		}
		if c != nil {
			out.Items = c
		}
		return nil
	})
	return out, err
}

type CommentInput struct {
	Body string `json:"body"`
}

func (s *Service) AddComment(ctx context.Context, a *Actor, issueID uuid.UUID, in CommentInput) (Comment, error) {
	body := strings.TrimSpace(in.Body)
	var out Comment
	err := s.inOrg(ctx, a, func(r Repo) error {
		iss, role, err := issueAccess(ctx, r, a, issueID, false, s)
		if err != nil {
			return err
		}
		// Developers may comment on any issue in their project, not only their own.
		if !rbac.Can(rbac.UpdateIssue, a.OrgRole, role, true) {
			return errForbidden()
		}
		if body == "" || utf8.RuneCountInString(body) > maxCommentLen || !validText(body) {
			return errField("body", "must be 1-10000 characters")
		}
		id := ids.New()
		if err := r.InsertComment(ctx, NewComment{ID: id, OrgID: a.OrgID, IssueID: iss.ID, AuthorID: a.UserID, Body: body}); err != nil {
			return err
		}
		uid := a.UserID
		if err := r.InsertIssueEvent(ctx, NewEvent{OrgID: a.OrgID, IssueID: iss.ID, ActorID: &uid, Type: "commented"}); err != nil {
			return err
		}
		if out, err = r.Comment(ctx, id); err != nil {
			return err
		}
		return s.audit(ctx, r, a, "comment.created", "issue", iss.ID.String(), map[string]any{"comment_id": id.String()})
	})
	return out, err
}
