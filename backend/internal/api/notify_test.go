package api

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/notify"
	"github.com/aupv9/warden/backend/internal/service"
	"github.com/aupv9/warden/backend/internal/service/servicetest"
)

func (e *env) me(method, path, email string, body any) resp {
	e.t.Helper()
	return e.call(method, "/api/v1/me"+path, email, body, nil)
}

func outboxTypes(e *env) []string {
	var out []string
	for _, ev := range e.f.Outbox() {
		out = append(out, ev.Type)
	}
	return out
}

func TestNotificationsEndpoints(t *testing.T) {
	e := newEnv(t)
	other := e.f.AddOrg("Other")
	e.f.AddMember(other, e.u[dev], "member")
	n1 := e.f.AddNotification(e.org, e.u[dev], notify.IssueAssigned, "WEB-1 assigned to you")
	n2 := e.f.AddNotification(other, e.u[dev], notify.IssueReopened, "API-2 reopened")
	e.f.AddNotification(e.org, e.u[dev2], notify.IssueAssigned, "WEB-3 assigned to you")
	left := e.f.AddOrg("Left") // dev isn't a member (any more)
	e.f.AddNotification(left, e.u[dev], notify.IssueAssigned, "OLD-1 assigned to you")

	r := e.me("GET", "/notifications", dev, nil)
	e.expect(r, 200, "")
	if len(r.items()) != 2 || r.obj()["next_cursor"] != nil {
		t.Fatal(r.body)
	}
	first := r.items()[0].(map[string]any)
	if first["id"] != n2.String() || first["read_at"] != nil || first["actor"] != nil || first["link"] == "" {
		t.Fatal(r.body)
	}
	if r := e.me("GET", "/notifications/unread-count", dev, nil); r.obj()["count"] != 2.0 {
		t.Fatal(r.body)
	}
	p1 := e.me("GET", "/notifications?limit=1", dev, nil)
	cur := p1.obj()["next_cursor"].(string)
	if p2 := e.me("GET", "/notifications?limit=1&cursor="+cur, dev, nil); len(p2.items()) != 1 || p2.items()[0].(map[string]any)["id"] != n1.String() {
		t.Fatal(p2.body)
	}
	e.expect(e.me("GET", "/notifications?unread=maybe", dev, nil), 422, "VALIDATION_FAILED")
	e.expect(e.me("GET", "/notifications?limit=0", dev, nil), 422, "VALIDATION_FAILED")
	e.expect(e.me("GET", "/notifications?cursor=!!!", dev, nil), 422, "VALIDATION_FAILED")

	// Marking: own rows only; validation.
	e.expect(e.me("POST", "/notifications/read", dev2, map[string]any{"ids": []string{n1.String()}}), 204, "")
	if e.f.NotificationRead(n1) {
		t.Fatal("someone else marked dev's notification read")
	}
	e.expect(e.me("POST", "/notifications/read", dev, map[string]any{"ids": []string{n1.String()}}), 204, "")
	if !e.f.NotificationRead(n1) {
		t.Fatal("not marked")
	}
	if r := e.me("GET", "/notifications?unread=true", dev, nil); len(r.items()) != 1 {
		t.Fatal(r.body)
	}
	e.expect(e.me("POST", "/notifications/read", dev, map[string]any{"all": true}), 204, "")
	if r := e.me("GET", "/notifications/unread-count", dev, nil); r.obj()["count"] != 0.0 {
		t.Fatal(r.body)
	}
	for _, bad := range []any{
		map[string]any{},
		map[string]any{"all": false},
		map[string]any{"all": true, "ids": []string{n1.String()}},
		map[string]any{"ids": []string{}},
		map[string]any{"ids": []string{"nope"}},
		map[string]any{"ids": make([]string, 201)},
		map[string]any{"bogus": 1},
	} {
		e.expect(e.me("POST", "/notifications/read", dev, bad), 422, "VALIDATION_FAILED")
	}

	// Preferences: every type with defaults, then changes.
	r = e.me("GET", "/notification-prefs", dev, nil)
	if len(r.items()) != len(notify.Types) {
		t.Fatal(r.body)
	}
	for _, it := range r.items() {
		p := it.(map[string]any)
		if p["email"] != (p["type"] != notify.ScanFinished) {
			t.Fatal(r.body)
		}
	}
	r = e.me("PUT", "/notification-prefs", dev, map[string]any{"items": []map[string]any{{"type": "scan.finished", "email": true}, {"type": "sla.overdue", "email": false}}})
	e.expect(r, 200, "")
	for _, it := range r.items() {
		p := it.(map[string]any)
		if p["type"] == "scan.finished" && p["email"] != true || p["type"] == "sla.overdue" && p["email"] != false {
			t.Fatal(r.body)
		}
	}
	for _, bad := range []any{
		map[string]any{"items": []map[string]any{}},
		map[string]any{"items": []map[string]any{{"type": "issue.deleted", "email": true}}},
		map[string]any{"items": []map[string]any{{"type": "scan.finished", "email": true}, {"type": "scan.finished", "email": false}}},
		map[string]any{"items": []map[string]any{{"type": "scan.finished", "email": "yes"}}},
	} {
		e.expect(e.me("PUT", "/notification-prefs", dev, bad), 422, "VALIDATION_FAILED")
	}

	e.f.Fail["InUser"] = errors.New("db down")
	e.expect(e.me("GET", "/notifications", dev, nil), 500, "INTERNAL")
	e.expect(e.me("GET", "/notifications/unread-count", dev, nil), 500, "INTERNAL")
	e.expect(e.me("GET", "/notification-prefs", dev, nil), 500, "INTERNAL")
	delete(e.f.Fail, "InUser")
	for _, m := range []string{"Notifications", "NotificationPrefs", "SetNotificationPref"} {
		e.f.Fail[m] = errors.New("db down")
	}
	e.expect(e.me("GET", "/notifications", dev, nil), 500, "INTERNAL")
	e.expect(e.me("PUT", "/notification-prefs", dev, map[string]any{"items": []map[string]any{{"type": "scan.finished", "email": true}}}), 500, "INTERNAL")
	delete(e.f.Fail, "SetNotificationPref")
	e.expect(e.me("PUT", "/notification-prefs", dev, map[string]any{"items": []map[string]any{{"type": "scan.finished", "email": true}}}), 500, "INTERNAL")
}

func TestWritesAppendOutboxEvents(t *testing.T) {
	e := newEnv(t)
	iss := e.f.AddIssue(e.web, "high", "open", nil)
	e.expect(e.do("POST", "/issues/"+iss.String()+"/transitions", owner, map[string]any{"to": "assigned", "version": 1, "assignee_id": e.u[dev].String()}), 200, "")
	other := e.f.AddIssue(e.web, "low", "open", nil)
	e.expect(e.do("POST", "/issues/assign", owner, map[string]any{"issue_ids": []string{other.String()}, "assignee_id": e.u[dev2].String()}), 200, "")
	reason := "only reachable from the admin network"
	r := e.do("POST", "/issues/"+iss.String()+"/exceptions", dev, map[string]any{"type": "false_positive", "reason": reason})
	e.expect(r, 201, "")
	e.expect(e.do("POST", "/exceptions/"+r.obj()["id"].(string)+"/decision", lead, map[string]any{"decision": "approve"}), 200, "")
	got := outboxTypes(e)
	want := []string{notify.IssueAssigned, notify.IssueAssigned, notify.ExceptionRequested, notify.ExceptionDecided}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatal(got)
	}
	ev := e.f.Outbox()
	if *ev[0].Payload.UserID != e.u[dev] || *ev[0].Payload.ActorID != e.u[owner] || ev[0].OrgID != e.org ||
		*ev[3].Payload.UserID != e.u[dev] || ev[3].Payload.Decision != "approve" {
		t.Fatalf("%+v", ev)
	}

	// A failing outbox write rolls the change back.
	third := e.f.AddIssue(e.web, "low", "open", nil)
	e.f.Fail["AppendOutbox"] = errors.New("outbox down")
	e.expect(e.do("POST", "/issues/"+third.String()+"/transitions", owner, map[string]any{"to": "assigned", "version": 1, "assignee_id": e.u[dev].String()}), 500, "INTERNAL")
	e.expect(e.do("POST", "/issues/assign", owner, map[string]any{"issue_ids": []string{third.String()}, "assignee_id": e.u[dev].String()}), 500, "INTERNAL")
	if e.f.IssueRow(third).Status != "open" {
		t.Fatal("change survived a failed outbox write")
	}
	e.expect(e.do("POST", "/issues/"+third.String()+"/exceptions", owner, map[string]any{"type": "false_positive", "reason": reason}), 500, "INTERNAL")
	pending := e.f.AddException(third, e.u[owner], "false_positive", nil)
	e.expect(e.do("POST", "/exceptions/"+pending.String()+"/decision", lead, map[string]any{"decision": "approve"}), 500, "INTERNAL")
	if e.f.ExceptionStatus(pending) != "pending" {
		t.Fatal("decision survived a failed outbox write")
	}
}

func TestOrgPolicy(t *testing.T) {
	e := newEnv(t)
	body := map[string]any{"sla_days": map[string]any{"critical": 3, "high": 14, "medium": 60, "low": 120}, "recompute_open": true}
	e.expect(e.call("PATCH", "/api/v1/orgs/"+e.org.String(), admin, body, nil), 403, "FORBIDDEN")
	due := time.Now().Add(-time.Hour)
	iss := e.f.AddIssue(e.web, "critical", "open", nil)
	e.f.SetIssue(iss, func(r *servicetest.IssueRow) { r.DueAt = &due })
	r := e.call("PATCH", "/api/v1/orgs/"+e.org.String(), lead, body, nil)
	e.expect(r, 200, "")
	if sla := r.obj()["sla_days"].(map[string]any); sla["critical"] != 3.0 || sla["low"] != 120.0 || r.obj()["my_role"] != "security_lead" {
		t.Fatal(r.body)
	}
	if d := e.f.IssueRow(iss).DueAt; d == nil || d.Equal(due) {
		t.Fatal("not recomputed")
	}
	audit := e.f.AuditLog()
	last := audit[len(audit)-1]
	if last.Action != "org.policy_changed" || last.Data["recomputed"] != 1 || last.Data["recompute_open"] != true {
		t.Fatalf("%+v", last)
	}
	// Without recompute, existing due dates stay.
	before := e.f.IssueRow(iss).DueAt
	e.expect(e.call("PATCH", "/api/v1/orgs/"+e.org.String(), lead, map[string]any{"sla_days": map[string]any{"critical": 5, "high": 14, "medium": 60, "low": 120}}, nil), 200, "")
	if !e.f.IssueRow(iss).DueAt.Equal(*before) || e.f.OrgSLA(e.org).Critical != 5 {
		t.Fatal("recomputed without asking")
	}
	for _, bad := range []any{
		map[string]any{},
		map[string]any{"sla_days": map[string]any{"critical": 0, "high": 14, "medium": 60, "low": 120}},
		map[string]any{"sla_days": map[string]any{"critical": 3, "high": 366, "medium": 60}},
		map[string]any{"sla_days": map[string]any{"critical": 3, "high": 3, "medium": 3, "low": 3, "info": 3}},
	} {
		r := e.call("PATCH", "/api/v1/orgs/"+e.org.String(), lead, bad, nil)
		e.expect(r, 422, "VALIDATION_FAILED")
	}
	for _, m := range []string{"Org", "SetOrgSLA", "RecomputeDueDates"} {
		e.f.Fail[m] = errors.New("db down")
		e.expect(e.call("PATCH", "/api/v1/orgs/"+e.org.String(), lead, body, nil), 500, "INTERNAL")
		delete(e.f.Fail, m)
	}
}

func TestAssignRules(t *testing.T) {
	e := newEnv(t)
	path := "/projects/" + e.web.String() + "/assign-rules"
	r := e.do("GET", path, viewer, nil)
	e.expect(r, 200, "")
	if len(r.items()) != 0 {
		t.Fatal(r.body)
	}
	rules := map[string]any{"items": []map[string]any{
		{"match": map[string]any{"path_glob": "src/**/*.py", "severity_at_least": "high"}, "assignee_id": e.u[dev].String()},
		{"match": map[string]any{"tool": "trivy"}, "assignee_id": e.u[owner].String()},
	}}
	e.expect(e.do("PUT", path, dev, rules), 403, "FORBIDDEN")
	e.expect(e.do("PUT", "/projects/"+e.api.String()+"/assign-rules", owner, rules), 404, "NOT_FOUND")
	r = e.do("PUT", path, owner, rules)
	e.expect(r, 200, "")
	if len(r.items()) != 2 || len(e.f.Rules(e.web)) != 2 {
		t.Fatal(r.body)
	}
	got := e.do("GET", path, dev, nil).items()[0].(map[string]any)
	if got["match"].(map[string]any)["path_glob"] != "src/**/*.py" || got["match"].(map[string]any)["tool"] != nil || got["assignee_id"] != e.u[dev].String() {
		t.Fatal(got)
	}
	audit := e.f.AuditLog()
	if a := audit[len(audit)-1]; a.Action != "project.assign_rules_set" || a.Data["rules"] != 2 {
		t.Fatalf("%+v", a)
	}

	check := func(body any, field string) {
		t.Helper()
		r := e.do("PUT", path, lead, body)
		e.expect(r, 422, "VALIDATION_FAILED")
		if _, ok := r.Error.Metadata["fields"].(map[string]any)[field]; !ok {
			t.Fatalf("%s not reported: %s", field, r.body)
		}
	}
	rule := func(match map[string]any, assignee string) map[string]any {
		return map[string]any{"items": []map[string]any{{"match": match, "assignee_id": assignee}}}
	}
	d := e.u[dev].String()
	check(map[string]any{}, "items")
	check(rule(map[string]any{}, d), "items[0].match")
	check(rule(map[string]any{"path_glob": strings.Repeat("a", 201)}, d), "items[0].match.path_glob")
	check(rule(map[string]any{"path_glob": "src/{a,b}"}, d), "items[0].match.path_glob")
	check(rule(map[string]any{"tool": "nmap"}, d), "items[0].match.tool")
	check(rule(map[string]any{"severity_at_least": "urgent"}, d), "items[0].match.severity_at_least")
	check(rule(map[string]any{"tool": "trivy"}, "nope"), "items[0].assignee_id")
	check(rule(map[string]any{"tool": "trivy"}, ""), "items[0].assignee_id")
	check(rule(map[string]any{"tool": "trivy"}, e.u[outsider].String()), "items[0].assignee_id") // not a project member
	check(rule(map[string]any{"tool": "trivy"}, uuid.NewString()), "items[0].assignee_id")
	many := make([]map[string]any, 51)
	for i := range many {
		many[i] = map[string]any{"match": map[string]any{"tool": "trivy"}, "assignee_id": d}
	}
	check(map[string]any{"items": many}, "items")
	e.expect(e.do("PUT", path, lead, rule(map[string]any{"tool": "trivy", "regex": ".*"}, d)), 422, "VALIDATION_FAILED")
	// Clearing.
	if r := e.do("PUT", path, lead, map[string]any{"items": []any{}}); r.code != 200 || len(r.items()) != 0 {
		t.Fatal(r.body)
	}
	for _, c := range []struct{ fail, method string }{{"AssignRules", "GET"}, {"SetAssignRules", "PUT"}, {"ProjectRole", "GET"}, {"ProjectRole", "PUT"}} {
		e.f.Fail[c.fail] = errors.New("db down")
		e.expect(e.do(c.method, path, lead, rules), 500, "INTERNAL")
		delete(e.f.Fail, c.fail)
	}
}

func TestArchiveProject(t *testing.T) {
	e := newEnv(t)
	pending := e.f.AddScan(e.web, e.u[dev], "pending_upload", 10)
	e.objects.sizes[service.ObjectKey(e.org, pending)] = 10
	e.f.AddIssue(e.web, "high", "open", nil)
	base := "/projects/" + e.web.String()
	e.expect(e.do("POST", base+"/archive", owner, nil), 403, "FORBIDDEN")
	e.expect(e.do("POST", "/projects/"+uuid.NewString()+"/archive", lead, nil), 404, "NOT_FOUND")
	r := e.do("POST", base+"/archive", lead, nil)
	e.expect(r, 200, "")
	if r.obj()["archived_at"] == nil {
		t.Fatal(r.body)
	}
	e.expect(e.do("POST", base+"/archive", lead, nil), 200, "") // idempotent, no second audit entry
	n := 0
	for _, a := range e.f.AuditLog() {
		if a.Action == "project.archived" {
			n++
		}
	}
	if n != 1 {
		t.Fatal(n)
	}
	e.expect(e.do("POST", base+"/scans", dev, scanBody()), 409, "PROJECT_ARCHIVED")
	e.expect(e.do("POST", "/scans/"+pending.String()+"/start", dev, nil), 409, "PROJECT_ARCHIVED")
	if r := e.do("GET", "/projects", dev, nil); len(r.items()) != 0 {
		t.Fatal(r.body)
	}
	if r := e.do("GET", "/projects?include_archived=true", dev, nil); len(r.items()) != 1 {
		t.Fatal(r.body)
	}
	e.expect(e.do("GET", "/projects?include_archived=1", dev, nil), 422, "VALIDATION_FAILED")
	e.expect(e.do("GET", base, dev, nil), 200, "")
	if r := e.do("GET", "/issues?project_id="+e.web.String(), dev, nil); len(r.items()) != 1 {
		t.Fatal("archived project's issues are readable", r.body)
	}
	if r := e.do("GET", "/issues", dev, nil); len(r.items()) != 0 {
		t.Fatal(r.body)
	}
	r = e.do("POST", base+"/unarchive", admin, nil)
	if r.code != 200 || r.obj()["archived_at"] != nil {
		t.Fatal(r.body)
	}
	e.expect(e.do("POST", "/scans/"+pending.String()+"/start", dev, nil), 200, "")
	e.f.Fail["SetProjectArchived"] = errors.New("db down")
	e.expect(e.do("POST", base+"/archive", lead, nil), 500, "INTERNAL")
	delete(e.f.Fail, "SetProjectArchived")
	e.f.Fail["ProjectArchived"] = errors.New("db down")
	e.expect(e.do("POST", "/scans/"+pending.String()+"/start", dev, nil), 500, "INTERNAL")
}

func TestMetricsAndCounts(t *testing.T) {
	e := newEnv(t)
	h := 36.5
	e.f.SetMetrics(service.MetricsData{
		OpenDeltas: map[string]service.SeverityCounts{
			"2026-09-26": {High: 2}, // before the window: the starting count
			"2026-10-20": {Critical: 1},
			"2026-10-25": {Critical: -1, Low: 1},
		},
		New:       map[string]int{"2026-10-20": 1, "2026-10-25": 1},
		Fixed:     map[string]int{"2026-10-25": 1},
		MTTRHours: service.MTTR{Critical: &h},
		SLA:       service.SLAStats{FixedInTime: 1, OpenOverdue: 2},
	})
	r := e.do("GET", "/metrics", dev, nil)
	e.expect(r, 200, "")
	m := r.obj()
	days := m["open_by_day"].([]any)
	if m["days"] != 30.0 || len(days) != 30 {
		t.Fatal(r.body)
	}
	first, last := days[0].(map[string]any), days[29].(map[string]any)
	if first["date"] != "2026-09-27" || first["high"] != 2.0 || last["date"] != "2026-10-26" || last["critical"] != 0.0 || last["low"] != 1.0 {
		t.Fatal(first, last)
	}
	if d := days[23].(map[string]any); d["date"] != "2026-10-20" || d["critical"] != 1.0 {
		t.Fatal(d)
	}
	if m["mttr_hours"].(map[string]any)["critical"] != 36.5 || m["mttr_hours"].(map[string]any)["high"] != nil {
		t.Fatal(r.body)
	}
	if nb := m["new_by_day"].([]any); len(nb) != 30 || nb[23].(map[string]any)["count"] != 1.0 {
		t.Fatal(nb)
	}
	// Cached per (org, visibility, params): the second identical call doesn't query.
	e.do("GET", "/metrics", dev, nil)
	if e.f.MetricsCalls() != 1 {
		t.Fatal(e.f.MetricsCalls())
	}
	e.do("GET", "/metrics", dev2, nil) // another user's visibility
	e.do("GET", "/metrics", lead, nil) // sees all projects
	e.do("GET", "/metrics", admin, nil)
	if e.f.MetricsCalls() != 3 {
		t.Fatal("cache shared across visibilities", e.f.MetricsCalls())
	}
	if r := e.do("GET", "/metrics?days=90&project_id="+e.web.String(), dev, nil); len(r.obj()["open_by_day"].([]any)) != 90 {
		t.Fatal(r.body)
	}
	e.do("GET", "/metrics?days=180", lead, nil)
	if e.f.MetricsCalls() != 5 {
		t.Fatal(e.f.MetricsCalls())
	}
	e.f.Now = e.f.Now.Add(6 * time.Minute) // expired
	e.do("GET", "/metrics", dev, nil)
	if e.f.MetricsCalls() != 6 {
		t.Fatal("stale cache served", e.f.MetricsCalls())
	}
	e.expect(e.do("GET", "/metrics?days=7", dev, nil), 422, "VALIDATION_FAILED")
	e.expect(e.do("GET", "/metrics?project_id=x", dev, nil), 422, "VALIDATION_FAILED")
	e.expect(e.do("GET", "/metrics?project_id="+e.api.String(), dev, nil), 404, "NOT_FOUND")
	e.f.Fail["Metrics"] = errors.New("db down")
	e.expect(e.do("GET", "/metrics?days=90", dev, nil), 500, "INTERNAL")
	delete(e.f.Fail, "Metrics")

	// Counts.
	due := e.f.Now.Add(-time.Hour)
	mine := e.f.AddIssue(e.web, "high", "assigned", &[]uuid.UUID{e.u[dev]}[0])
	e.f.SetIssue(mine, func(r *servicetest.IssueRow) { r.DueAt = &due })
	secret := e.f.AddIssue(e.web, "critical", "open", nil)
	e.f.SetIssue(secret, func(r *servicetest.IssueRow) { r.Tool = "gitleaks" })
	e.f.AddIssue(e.web, "low", "fixed", nil)
	e.f.AddIssue(e.api, "low", "open", nil)
	r = e.do("GET", "/issues/counts", dev, nil)
	e.expect(r, 200, "")
	if c := r.obj(); c["active"] != 2.0 || c["mine"] != 1.0 || c["past_sla"] != 1.0 || c["secrets"] != 1.0 {
		t.Fatal(r.body)
	}
	if r := e.do("GET", "/issues/counts", lead, nil); r.obj()["active"] != 3.0 {
		t.Fatal(r.body)
	}
	if r := e.do("GET", "/issues/counts?project_id="+e.api.String(), lead, nil); r.obj()["active"] != 1.0 {
		t.Fatal(r.body)
	}
	e.expect(e.do("GET", "/issues/counts?project_id="+e.api.String(), dev, nil), 404, "NOT_FOUND")
	e.expect(e.do("GET", "/issues/counts?project_id=nope", dev, nil), 422, "VALIDATION_FAILED")
	e.f.Fail["IssueTotals"] = errors.New("db down")
	e.expect(e.do("GET", "/issues/counts", dev, nil), 500, "INTERNAL")
}
