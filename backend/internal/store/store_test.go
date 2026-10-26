package store

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/aupv9/warden/backend/internal/service"
)

func TestMapErr(t *testing.T) {
	if mapErr(nil) != nil {
		t.Fatal("nil")
	}
	if !errors.Is(mapErr(pgx.ErrNoRows), service.ErrNotFound) {
		t.Fatal("no rows")
	}
	if !errors.Is(mapErr(fmt.Errorf("x: %w", &pgconn.PgError{Code: "23505"})), service.ErrConflict) {
		t.Fatal("unique")
	}
	other := &pgconn.PgError{Code: "42501"}
	if err := mapErr(other); errors.Is(err, service.ErrConflict) || errors.Is(err, service.ErrNotFound) {
		t.Fatal(err)
	}
}

func TestUserRef(t *testing.T) {
	if userRef(nil, nil, nil) != nil {
		t.Fatal("nil id")
	}
	id := uuid.New()
	e, n := "a@b.c", "A"
	if r := userRef(&id, &e, &n); r.ID != id || r.Email != e || r.DisplayName != n {
		t.Fatal(r)
	}
	if r := userRef(&id, nil, nil); r.Email != "" {
		t.Fatal(r)
	}
}

// Every parameter placeholder must have an argument and vice versa.
func checkParams(t *testing.T, sql string, a args) {
	t.Helper()
	for i := 1; i <= len(a); i++ {
		if !strings.Contains(sql, fmt.Sprintf("$%d", i)) {
			t.Fatalf("$%d unused in %s", i, sql)
		}
	}
	if strings.Contains(sql, fmt.Sprintf("$%d", len(a)+1)) {
		t.Fatalf("missing arg $%d in %s", len(a)+1, sql)
	}
}

func TestBuildIssueList(t *testing.T) {
	now := time.Now()
	org, user, proj := uuid.New(), uuid.New(), uuid.New()
	base := service.IssueQuery{Vis: service.Visibility{OrgID: org, UserID: user}, Now: now, Limit: 51, Sort: service.SortDueAt}

	sql, a := buildIssueList(base)
	checkParams(t, sql, a)
	if !strings.Contains(sql, "project_member vm") || !strings.Contains(sql, "ORDER BY i.due_at ASC NULLS LAST") ||
		!strings.Contains(sql, "p.org_id = ") || !strings.Contains(sql, "p.archived_at IS NULL") {
		t.Fatal(sql)
	}

	due := now.Add(time.Hour)
	full := base
	full.Vis.All = true
	full.ProjectID, full.Statuses, full.Severities = &proj, []string{"open"}, []string{"high"}
	full.AssigneeID, full.Tool, full.PastSLA, full.Text = &user, "trivy", true, `50%_off\`
	full.After = &service.IssueCursor{Sort: service.SortDueAt, DueAt: &due, ID: uuid.New()}
	sql, a = buildIssueList(full)
	checkParams(t, sql, a)
	for _, want := range []string{"i.project_id = ", "issue_status[]", "severity[]", "i.assignee_id = ", "i.tool = ",
		"i.due_at < ", "ILIKE", "i.due_at IS NULL OR"} {
		if !strings.Contains(sql, want) {
			t.Fatalf("%q missing: %s", want, sql)
		}
	}
	if strings.Contains(sql, "project_member vm") {
		t.Fatal("visibility filter for a lead")
	}
	found := false
	for _, v := range a {
		if v == `%50\%\_off\\%` {
			found = true
		}
	}
	if !found {
		t.Fatalf("LIKE pattern not escaped: %v", a)
	}

	for _, c := range []struct {
		q     service.IssueQuery
		wants []string
	}{
		{service.IssueQuery{AssigneeNone: true, KeyProject: "WEB", KeyNumber: 4, Sort: service.SortSeverity,
			After: &service.IssueCursor{Sort: service.SortSeverity, Severity: "high", ID: uuid.New()}},
			[]string{"i.assignee_id IS NULL", "p.key = ", "i.number = ", "(i.severity, i.id) > (", "ORDER BY i.severity ASC"}},
		{service.IssueQuery{Sort: service.SortUpdatedAt, After: &service.IssueCursor{Sort: service.SortUpdatedAt, UpdatedAt: now, ID: uuid.New()}},
			[]string{"(i.updated_at, i.id) < (", "ORDER BY i.updated_at DESC"}},
		{service.IssueQuery{Sort: service.SortDueAt, After: &service.IssueCursor{Sort: service.SortDueAt, ID: uuid.New()}},
			[]string{"(i.due_at IS NULL AND i.id > "}},
	} {
		c.q.Vis, c.q.Now, c.q.Limit = base.Vis, now, 10
		sql, a := buildIssueList(c.q)
		checkParams(t, sql, a)
		for _, w := range c.wants {
			if !strings.Contains(sql, w) {
				t.Fatalf("%q missing: %s", w, sql)
			}
		}
	}

	sql, a = buildIssueCounts(full)
	checkParams(t, sql, a)
	if !strings.Contains(sql, "GROUP BY 1") || strings.Contains(sql, "LIMIT") {
		t.Fatal(sql)
	}
}

func TestBuildExceptionAndAuditLists(t *testing.T) {
	now := time.Now()
	user := uuid.New()
	for _, st := range []string{"", "pending", "expiring"} {
		q := service.ExceptionQuery{Status: st, Now: now, Limit: 10, RequestedBy: &user,
			After: &service.ExceptionCursor{CreatedAt: now, ID: uuid.New()}}
		sql, a := buildExceptionList(q)
		checkParams(t, sql, a)
		if !strings.Contains(sql, "e.requested_by = ") || !strings.Contains(sql, "(e.created_at, e.id) < (") {
			t.Fatal(sql)
		}
		if st == "expiring" && !strings.Contains(sql, "interval '14 days'") {
			t.Fatal(sql)
		}
	}
	sql, a := buildExceptionList(service.ExceptionQuery{Limit: 5})
	checkParams(t, sql, a)
	if strings.Contains(sql, "WHERE") {
		t.Fatal(sql)
	}

	from, to := now.Add(-time.Hour), now
	sql, a = buildAuditList(service.AuditQuery{OrgID: uuid.New(), Action: "x", ActorID: &user, AfterID: 9, Limit: 3, From: &from, To: &to})
	checkParams(t, sql, a)
	for _, w := range []string{"l.org_id = ", "l.action = ", "l.actor_id = ", "l.id < ", "l.created_at >= ", "l.created_at <= "} {
		if !strings.Contains(sql, w) {
			t.Fatalf("%q missing: %s", w, sql)
		}
	}
	sql, a = buildAuditList(service.AuditQuery{OrgID: uuid.New(), ActorSystem: true, ActorID: &user, Limit: 3})
	checkParams(t, sql, a)
	if !strings.Contains(sql, "l.actor_id IS NULL") || strings.Contains(sql, "l.actor_id = ") {
		t.Fatal(sql)
	}
}

func TestProjectQuery(t *testing.T) {
	id := uuid.New()
	sql, a := projectQuery(service.Visibility{OrgID: uuid.New(), UserID: uuid.New()}, &id, time.Now(), false)
	checkParams(t, sql, a)
	// One project by id: archived or not.
	if !strings.Contains(sql, "pm.user_id IS NOT NULL") || !strings.Contains(sql, "p.id = ") || strings.Contains(sql, "archived_at IS NULL") {
		t.Fatal(sql)
	}
	sql, a = projectQuery(service.Visibility{OrgID: uuid.New(), UserID: uuid.New(), All: true}, nil, time.Now(), false)
	checkParams(t, sql, a)
	if strings.Contains(sql, "pm.user_id IS NOT NULL") || !strings.Contains(sql, "p.archived_at IS NULL") {
		t.Fatal(sql)
	}
	sql, _ = projectQuery(service.Visibility{OrgID: uuid.New(), UserID: uuid.New(), All: true}, nil, time.Now(), true)
	if strings.Contains(sql, "archived_at IS NULL") {
		t.Fatal(sql)
	}
}

func TestChainHash(t *testing.T) {
	actor := uuid.New()
	tt, tid, ip := "issue", "x", "10.0.0.1"
	row := AuditRow{OrgID: uuid.New(), ActorID: &actor, Action: "issue.transitioned", TargetType: &tt, TargetID: &tid, IP: &ip,
		Data: []byte(`{"to":"fixed","from":"open","n":12345678901234567890}`), CreatedAt: time.Date(2026, 10, 26, 1, 2, 3, 456789000, time.UTC)}
	h1, err := ChainHash("", row)
	if err != nil || len(h1) != 64 {
		t.Fatal(h1, err)
	}
	// Postgres returns jsonb re-formatted (key order, spaces); the hash must not change.
	row2 := row
	row2.Data = []byte(`{"from": "open", "n": 12345678901234567890, "to": "fixed"}`)
	row2.CreatedAt = row.CreatedAt.In(time.FixedZone("x", 3600))
	if h2, _ := ChainHash("", row2); h2 != h1 {
		t.Fatal("hash depends on JSON formatting or time zone")
	}
	// Any change to content or link changes the hash.
	for _, mut := range []func(*AuditRow){
		func(r *AuditRow) { r.Action = "issue.assigned" },
		func(r *AuditRow) { r.Data = []byte(`{"to":"verified","from":"open","n":12345678901234567890}`) },
		func(r *AuditRow) { r.ActorID = nil },
		func(r *AuditRow) { r.CreatedAt = r.CreatedAt.Add(time.Microsecond) },
		func(r *AuditRow) { other := "10.0.0.2"; r.IP = &other },
	} {
		r := row
		mut(&r)
		if h, _ := ChainHash("", r); h == h1 {
			t.Fatal("mutation not detected")
		}
	}
	if h, _ := ChainHash(h1, row); h == h1 {
		t.Fatal("prev hash ignored")
	}
	row.Data = []byte(`{bad`)
	if _, err := ChainHash("", row); err == nil {
		t.Fatal("bad json accepted")
	}
}

func TestNormalizers(t *testing.T) {
	if normIP("not an ip") != nil || *normIP("::ffff:10.1.2.3") != "10.1.2.3" || *normIP(" 2001:db8::1 ") != "2001:db8::1" {
		t.Fatal("normIP")
	}
	if nonEmpty("") != nil || *nonEmpty("a") != "a" {
		t.Fatal("nonEmpty")
	}
	if got := truncate("ab\x00c\xffd", 10); got != "abcd" {
		t.Fatalf("%q", got)
	}
	if got := truncate(strings.Repeat("é", 10), 5); got != "éé" {
		t.Fatalf("%q", got)
	}
	if likePattern(`a%b_c\`) != `%a\%b\_c\\%` {
		t.Fatal(likePattern(`a%b_c\`))
	}
}
