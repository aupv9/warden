package store

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/notify"
	"github.com/aupv9/warden/backend/internal/service"
)

func TestRepoNotifications(t *testing.T) {
	user, org, actor, id := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	r, tx := repoWith(on(map[string][][]any{
		"FROM notification n\n":               {{id, org, "issue.assigned", "WEB-1 assigned to you", "/orgs/x", actor, "a@b.c", "A", nil, now}},
		"SELECT count(*) FROM notification n": {{3}},
		"FROM notification_pref":              {{"scan.finished", true}, {"issue.assigned", false}},
	}))
	after := &service.NotificationCursor{CreatedAt: now, ID: id}
	n, err := r.Notifications(ctx, service.NotificationQuery{UserID: user, Unread: true, After: after, Limit: 5})
	if err != nil || len(n) != 1 || n[0].Actor == nil || n[0].Actor.ID != actor || n[0].ReadAt != nil {
		t.Fatal(n, err)
	}
	q := tx.sqls[len(tx.sqls)-1]
	if !strings.Contains(q, "read_at IS NULL") || !strings.Contains(q, "(n.created_at, n.id) <") || !strings.Contains(q, "JOIN org_member m") {
		t.Fatal(q)
	}
	if c, err := r.UnreadCount(ctx, user); err != nil || c != 3 {
		t.Fatal(c, err)
	}
	if err := r.MarkRead(ctx, user, nil); err != nil || strings.Contains(tx.sqls[len(tx.sqls)-1], "ANY") {
		t.Fatal(err)
	}
	if err := r.MarkRead(ctx, user, []uuid.UUID{id}); err != nil || !strings.Contains(tx.sqls[len(tx.sqls)-1], "id = ANY($2)") {
		t.Fatal(err)
	}
	if p, err := r.NotificationPrefs(ctx, user); err != nil || !p["scan.finished"] || p["issue.assigned"] {
		t.Fatal(p, err)
	}
	if err := r.SetNotificationPref(ctx, user, "scan.finished", false); err != nil {
		t.Fatal(err)
	}
	// No job client: the outbox row alone.
	if err := r.AppendOutbox(ctx, notify.Event{OrgID: org, Type: notify.IssueAssigned}); err != nil || !strings.Contains(tx.sqls[len(tx.sqls)-1], "INSERT INTO outbox_event") {
		t.Fatal(err)
	}
	if err := r.AppendOutbox(ctx, notify.Event{OrgID: org, Type: "nope"}); err == nil {
		t.Fatal("invalid event accepted")
	}

	bad, _ := repoWith(failing)
	if _, err := bad.Notifications(ctx, service.NotificationQuery{UserID: user, Limit: 1}); !errors.Is(err, errDB) {
		t.Fatal(err)
	}
	if _, err := bad.UnreadCount(ctx, user); !errors.Is(err, errDB) {
		t.Fatal(err)
	}
	if err := bad.MarkRead(ctx, user, nil); !errors.Is(err, errDB) {
		t.Fatal(err)
	}
	if _, err := bad.NotificationPrefs(ctx, user); !errors.Is(err, errDB) {
		t.Fatal(err)
	}
	if err := bad.SetNotificationPref(ctx, user, "x", true); !errors.Is(err, errDB) {
		t.Fatal(err)
	}
	if err := bad.AppendOutbox(ctx, notify.Event{OrgID: org, Type: notify.IssueAssigned}); !errors.Is(err, errDB) {
		t.Fatal(err)
	}
	if err := (&DB{}).InUser(ctx, uuid.Nil, nil); err == nil {
		t.Fatal("InUser without a user")
	}
}

func TestRepoPolicy(t *testing.T) {
	org, proj, dev := uuid.New(), uuid.New(), uuid.New()
	rules := `[{"match":{"path_glob":"src/**"},"assignee_id":"` + dev.String() + `"}]`
	r, tx := repoWith(on(map[string][][]any{
		"UPDATE organization":            {{1}},
		"UPDATE issue SET due_at":        {{1}, {2}},
		"SELECT assign_rules":            {{[]byte(rules)}},
		"UPDATE project SET archived":    {{1}},
		"SELECT archived_at IS NOT NULL": {{true}},
	}))
	sla := service.SLADays{Critical: 1, High: 2, Medium: 3, Low: 4}
	if err := r.SetOrgSLA(ctx, org, sla); err != nil {
		t.Fatal(err)
	}
	if n, err := r.RecomputeDueDates(ctx, org, sla); err != nil || n != 2 || !strings.Contains(tx.sqls[len(tx.sqls)-1], "severity <> 'info'") {
		t.Fatal(n, err)
	}
	got, err := r.AssignRules(ctx, proj)
	if err != nil || len(got) != 1 || got[0].AssigneeID != dev || *got[0].Match.PathGlob != "src/**" {
		t.Fatal(got, err)
	}
	if err := r.SetAssignRules(ctx, proj, nil); err != nil {
		t.Fatal(err)
	}
	if changed, err := r.SetProjectArchived(ctx, proj, true); err != nil || !changed || !strings.Contains(tx.sqls[len(tx.sqls)-1], "archived_at IS NULL") {
		t.Fatal(changed, err)
	}
	if _, err := r.SetProjectArchived(ctx, proj, false); err != nil || !strings.Contains(tx.sqls[len(tx.sqls)-1], "archived_at = NULL") {
		t.Fatal(err)
	}
	if a, err := r.ProjectArchived(ctx, proj); err != nil || !a {
		t.Fatal(a, err)
	}

	empty, _ := repoWith(nil)
	if err := empty.SetOrgSLA(ctx, org, sla); !errors.Is(err, service.ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := empty.AssignRules(ctx, proj); !errors.Is(err, service.ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := empty.ProjectArchived(ctx, proj); !errors.Is(err, service.ErrNotFound) {
		t.Fatal(err)
	}
	corrupt, _ := repoWith(on(map[string][][]any{"SELECT assign_rules": {{[]byte("{")}}}))
	if _, err := corrupt.AssignRules(ctx, proj); err == nil {
		t.Fatal("corrupt rules accepted")
	}
	bad, _ := repoWith(failing)
	if err := bad.SetOrgSLA(ctx, org, sla); !errors.Is(err, errDB) {
		t.Fatal(err)
	}
	if _, err := bad.RecomputeDueDates(ctx, org, sla); !errors.Is(err, errDB) {
		t.Fatal(err)
	}
	if err := bad.SetAssignRules(ctx, proj, nil); !errors.Is(err, errDB) {
		t.Fatal(err)
	}
	if _, err := bad.SetProjectArchived(ctx, proj, true); !errors.Is(err, errDB) {
		t.Fatal(err)
	}
}

func TestRepoMetrics(t *testing.T) {
	org, user, proj := uuid.New(), uuid.New(), uuid.New()
	r, tx := repoWith(on(map[string][][]any{
		"GREATEST":                             {{"2026-10-20", "critical", 1}, {"2026-10-20", "high", 2}, {"2026-10-21", "critical", -1}},
		"i.created_at AT TIME ZONE":            {{"2026-10-20", 3}},
		"e.to_value = 'fixed'":                 {{"2026-10-21", 1}},
		"WITH first_fix":                       {{"critical", 24.0, 1, 0}, {"high", 48.0, 0, 1}, {"medium", 1.0, 0, 0}, {"low", 2.0, 1, 0}, {"info", 3.0, 0, 0}},
		"SELECT count(*)::int FROM":            {{4}},
		"count(*) FILTER (WHERE i.assignee_id": {{5, 1, 2, 3}},
	}))
	v := service.Visibility{OrgID: org, UserID: user}
	d, err := r.Metrics(ctx, service.MetricsQuery{Vis: v, ProjectID: &proj, Start: now.AddDate(0, 0, -29), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if d.OpenDeltas["2026-10-20"].Critical != 1 || d.OpenDeltas["2026-10-20"].High != 2 || d.OpenDeltas["2026-10-21"].Critical != -1 ||
		d.New["2026-10-20"] != 3 || d.Fixed["2026-10-21"] != 1 || *d.MTTRHours.Critical != 24 || *d.MTTRHours.High != 48 ||
		*d.MTTRHours.Medium != 1 || *d.MTTRHours.Low != 2 || d.SLA != (service.SLAStats{FixedInTime: 2, FixedLate: 1, OpenOverdue: 4}) {
		t.Fatalf("%+v", d)
	}
	for _, q := range tx.sqls {
		if !strings.Contains(q, "i.project_id = ") || !strings.Contains(q, "project_member vm") {
			t.Fatalf("unscoped metrics query: %s", q)
		}
	}
	all := service.Visibility{OrgID: org, UserID: user, All: true}
	if tot, err := r.IssueTotals(ctx, service.TotalsQuery{Vis: all, Now: now}); err != nil || tot != (service.IssueTotals{Active: 5, Mine: 1, PastSLA: 2, Secrets: 3}) {
		t.Fatal(tot, err)
	}
	if q := tx.sqls[len(tx.sqls)-1]; !strings.Contains(q, "p.archived_at IS NULL") || strings.Contains(q, "project_member vm") {
		t.Fatal(q)
	}
	for _, key := range []string{"GREATEST", "i.created_at AT TIME ZONE", "e.to_value = 'fixed'", "WITH first_fix", "SELECT count(*)::int FROM"} {
		failOn := key
		bad, _ := repoWith(func(sql string, _ []any) ([][]any, error) {
			if strings.Contains(sql, failOn) {
				return nil, errDB
			}
			return nil, nil
		})
		if _, err := bad.Metrics(ctx, service.MetricsQuery{Vis: v, Start: now, Now: now}); !errors.Is(err, errDB) {
			t.Errorf("%s: %v", key, err)
		}
	}
	bad, _ := repoWith(failing)
	if _, err := bad.IssueTotals(ctx, service.TotalsQuery{Vis: v, Now: now}); !errors.Is(err, errDB) {
		t.Fatal(err)
	}
}
