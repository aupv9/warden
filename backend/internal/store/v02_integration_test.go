//go:build integration

package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/aupv9/warden/backend/internal/db"
	"github.com/aupv9/warden/backend/internal/domain/autoassign"
	"github.com/aupv9/warden/backend/internal/notify"
	"github.com/aupv9/warden/backend/internal/notify/smtptest"
	"github.com/aupv9/warden/backend/internal/service"
)

func (w *world) count(org uuid.UUID, sql string, args ...any) int {
	w.t.Helper()
	var n int
	err := db.WithOrg(ctx, w.pool, org, func(tx pgx.Tx) error { return tx.QueryRow(ctx, sql, args...).Scan(&n) })
	if err != nil {
		w.t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func (w *world) dispatcher(mailer notify.Sender) *notify.Dispatcher {
	return &notify.Dispatcher{
		Tx: func(c context.Context, org uuid.UUID, fn func(notify.DB) error) error {
			return db.WithOrg(c, w.pool, org, func(tx pgx.Tx) error { return fn(tx) })
		},
		Mailer: mailer, BaseURL: "https://warden.example", Now: time.Now, Log: slog.New(slog.DiscardHandler),
	}
}

func TestOutboxIsWrittenInTheChangesTransaction(t *testing.T) {
	w := newWorld(t)
	f := w.org("OBX")
	dev := w.users["OBXdev"].ID
	iss := w.issue(f, 1, "high", "open", nil, nil)

	must(w.svc.Transition(ctx, w.actor("OBXlead", f.id), iss, service.TransitionInput{To: "assigned", Version: ptr(1), AssigneeID: ptr(dev.String())}))
	var typ string
	var payload []byte
	err := db.WithOrg(ctx, w.pool, f.id, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT type, payload FROM outbox_event WHERE payload->>'issue_id' = $1`, iss.String()).Scan(&typ, &payload)
	})
	if err != nil || typ != notify.IssueAssigned || !strings.Contains(string(payload), dev.String()) || strings.Contains(string(payload), "title") {
		t.Fatal(typ, string(payload), err)
	}
	// The dispatch job was enqueued in the same transaction.
	var jobs int
	if err := w.pool.QueryRow(ctx, `SELECT count(*) FROM river_job WHERE kind = 'dispatch_notifications'`).Scan(&jobs); err != nil || jobs < 1 {
		t.Fatal(jobs, err)
	}

	// One dispatch per transaction, never swallowed by an earlier job: a
	// transaction with two events right after another dispatch adds exactly one.
	if _, err := w.pool.Exec(ctx, `UPDATE river_job SET state = 'completed', finalized_at = now() WHERE kind = 'dispatch_notifications'`); err != nil {
		t.Fatal(err)
	}
	jobs0 := jobs
	err = w.db.InOrg(ctx, f.id, func(r service.Repo) error {
		for range 2 {
			if err := r.AppendOutbox(ctx, notify.Event{OrgID: f.id, Type: notify.IssueReopened, Payload: notify.Payload{IssueID: &iss}}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.pool.QueryRow(ctx, `SELECT count(*) FROM river_job WHERE kind = 'dispatch_notifications'`).Scan(&jobs); err != nil || jobs != jobs0+1 {
		t.Fatal("want one new dispatch job", jobs0, jobs, err)
	}

	// A change that fails after writing its event leaves neither behind.
	before := w.count(f.id, `SELECT count(*) FROM outbox_event`)
	boom := errors.New("boom")
	err = w.db.InOrg(ctx, f.id, func(r service.Repo) error {
		if err := r.AppendOutbox(ctx, notify.Event{OrgID: f.id, Type: notify.IssueReopened, Payload: notify.Payload{IssueID: &iss}}); err != nil {
			return err
		}
		if err := r.UpdateIssueState(ctx, iss, "open", nil); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) || w.count(f.id, `SELECT count(*) FROM outbox_event`) != before ||
		w.count(f.id, `SELECT count(*) FROM issue WHERE id = $1 AND status = 'assigned'`, iss) != 1 {
		t.Fatal("outbox row survived the rollback", err)
	}
	// RLS: another org's scope can't write into this org's outbox.
	other := w.org("OBY")
	err = w.db.InOrg(ctx, other.id, func(r service.Repo) error {
		return r.AppendOutbox(ctx, notify.Event{OrgID: f.id, Type: notify.IssueReopened, Payload: notify.Payload{IssueID: &iss}})
	})
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "42501" {
		t.Fatal(err)
	}
	// Digest dedupe keys are per org: the same key in two orgs is two rows.
	for _, org := range []uuid.UUID{f.id, other.id} {
		for range 2 {
			if err := db.WithOrg(ctx, w.pool, org, func(tx pgx.Tx) error {
				return notify.Insert(ctx, tx, notify.Event{OrgID: org, Type: notify.SLAOverdue, DedupeKey: "sla:x:2026-10-26",
					Payload: notify.Payload{UserID: &dev}})
			}); err != nil {
				t.Fatal(err)
			}
		}
		if n := w.count(org, `SELECT count(*) FROM outbox_event WHERE dedupe_key = 'sla:x:2026-10-26'`); n != 1 {
			t.Fatal(n)
		}
	}
}

func TestDispatchNotificationsAndEmail(t *testing.T) {
	w := newWorld(t)
	f := w.org("NTF")
	smtp, err := smtptest.Start(smtptest.Options{RejectRcpt: []string{w.users["NTFowner"].Email}})
	if err != nil {
		t.Fatal(err)
	}
	defer smtp.Close()
	host, port := smtp.Addr()
	mailer := must(notify.NewSMTP(notify.SMTPConfig{Host: host, Port: port, From: "warden@example.com"}))
	d := w.dispatcher(mailer)

	dev, dev2, owner := w.users["NTFdev"].ID, w.users["NTFdev2"].ID, w.users["NTFowner"].ID
	lead := w.actor("NTFlead", f.id)
	iss := w.issue(f, 1, "critical", "open", nil, nil)
	// What scanned code put in the issue: markup in the title, a masked secret
	// in the snippet, text in the description. Plus a comment.
	ownerExec(t, f.id, `UPDATE issue SET title = '<script>alert(1)</script> in config', snippet = 'AKIA****SNIPPETMARK',
		description = 'DESCRIPTIONMARK', remediation = 'REMEDIATIONMARK' WHERE id = $1`, iss)
	must(w.svc.AddComment(ctx, w.actor("NTFdev", f.id), iss, service.CommentInput{Body: "COMMENTMARK"}))
	must(w.svc.Transition(ctx, lead, iss, service.TransitionInput{To: "assigned", Version: ptr(1), AssigneeID: ptr(dev.String())}))
	// dev2 is assigned another issue, then leaves the org before dispatch.
	iss2 := w.issue(f, 2, "high", "open", nil, nil)
	must(w.svc.Transition(ctx, lead, iss2, service.TransitionInput{To: "assigned", Version: ptr(1), AssigneeID: ptr(dev2.String())}))
	if err := w.svc.RemoveMember(ctx, w.actor("NTFadmin", f.id), dev2); err != nil {
		t.Fatal(err)
	}
	// An unassigned issue reopened by a scan goes to the project owner, whose
	// mailbox rejects mail.
	iss3 := w.issue(f, 3, "medium", "fixed", nil, nil)
	err = w.db.InOrg(ctx, f.id, func(r service.Repo) error {
		return r.AppendOutbox(ctx, notify.Event{OrgID: f.id, Type: notify.IssueReopened, Payload: notify.Payload{IssueID: &iss3}})
	})
	if err != nil {
		t.Fatal(err)
	}
	// scan.finished: email is off by default.
	err = w.db.InOrg(ctx, f.id, func(r service.Repo) error {
		return r.AppendOutbox(ctx, notify.Event{OrgID: f.id, Type: notify.ScanFinished, Payload: notify.Payload{ScanID: &f.scan}})
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := d.DispatchOrg(ctx, f.id); err != nil {
		t.Fatal(err)
	}
	if n := w.count(f.id, `SELECT count(*) FROM outbox_event WHERE dispatched_at IS NULL`); n != 0 {
		t.Fatal("undispatched", n)
	}
	if n := w.count(f.id, `SELECT count(*) FROM notification WHERE user_id = $1`, dev2); n != 0 {
		t.Fatal("a former member was notified")
	}
	total := w.count(f.id, `SELECT count(*) FROM notification`)
	if total != 3 { // dev (assigned), owner (reopened), dev (scan.finished: the scan's creator)
		t.Fatal(total)
	}
	// Idempotent: a second run, and a crashed run that left dispatched_at unset.
	if err := d.DispatchOrg(ctx, f.id); err != nil {
		t.Fatal(err)
	}
	ownerExec(t, f.id, `UPDATE outbox_event SET dispatched_at = NULL`)
	if err := d.DispatchOrg(ctx, f.id); err != nil {
		t.Fatal(err)
	}
	if n := w.count(f.id, `SELECT count(*) FROM notification`); n != total {
		t.Fatal("duplicated", n)
	}

	// Email: one to dev (assigned); scan.finished is off; the owner's address
	// is rejected, retried later, and didn't stop dev's mail.
	msgs := smtp.Messages()
	if len(msgs) != 1 || msgs[0].To[0] != w.users["NTFdev"].Email {
		t.Fatalf("%+v", msgs)
	}
	m, err := smtptest.Parse(msgs[0].Data)
	if err != nil {
		t.Fatal(err)
	}
	if m.Header.Get("Subject") != "[Warden] NTF-1 assigned to you" {
		t.Fatal(m.Header.Get("Subject"))
	}
	for _, mark := range []string{"SNIPPETMARK", "AKIA", "DESCRIPTIONMARK", "REMEDIATIONMARK", "COMMENTMARK"} {
		if strings.Contains(msgs[0].Data, mark) || strings.Contains(m.Text, mark) || strings.Contains(m.HTML, mark) {
			t.Fatalf("%s leaked into the email", mark)
		}
	}
	if strings.Contains(m.HTML, "<script>") || !strings.Contains(m.HTML, "&lt;script&gt;") {
		t.Fatal(m.HTML)
	}
	link := "https://warden.example/orgs/" + f.id.String() + "/issues/" + iss.String()
	if !strings.Contains(m.Text, link) || !strings.Contains(m.Text, "Org NTF") || !strings.Contains(m.Text, "NTFlead") {
		t.Fatal(m.Text)
	}
	var state string
	var attempts int
	var next time.Time
	err = db.WithOrg(ctx, w.pool, f.id, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT email_state, email_attempts, email_next_at FROM notification WHERE user_id = $1`, owner).
			Scan(&state, &attempts, &next)
	})
	if err != nil || state != "pending" || attempts != 1 || !next.After(time.Now()) {
		t.Fatal(state, attempts, next, err)
	}

	// The recipient reads their notifications across orgs; nobody else can.
	devID := dev
	page := must(w.svc.Notifications(ctx, devID, service.NotificationFilter{}))
	if len(page.Items) != 2 || page.Items[0].OrgID != f.id {
		t.Fatalf("%+v", page)
	}
	var assigned service.Notification
	for _, n := range page.Items {
		if n.Type == notify.IssueAssigned {
			assigned = n
		}
	}
	if assigned.Title != "NTF-1 assigned to you" || assigned.Actor == nil || assigned.Actor.ID != w.users["NTFlead"].ID ||
		assigned.Link != "/orgs/"+f.id.String()+"/issues/"+iss.String() {
		t.Fatalf("%+v", assigned)
	}
	if c := must(w.svc.UnreadNotifications(ctx, devID)); c.Count != 2 {
		t.Fatal(c)
	}
	// Someone else marking dev's notification read changes nothing (RLS + user filter).
	if err := w.svc.MarkNotificationsRead(ctx, owner, service.MarkReadInput{IDs: &[]string{assigned.ID.String()}}); err != nil {
		t.Fatal(err)
	}
	if c := must(w.svc.UnreadNotifications(ctx, devID)); c.Count != 2 {
		t.Fatal(c)
	}
	if err := w.svc.MarkNotificationsRead(ctx, devID, service.MarkReadInput{IDs: &[]string{assigned.ID.String()}}); err != nil {
		t.Fatal(err)
	}
	if p := must(w.svc.Notifications(ctx, devID, service.NotificationFilter{Unread: "true"})); len(p.Items) != 1 {
		t.Fatalf("%+v", p)
	}
	if err := w.svc.MarkNotificationsRead(ctx, devID, service.MarkReadInput{All: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	if c := must(w.svc.UnreadNotifications(ctx, devID)); c.Count != 0 {
		t.Fatal(c)
	}
	// Pagination.
	p1 := must(w.svc.Notifications(ctx, devID, service.NotificationFilter{PageParams: service.PageParams{Limit: "1"}}))
	p2 := must(w.svc.Notifications(ctx, devID, service.NotificationFilter{PageParams: service.PageParams{Limit: "1", Cursor: *p1.NextCursor}}))
	if len(p1.Items) != 1 || len(p2.Items) != 1 || p1.Items[0].ID == p2.Items[0].ID || p2.NextCursor != nil {
		t.Fatal(p1, p2)
	}

	// Preferences.
	prefs := must(w.svc.SetNotificationPrefs(ctx, devID, service.NotificationPrefsInput{Items: []service.NotificationPref{
		{Type: notify.ScanFinished, Email: true}, {Type: notify.IssueAssigned, Email: false}}}))
	for _, p := range prefs.Items {
		if p.Type == notify.ScanFinished && !p.Email || p.Type == notify.IssueAssigned && p.Email {
			t.Fatalf("%+v", prefs)
		}
	}
	if again := must(w.svc.NotificationPrefs(ctx, devID)); len(again.Items) != len(notify.Types) {
		t.Fatal(again)
	}
	iss4 := w.issue(f, 4, "low", "open", nil, nil)
	must(w.svc.Transition(ctx, lead, iss4, service.TransitionInput{To: "assigned", Version: ptr(1), AssigneeID: ptr(dev.String())}))
	if err := d.DispatchOrg(ctx, f.id); err != nil {
		t.Fatal(err)
	}
	if len(smtp.Messages()) != 1 || w.count(f.id, `SELECT count(*) FROM notification WHERE user_id = $1 AND email_state = 'none'`, dev) != 2 {
		t.Fatal("email sent despite the preference")
	}

	// RLS: without app.org_id nothing in the outbox or notifications is visible,
	// and another org's scope sees none of this org's rows.
	other := w.org("NTG")
	for _, org := range []uuid.UUID{uuid.Nil, other.id} {
		if n := w.count(org, `SELECT count(*) FROM notification`) + w.count(org, `SELECT count(*) FROM outbox_event`); n != 0 {
			t.Fatal("rows leaked across orgs", n)
		}
	}
	// A former member no longer sees notifications from that org.
	ownerExec(t, f.id, `INSERT INTO notification (id, org_id, user_id, event_id, type, title, link, payload)
		SELECT gen_random_uuid(), org_id, $1, id, type, 'x', '/x', '{}' FROM outbox_event LIMIT 1`, dev2)
	if p := must(w.svc.Notifications(ctx, dev2, service.NotificationFilter{})); len(p.Items) != 0 {
		t.Fatal(p)
	}
}

func TestSMTPOverSTARTTLSWithAuth(t *testing.T) {
	smtp, err := smtptest.Start(smtptest.Options{STARTTLS: true, Username: "warden", Password: "pw-from-config"})
	if err != nil {
		t.Fatal(err)
	}
	defer smtp.Close()
	host, port := smtp.Addr()
	s := must(notify.NewSMTP(notify.SMTPConfig{Host: host, Port: port, From: "warden@example.com", Username: "warden",
		Password: "pw-from-config", TLSConfig: smtp.ClientTLS()}))
	if err := s.Send(ctx, notify.Mail{To: "dev@example.com", Subject: "[Warden] x", Text: "t", HTML: "<p>h</p>"}); err != nil {
		t.Fatal(err)
	}
	if m := smtp.Messages(); len(m) != 1 || !m[0].TLS || m[0].Auth != "warden" {
		t.Fatalf("%+v", m)
	}
}

func TestArchiveBlocksScans(t *testing.T) {
	w := newWorld(t)
	f := w.org("ARC")
	lead, dev := w.actor("ARClead", f.id), w.actor("ARCdev", f.id)
	iss := w.issue(f, 1, "high", "open", nil, nil)
	w.objs.sizes[service.ObjectKey(f.id, f.scan)] = 10

	p := must(w.svc.ArchiveProject(ctx, lead, f.project, true))
	if p.ArchivedAt == nil {
		t.Fatal(p)
	}
	if _, err := w.svc.ArchiveProject(ctx, dev, f.project, false); code(err) != "FORBIDDEN" {
		t.Fatal(err)
	}
	if _, err := w.svc.CreateScan(ctx, dev, f.project, service.CreateScanInput{FileName: "a.zip", FileSize: 10, SHA256: strings.Repeat("c", 64)}); code(err) != "PROJECT_ARCHIVED" {
		t.Fatal(err)
	}
	if _, err := w.svc.StartScan(ctx, dev, f.scan); code(err) != "PROJECT_ARCHIVED" {
		t.Fatal(err)
	}
	if l := must(w.svc.Projects(ctx, dev, "")); len(l.Items) != 0 {
		t.Fatal(l)
	}
	if l := must(w.svc.Projects(ctx, dev, "true")); len(l.Items) != 1 || l.Items[0].ArchivedAt == nil {
		t.Fatal(l)
	}
	// Issues stay readable.
	if _, err := w.svc.Issue(ctx, dev, iss); err != nil {
		t.Fatal(err)
	}
	if l := must(w.svc.Issues(ctx, dev, service.IssueFilter{ProjectID: f.project.String()})); len(l.Items) != 1 {
		t.Fatal(l)
	}
	if l := must(w.svc.Issues(ctx, dev, service.IssueFilter{})); len(l.Items) != 0 {
		t.Fatal("archived project's issues in the default list", l)
	}
	must(w.svc.ArchiveProject(ctx, lead, f.project, false))
	if sc := must(w.svc.StartScan(ctx, dev, f.scan)); sc.Status != "queued" {
		t.Fatal(sc)
	}
	if n := w.count(f.id, `SELECT count(*) FROM audit_log WHERE org_id = $1 AND action IN ('project.archived', 'project.unarchived')`, f.id); n != 2 {
		t.Fatal(n)
	}
}

func TestPolicyAndAssignRules(t *testing.T) {
	w := newWorld(t)
	f := w.org("POL")
	lead := w.actor("POLlead", f.id)
	created := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	iss := w.issue(f, 1, "critical", "open", nil, nil)
	info := w.issue(f, 2, "info", "open", nil, nil)
	done := w.issue(f, 3, "high", "verified", nil, nil)
	ownerExec(t, f.id, `UPDATE issue SET created_at = $1`, created)

	if _, err := w.svc.SetOrgPolicy(ctx, w.actor("POLadmin", f.id), service.OrgPolicyInput{}); code(err) != "FORBIDDEN" {
		t.Fatal(err)
	}
	sla := &service.SLAInput{Critical: ptr(3), High: ptr(10), Medium: ptr(20), Low: ptr(40)}
	o := must(w.svc.SetOrgPolicy(ctx, lead, service.OrgPolicyInput{SLADays: sla, RecomputeOpen: ptr(true)}))
	if o.SLADays != (service.SLADays{Critical: 3, High: 10, Medium: 20, Low: 40}) || o.MyRole != "security_lead" {
		t.Fatalf("%+v", o)
	}
	due := func(id uuid.UUID) *time.Time {
		var d *time.Time
		if err := db.WithOrg(ctx, w.pool, f.id, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT due_at FROM issue WHERE id = $1`, id).Scan(&d)
		}); err != nil {
			t.Fatal(err)
		}
		return d
	}
	if d := due(iss); d == nil || !d.Equal(created.AddDate(0, 0, 3)) {
		t.Fatal(d)
	}
	if due(info) != nil || due(done) != nil {
		t.Fatal("info and finished issues keep no SLA")
	}
	if n := w.count(f.id, `SELECT count(*) FROM audit_log WHERE org_id = $1 AND action = 'org.policy_changed' AND data->>'recomputed' = '1'`, f.id); n != 1 {
		t.Fatal(n)
	}

	glob := "src/**/*.go"
	dev := w.users["POLdev"].ID
	rules := must(w.svc.SetAssignRules(ctx, w.actor("POLowner", f.id), f.project, service.AssignRulesInput{Items: []service.AssignRuleInput{
		{Match: autoassign.Match{PathGlob: &glob}, AssigneeID: dev.String()}}}))
	if len(rules.Items) != 1 {
		t.Fatal(rules)
	}
	if got := must(w.svc.AssignRules(ctx, w.actor("POLdev2", f.id), f.project)); len(got.Items) != 1 || *got.Items[0].Match.PathGlob != glob {
		t.Fatalf("%+v", got)
	}
	if _, err := w.svc.SetAssignRules(ctx, w.actor("POLowner", f.id), f.project, service.AssignRulesInput{Items: []service.AssignRuleInput{
		{Match: autoassign.Match{PathGlob: &glob}, AssigneeID: w.users["POLadmin"].ID.String()}}}); code(err) != "VALIDATION_FAILED" {
		t.Fatal(err)
	}
	var raw []byte
	if err := db.WithOrg(ctx, w.pool, f.id, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT assign_rules FROM project WHERE id = $1`, f.project).Scan(&raw)
	}); err != nil {
		t.Fatal(err)
	}
	var stored []map[string]any
	if json.Unmarshal(raw, &stored) != nil || len(stored) != 1 {
		t.Fatal(string(raw))
	}
}

func TestMetricsOnSeededHistory(t *testing.T) {
	w := newWorld(t)
	f := w.org("MET")
	hidden := must(w.svc.CreateProject(ctx, w.actor("METlead", f.id), service.CreateProjectInput{Key: "HID", Name: "hidden"}))
	day := func(d, h int) time.Time { return time.Date(2026, 10, d, h, 0, 0, 0, time.UTC) }
	now := day(26, 12)
	w.svc.SetClock(func() time.Time { return now })

	// a: critical, created Oct 20 (late evening UTC), fixed Oct 22 → within SLA (due Oct 27).
	// b: high, created Oct 1 (before the window of 7… we use 30 days), still open, overdue.
	// c: low, created Oct 24, fixed Oct 25, reopened Oct 26.
	// x: high in a project the developer can't see.
	seed := func(project uuid.UUID, n int, sev, status string, created time.Time, due *time.Time, events [][3]any) uuid.UUID {
		id := uuid.New()
		ownerExec(t, f.id, `INSERT INTO issue (id, org_id, project_id, number, fingerprint, tool, rule_id, title, severity, status,
			first_seen_scan_id, last_seen_scan_id, due_at, created_at)
			VALUES ($1, $2, $3, $4, $5, 'trivy', 'r', 't', $6, $7, $8, $8, $9, $10)`,
			id, f.id, project, n, strings.Repeat("f", 63)+string(rune('0'+n)), sev, status, f.scan, due, created)
		ownerExec(t, f.id, `INSERT INTO issue_event (org_id, issue_id, type, to_value, created_at) VALUES ($1, $2, 'created', 'open', $3)`, f.id, id, created)
		for _, e := range events {
			ownerExec(t, f.id, `INSERT INTO issue_event (org_id, issue_id, type, from_value, to_value, created_at)
				VALUES ($1, $2, 'status_changed', $3, $4, $5)`, f.id, id, e[0], e[1], e[2])
		}
		return id
	}
	dueA, dueB := day(27, 0), day(15, 0)
	seed(f.project, 1, "critical", "fixed", day(20, 23), &dueA, [][3]any{{"open", "assigned", day(21, 1)}, {"assigned", "fixed", day(22, 23)}})
	seed(f.project, 2, "high", "open", day(1, 0), &dueB, nil)
	seed(f.project, 3, "low", "reopened", day(24, 6), nil, [][3]any{{"open", "fixed", day(25, 6)}, {"fixed", "reopened", day(26, 6)}})
	// Hidden project: the scan fixture belongs to f.project, which is fine for the FK.
	seed(hidden.ID, 4, "high", "open", day(25, 0), nil, nil)

	m := must(w.svc.Metrics(ctx, w.actor("METdev", f.id), service.MetricsFilter{}))
	if m.Days != 30 || len(m.OpenByDay) != 30 || m.OpenByDay[29].Date != "2026-10-26" || m.OpenByDay[0].Date != "2026-09-27" {
		t.Fatalf("%+v", m.OpenByDay)
	}
	at := func(date string) service.DaySeverity {
		for _, d := range m.OpenByDay {
			if d.Date == date {
				return d
			}
		}
		t.Fatalf("no %s", date)
		return service.DaySeverity{}
	}
	// Oct 20 (UTC): a open (created 23:00) and b → critical 1, high 1.
	if d := at("2026-10-20"); d.Critical != 1 || d.High != 1 || d.Low != 0 {
		t.Fatalf("%+v", d)
	}
	if d := at("2026-10-22"); d.Critical != 0 || d.High != 1 { // a fixed at 23:00 on the 22nd
		t.Fatalf("%+v", d)
	}
	if d := at("2026-10-25"); d.Low != 0 || d.High != 1 { // c created 24th, fixed 25th; the hidden issue doesn't count
		t.Fatalf("%+v", d)
	}
	if d := at("2026-10-26"); d.Low != 1 || d.High != 1 {
		t.Fatalf("%+v", d)
	}
	if m.MTTRHours.Critical == nil || *m.MTTRHours.Critical != 48 || m.MTTRHours.Low == nil || *m.MTTRHours.Low != 24 || m.MTTRHours.High != nil {
		t.Fatalf("%+v", m.MTTRHours)
	}
	if m.SLA != (service.SLAStats{FixedInTime: 1, FixedLate: 0, OpenOverdue: 1}) {
		t.Fatalf("%+v", m.SLA)
	}
	newAt := map[string]int{}
	for _, d := range m.NewByDay {
		newAt[d.Date] = d.Count
	}
	if newAt["2026-10-20"] != 1 || newAt["2026-10-24"] != 1 || newAt["2026-10-25"] != 0 {
		t.Fatalf("%+v", newAt)
	}
	fixedAt := map[string]int{}
	for _, d := range m.FixedByDay {
		fixedAt[d.Date] = d.Count
	}
	if fixedAt["2026-10-22"] != 1 || fixedAt["2026-10-25"] != 1 {
		t.Fatalf("%+v", fixedAt)
	}
	// The lead sees the hidden project too.
	ml := must(w.svc.Metrics(ctx, w.actor("METlead", f.id), service.MetricsFilter{Days: "90"}))
	if ml.OpenByDay[89].High != 2 {
		t.Fatalf("%+v", ml.OpenByDay[89])
	}
	if one := must(w.svc.Metrics(ctx, w.actor("METlead", f.id), service.MetricsFilter{ProjectID: hidden.ID.String()})); one.OpenByDay[29].High != 1 {
		t.Fatalf("%+v", one.OpenByDay[29])
	}
	if _, err := w.svc.Metrics(ctx, w.actor("METdev", f.id), service.MetricsFilter{ProjectID: hidden.ID.String()}); code(err) != "NOT_FOUND" {
		t.Fatal(err)
	}

	tot := must(w.svc.IssueTotals(ctx, w.actor("METlead", f.id), ""))
	if tot.Active != 3 || tot.PastSLA != 1 || tot.Mine != 0 || tot.Secrets != 0 {
		t.Fatalf("%+v", tot)
	}
	if tot := must(w.svc.IssueTotals(ctx, w.actor("METdev", f.id), f.project.String())); tot.Active != 2 {
		t.Fatalf("%+v", tot)
	}
}
