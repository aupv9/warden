package notify

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/worker/dbtest"
)

var (
	now    = time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)
	errDB  = errors.New("db down")
	quiet  = slog.New(slog.DiscardHandler)
	orgID  = uuid.MustParse("00000000-0000-7000-8000-00000000000a")
	projID = uuid.MustParse("00000000-0000-7000-8000-00000000000b")
)

type fakeMailer struct {
	mu   sync.Mutex
	sent []Mail
	fail map[string]error
}

func (m *fakeMailer) Send(_ context.Context, mail Mail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail[mail.To]; err != nil {
		return err
	}
	m.sent = append(m.sent, mail)
	return nil
}

type user struct {
	id     uuid.UUID
	email  string
	role   string
	active bool
	inProj bool
}

// world answers the dispatcher's statements from a small in-memory model.
type world struct {
	t      *testing.T
	users  map[uuid.UUID]user
	issues map[uuid.UUID][]any // issue facts row
	events [][]any
	prefs  map[string]bool // user|type → email
	claim  [][]any
	db     *dbtest.DB
	mailer *fakeMailer
	d      *Dispatcher
}

func payload(p Payload) []byte { b, _ := json.Marshal(p); return b }

func newWorld(t *testing.T, extra ...dbtest.Step) *world {
	w := &world{t: t, users: map[uuid.UUID]user{}, issues: map[uuid.UUID][]any{}, prefs: map[string]bool{},
		mailer: &fakeMailer{fail: map[string]error{}}}
	steps := []dbtest.Step{
		{Prefix: "SELECT id, type, payload FROM outbox_event", Do: func([]any) dbtest.Step { return dbtest.Step{Rows: w.events} }},
		{Prefix: "SELECT name FROM organization", Rows: [][]any{{"Acme"}}},
		{Prefix: "SELECT display_name FROM app_user", Do: func(args []any) dbtest.Step {
			if u, ok := w.users[args[0].(uuid.UUID)]; ok {
				return dbtest.Step{Rows: [][]any{{u.email[:strings.IndexByte(u.email, '@')]}}}
			}
			return dbtest.Step{}
		}},
		{Prefix: "SELECT i.id, p.id, p.key", Do: func(args []any) dbtest.Step {
			if len(args) == 1 {
				if r, ok := w.issues[args[0].(uuid.UUID)]; ok {
					return dbtest.Step{Rows: [][]any{r}}
				}
				return dbtest.Step{}
			}
			var rows [][]any
			for _, r := range w.issues {
				if a, ok := r[7].(uuid.UUID); ok && a == args[0].(uuid.UUID) {
					rows = append(rows, r)
				}
			}
			return dbtest.Step{Rows: rows}
		}},
		{Prefix: "SELECT user_id FROM project_member", Do: func([]any) dbtest.Step { return w.userRows(func(u user) bool { return u.role == "owner" }) }},
		{Prefix: "SELECT user_id FROM org_member", Do: func([]any) dbtest.Step {
			return w.userRows(func(u user) bool { return u.role == "security_lead" })
		}},
		{Prefix: "SELECT s.created_by", Do: func([]any) dbtest.Step {
			return dbtest.Step{Rows: [][]any{{w.uid("dev"), "completed", projID, "WEB"}}}
		}},
		{Prefix: "SELECT u.email::text, u.is_active", Do: func(args []any) dbtest.Step {
			u, ok := w.users[args[1].(uuid.UUID)]
			if !ok {
				return dbtest.Step{}
			}
			role := u.role
			if role == "owner" || role == "developer" {
				role = "member"
			}
			return dbtest.Step{Rows: [][]any{{u.email, u.active, role, u.inProj}}}
		}},
		{Prefix: "SELECT email FROM notification_pref", Do: func(args []any) dbtest.Step {
			if v, ok := w.prefs[args[0].(uuid.UUID).String()+"|"+args[1].(string)]; ok {
				return dbtest.Step{Rows: [][]any{{v}}}
			}
			return dbtest.Step{}
		}},
		{Prefix: "INSERT INTO notification", Affected: 1},
		{Prefix: "UPDATE outbox_event SET dispatched_at", Affected: 1},
		{Prefix: "UPDATE notification SET email_next_at", Do: func([]any) dbtest.Step { return dbtest.Step{Rows: w.claim} }},
		{Prefix: "UPDATE notification SET email_state", Affected: 1},
		{Prefix: "UPDATE notification SET email_attempts", Affected: 1},
		{Prefix: "SELECT i.assignee_id, count(*)", Rows: [][]any{{uuid.New(), 2}, {uuid.New(), 0}}},
		{Prefix: "INSERT INTO outbox_event", Affected: 1},
	}
	w.db = dbtest.Loose(t, append(steps, extra...)...)
	w.d = &Dispatcher{
		Tx:     func(_ context.Context, _ uuid.UUID, fn func(DB) error) error { return fn(w.db) },
		Mailer: w.mailer, BaseURL: "https://warden.example", Now: func() time.Time { return now }, Log: quiet,
	}
	return w
}

func (w *world) userRows(keep func(user) bool) dbtest.Step {
	var rows [][]any
	for id, u := range w.users {
		if keep(u) {
			rows = append(rows, []any{id})
		}
	}
	return dbtest.Step{Rows: rows}
}

func (w *world) uid(name string) uuid.UUID {
	for id, u := range w.users {
		if strings.HasPrefix(u.email, name+"@") {
			return id
		}
	}
	return uuid.Nil
}

func (w *world) addUser(name, role string, active, inProj bool) uuid.UUID {
	id := uuid.New()
	w.users[id] = user{id: id, email: name + "@example.com", role: role, active: active, inProj: inProj}
	return id
}

func (w *world) addIssue(n int, title string, assignee *uuid.UUID, due *time.Time) uuid.UUID {
	id := uuid.New()
	var a any
	if assignee != nil {
		a = *assignee
	}
	var d any
	if due != nil {
		d = *due
	}
	w.issues[id] = []any{id, projID, "WEB", n, title, "high", "assigned", a, d}
	return id
}

func (w *world) event(id int64, typ string, p Payload) {
	w.events = append(w.events, []any{id, typ, payload(p)})
}

// inserted returns (user, type, title, email_state) of each notification insert.
func (w *world) inserted() [][4]any {
	var out [][4]any
	for _, c := range w.db.Calls("INSERT INTO notification") {
		out = append(out, [4]any{c.Args[2], c.Args[4], c.Args[5], c.Args[9]})
	}
	return out
}

func TestDispatchResolvesRecipients(t *testing.T) {
	w := newWorld(t)
	lead := w.addUser("lead", "security_lead", true, false)
	lead2 := w.addUser("lead2", "security_lead", true, false)
	dev := w.addUser("dev", "developer", true, true)
	owner := w.addUser("owner", "owner", true, true)
	gone := w.addUser("gone", "developer", false, true) // deactivated
	outsider := w.addUser("outsider", "member", true, false)
	assigned := w.addIssue(1, "<b>t</b>", &dev, nil)
	unassigned := w.addIssue(2, "t2", nil, nil)
	w.prefs[owner.String()+"|"+IssueReopened] = false

	w.event(1, IssueAssigned, Payload{IssueID: &assigned, UserID: &dev, ActorID: &lead})
	w.event(2, IssueAssigned, Payload{IssueID: &assigned, UserID: &lead, ActorID: &lead}) // self-assignment: nobody
	w.event(3, IssueReopened, Payload{IssueID: &unassigned})                              // → project owners
	w.event(4, IssueReopened, Payload{IssueID: &assigned})                                // → assignee
	w.event(5, ExceptionRequested, Payload{IssueID: &assigned, ActorID: &lead2})          // → leads but the requester
	w.event(6, ExceptionDecided, Payload{IssueID: &assigned, UserID: &dev, ActorID: &lead, Decision: "approve"})
	w.event(7, ExceptionDecided, Payload{IssueID: &assigned, UserID: &dev, ActorID: &lead, Decision: "reject"})
	w.event(8, ScanFinished, Payload{ScanID: ID(uuid.New())}) // → creator (dev); email off by default
	w.event(9, IssueAssigned, Payload{IssueID: &assigned, UserID: &gone})
	w.event(10, IssueAssigned, Payload{IssueID: &assigned, UserID: &outsider}) // can't see the project
	missing := uuid.New()
	w.event(11, IssueAssigned, Payload{IssueID: &missing, UserID: &dev})         // deleted issue
	w.event(12, IssueAssigned, Payload{UserID: &dev})                            // malformed: skipped
	w.events = append(w.events, []any{int64(13), "issue.assigned", []byte("{")}) // undecodable
	w.event(14, "issue.exploded", Payload{})

	if err := w.d.DispatchOrg(context.Background(), orgID); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, n := range w.inserted() {
		got[w.users[n[0].(uuid.UUID)].email+" "+n[1].(string)+" "+n[2].(string)+" "+n[3].(string)] = true
	}
	want := []string{
		"dev@example.com issue.assigned WEB-1 assigned to you pending",
		"owner@example.com issue.reopened WEB-2 reopened none",
		"dev@example.com issue.reopened WEB-1 reopened pending",
		"lead@example.com exception.requested Exception requested for WEB-1 pending",
		"dev@example.com exception.decided Exception for WEB-1 approved pending",
		"dev@example.com exception.decided Exception for WEB-1 rejected pending",
		"dev@example.com scan.finished Scan of WEB finished: completed none",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for _, k := range want {
		if !got[k] {
			t.Errorf("missing %q in %v", k, got)
		}
	}
	if n := len(w.db.Calls("UPDATE outbox_event SET dispatched_at")); n != 14 {
		t.Fatalf("dispatched %d of 14 (malformed rows must not block)", n)
	}
	// Notification payloads carry the allow-listed content only.
	for _, c := range w.db.Calls("INSERT INTO notification") {
		var content Content
		if err := json.Unmarshal(c.Args[8].([]byte), &content); err != nil || content.OrgName != "Acme" {
			t.Fatal(string(c.Args[8].([]byte)), err)
		}
	}
}

// component.malicious goes to the security leads and the project's owners
// (once each, even when a lead owns the project), email on by default.
func TestDispatchComponentMalicious(t *testing.T) {
	var w *world
	w = newWorld(t, dbtest.Step{Prefix: "SELECT user_id FROM org_member WHERE org_id = $1 AND role = 'security_lead' UNION",
		Do: func(args []any) dbtest.Step {
			if args[1] != projID {
				t.Errorf("project %v", args[1])
			}
			return w.userRows(func(u user) bool { return u.role == "security_lead" || u.role == "owner" })
		}})
	w.addUser("lead", "security_lead", true, false)
	owner := w.addUser("owner", "owner", true, true)
	w.addUser("dev", "developer", true, true)
	w.addUser("gone", "owner", false, true)
	w.prefs[owner.String()+"|"+ComponentMalicious] = false
	dev := w.uid("dev")
	iss := w.addIssue(3, "evil 1.0.0 is a malicious package (MAL-2026-1)", &dev, nil)
	w.event(1, ComponentMalicious, Payload{IssueID: &iss})
	w.event(2, ComponentMalicious, Payload{}) // malformed: skipped
	if err := w.d.DispatchOrg(context.Background(), orgID); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, n := range w.inserted() {
		got[w.users[n[0].(uuid.UUID)].email+" "+n[1].(string)+" "+n[2].(string)+" "+n[3].(string)] = true
	}
	want := map[string]bool{
		"lead@example.com component.malicious Malicious package found: WEB-3 pending": true,
		"owner@example.com component.malicious Malicious package found: WEB-3 none":   true,
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for k := range want {
		if !got[k] {
			t.Errorf("missing %q in %v", k, got)
		}
	}
	if !DefaultEmail(ComponentMalicious) {
		t.Fatal("component.malicious email must be on by default")
	}
}

func TestDispatchPropagatesDatabaseErrors(t *testing.T) {
	for _, prefix := range []string{
		"SELECT id, type, payload FROM outbox_event", "SELECT name FROM organization", "SELECT display_name FROM app_user",
		"SELECT i.id, p.id, p.key", "SELECT user_id FROM project_member", "SELECT u.email::text, u.is_active",
		"SELECT email FROM notification_pref", "INSERT INTO notification", "UPDATE outbox_event SET dispatched_at",
	} {
		w := newWorld(t, dbtest.Step{Prefix: prefix, Err: errDB})
		lead := w.addUser("lead", "security_lead", true, false)
		w.addUser("owner", "owner", true, true)
		iss := w.addIssue(1, "t", nil, nil)
		w.event(1, IssueReopened, Payload{IssueID: &iss, ActorID: &lead})
		if err := w.d.DispatchOrg(context.Background(), orgID); !errors.Is(err, errDB) {
			t.Errorf("%s: %v", prefix, err)
		}
	}
	for _, prefix := range []string{"SELECT user_id FROM org_member", "SELECT s.created_by"} {
		w := newWorld(t, dbtest.Step{Prefix: prefix, Err: errDB})
		iss := w.addIssue(1, "t", nil, nil)
		w.event(1, ExceptionRequested, Payload{IssueID: &iss})
		w.event(2, ScanFinished, Payload{ScanID: &iss})
		if err := w.d.DispatchOrg(context.Background(), orgID); !errors.Is(err, errDB) {
			t.Errorf("%s: %v", prefix, err)
		}
	}
}

func TestDigest(t *testing.T) {
	w := newWorld(t)
	dev := w.addUser("dev", "developer", true, true)
	gone := w.addUser("gone", "developer", true, false)
	past, soon := now.Add(-time.Hour), now.Add(time.Hour)
	for i := range 25 {
		w.addIssue(i+1, "t", &dev, &past)
	}
	w.addIssue(30, "soon", &dev, &soon)
	w.addIssue(31, "x", &gone, &soon)
	n, err := w.d.Digest(context.Background(), orgID)
	if err != nil || n != 2 {
		t.Fatal(n, err)
	}
	calls := w.db.Calls("INSERT INTO outbox_event")
	if len(calls) != 2 || calls[0].Args[1] != SLAOverdue || calls[1].Args[1] != SLADueSoon ||
		!strings.HasPrefix(*calls[0].Args[3].(*string), "sla:") || !strings.HasSuffix(*calls[0].Args[3].(*string), ":2026-10-26") {
		t.Fatalf("%+v", calls)
	}

	w.event(1, SLAOverdue, Payload{UserID: &dev, Date: "2026-10-26"})
	w.event(2, SLADueSoon, Payload{UserID: &gone, Date: "2026-10-26"}) // sees none of the projects
	w.event(3, SLADueSoon, Payload{})                                  // malformed
	if err := w.d.DispatchOrg(context.Background(), orgID); err != nil {
		t.Fatal(err)
	}
	ins := w.db.Calls("INSERT INTO notification")
	if len(ins) != 1 || ins[0].Args[5] != "25 issues overdue, 1 due soon" || !strings.HasSuffix(ins[0].Args[6].(string), "?assignee=me&past_sla=true") {
		t.Fatalf("%+v", ins)
	}
	var c Content
	_ = json.Unmarshal(ins[0].Args[8].([]byte), &c)
	if len(c.Items) != digestItems || c.Overdue != 25 || c.DueSoon != 1 {
		t.Fatalf("%+v", c)
	}
	for _, x := range []struct {
		o, s int
		want string
	}{{1, 0, "1 issue overdue"}, {0, 2, "2 issues due soon"}} {
		if got := digestTitle(x.o, x.s); got != x.want {
			t.Error(got)
		}
	}

	bad := newWorld(t, dbtest.Step{Prefix: "SELECT i.assignee_id, count(*)", Err: errDB})
	if _, err := bad.d.Digest(context.Background(), orgID); !errors.Is(err, errDB) {
		t.Fatal(err)
	}
	bad = newWorld(t, dbtest.Step{Prefix: "INSERT INTO outbox_event", Err: errDB})
	if _, err := bad.d.Digest(context.Background(), orgID); !errors.Is(err, errDB) {
		t.Fatal(err)
	}
}

func claimRow(id, user uuid.UUID, c Content, attempts int) []any {
	raw, _ := json.Marshal(c)
	return []any{id, user, raw, attempts}
}

func TestSendEmails(t *testing.T) {
	w := newWorld(t)
	dev := w.addUser("dev", "developer", true, true)
	bounce := w.addUser("bounce", "developer", true, true)
	left := w.addUser("left", "developer", true, false)
	c := contentFor(IssueAssigned)
	c.ProjectID = projID.String()
	sent, failing, skipped, broken, last := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	w.claim = [][]any{
		claimRow(sent, dev, c, 0),
		claimRow(failing, bounce, c, 0),
		claimRow(skipped, left, c, 0), // no longer in the project
		{broken, dev, []byte("{"), 0},
		claimRow(last, bounce, c, MaxEmailAttempts-1),
	}
	w.mailer.fail["bounce@example.com"] = errors.New("550 no such user")
	if err := w.d.DispatchOrg(context.Background(), orgID); err != nil {
		t.Fatal(err)
	}
	if len(w.mailer.sent) != 1 || w.mailer.sent[0].To != "dev@example.com" || !strings.Contains(w.mailer.sent[0].Text, "https://warden.example/orgs/o/issues/i") {
		t.Fatalf("%+v", w.mailer.sent)
	}
	states := map[uuid.UUID]string{}
	for _, call := range w.db.Calls("UPDATE notification SET email_state") {
		switch {
		case strings.Contains(call.SQL, "'sent'"):
			states[call.Args[0].(uuid.UUID)] = "sent"
		case strings.Contains(call.SQL, "'none'"):
			states[call.Args[0].(uuid.UUID)] = "none"
		case strings.Contains(call.SQL, "'failed'"):
			states[call.Args[0].(uuid.UUID)] = "failed"
		}
	}
	for _, call := range w.db.Calls("UPDATE notification SET email_attempts") {
		id := call.Args[0].(uuid.UUID)
		states[id] = call.Args[3].(string)
		if next := call.Args[2].(time.Time); id == failing && !next.Equal(now.Add(time.Minute)) {
			t.Fatal(next)
		}
	}
	if states[sent] != "sent" || states[failing] != "pending" || states[skipped] != "none" || states[broken] != "failed" || states[last] != "failed" {
		t.Fatalf("%v", states)
	}

	// An unreachable server stops this run; the rest keep their lease.
	w2 := newWorld(t)
	a, b := w2.addUser("a", "developer", true, true), w2.addUser("b", "developer", true, true)
	w2.claim = [][]any{claimRow(uuid.New(), a, c, 0), claimRow(uuid.New(), b, c, 0)}
	w2.mailer.fail["a@example.com"] = &ConnError{Err: errors.New("connection refused")}
	if err := w2.d.DispatchOrg(context.Background(), orgID); err != nil {
		t.Fatal(err)
	}
	if len(w2.mailer.sent) != 0 || len(w2.db.Calls("UPDATE notification SET email_attempts")) != 1 {
		t.Fatal("kept sending to an unreachable server")
	}

	// No mailer: notifications only.
	w3 := newWorld(t)
	w3.d.Mailer = nil
	if err := w3.d.DispatchOrg(context.Background(), orgID); err != nil || len(w3.db.Calls("UPDATE notification SET email_next_at")) != 0 {
		t.Fatal(err)
	}

	for _, prefix := range []string{"UPDATE notification SET email_next_at", "SELECT u.email::text, u.is_active",
		"UPDATE notification SET email_state", "UPDATE notification SET email_attempts"} {
		w := newWorld(t, dbtest.Step{Prefix: prefix, Err: errDB})
		u := w.addUser("u", "developer", true, true)
		lost := w.addUser("lost", "developer", true, false)
		w.mailer.fail["u@example.com"] = errors.New("452 try later")
		w.claim = [][]any{claimRow(uuid.New(), lost, c, 0), claimRow(uuid.New(), u, c, 0), {uuid.New(), u, []byte("{"), 0}}
		if err := w.d.DispatchOrg(context.Background(), orgID); !errors.Is(err, errDB) {
			t.Errorf("%s: %v", prefix, err)
		}
	}
}
