//go:build integration

package worker

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/aupv9/warden/backend/internal/db"
	"github.com/aupv9/warden/backend/internal/notify"
)

type pruneTest struct {
	*itest
	webhook uuid.UUID
}

func newPruneTest(t *testing.T) *pruneTest {
	p := &pruneTest{itest: newITest(t), webhook: uuid.New()}
	p.env.NotifyRetention = notify.Retention{Read: 90 * 24 * time.Hour, Unread: 365 * 24 * time.Hour}
	owner(t, p.org, fmt.Sprintf(`INSERT INTO webhook (id, org_id, kind, name, url_hint, url_enc, key_id, events, created_by)
		VALUES ('%s', '%s', 'slack', 'h', 'https://hooks.example', '\x00', 'k1', '{issue.assigned}', '%s')`, p.webhook, p.org, p.user))
	return p
}

// event writes an outbox event aged days, dispatched or not, and returns its id.
func (p *pruneTest) event(days int, dispatched bool) int64 {
	p.t.Helper()
	var id int64
	err := db.WithOrg(context.Background(), ownerPool, p.org, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `INSERT INTO outbox_event (org_id, type, payload, created_at, dispatched_at)
			VALUES ($1, 'issue.assigned', '{}', now() - make_interval(days => $2),
				CASE WHEN $3 THEN now() - make_interval(days => $2) END) RETURNING id`, p.org, days, dispatched).Scan(&id)
	})
	if err != nil {
		p.t.Fatal(err)
	}
	return id
}

// note writes a notification for event aged days, read or not.
func (p *pruneTest) note(event int64, days int, read bool, email string) uuid.UUID {
	p.t.Helper()
	id := uuid.New()
	readAt := "NULL"
	if read {
		readAt = "now()"
	}
	owner(p.t, p.org, fmt.Sprintf(`INSERT INTO notification (id, org_id, user_id, event_id, type, payload, title, link, read_at, created_at, email_state, email_next_at)
		VALUES ('%s', '%s', '%s', %d, 'issue.assigned', '{}', 't', '/x', %s, now() - interval '%d days', '%s', %s)`,
		id, p.org, p.user, event, readAt, days, email, map[bool]string{true: "now()", false: "NULL"}[email == "pending"]))
	return id
}

func (p *pruneTest) delivery(event int64) {
	owner(p.t, p.org, fmt.Sprintf(`INSERT INTO webhook_delivery (id, org_id, webhook_id, event_id, type, payload, state, created_at)
		VALUES ('%s', '%s', '%s', %d, 'issue.assigned', '{}', 'delivered', now() - interval '100 days')`, uuid.New(), p.org, p.webhook, event))
}

// left returns which of the notifications and events still exist.
func (p *pruneTest) left(notes []uuid.UUID, events []int64) (n, e []bool) {
	p.t.Helper()
	for _, id := range notes {
		var ok bool
		p.one(fmt.Sprintf(`SELECT EXISTS (SELECT 1 FROM notification WHERE id = '%s')`, id), &ok)
		n = append(n, ok)
	}
	for _, id := range events {
		var ok bool
		p.one(fmt.Sprintf(`SELECT EXISTS (SELECT 1 FROM outbox_event WHERE id = %d)`, id), &ok)
		e = append(e, ok)
	}
	return n, e
}

// Old read and unread notifications go (each after its own retention), with
// the dispatched outbox events nothing refers to any more; recent rows, rows
// still in use and other orgs' rows stay.
func TestPruneNotifications(t *testing.T) {
	a, b := newPruneTest(t), newPruneTest(t)
	seed := func(p *pruneTest) ([]uuid.UUID, []int64) {
		e0, e1, e2, e3 := p.event(100, true), p.event(100, true), p.event(400, true), p.event(10, true)
		e4, e5, e6, e7 := p.event(400, false), p.event(100, true), p.event(100, true), p.event(100, true)
		notes := []uuid.UUID{
			p.note(e0, 100, true, "sent"),    // read, past 90 days: goes
			p.note(e1, 100, false, "none"),   // unread, under 365 days: stays
			p.note(e2, 400, false, "failed"), // unread, past 365 days: goes
			p.note(e3, 10, true, "none"),     // read, recent: stays
			p.note(e7, 100, true, "pending"), // its email is being sent: stays
		}
		p.delivery(e5) // a webhook delivery still refers to e5
		// e0, e2: freed with their notification; e4: never dispatched; e6: unreferenced.
		return notes, []int64{e0, e1, e2, e3, e4, e5, e6, e7}
	}
	notesA, eventsA := seed(a)
	notesB, eventsB := seed(b)
	wantN := []bool{false, true, false, true, true}
	wantE := []bool{false, true, false, true, true, true, false, true}

	// One org at a time: org B is untouched by org A's prune.
	notes, events, err := notify.PruneOrg(context.Background(), func(ctx context.Context, org uuid.UUID, fn func(notify.DB) error) error {
		return a.env.Tx(ctx, org, func(db DB) error { return fn(db) })
	}, a.org, time.Now(), a.env.NotifyRetention)
	if err != nil || notes != 2 || events != 3 {
		t.Fatal(notes, events, err)
	}
	if n, e := a.left(notesA, eventsA); fmt.Sprint(n, e) != fmt.Sprint(wantN, wantE) {
		t.Fatalf("org A: notifications %v, events %v", n, e)
	}
	if n, e := b.left(notesB, eventsB); fmt.Sprint(n, e) != fmt.Sprint([]bool{true, true, true, true, true}, []bool{true, true, true, true, true, true, true, true}) {
		t.Fatalf("org B touched: notifications %v, events %v", n, e)
	}

	// The job prunes every org; a second run finds nothing.
	if err := b.env.PruneNotifications(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n, e := b.left(notesB, eventsB); fmt.Sprint(n, e) != fmt.Sprint(wantN, wantE) {
		t.Fatalf("org B: notifications %v, events %v", n, e)
	}
	if notes, events, err := notify.PruneOrg(context.Background(), func(ctx context.Context, org uuid.UUID, fn func(notify.DB) error) error {
		return a.env.Tx(ctx, org, func(db DB) error { return fn(db) })
	}, a.org, time.Now(), a.env.NotifyRetention); err != nil || notes+events != 0 {
		t.Fatal(notes, events, err)
	}
}

// The app can prune only through the function, only in its org, and never
// anything written in the last day.
func TestPruneFunctionRefuses(t *testing.T) {
	p := newPruneTest(t)
	fresh := p.note(p.event(0, true), 0, true, "none")
	call := func(org uuid.UUID, read, unread time.Duration, limit int) error {
		return db.WithOrg(context.Background(), appPool, org, func(tx pgx.Tx) error {
			var n, e int64
			return tx.QueryRow(context.Background(), `SELECT notifications, events FROM warden_prune_notifications($1, $2, $3)`,
				time.Now().Add(-read), time.Now().Add(-unread), limit).Scan(&n, &e)
		})
	}
	code := func(err error) string {
		var pg *pgconn.PgError
		if errors.As(err, &pg) {
			return pg.Code
		}
		return fmt.Sprint(err)
	}
	const day = 24 * time.Hour
	for _, c := range []struct {
		name         string
		org          uuid.UUID
		read, unread time.Duration
		limit        int
		want         string
	}{
		{"no org scope", uuid.Nil, 90 * day, 365 * day, 100, "42501"},
		{"read cutoff an hour ago", p.org, time.Hour, 365 * day, 100, "22023"},
		{"unread cutoff now", p.org, 90 * day, 0, 100, "22023"},
		{"cutoff in the future", p.org, -day, -day, 100, "22023"},
		{"no limit", p.org, 90 * day, 365 * day, 0, "22023"},
		{"limit too large", p.org, 90 * day, 365 * day, 1_000_000, "22023"},
	} {
		if got := code(call(c.org, c.read, c.unread, c.limit)); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
	// A day and a bit is the shortest retention; the fresh row survives it.
	if err := call(p.org, 25*time.Hour, 25*time.Hour, 100); err != nil {
		t.Fatal(err)
	}
	if n, _ := p.left([]uuid.UUID{fresh}, nil); !n[0] {
		t.Fatal("fresh notification deleted")
	}
	// Plain DELETE stays forbidden to the app.
	for _, table := range []string{"notification", "outbox_event"} {
		err := db.WithOrg(context.Background(), appPool, p.org, func(tx pgx.Tx) error {
			_, err := tx.Exec(context.Background(), "DELETE FROM "+table)
			return err
		})
		if code(err) != "42501" {
			t.Errorf("app deleted from %s: %v", table, err)
		}
	}
}
