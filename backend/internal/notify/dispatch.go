package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aupv9/warden/backend/internal/ids"
)

// TxFunc runs fn in one transaction with app.org_id set to org (db.WithOrg).
type TxFunc func(ctx context.Context, org uuid.UUID, fn func(DB) error) error

// Dispatcher turns one org's outbox into notifications and sends their email.
type Dispatcher struct {
	Tx TxFunc
	// Mailer sends email; nil disables email (notifications are still written).
	Mailer Sender
	// BaseURL is the validated smtp.public_base_url.
	BaseURL string
	Now     func() time.Time
	Log     *slog.Logger
}

const (
	outboxBatch = 100
	maxBatches  = 20 // per run; the next run continues
	emailBatch  = 50
	// emailLease: a claimed email is retried after this if its sender died.
	emailLease = 10 * time.Minute
	// MaxEmailAttempts: after this many failed deliveries an email is given up.
	MaxEmailAttempts = 8
	// DueSoonWindow: issues due within this are "due soon" in the digest.
	DueSoonWindow = 72 * time.Hour
	digestScan    = 200
	digestItems   = 20
)

// activeSQL mirrors issuestate.Active.
const activeSQL = `('open','assigned','in_progress','reopened')`

type note struct {
	user    uuid.UUID
	project uuid.UUID // the object's project; Nil for org-level (digests)
	content Content
}

type outboxRow struct {
	ID      int64
	Type    string
	Payload []byte
}

// DispatchOrg processes the org's undispatched outbox rows, then its due emails.
func (d *Dispatcher) DispatchOrg(ctx context.Context, org uuid.UUID) error {
	for range maxBatches {
		n, err := d.dispatchBatch(ctx, org)
		if err != nil {
			return err
		}
		if n < outboxBatch {
			break
		}
	}
	if d.Mailer == nil {
		return nil
	}
	return d.sendEmails(ctx, org)
}

// dispatchBatch handles up to outboxBatch events in one transaction. Rows are
// taken FOR UPDATE SKIP LOCKED, so concurrent dispatchers split the work; the
// notification insert is idempotent per (event, user) and dispatched_at is
// set in the same transaction, so a retry never duplicates.
func (d *Dispatcher) dispatchBatch(ctx context.Context, org uuid.UUID) (int, error) {
	var n int
	err := d.Tx(ctx, org, func(db DB) error {
		rows, err := db.Query(ctx, `SELECT id, type, payload FROM outbox_event WHERE dispatched_at IS NULL
			ORDER BY id LIMIT $1 FOR UPDATE SKIP LOCKED`, outboxBatch)
		if err != nil {
			return err
		}
		events, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (outboxRow, error) {
			var e outboxRow
			return e, r.Scan(&e.ID, &e.Type, &e.Payload)
		})
		if err != nil {
			return err
		}
		n = len(events)
		r := &resolver{d: d, db: db, org: org, now: d.Now().UTC(), access: map[[2]uuid.UUID]bool{}}
		for _, ev := range events {
			notes, err := r.resolve(ctx, ev)
			var bad *badEvent
			if errors.As(err, &bad) {
				// A malformed row must not block the queue; it is marked dispatched.
				d.Log.Error("skipping malformed outbox event", "org_id", org, "event_id", ev.ID, "type", ev.Type, "err", err)
				notes, err = nil, nil
			}
			if err != nil {
				return fmt.Errorf("outbox event %d: %w", ev.ID, err)
			}
			for _, nt := range notes {
				if err := r.insert(ctx, ev, nt); err != nil {
					return err
				}
			}
			if _, err := db.Exec(ctx, `UPDATE outbox_event SET dispatched_at = $2 WHERE id = $1`, ev.ID, r.now); err != nil {
				return err
			}
		}
		return nil
	})
	return n, err
}

type badEvent struct{ err error }

func (b *badEvent) Error() string { return b.err.Error() }

type resolver struct {
	d       *Dispatcher
	db      DB
	org     uuid.UUID
	now     time.Time
	orgName *string
	access  map[[2]uuid.UUID]bool // (user, project) → may see
}

func (r *resolver) name(ctx context.Context) (string, error) {
	if r.orgName == nil {
		var n string
		if err := r.db.QueryRow(ctx, `SELECT name FROM organization WHERE id = $1`, r.org).Scan(&n); err != nil {
			return "", err
		}
		r.orgName = &n
	}
	return *r.orgName, nil
}

func (r *resolver) actorName(ctx context.Context, id *uuid.UUID) (string, error) {
	if id == nil {
		return "", nil
	}
	var n string
	err := r.db.QueryRow(ctx, `SELECT display_name FROM app_user WHERE id = $1`, *id).Scan(&n)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return n, err
}

// issueFacts is the allow-list of issue columns a notification may show.
type issueFacts struct {
	ID         uuid.UUID
	ProjectID  uuid.UUID
	ProjectKey string
	Number     int
	Title      string
	Severity   string
	Status     string
	AssigneeID *uuid.UUID
	DueAt      *time.Time
}

func (f issueFacts) key() string { return f.ProjectKey + "-" + strconv.Itoa(f.Number) }

const issueFactsSQL = `SELECT i.id, p.id, p.key, i.number, i.title, i.severity::text, i.status::text, i.assignee_id, i.due_at
	FROM issue i JOIN project p ON p.id = i.project_id`

func scanFacts(row pgx.Row) (issueFacts, error) {
	var f issueFacts
	err := row.Scan(&f.ID, &f.ProjectID, &f.ProjectKey, &f.Number, &f.Title, &f.Severity, &f.Status, &f.AssigneeID, &f.DueAt)
	return f, err
}

func (r *resolver) userIDs(ctx context.Context, sql string, args ...any) ([]uuid.UUID, error) {
	rows, err := r.db.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

func without(users []uuid.UUID, actor *uuid.UUID) []uuid.UUID {
	var out []uuid.UUID
	for _, u := range users {
		if actor == nil || u != *actor {
			out = append(out, u)
		}
	}
	return out
}

func one(id *uuid.UUID) []uuid.UUID {
	if id == nil {
		return nil
	}
	return []uuid.UUID{*id}
}

func need(id *uuid.UUID, field string) error {
	if id == nil {
		return &badEvent{fmt.Errorf("payload has no %s", field)}
	}
	return nil
}

// resolve returns the event's notifications for recipients who are, right
// now, active members of the org and can see the object.
func (r *resolver) resolve(ctx context.Context, ev outboxRow) ([]note, error) {
	var p Payload
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		return nil, &badEvent{err}
	}
	orgName, err := r.name(ctx)
	if err != nil {
		return nil, err
	}
	actor, err := r.actorName(ctx, p.ActorID)
	if err != nil {
		return nil, err
	}
	var (
		users   []uuid.UUID
		project uuid.UUID
		c       = Content{Type: ev.Type, OrgName: orgName, ActorName: actor}
	)
	switch ev.Type {
	case IssueAssigned, IssueReopened, ExceptionRequested, ExceptionDecided:
		if err := need(p.IssueID, "issue_id"); err != nil {
			return nil, err
		}
		f, err := scanFacts(r.db.QueryRow(ctx, issueFactsSQL+` WHERE i.id = $1`, *p.IssueID))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil // deleted, or not in this org
		}
		if err != nil {
			return nil, err
		}
		project = f.ProjectID
		c.ProjectID, c.ProjectKey, c.IssueKey, c.IssueTitle = f.ProjectID.String(), f.ProjectKey, f.key(), f.Title
		c.Severity, c.Status = f.Severity, f.Status
		c.Link = "/orgs/" + r.org.String() + "/issues/" + f.ID.String()
		switch ev.Type {
		case IssueAssigned:
			c.Title = f.key() + " assigned to you"
			users = without(one(p.UserID), p.ActorID)
		case IssueReopened:
			c.Title = f.key() + " reopened"
			if f.AssigneeID != nil {
				users = one(f.AssigneeID)
			} else if users, err = r.userIDs(ctx, `SELECT user_id FROM project_member WHERE project_id = $1 AND role = 'owner'
				ORDER BY user_id`, f.ProjectID); err != nil {
				return nil, err
			}
		case ExceptionRequested:
			c.Title = "Exception requested for " + f.key()
			if users, err = r.userIDs(ctx, `SELECT user_id FROM org_member WHERE org_id = $1 AND role = 'security_lead'
				ORDER BY user_id`, r.org); err != nil {
				return nil, err
			}
			users = without(users, p.ActorID)
		case ExceptionDecided:
			c.Decision = "rejected"
			if p.Decision == "approve" {
				c.Decision = "approved"
			}
			c.Title = "Exception for " + f.key() + " " + c.Decision
			users = without(one(p.UserID), p.ActorID)
		}
	case ScanFinished:
		if err := need(p.ScanID, "scan_id"); err != nil {
			return nil, err
		}
		var by uuid.UUID
		err := r.db.QueryRow(ctx, `SELECT s.created_by, s.status::text, p.id, p.key FROM scan s JOIN project p ON p.id = s.project_id
			WHERE s.id = $1`, *p.ScanID).Scan(&by, &c.Status, &project, &c.ProjectKey)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		c.ProjectID = project.String()
		c.Title = "Scan of " + c.ProjectKey + " finished: " + c.Status
		c.Link = "/orgs/" + r.org.String() + "/projects/" + project.String() + "/scans"
		users = []uuid.UUID{by}
	case SLADueSoon, SLAOverdue:
		if err := need(p.UserID, "user_id"); err != nil {
			return nil, err
		}
		return r.digest(ctx, ev.Type, *p.UserID, c)
	default:
		return nil, &badEvent{fmt.Errorf("unknown type %q", ev.Type)}
	}
	var out []note
	for _, u := range users {
		ok, err := r.canSee(ctx, u, project)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, note{user: u, project: project, content: c})
		}
	}
	return out, nil
}

// digest lists the user's active issues that are overdue or due soon, in
// projects they can still see.
func (r *resolver) digest(ctx context.Context, typ string, user uuid.UUID, c Content) ([]note, error) {
	if ok, err := r.canSee(ctx, user, uuid.Nil); err != nil || !ok {
		return nil, err
	}
	rows, err := r.db.Query(ctx, issueFactsSQL+` WHERE i.assignee_id = $1 AND i.status IN `+activeSQL+`
		AND i.due_at < $2 AND p.archived_at IS NULL ORDER BY i.due_at, i.id LIMIT $3`, user, r.now.Add(DueSoonWindow), digestScan)
	if err != nil {
		return nil, err
	}
	facts, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (issueFacts, error) { return scanFacts(row) })
	if err != nil {
		return nil, err
	}
	for _, f := range facts {
		ok, err := r.canSee(ctx, user, f.ProjectID)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		overdue := f.DueAt != nil && f.DueAt.Before(r.now)
		if overdue {
			c.Overdue++
		} else {
			c.DueSoon++
		}
		if len(c.Items) < digestItems {
			it := Item{ProjectKey: f.ProjectKey, IssueKey: f.key(), Title: f.Title, Severity: f.Severity, Status: f.Status,
				Overdue: overdue, Link: "/orgs/" + r.org.String() + "/issues/" + f.ID.String()}
			if f.DueAt != nil {
				it.DueAt = f.DueAt.UTC().Format(time.RFC3339)
			}
			c.Items = append(c.Items, it)
		}
	}
	if c.Overdue+c.DueSoon == 0 {
		return nil, nil
	}
	c.Link = "/orgs/" + r.org.String() + "/issues?assignee=me"
	c.Title = digestTitle(c.Overdue, c.DueSoon)
	if c.Overdue > 0 {
		c.Link += "&past_sla=true"
	}
	c.Type = typ
	return []note{{user: user, content: c}}, nil
}

func digestTitle(overdue, dueSoon int) string {
	switch {
	case overdue > 0 && dueSoon > 0:
		return plural(overdue) + " overdue, " + strconv.Itoa(dueSoon) + " due soon"
	case overdue > 0:
		return plural(overdue) + " overdue"
	default:
		return plural(dueSoon) + " due soon"
	}
}

func plural(n int) string {
	if n == 1 {
		return "1 issue"
	}
	return strconv.Itoa(n) + " issues"
}

// canSee: the user is an active member of the org and, for a project object,
// a member of the project or an org admin / security lead.
func (r *resolver) canSee(ctx context.Context, user, project uuid.UUID) (bool, error) {
	k := [2]uuid.UUID{user, project}
	if v, ok := r.access[k]; ok {
		return v, nil
	}
	ok, _, err := recipient(ctx, r.db, r.org, user, project)
	if err != nil {
		return false, err
	}
	r.access[k] = ok
	return ok, nil
}

// recipient checks access as canSee does and returns the user's email address.
func recipient(ctx context.Context, db DB, org, user, project uuid.UUID) (bool, string, error) {
	var (
		email, role string
		active, pm  bool
	)
	err := db.QueryRow(ctx, `SELECT u.email::text, u.is_active, m.role::text,
			EXISTS (SELECT 1 FROM project_member pm WHERE pm.project_id = $3 AND pm.user_id = u.id)
		FROM org_member m JOIN app_user u ON u.id = m.user_id WHERE m.org_id = $1 AND m.user_id = $2`,
		org, user, project).Scan(&email, &active, &role, &pm)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}
	ok := active && (project == uuid.Nil || pm || role == "org_admin" || role == "security_lead")
	return ok, email, nil
}

func (r *resolver) insert(ctx context.Context, ev outboxRow, n note) error {
	email := DefaultEmail(n.content.Type)
	err := r.db.QueryRow(ctx, `SELECT email FROM notification_pref WHERE user_id = $1 AND type = $2`, n.user, n.content.Type).Scan(&email)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	state, next := "none", (*time.Time)(nil)
	if email {
		state, next = "pending", &r.now
	}
	payload, err := json.Marshal(n.content)
	if err != nil {
		return err
	}
	var actor *uuid.UUID
	var p Payload
	if json.Unmarshal(ev.Payload, &p) == nil {
		actor = p.ActorID
	}
	_, err = r.db.Exec(ctx, `INSERT INTO notification (id, org_id, user_id, event_id, type, title, link, actor_id, payload,
			email_state, email_next_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) ON CONFLICT (event_id, user_id) DO NOTHING`,
		ids.New(), r.org, n.user, ev.ID, n.content.Type, n.content.Title, n.content.Link, actor, payload, state, next, r.now)
	return err
}

type queuedEmail struct {
	ID       uuid.UUID
	User     uuid.UUID
	Payload  []byte
	Attempts int
	to       string
	content  Content
}

// sendEmails delivers the org's due emails. Rows are claimed with a lease in
// a short transaction (SKIP LOCKED), sent outside any transaction, and each
// result is recorded on its own, so one failing address never holds up the
// others and a crash can at worst resend after the lease.
func (d *Dispatcher) sendEmails(ctx context.Context, org uuid.UUID) error {
	var batch []queuedEmail
	now := d.Now().UTC()
	err := d.Tx(ctx, org, func(db DB) error {
		rows, err := db.Query(ctx, `UPDATE notification SET email_next_at = $2 WHERE id IN (
				SELECT id FROM notification WHERE email_state = 'pending' AND email_next_at <= $1
				ORDER BY email_next_at, id LIMIT $3 FOR UPDATE SKIP LOCKED)
			RETURNING id, user_id, payload, email_attempts`, now, now.Add(emailLease), emailBatch)
		if err != nil {
			return err
		}
		claimed, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (queuedEmail, error) {
			var q queuedEmail
			return q, r.Scan(&q.ID, &q.User, &q.Payload, &q.Attempts)
		})
		if err != nil {
			return err
		}
		for _, q := range claimed {
			if err := json.Unmarshal(q.Payload, &q.content); err != nil {
				d.Log.Error("undecodable notification payload", "notification_id", q.ID, "err", err)
				if _, err := db.Exec(ctx, `UPDATE notification SET email_state = 'failed' WHERE id = $1`, q.ID); err != nil {
					return err
				}
				continue
			}
			project, _ := uuid.Parse(q.content.ProjectID)
			// Memberships may have changed since the notification was written.
			ok, to, err := recipient(ctx, db, org, q.User, project)
			if err != nil {
				return err
			}
			if !ok {
				if _, err := db.Exec(ctx, `UPDATE notification SET email_state = 'none' WHERE id = $1`, q.ID); err != nil {
					return err
				}
				continue
			}
			q.to = to
			batch = append(batch, q)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for i, q := range batch {
		err := d.sendOne(ctx, org, q)
		var ce *ConnError
		if errors.As(err, &ce) {
			// The server is unreachable: the rest keep their lease and are
			// retried on a later run instead of each waiting for a timeout.
			d.Log.Warn("smtp server unreachable; postponing emails", "org_id", org, "postponed", len(batch)-i-1, "err", err)
			return nil
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// Backoff is the wait before retry n (1-based): 1m, 2m, 4m … capped at 1h.
func Backoff(n int) time.Duration {
	if n < 1 {
		n = 1
	}
	if n > 7 {
		return time.Hour
	}
	return min(time.Minute<<(n-1), time.Hour)
}

func (d *Dispatcher) sendOne(ctx context.Context, org uuid.UUID, q queuedEmail) error {
	m, err := Render(q.content, q.to, d.BaseURL)
	if err == nil {
		err = d.Mailer.Send(ctx, m)
	}
	now := d.Now().UTC()
	txErr := d.Tx(ctx, org, func(db DB) error {
		if err == nil {
			_, e := db.Exec(ctx, `UPDATE notification SET email_state = 'sent', emailed_at = $2 WHERE id = $1`, q.ID, now)
			return e
		}
		// Never log the address; the notification id identifies it.
		d.Log.Warn("email delivery failed", "org_id", org, "notification_id", q.ID, "attempt", q.Attempts+1, "err", err)
		attempts, state := q.Attempts+1, "pending"
		if attempts >= MaxEmailAttempts || errors.Is(err, ErrHeaderInjection) {
			state = "failed"
		}
		_, e := db.Exec(ctx, `UPDATE notification SET email_attempts = $2, email_next_at = $3, email_state = $4 WHERE id = $1`,
			q.ID, attempts, now.Add(Backoff(attempts)), state)
		return e
	})
	if txErr != nil {
		return txErr
	}
	var ce *ConnError
	if errors.As(err, &ce) {
		return err
	}
	return nil
}

// Digest writes the day's SLA digest events: one per assignee with active
// issues overdue or due within DueSoonWindow. The dedupe key makes a rerun on
// the same UTC day a no-op.
func (d *Dispatcher) Digest(ctx context.Context, org uuid.UUID) (int, error) {
	now := d.Now().UTC()
	date := now.Format(time.DateOnly)
	n := 0
	err := d.Tx(ctx, org, func(db DB) error {
		rows, err := db.Query(ctx, `SELECT i.assignee_id, count(*) FILTER (WHERE i.due_at < $1)
			FROM issue i JOIN project p ON p.id = i.project_id
			WHERE i.status IN `+activeSQL+` AND i.assignee_id IS NOT NULL AND i.due_at < $2 AND p.archived_at IS NULL
			GROUP BY i.assignee_id ORDER BY i.assignee_id`, now, now.Add(DueSoonWindow))
		if err != nil {
			return err
		}
		type due struct {
			user    uuid.UUID
			overdue int
		}
		list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (due, error) {
			var x due
			return x, r.Scan(&x.user, &x.overdue)
		})
		if err != nil {
			return err
		}
		for _, x := range list {
			typ := SLADueSoon
			if x.overdue > 0 {
				typ = SLAOverdue
			}
			if err := Insert(ctx, db, Event{OrgID: org, Type: typ, Payload: Payload{UserID: ID(x.user), Date: date},
				DedupeKey: "sla:" + x.user.String() + ":" + date}); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}
