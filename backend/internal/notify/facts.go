package notify

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Facts is what a webhook may say about an outbox event. It follows the rule in
// the package comment: a fixed list of columns, the same ones an email shows
// (org, project key, issue key, title, severity, status, actor's display name),
// plus the ids, names, tool, rule, target, scan counts and exception type a
// receiver needs to act. Snippets, descriptions, file paths and contents,
// comment bodies, email addresses and secrets are never selected.
type Facts struct {
	At        time.Time // when the event happened (outbox_event.created_at)
	OrgID     uuid.UUID
	OrgName   string
	Project   *ProjectFacts
	Scan      *ScanFacts
	Issue     *IssueFacts
	Exception *ExceptionFacts
	Actor     string // display name; "" for Warden itself
}

type ProjectFacts struct {
	ID   uuid.UUID
	Key  string
	Name string
}

type ScanFacts struct {
	ID       uuid.UUID
	Kind     string
	Target   string
	Status   string
	New      int
	Fixed    int
	Reopened int
	Total    int
}

type IssueFacts struct {
	ID       uuid.UUID
	Key      string
	Title    string
	Severity string
	Status   string
	Tool     string
	RuleID   string
	Target   string
}

type ExceptionFacts struct {
	ID       uuid.UUID
	Type     string
	Decision string // approve or reject; "" while pending
}

// ErrMalformed: the outbox payload lacks what its type needs.
var ErrMalformed = errors.New("notify: malformed outbox event")

// LoadFacts loads an outbox event's facts. ok is false when the object it is
// about no longer exists (or isn't in this org).
func LoadFacts(ctx context.Context, db DB, org uuid.UUID, eventID int64, typ string, raw []byte) (Facts, bool, error) {
	var p Payload
	if err := json.Unmarshal(raw, &p); err != nil {
		return Facts{}, false, ErrMalformed
	}
	f := Facts{OrgID: org}
	if err := db.QueryRow(ctx, `SELECT e.created_at, o.name FROM outbox_event e JOIN organization o ON o.id = e.org_id
		WHERE e.id = $1`, eventID).Scan(&f.At, &f.OrgName); err != nil {
		return Facts{}, false, noRows(err)
	}
	if p.ActorID != nil {
		err := db.QueryRow(ctx, `SELECT display_name FROM app_user WHERE id = $1`, *p.ActorID).Scan(&f.Actor)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return Facts{}, false, err
		}
	}
	switch typ {
	case ScanFinished:
		if p.ScanID == nil {
			return Facts{}, false, ErrMalformed
		}
		var (
			s     ScanFacts
			pr    ProjectFacts
			stats []byte
		)
		err := db.QueryRow(ctx, `SELECT s.id, s.kind, s.target, s.status::text, s.stats, p.id, p.key, p.name
			FROM scan s JOIN project p ON p.id = s.project_id WHERE s.id = $1`, *p.ScanID).
			Scan(&s.ID, &s.Kind, &s.Target, &s.Status, &stats, &pr.ID, &pr.Key, &pr.Name)
		if err != nil {
			return Facts{}, false, noRows(err)
		}
		var st struct{ New, Fixed, Reopened, Total int }
		_ = json.Unmarshal(stats, &st) // {} before results: all zero
		s.New, s.Fixed, s.Reopened, s.Total = st.New, st.Fixed, st.Reopened, st.Total
		f.Scan, f.Project = &s, &pr
	case IssueAssigned, IssueReopened, ExceptionRequested, ExceptionDecided, ComponentMalicious:
		if p.IssueID == nil {
			return Facts{}, false, ErrMalformed
		}
		var (
			i      IssueFacts
			pr     ProjectFacts
			number int
		)
		err := db.QueryRow(ctx, `SELECT i.id, i.number, i.title, i.severity::text, i.status::text, i.tool, i.rule_id, i.target,
				p.id, p.key, p.name
			FROM issue i JOIN project p ON p.id = i.project_id WHERE i.id = $1`, *p.IssueID).
			Scan(&i.ID, &number, &i.Title, &i.Severity, &i.Status, &i.Tool, &i.RuleID, &i.Target, &pr.ID, &pr.Key, &pr.Name)
		if err != nil {
			return Facts{}, false, noRows(err)
		}
		i.Key = pr.Key + "-" + strconv.Itoa(number)
		f.Issue, f.Project = &i, &pr
		if typ == ExceptionRequested || typ == ExceptionDecided {
			if p.ExceptionID == nil {
				return Facts{}, false, ErrMalformed
			}
			e := ExceptionFacts{Decision: p.Decision}
			err := db.QueryRow(ctx, `SELECT id, type::text FROM exception_request WHERE id = $1`, *p.ExceptionID).Scan(&e.ID, &e.Type)
			if err != nil {
				return Facts{}, false, noRows(err)
			}
			if e.Decision != "approve" && e.Decision != "reject" {
				e.Decision = ""
			}
			f.Exception = &e
		}
	default:
		return Facts{}, false, ErrMalformed
	}
	return f, true, nil
}

// noRows turns "no such row" into (ok=false, err=nil) for LoadFacts' callers.
func noRows(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	return err
}
