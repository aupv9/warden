package webhook

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/notify"
)

// Event is the body of a generic webhook (OpenAPI WebhookEvent). Every field
// comes from notify.Facts; nothing else may be added here.
type Event struct {
	ID        uuid.UUID       `json:"id"` // the delivery id, also the webhook-id header
	Type      string          `json:"type"`
	Timestamp string          `json:"timestamp"`
	Org       EventOrg        `json:"org"`
	Project   *EventProject   `json:"project"`
	Scan      *EventScan      `json:"scan"`
	Issue     *EventIssue     `json:"issue"`
	Exception *EventException `json:"exception"`
	Actor     *EventActor     `json:"actor"`
}

type EventOrg struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

type EventProject struct {
	ID   uuid.UUID `json:"id"`
	Key  string    `json:"key"`
	Name string    `json:"name"`
}

type EventStats struct {
	New      int `json:"new"`
	Fixed    int `json:"fixed"`
	Reopened int `json:"reopened"`
	Total    int `json:"total"`
}

type EventScan struct {
	ID     uuid.UUID  `json:"id"`
	Kind   string     `json:"kind"`
	Target string     `json:"target"`
	Status string     `json:"status"`
	Stats  EventStats `json:"stats"`
	URL    string     `json:"url"`
}

type EventIssue struct {
	ID       uuid.UUID `json:"id"`
	Key      string    `json:"key"`
	Title    string    `json:"title"`
	Severity string    `json:"severity"`
	Status   string    `json:"status"`
	Tool     string    `json:"tool"`
	RuleID   string    `json:"rule_id"`
	Target   string    `json:"target"`
	URL      string    `json:"url"`
}

type EventException struct {
	ID       uuid.UUID `json:"id"`
	Type     string    `json:"type"`
	Decision *string   `json:"decision"`
	URL      string    `json:"url"`
}

type EventActor struct {
	DisplayName string `json:"display_name"`
}

// NewEvent builds the generic body for delivery id. base is the validated
// smtp.public_base_url that links start with.
func NewEvent(id uuid.UUID, typ string, f notify.Facts, base string) Event {
	org := f.OrgID.String()
	ev := Event{ID: id, Type: typ, Timestamp: f.At.UTC().Format(time.RFC3339), Org: EventOrg{ID: f.OrgID, Name: f.OrgName}}
	if p := f.Project; p != nil {
		ev.Project = &EventProject{ID: p.ID, Key: p.Key, Name: p.Name}
	}
	if s := f.Scan; s != nil && f.Project != nil {
		ev.Scan = &EventScan{ID: s.ID, Kind: s.Kind, Target: s.Target, Status: s.Status,
			Stats: EventStats{New: s.New, Fixed: s.Fixed, Reopened: s.Reopened, Total: s.Total},
			URL:   base + "/orgs/" + org + "/projects/" + f.Project.ID.String() + "/scans"}
	}
	if i := f.Issue; i != nil {
		ev.Issue = &EventIssue{ID: i.ID, Key: i.Key, Title: i.Title, Severity: i.Severity, Status: i.Status, Tool: i.Tool,
			RuleID: i.RuleID, Target: i.Target, URL: base + "/orgs/" + org + "/issues/" + i.ID.String()}
	}
	if e := f.Exception; e != nil {
		ev.Exception = &EventException{ID: e.ID, Type: e.Type, URL: base + "/orgs/" + org + "/exceptions"}
		if e.Decision != "" {
			d := e.Decision
			ev.Exception.Decision = &d
		}
	}
	if f.Actor != "" {
		ev.Actor = &EventActor{DisplayName: f.Actor}
	}
	return ev
}

// TestFacts are the facts of a webhook.test delivery: the org only.
func TestFacts(org uuid.UUID, name string, at time.Time) notify.Facts {
	return notify.Facts{At: at, OrgID: org, OrgName: name}
}

// MaxBody is the largest body stored (webhook_delivery.payload's CHECK).
const MaxBody = 60 << 10

// maxSlackTitle bounds an issue title in a Slack message.
const maxSlackTitle = 300

// Body returns what a webhook of kind receives for the event, as JSON.
func Body(kind string, ev Event) ([]byte, error) {
	if kind == KindSlack {
		return json.Marshal(slackMessage(ev))
	}
	return json.Marshal(ev)
}

// SlackMessage is an Incoming Webhook message. Only text is set: no
// link_names or parse (so "@channel" in a title stays text), and no unfurling.
type SlackMessage struct {
	Text        string `json:"text"`
	UnfurlLinks bool   `json:"unfurl_links"`
	UnfurlMedia bool   `json:"unfurl_media"`
}

// slackEscaper escapes Slack's control characters. Titles, rule ids, names and
// org names come from scanned code or users; escaped, "<!channel>",
// "<@U123>" or "<https://evil|click>" in them are shown as text, never as a
// mention or a link.
var slackEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

func esc(s string) string { return slackEscaper.Replace(cleanLine(s)) }

// slackLink is a link Warden built; it is dropped if it could break out of
// the <url|text> syntax.
func slackLink(url, text string) string {
	if url == "" || strings.ContainsAny(url, "<>| \t\r\n") {
		return ""
	}
	return "<" + slackEscaper.Replace(url) + "|" + text + ">"
}

func truncateRunes(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

func slackMessage(ev Event) SlackMessage {
	var lines []string
	head := "[" + esc(ev.Org.Name) + "] "
	by := ""
	if ev.Actor != nil {
		by = " by " + esc(ev.Actor.DisplayName)
	}
	link := ""
	switch ev.Type {
	case notify.WebhookTest:
		lines = append(lines, head+"*Test message from Warden*", "This webhook is set up.")
	case notify.ScanFinished:
		if s, p := ev.Scan, ev.Project; s != nil && p != nil {
			what := esc(p.Key)
			if s.Target != "" {
				what += " (" + esc(s.Target) + ")"
			}
			lines = append(lines, head+"*Scan of "+what+" finished: "+esc(s.Status)+"*",
				strconv.Itoa(s.Stats.New)+" new · "+strconv.Itoa(s.Stats.Reopened)+" reopened · "+
					strconv.Itoa(s.Stats.Fixed)+" fixed · "+strconv.Itoa(s.Stats.Total)+" found")
			link = slackLink(s.URL, "Open in Warden")
		}
	default:
		if i := ev.Issue; i != nil {
			key := esc(i.Key)
			var title string
			switch ev.Type {
			case notify.IssueAssigned:
				title = key + " assigned" + by
			case notify.IssueReopened:
				title = key + " reopened"
			case notify.ExceptionRequested:
				title = "Exception requested for " + key + by
			case notify.ExceptionDecided:
				verb := "decided"
				if e := ev.Exception; e != nil && e.Decision != nil {
					verb = map[string]string{"approve": "approved", "reject": "rejected"}[*e.Decision]
				}
				title = "Exception for " + key + " " + verb + by
			case notify.ComponentMalicious:
				title = "Malicious package found: " + key
			default:
				title = key
			}
			detail := "*" + esc(strings.ToUpper(i.Severity[:min(1, len(i.Severity))])+i.Severity[min(1, len(i.Severity)):]) + "* · " +
				esc(truncateRunes(i.Title, maxSlackTitle)) + " · " + esc(i.Tool) + " " + esc(i.RuleID) + " · " + esc(i.Status)
			if i.Target != "" {
				detail += " · " + esc(i.Target)
			}
			lines = append(lines, head+"*"+title+"*", detail)
			link = slackLink(i.URL, "Open in Warden")
		}
	}
	if link != "" {
		lines = append(lines, link)
	}
	return SlackMessage{Text: strings.Join(lines, "\n")}
}
