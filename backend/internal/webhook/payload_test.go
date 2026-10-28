package webhook

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/notify"
)

// What scanned code or users control: titles, rule ids, targets, names. Built
// to try every Slack escape: mentions, broadcasts, disguised links, layout.
const hostile = "<!channel> <@U024BE7LH> <!subteam^S1|team> <https://evil.example|Open in Warden> &lt;!here&gt; @channel\n*fake* line x"

func facts() notify.Facts {
	return notify.Facts{
		At: time.Date(2026, 10, 29, 8, 0, 0, 0, time.UTC), OrgID: uuid.MustParse("00000000-0000-7000-8000-00000000000a"),
		OrgName: "Acme " + hostile,
		Project: &notify.ProjectFacts{ID: uuid.MustParse("00000000-0000-7000-8000-00000000000b"), Key: "WEB", Name: "Web " + hostile},
		Issue: &notify.IssueFacts{ID: uuid.MustParse("00000000-0000-7000-8000-00000000000c"), Key: "WEB-41", Title: hostile,
			Severity: "critical", Status: "open", Tool: "opengrep", RuleID: "rule." + hostile, Target: "ghcr.io/acme/api"},
		Exception: &notify.ExceptionFacts{ID: uuid.MustParse("00000000-0000-7000-8000-00000000000d"), Type: "false_positive", Decision: "approve"},
		Scan: &notify.ScanFacts{ID: uuid.MustParse("00000000-0000-7000-8000-00000000000e"), Kind: "image", Target: "ghcr.io/acme/" + hostile,
			Status: "completed", New: 3, Fixed: 1, Reopened: 2, Total: 9},
		Actor: "Mallory " + hostile,
	}
}

// The generic body is exactly the OpenAPI WebhookEvent: these fields and no
// others. Adding one (a snippet, a description, an email …) must be a
// deliberate change to this test.
func TestEventIsAnAllowList(t *testing.T) {
	names := func(v any) []string {
		var out []string
		rt := reflect.TypeOf(v)
		for i := range rt.NumField() {
			out = append(out, strings.Split(rt.Field(i).Tag.Get("json"), ",")[0])
		}
		return out
	}
	for v, want := range map[any][]string{
		Event{}:          {"id", "type", "timestamp", "org", "project", "scan", "issue", "exception", "actor"},
		EventOrg{}:       {"id", "name"},
		EventProject{}:   {"id", "key", "name"},
		EventScan{}:      {"id", "kind", "target", "status", "stats", "url"},
		EventStats{}:     {"new", "fixed", "reopened", "total"},
		EventIssue{}:     {"id", "key", "title", "severity", "status", "tool", "rule_id", "target", "url"},
		EventException{}: {"id", "type", "decision", "url"},
		EventActor{}:     {"display_name"},
		SlackMessage{}:   {"text", "unfurl_links", "unfurl_media"},
	} {
		if got := names(v); !slices.Equal(got, want) {
			t.Errorf("%T: %v", v, got)
		}
	}
	// Facts carries no field a payload mustn't have.
	for _, typ := range []reflect.Type{reflect.TypeFor[notify.Facts](), reflect.TypeFor[notify.IssueFacts](),
		reflect.TypeFor[notify.ScanFacts](), reflect.TypeFor[notify.ProjectFacts](), reflect.TypeFor[notify.ExceptionFacts]()} {
		for i := range typ.NumField() {
			n := strings.ToLower(typ.Field(i).Name)
			for _, bad := range []string{"snippet", "description", "file", "path", "comment", "email", "secret", "reason", "body"} {
				if strings.Contains(n, bad) {
					t.Errorf("%s.%s", typ.Name(), typ.Field(i).Name)
				}
			}
		}
	}
}

func TestGenericBody(t *testing.T) {
	id := uuid.MustParse("00000000-0000-7000-8000-0000000000ff")
	f := facts()
	raw, err := Body(KindGeneric, NewEvent(id, notify.ExceptionDecided, f, "https://warden.example"))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got["id"] != id.String() || got["type"] != "exception.decided" || got["timestamp"] != "2026-10-29T08:00:00Z" {
		t.Fatal(got)
	}
	issue := got["issue"].(map[string]any)
	if issue["url"] != "https://warden.example/orgs/"+f.OrgID.String()+"/issues/"+f.Issue.ID.String() || issue["title"] != hostile {
		t.Fatal(issue)
	}
	if e := got["exception"].(map[string]any); e["decision"] != "approve" || e["type"] != "false_positive" {
		t.Fatal(e)
	}
	if got["actor"].(map[string]any)["display_name"] != "Mallory "+hostile {
		t.Fatal(got["actor"])
	}

	// webhook.test: org only, every other object null (present, not omitted).
	raw, _ = Body(KindGeneric, NewEvent(id, notify.WebhookTest, TestFacts(f.OrgID, "Acme", f.At), ""))
	got = nil
	_ = json.Unmarshal(raw, &got)
	for _, k := range []string{"project", "scan", "issue", "exception", "actor"} {
		if v, ok := got[k]; !ok || v != nil {
			t.Fatalf("%s: %v", k, got)
		}
	}
	if got["org"].(map[string]any)["name"] != "Acme" {
		t.Fatal(got)
	}
	// A pending exception has a null decision.
	f.Exception.Decision = ""
	raw, _ = Body(KindGeneric, NewEvent(id, notify.ExceptionRequested, f, "https://w"))
	if !strings.Contains(string(raw), `"decision":null`) {
		t.Fatal(string(raw))
	}
}

// Slack messages carry the same facts with Slack's control characters
// escaped: nothing from a title can mention, broadcast or link.
func TestSlackEscapesHostileText(t *testing.T) {
	f := facts()
	types := append(slices.Clone(notify.WebhookTypes), notify.WebhookTest)
	for _, typ := range types {
		raw, err := Body(KindSlack, NewEvent(uuid.New(), typ, f, "https://warden.example"))
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		if _, ok := m["link_names"]; ok || m["unfurl_links"] != false || m["unfurl_media"] != false || len(m) != 3 {
			t.Fatalf("%s: %v", typ, m)
		}
		text := m["text"].(string)
		// Every "<" Slack sees is one Warden wrote: the link to the web UI.
		if strings.Count(text, "<") != strings.Count(text, "<https://warden.example/") {
			t.Fatalf("%s: unescaped <:\n%s", typ, text)
		}
		for _, bad := range []string{"<!channel>", "<@U", "<!subteam", "|Open in Warden>\n", "&lt;!here&gt;", " "} {
			if strings.Contains(text, bad) {
				t.Fatalf("%s: %q in\n%s", typ, bad, text)
			}
		}
		if typ != notify.WebhookTest && !strings.Contains(text, "&amp;lt;!here&amp;gt;") {
			t.Fatalf("%s: & not escaped:\n%s", typ, text)
		}
		// Lines are Warden's own: a newline in a title doesn't start one.
		for _, line := range strings.Split(text, "\n") {
			if strings.HasPrefix(line, "*fake*") {
				t.Fatalf("%s: injected line:\n%s", typ, text)
			}
		}
	}
	// A link Warden can't express safely is dropped, not broken.
	if slackLink("https://w/x|evil", "t") != "" || slackLink("https://w/x>", "t") != "" || slackLink("https://w/a&b", "t") != "<https://w/a&amp;b|t>" {
		t.Fatal("slackLink")
	}
	text := slackMessage(NewEvent(uuid.New(), notify.ScanFinished, f, "https://w")).Text
	if !strings.Contains(text, "3 new · 2 reopened · 1 fixed · 9 found") || !strings.Contains(text, "<https://w/orgs/") {
		t.Fatal(text)
	}
}
