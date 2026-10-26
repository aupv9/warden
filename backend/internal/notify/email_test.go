package notify

import (
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aupv9/warden/backend/internal/notify/smtptest"
)

// What a hostile scanned repository controls: the finding's title (shown, so
// it must be escaped) and its snippet, description and file content (never
// shown). The secret is built at test time, never committed.
var (
	hostileTitle = `<script>alert("x")</script><img src=x onerror=alert(1)> & "quotes"`
	secret       = "AKIA" + strings.Repeat("Q", 16)
	masked       = secret[:4] + "****"
)

func contentFor(typ string) Content {
	c := Content{Type: typ, Title: "WEB-41 assigned to you", OrgName: "Acme <b>Corp</b>", ProjectID: "p", ProjectKey: "WEB",
		IssueKey: "WEB-41", IssueTitle: hostileTitle, Severity: "critical", Status: "assigned", ActorName: "Mallory <i>",
		Link: "/orgs/o/issues/i"}
	switch typ {
	case ExceptionDecided:
		c.Decision = "approved"
	case ScanFinished:
		c.IssueKey, c.IssueTitle, c.Severity, c.Status = "", "", "", "completed"
	case SLADueSoon, SLAOverdue:
		c.IssueKey, c.IssueTitle, c.Severity, c.Status, c.ActorName = "", "", "", "", ""
		c.Overdue, c.DueSoon = 1, 1
		c.Items = []Item{{ProjectKey: "WEB", IssueKey: "WEB-1", Title: hostileTitle, Severity: "high", Status: "open", Overdue: true,
			Link: "/orgs/o/issues/1"}, {ProjectKey: "WEB", IssueKey: "WEB-2", Title: "t", Severity: "low", Link: "javascript:alert(1)"}}
	}
	return c
}

// Content is the whole allow-list of what an email may show. Adding a field
// (a snippet, a description …) must be a deliberate change to this test.
func TestContentIsAnAllowList(t *testing.T) {
	names := func(t reflect.Type) []string {
		var out []string
		for i := range t.NumField() {
			out = append(out, t.Field(i).Name)
		}
		return out
	}
	fields := names(reflect.TypeFor[Content]())
	want := []string{"Type", "Title", "OrgName", "ProjectID", "ProjectKey", "IssueKey", "IssueTitle", "Severity", "Status",
		"ActorName", "Decision", "Overdue", "DueSoon", "Items", "Link"}
	if !slices.Equal(fields, want) {
		t.Fatalf("Content fields changed: %v", fields)
	}
	item := names(reflect.TypeFor[Item]())
	if !slices.Equal(item, []string{"ProjectKey", "IssueKey", "Title", "Severity", "Status", "DueAt", "Overdue", "Link"}) {
		t.Fatalf("Item fields changed: %v", item)
	}
	// The dispatcher only ever selects allow-listed issue columns.
	for _, col := range []string{"snippet", "description", "remediation", "raw", "body", "file_path"} {
		if strings.Contains(issueFactsSQL, col) {
			t.Fatalf("issue facts select %s", col)
		}
	}
}

func TestRenderEveryTypeEscapesAndLeaksNothing(t *testing.T) {
	for _, typ := range Types {
		c := contentFor(typ)
		// A snippet or secret could only reach an email through Content; make
		// sure a round trip through the stored payload adds nothing.
		raw, _ := json.Marshal(c)
		var stored Content
		if err := json.Unmarshal(raw, &stored); err != nil {
			t.Fatal(err)
		}
		m, err := Render(stored, "dev@example.com", "https://warden.example")
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		msg, err := Build("warden@example.com", m, time.Date(2026, 10, 26, 8, 0, 0, 0, time.UTC))
		if err != nil {
			t.Fatal(err)
		}
		p, err := smtptest.Parse(string(msg))
		if err != nil {
			t.Fatal(err)
		}
		for _, body := range []string{string(msg), p.Text, p.HTML} {
			if strings.Contains(body, secret) || strings.Contains(body, masked) {
				t.Fatalf("%s: secret in email", typ)
			}
		}
		if strings.Contains(p.HTML, "<script>") || strings.Contains(p.HTML, "<img") || strings.Contains(p.HTML, "<b>Corp") ||
			strings.Contains(p.HTML, "javascript:") {
			t.Fatalf("%s: unescaped HTML:\n%s", typ, p.HTML)
		}
		if typ != ScanFinished && !strings.Contains(p.HTML, "&lt;script&gt;") {
			t.Fatalf("%s: title missing:\n%s", typ, p.HTML)
		}
		if !strings.Contains(p.Text, "https://warden.example/orgs/o/issues/") || !strings.Contains(p.Text, "Acme") {
			t.Fatalf("%s: text:\n%s", typ, p.Text)
		}
		if p.Header.Get("Subject") != "[Warden] WEB-41 assigned to you" || p.Header.Get("Auto-Submitted") != "auto-generated" ||
			p.Header.Get("From") != `"Warden" <warden@example.com>` || p.Header.Get("To") != "<dev@example.com>" {
			t.Fatalf("%s: headers %v", typ, p.Header)
		}
	}
}

func TestHeaderInjectionIsRejected(t *testing.T) {
	c := contentFor(IssueAssigned)
	if _, err := Render(c, "dev@example.com\r\nBcc: all@example.com", "https://w"); !errors.Is(err, ErrHeaderInjection) {
		t.Fatal(err)
	}
	c.Title = "x\nBcc: all@example.com"
	if _, err := Render(c, "dev@example.com", "https://w"); !errors.Is(err, ErrHeaderInjection) {
		t.Fatal(err)
	}
	m := Mail{To: "dev@example.com", Subject: "ok", Text: "t", HTML: "h"}
	for _, bad := range []struct{ from, to, subject string }{
		{"warden@example.com\r\nX: y", m.To, m.Subject},
		{"warden@example.com", "dev@example.com\nX: y", m.Subject},
		{"warden@example.com", m.To, "s\rX: y"},
	} {
		if _, err := Build(bad.from, Mail{To: bad.to, Subject: bad.subject}, time.Now()); !errors.Is(err, ErrHeaderInjection) {
			t.Errorf("%+v: %v", bad, err)
		}
	}
	if _, err := Build("not an address", m, time.Now()); err == nil {
		t.Fatal("bad from accepted")
	}
	if _, err := Build("warden@example.com", Mail{To: "nope", Subject: "s"}, time.Now()); err == nil {
		t.Fatal("bad recipient accepted")
	}
	// Non-ASCII subjects are encoded, not sent raw.
	msg, err := Build("Warden Bot <warden@example.com>", Mail{To: "dev@example.com", Subject: "[Warden] Ünïcode"}, time.Now())
	if err != nil || !strings.Contains(string(msg), "Subject: =?utf-8?q?") || !strings.Contains(string(msg), `From: "Warden Bot"`) {
		t.Fatal(string(msg), err)
	}
}

func TestBaseURL(t *testing.T) {
	if u, err := BaseURL("https://warden.example/app/"); err != nil || u != "https://warden.example/app" {
		t.Fatal(u, err)
	}
	for _, bad := range []string{"", "javascript:alert(1)", "ftp://x", "https://u:p@x", "https://x/?q=1", "https://x/#f", "https://x/\r\n", "//x"} {
		if _, err := BaseURL(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if absolute("https://w", "//evil.example/x") != "https://w" || absolute("https://w", "relative") != "https://w" {
		t.Fatal("non-path link kept")
	}
}

func TestTypesAndDefaults(t *testing.T) {
	for _, typ := range Types {
		if !ValidType(typ) || DefaultEmail(typ) == (typ == ScanFinished) {
			t.Fatal(typ)
		}
	}
	if ValidType("issue.deleted") {
		t.Fatal("unknown type accepted")
	}
	if Backoff(0) != time.Minute || Backoff(2) != 2*time.Minute || Backoff(7) != time.Hour || Backoff(20) != time.Hour {
		t.Fatal(Backoff(2), Backoff(7))
	}
}
