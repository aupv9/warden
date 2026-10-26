package notify

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	htmltemplate "html/template"
	"mime"
	"mime/quotedprintable"
	"net/mail"
	"net/url"
	"strings"
	texttemplate "text/template"
	"time"
)

// Item is one issue in an SLA digest.
type Item struct {
	ProjectKey string `json:"project_key"`
	IssueKey   string `json:"issue_key"`
	Title      string `json:"title"`
	Severity   string `json:"severity"`
	Status     string `json:"status"`
	DueAt      string `json:"due_at,omitempty"`
	Overdue    bool   `json:"overdue,omitempty"`
	Link       string `json:"link"` // app path
}

// Content is everything a notification shows. It is stored as the
// notification's payload and rendered into the email at send time. Keep it to
// these fields: they are the whole allow-list of what an email may contain.
type Content struct {
	Type       string `json:"type"`
	Title      string `json:"title"` // server-built, e.g. "WEB-41 assigned to you"
	OrgName    string `json:"org_name"`
	ProjectID  string `json:"project_id,omitempty"`
	ProjectKey string `json:"project_key,omitempty"`
	IssueKey   string `json:"issue_key,omitempty"`
	IssueTitle string `json:"issue_title,omitempty"`
	Severity   string `json:"severity,omitempty"`
	Status     string `json:"status,omitempty"`
	ActorName  string `json:"actor_name,omitempty"`
	Decision   string `json:"decision,omitempty"`
	Overdue    int    `json:"overdue,omitempty"`
	DueSoon    int    `json:"due_soon,omitempty"`
	Items      []Item `json:"items,omitempty"`
	Link       string `json:"link"` // app path, e.g. /orgs/…/issues/…
}

// Mail is a rendered email.
type Mail struct {
	To      string
	Subject string
	Text    string
	HTML    string
}

// ErrHeaderInjection: a header value contained CR or LF.
var ErrHeaderInjection = errors.New("notify: line break in an email header value")

const textTmpl = `{{.Title}}
{{if .IssueKey}}
Organization: {{.OrgName}}
Project:      {{.ProjectKey}}
Issue:        {{.IssueKey}} {{.IssueTitle}}
Severity:     {{.Severity}}
Status:       {{.Status}}
{{- if .Decision}}
Decision:     {{.Decision}}{{end}}
{{- if .ActorName}}
By:           {{.ActorName}}{{end}}
{{else if .Items}}
Organization: {{.OrgName}}
{{range .Items}}
- {{.IssueKey}} [{{.Severity}}{{if .Overdue}}, overdue{{end}}] {{.Title}}
  {{.Link}}
{{- end}}
{{else}}
Organization: {{.OrgName}}
{{- if .ProjectKey}}
Project:      {{.ProjectKey}}{{end}}
{{- if .Status}}
Status:       {{.Status}}{{end}}
{{- if .ActorName}}
By:           {{.ActorName}}{{end}}
{{end}}
Open in Warden: {{.Link}}

You get this email because of your Warden notification preferences.
`

const htmlTmpl = `<!doctype html>
<html><body style="font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;font-size:14px;color:#1f2328">
<p style="font-size:16px;font-weight:600">{{.Title}}</p>
<table cellpadding="4" style="border-collapse:collapse">
<tr><td style="color:#59636e">Organization</td><td>{{.OrgName}}</td></tr>
{{- if .ProjectKey}}
<tr><td style="color:#59636e">Project</td><td>{{.ProjectKey}}</td></tr>{{end}}
{{- if .IssueKey}}
<tr><td style="color:#59636e">Issue</td><td>{{.IssueKey}} {{.IssueTitle}}</td></tr>
<tr><td style="color:#59636e">Severity</td><td>{{.Severity}}</td></tr>{{end}}
{{- if .Status}}
<tr><td style="color:#59636e">Status</td><td>{{.Status}}</td></tr>{{end}}
{{- if .Decision}}
<tr><td style="color:#59636e">Decision</td><td>{{.Decision}}</td></tr>{{end}}
{{- if .ActorName}}
<tr><td style="color:#59636e">By</td><td>{{.ActorName}}</td></tr>{{end}}
</table>
{{- if .Items}}
<ul>
{{- range .Items}}
<li><a href="{{.Link}}">{{.IssueKey}}</a> [{{.Severity}}{{if .Overdue}}, overdue{{end}}] {{.Title}}</li>
{{- end}}
</ul>{{end}}
<p><a href="{{.Link}}">Open in Warden</a></p>
<p style="color:#59636e;font-size:12px">You get this email because of your Warden notification preferences.</p>
</body></html>
`

var (
	textT = texttemplate.Must(texttemplate.New("text").Parse(textTmpl))
	// html/template escapes every value for its context; titles come from
	// scanned code and may contain markup.
	htmlT = htmltemplate.Must(htmltemplate.New("html").Parse(htmlTmpl))
)

// BaseURL validates the public base URL links are built from.
func BaseURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(raw, "\r\n") {
		return "", errors.New("notify: public_base_url must be an http(s) URL without credentials, query or fragment")
	}
	return u.String(), nil
}

// Render builds the email for one recipient. base is a validated BaseURL;
// app paths in c become absolute links.
func Render(c Content, to, base string) (Mail, error) {
	if strings.ContainsAny(to, "\r\n") || strings.ContainsAny(c.Title, "\r\n") {
		return Mail{}, ErrHeaderInjection
	}
	c.Link = absolute(base, c.Link)
	items := make([]Item, len(c.Items))
	for i, it := range c.Items {
		it.Link = absolute(base, it.Link)
		items[i] = it
	}
	c.Items = items
	var text, html bytes.Buffer
	if err := textT.Execute(&text, c); err != nil {
		return Mail{}, err
	}
	if err := htmlT.Execute(&html, c); err != nil {
		return Mail{}, err
	}
	return Mail{To: to, Subject: "[Warden] " + c.Title, Text: text.String(), HTML: html.String()}, nil
}

// absolute joins base and an app path. Paths are built by the dispatcher;
// anything else is dropped rather than turned into a link.
func absolute(base, path string) string {
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		return base
	}
	return base + path
}

// Build serializes m as an RFC 5322 message with a text and an HTML part.
// Every header value is checked for CR/LF: To comes from the user's OIDC
// profile and Subject from scanned data, so neither may add headers.
func Build(from string, m Mail, now time.Time) ([]byte, error) {
	for _, v := range []string{from, m.To, m.Subject} {
		if strings.ContainsAny(v, "\r\n") {
			return nil, ErrHeaderInjection
		}
	}
	fromAddr, err := mail.ParseAddress(from)
	if err != nil {
		return nil, errors.New("notify: invalid from address")
	}
	toAddr, err := mail.ParseAddress(m.To)
	if err != nil {
		return nil, errors.New("notify: invalid recipient address")
	}
	if fromAddr.Name == "" {
		fromAddr.Name = "Warden"
	}
	var rnd [12]byte
	_, _ = rand.Read(rnd[:])
	boundary := "warden-" + hex.EncodeToString(rnd[:])
	domain := fromAddr.Address[strings.LastIndexByte(fromAddr.Address, '@')+1:]

	var b bytes.Buffer
	hdr := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	hdr("From", fromAddr.String())
	hdr("To", (&mail.Address{Address: toAddr.Address}).String())
	hdr("Subject", mime.QEncoding.Encode("utf-8", m.Subject))
	hdr("Date", now.UTC().Format(time.RFC1123Z))
	hdr("Message-ID", "<"+hex.EncodeToString(rnd[:])+"@"+domain+">")
	hdr("MIME-Version", "1.0")
	hdr("Auto-Submitted", "auto-generated")
	hdr("Content-Type", `multipart/alternative; boundary="`+boundary+`"`)
	b.WriteString("\r\n")
	for _, part := range []struct{ typ, body string }{{"text/plain", m.Text}, {"text/html", m.HTML}} {
		b.WriteString("--" + boundary + "\r\n")
		hdr("Content-Type", part.typ+"; charset=utf-8")
		hdr("Content-Transfer-Encoding", "quoted-printable")
		b.WriteString("\r\n")
		w := quotedprintable.NewWriter(&b)
		if _, err := w.Write([]byte(part.body)); err != nil {
			return nil, err
		}
		if err := w.Close(); err != nil {
			return nil, err
		}
		b.WriteString("\r\n")
	}
	b.WriteString("--" + boundary + "--\r\n")
	return b.Bytes(), nil
}
