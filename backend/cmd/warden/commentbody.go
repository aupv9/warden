package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"github.com/google/uuid"
)

// The pull/merge request comment. Everything in the gate that came from
// scanned code (titles, rule ids, paths, package names and versions) is
// hostile: GitHub and GitLab render Markdown and a subset of HTML, link
// @mentions, #/!/~ references and bare URLs, and a comment is posted under
// the CI's identity. So each such field is cleaned (no control, format or
// bidi characters), capped, and rendered either as escaped text or as a code
// span, never as Markdown or HTML of its own.

const (
	// maxCommentRows: blocking issues listed; the rest are counted.
	maxCommentRows = 20
	// maxCommentBody stays under GitHub's 65,536-character limit (GitLab's is
	// higher) even when every character is counted as a byte.
	maxCommentBody = 60000

	maxTitle    = 100
	maxRule     = 80
	maxLocation = 120
	maxKey      = 40
)

// mdPunct is CommonMark's ASCII punctuation: each can be backslash-escaped,
// which makes it literal text.
const mdPunct = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

// refSigils start a mention or a reference once rendered: @user and @org/team;
// #1, !1 (GitLab MR), ~label, %milestone, $snippet, &epic, ^alert, [vulnerability:1],
// {+inline diff+}. A word joiner after one keeps the text but breaks the link.
const refSigils = "@#!~%$&^[{*"

// wordJoiner is invisible and not a word character, so it breaks mention,
// reference and autolink patterns without changing what the reader sees.
const wordJoiner = '⁠'

var severityLabels = map[string]string{"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}

// cleanText drops what must never reach a comment: invalid UTF-8, control
// characters, format characters (bidi overrides that reorder what the reader
// sees, zero-width characters that hide text, Unicode tags), private-use and
// surrogate code points. Line breaks (which would end a table row) and other
// spaces become one ' '. Then it caps the length in runes.
func cleanText(s string, limit int) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\t' || r == '\n' || r == '\r' || unicode.Is(unicode.Zs, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r):
			return ' '
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r) ||
			unicode.Is(unicode.Co, r) || unicode.Is(unicode.Cs, r) || r == unicode.ReplacementChar:
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))
	return truncate(strings.Join(strings.Fields(s), " "), limit)
}

// mdText renders hostile text as inline Markdown that displays exactly the
// cleaned text: every ASCII punctuation character is backslash-escaped (no
// emphasis, links, images, HTML, entities or table pipes), and a word joiner
// follows each reference sigil, "://" and "www" so nothing is linked.
func mdText(s string, limit int) string {
	rs := []rune(cleanText(s, limit))
	var b strings.Builder
	for i, r := range rs {
		if r == '.' && i >= 3 && strings.EqualFold(string(rs[i-3:i]), "www") {
			b.WriteRune(wordJoiner)
		}
		if r < 0x80 && strings.ContainsRune(mdPunct, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
		if strings.ContainsRune(refSigils, r) || r == ':' && i+1 < len(rs) && rs[i+1] == '/' {
			b.WriteRune(wordJoiner)
		}
	}
	return b.String()
}

// mdCode renders hostile text as a code span: no Markdown, HTML, mentions or
// references are processed inside one. The fence is longer than any run of
// backticks in the text, and pipes are escaped for the table (GFM unescapes
// \| even inside code spans).
func mdCode(s string, limit int) string {
	s = cleanText(s, limit)
	if s == "" {
		return "-"
	}
	run, longest := 0, 0
	for _, r := range s {
		if r == '`' {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	fence, pad := strings.Repeat("`", longest+1), ""
	if longest > 0 {
		pad = " " // a space on both sides is stripped, so text may start or end with a backtick
	}
	return fence + pad + strings.ReplaceAll(s, "|", `\|`) + pad + fence
}

// commentMarker starts the body and finds the comment again on the next run.
// Image scans of the project get their own comment per target (a hash, so
// the marker holds no repository text).
// commentTarget is the target the scan's issues are tracked under, so source,
// image, history scans and each import (tool and category) of one project
// keep their own comment.
func (o *options) commentTarget() string {
	switch {
	case o.history:
		return "(history)"
	case o.importFile != "":
		return importTarget(o.importTool, o.importCategory)
	}
	return o.target
}

func commentMarker(project uuid.UUID, target string) string {
	if target == "" {
		return "<!-- warden:" + project.String() + " -->"
	}
	h := sha256.Sum256([]byte(target))
	return "<!-- warden:" + project.String() + ":" + hex.EncodeToString(h[:8]) + " -->"
}

// webLink builds a link into the Warden web UI from the server URL (operator
// configuration, already checked) and ids parsed as UUIDs; parentheses,
// angle brackets and spaces are percent-encoded so the URL can't end the
// Markdown link early.
func webLink(server, path string) string {
	u := strings.TrimRight(server, "/") + path
	return strings.NewReplacer("(", "%28", ")", "%29", "<", "%3C", ">", "%3E", " ", "%20").Replace(u)
}

// commentBody renders the summary for one gate.
func (c client) commentBody(g gate, scanID string) string {
	o := c.o
	server := o.server.String()
	org := o.org.String()
	failOn := g.FailOn
	if _, ok := severityLabels[failOn]; !ok || failOn == "info" {
		failOn = o.failOn
	}
	counts := fmt.Sprintf("Critical %d · High %d · Medium %d · Low %d · Info %d",
		g.Counts["critical"], g.Counts["high"], g.Counts["medium"], g.Counts["low"], g.Counts["info"])
	which := "at or above " + severityLabels[failOn]
	if g.FailOnKEV {
		which += " or known exploited (CISA KEV)"
	}
	var head strings.Builder
	// The same marker comment() looks for: with o.target alone, a history
	// scan's comment carried the source marker, so the source scan's run
	// replaced it and the history scan posted a new one each time.
	head.WriteString(commentMarker(o.project, o.commentTarget()) + "\n")
	nBlocking := 0
	for _, s := range []string{"critical", "high", "medium", "low"} {
		nBlocking += g.Counts[s]
		if s == failOn {
			break
		}
	}
	if g.FailOnKEV {
		nBlocking = max(nBlocking, len(g.Blocking))
	}
	switch {
	case g.Pass:
		fmt.Fprintf(&head, "### Warden: passed\n\nNo active issues %s.\n\n", which)
	case !g.Finished:
		head.WriteString("### Warden: failed\n\nThe scan hasn't finished.\n\n")
	case len(g.Blocking) == 0:
		fmt.Fprintf(&head, "### Warden: failed\n\nThe scan ended %s.\n\n", mdText(g.Status, 20))
	default:
		fmt.Fprintf(&head, "### Warden: failed\n\n%d blocking issue(s) %s.\n\n", nBlocking, which)
	}
	head.WriteString(counts + "\n")
	if g.FailOnKEV {
		fmt.Fprintf(&head, "\nKnown exploited (CISA KEV): %d.\n", g.KEV)
	}

	var foot strings.Builder
	foot.WriteString("\n")
	if id, err := uuid.Parse(scanID); err == nil {
		fmt.Fprintf(&foot, "[Scan in Warden](<%s>)\n", webLink(server, "/orgs/"+org+"/projects/"+o.project.String()+"/scans?scan="+id.String()))
	}

	isNew := map[string]bool{}
	for _, id := range g.BlockingNew {
		isNew[id] = true
	}
	var rows []string
	for _, i := range g.Blocking[:min(len(g.Blocking), maxCommentRows)] {
		rows = append(rows, c.commentRow(i, isNew[i.ID], server, org))
	}
	table := func(rows []string) string {
		if len(rows) == 0 {
			return ""
		}
		return "\n|  | Severity | Issue | Rule | Location |\n|---|---|---|---|---|\n" + strings.Join(rows, "")
	}
	more := func(shown int) string {
		if n := max(nBlocking, len(g.Blocking)) - shown; n > 0 && len(g.Blocking) > 0 {
			return fmt.Sprintf("\n…and %d more.\n", n)
		}
		return ""
	}
	// Drop rows until the whole body fits (each row is capped, so this only
	// matters if the caps change).
	for len(rows) > 0 && head.Len()+len(table(rows))+len(more(len(rows)))+foot.Len() > maxCommentBody {
		rows = rows[:len(rows)-1]
	}
	return head.String() + table(rows) + more(len(rows)) + foot.String()
}

func (c client) commentRow(i issue, isNew bool, server, org string) string {
	var mark []string
	if isNew {
		mark = append(mark, "**New**")
	}
	if i.KEV {
		mark = append(mark, "KEV")
	}
	sev, ok := severityLabels[i.Severity]
	if !ok {
		sev = "Unknown"
	}
	key := mdText(i.Key, maxKey)
	if id, err := uuid.Parse(i.ID); err == nil && key != "" {
		key = "[" + key + "](<" + webLink(server, "/orgs/"+org+"/issues/"+id.String()) + ">)"
	}
	loc := "-"
	switch {
	case i.FilePath != nil && *i.FilePath != "":
		l := *i.FilePath
		if i.StartLine != nil && *i.StartLine > 0 {
			l = truncate(cleanText(l, maxLocation), maxLocation-12) + ":" + strconv.Itoa(*i.StartLine)
		}
		loc = mdCode(l, maxLocation)
	case i.PackageName != nil && *i.PackageName != "":
		l := *i.PackageName
		if i.PackageVersion != nil && *i.PackageVersion != "" {
			l = truncate(cleanText(l, maxLocation/2), maxLocation/2) + "@" + cleanText(*i.PackageVersion, maxLocation/2)
		}
		loc = mdCode(l, maxLocation)
	}
	// An imported issue's rule is another tool's: name the tool. Both come
	// from the report and go through the same code span.
	rule := i.RuleID
	if i.ExternalTool != nil && *i.ExternalTool != "" {
		rule = cleanText(*i.ExternalTool, maxRule/2) + ": " + rule
	}
	return fmt.Sprintf("| %s | %s | %s %s | %s | %s |\n", strings.Join(mark, " "), sev, key, mdText(i.Title, maxTitle),
		mdCode(rule, maxRule), loc)
}
