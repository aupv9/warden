package main

import (
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

const wj = string(wordJoiner)

func TestMDText(t *testing.T) {
	for in, want := range map[string]string{
		"plain words 42":                                          "plain words 42",
		"<img src=x onerror=alert(1)>":                            `\<img src\=x onerror\=alert\(1\)\>`,
		"<!-- warden:x -->":                                       `\<\!` + wj + `\-\- warden\:x \-\-\>`,
		"[click](https://evil.example/p)":                         `\[` + wj + `click\]\(https\:` + wj + `\/\/evil\.example\/p\)`,
		"![px](https://t.example/p.gif)":                          `\!` + wj + `\[` + wj + `px\]\(https\:` + wj + `\/\/t\.example\/p\.gif\)`,
		"see www.evil.example":                                    "see www" + wj + `\.evil\.example`,
		"ping @everyone and @acme/admins":                         `ping \@` + wj + `everyone and \@` + wj + `acme\/admins`,
		"fixes #1, !2, ~bug, %v1, $3, &4":                         `fixes \#` + wj + `1\, \!` + wj + `2\, \~` + wj + `bug\, \%` + wj + `v1\, \$` + wj + `3\, \&` + wj + `4`,
		"&#64;user &lt;b&gt;":                                     `\&` + wj + `\#` + wj + `64\;user \&` + wj + `lt\;b\&` + wj + `gt\;`,
		"**bold** _it_ `code` | pipe \\":                          `\*` + wj + `\*` + wj + `bold\*` + wj + `\*` + wj + ` \_it\_ \` + "`" + `code\` + "`" + ` \| pipe \\`,
		"line1\nline2\r\n| x | y |":                               `line1 line2 \| x \| y \|`,
		"a\x1b[31mb\u202ec\u2066d\u200be\ufeff\U000E0041f\u2028g": `a\[` + wj + `31mbcdef g`,
		"bad \xff utf8":                                           "bad utf8",
		"$x$ math {+diff+}":                                       `\$` + wj + `x\$` + wj + ` math \{` + wj + `\+diff\+\}`,
	} {
		if got := mdText(in, 200); got != want {
			t.Errorf("%q:\n got %q\nwant %q", in, got, want)
		}
	}
	if got := mdText(strings.Repeat("é", 300), 10); got != strings.Repeat("é", 9)+"…" {
		t.Error(got)
	}
}

func TestMDCode(t *testing.T) {
	for in, want := range map[string]string{
		"src/app.go:12":        "`src/app.go:12`",
		"a`b":                  "`` a`b ``",
		"``x```":               "```` ``x``` ````",
		"`":                    "`` ` ``",
		"a|b\\|c":              "`a\\|b\\\\|c`",
		"<img src=x>@user #1":  "`<img src=x>@user #1`",
		"new\nline\u202e\x00x": "`new linex`",
		"":                     "-",
		" \u200b\n":            "-",
	} {
		if got := mdCode(in, 200); got != want {
			t.Errorf("%q:\n got %q\nwant %q", in, got, want)
		}
	}
}

// cells splits a table row the way GFM's table scanner does (cmark-gfm and
// comrak): a cell is any run of `\|` or characters other than '|', so only a
// backslash directly before a pipe protects it, even in a code span, and `\\|`
// is a backslash and a protected pipe.
func cells(row string) []string {
	var out []string
	var cur strings.Builder
	for i := 0; i < len(row); i++ {
		if row[i] == '\\' && i+1 < len(row) && row[i+1] == '|' {
			cur.WriteByte(row[i])
			cur.WriteByte(row[i+1])
			i++
			continue
		}
		if row[i] == '|' {
			out = append(out, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(row[i])
	}
	return append(out, cur.String())
}

// checkEscapedText fails unless s renders as plain text: every ASCII
// punctuation character backslash-escaped, a word joiner after each reference
// sigil, no control or format characters other than the word joiner.
func checkEscapedText(t *testing.T, s string) {
	t.Helper()
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case r == '\\':
			if i+1 >= len(rs) || !strings.ContainsRune(mdPunct, rs[i+1]) {
				t.Fatalf("stray backslash at %d in %q", i, s)
			}
			i++
			if strings.ContainsRune(refSigils, rs[i]) && (i+1 >= len(rs) || rs[i+1] != wordJoiner) {
				t.Fatalf("sigil %q not neutralised in %q", rs[i], s)
			}
		case r < 0x80 && strings.ContainsRune(mdPunct, r):
			t.Fatalf("unescaped %q at %d in %q", r, i, s)
		case r == wordJoiner:
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r):
			t.Fatalf("control/format character %U in %q", r, s)
		}
	}
	if strings.Contains(strings.ToLower(strings.ReplaceAll(s, `\`, "")), "://") || strings.Contains(strings.ToLower(s), "www\\.") {
		t.Fatalf("autolinkable URL in %q", s)
	}
}

// checkCode fails unless s is one code span holding no line break.
func checkCode(t *testing.T, s string) {
	t.Helper()
	if s == "-" {
		return
	}
	n := len(s) - len(strings.TrimLeft(s, "`"))
	fence := s[:n]
	inner := strings.TrimSuffix(s[n:], fence)
	if n == 0 || len(inner) == len(s[n:]) || strings.Contains(inner, fence) || strings.ContainsAny(inner, "\r\n") {
		t.Fatalf("not a single code span: %q", s)
	}
}

var issueLink = regexp.MustCompile(`^\[([^\]]*(?:\\\][^\]]*)*)\]\(<https://warden\.example/orgs/[0-9a-f-]{36}/issues/[0-9a-f-]{36}>\)(?: |$)`)

// checkRow checks one rendered table row cell by cell.
func checkRow(t *testing.T, row string) {
	t.Helper()
	c := cells(strings.TrimSuffix(row, "\n"))
	if len(c) != 7 || c[0] != "" || c[6] != "" {
		t.Fatalf("row broke out of its cells: %q", row)
	}
	mark, sev, iss, rule, loc := strings.TrimSpace(c[1]), strings.TrimSpace(c[2]), strings.TrimSpace(c[3]), strings.TrimSpace(c[4]), strings.TrimSpace(c[5])
	if mark != "" && mark != "**New**" && mark != "KEV" && mark != "**New** KEV" {
		t.Fatalf("mark %q", mark)
	}
	if severityLabels[strings.ToLower(sev)] != sev && sev != "Unknown" {
		t.Fatalf("severity %q", sev)
	}
	if m := issueLink.FindStringSubmatch(iss); m != nil {
		checkEscapedText(t, m[1])
		iss = iss[len(m[0]):]
	}
	checkEscapedText(t, iss)
	checkCode(t, rule)
	checkCode(t, loc)
}

func bodyClient() client {
	srv, _ := url.Parse("https://warden.example")
	return client{o: options{server: srv, org: uuid.New(), project: uuid.New(), failOn: "high", stdout: io.Discard, stderr: io.Discard}}
}

func checkBody(t *testing.T, c client, body string) {
	t.Helper()
	if !strings.HasPrefix(body, commentMarker(c.o.project, c.o.commentTarget())+"\n") || len(body) > maxCommentBody || !utf8.ValidString(body) {
		t.Fatalf("marker/size: %d %q", len(body), body[:min(len(body), 200)])
	}
	rows := 0
	for _, line := range strings.Split(body, "\n")[1:] {
		switch {
		case strings.HasPrefix(line, "| ") && !strings.HasPrefix(line, "|  | Severity"):
			checkRow(t, line)
			rows++
		case strings.HasPrefix(line, "[Scan in Warden](<https://warden.example/orgs/"), strings.HasPrefix(line, "### Warden: "),
			line == "|---|---|---|---|---|":
		case strings.HasPrefix(line, "The scan ended "):
			checkEscapedText(t, strings.TrimSuffix(strings.TrimPrefix(line, "The scan ended "), "."))
		case strings.ContainsAny(line, "<>@#![]`|&~$%") && !strings.HasPrefix(line, "|"):
			t.Fatalf("unexpected markup outside the table: %q", line)
		}
	}
	if rows > maxCommentRows {
		t.Fatalf("%d rows", rows)
	}
}

// hostile is what scanned code can put in a title, rule id, path or package.
var hostile = []string{
	"<img src=https://t.example/p.gif>", "<script>alert(1)</script>", "[x](javascript:alert(1))",
	"![](https://t.example/pixel.png)", "@everyone @acme/security", "#1 !2 ~label %ms $9 &3 ^alert#1",
	"https://evil.example/login", "www.evil.example", "<!-- warden:00000000-0000-0000-0000-000000000000 -->",
	"`` code ` breaker ```", "| fake | row |\n| --- |", "a\r\n\r\n## heading\n> quote", "\u202egnp.exe\u2066",
	"zero\u200bwidth\u200d\ufeff", "&lt;b&gt; &#x40;user", "\\|\\", "$$\\href{https://e}{x}$$", "{+ins+} [-del-]",
	"**bold** __u__ ~~s~~", ":tada: \x1b]8;;https://e\x07link\x1b]8;;\x07", strings.Repeat("@", 5000),
	strings.Repeat("\U0001F600", 3000), "\xff\xfe invalid",
}

func hostileIssue(i int) issue {
	s := func(k int) string { return hostile[(i+k)%len(hostile)] }
	line := 7
	is := issue{ID: uuid.NewString(), Key: "WEB-" + s(0), Title: s(1), Severity: s(2), RuleID: s(3), KEV: i%2 == 0}
	if i%3 == 0 {
		p, v := s(4), s(5)
		is.PackageName, is.PackageVersion = &p, &v
	} else {
		p := s(6)
		is.FilePath, is.StartLine = &p, &line
	}
	if i%5 == 0 {
		is.ID = "not-a-uuid)](https://evil.example)"
	}
	if i%7 == 0 { // an imported issue: the tool joins the rule's code span
		t := s(7)
		is.ExternalTool = &t
	}
	return is
}

func TestCommentBodyEscapesHostileFields(t *testing.T) {
	c := bodyClient()
	g := gate{Status: "completed", Finished: true, FailOn: "high", FailOnKEV: true, KEV: 3,
		Counts: map[string]int{"critical": 40, "high": 60, "medium": 2}}
	for i := range 100 {
		is := hostileIssue(i)
		g.Blocking = append(g.Blocking, is)
		if i%4 == 0 {
			g.BlockingNew = append(g.BlockingNew, is.ID)
		}
	}
	body := c.commentBody(g, uuid.NewString())
	checkBody(t, c, body)
	for _, want := range []string{"### Warden: failed", "100 blocking issue(s) at or above High or known exploited (CISA KEV)",
		"Critical 40 · High 60 · Medium 2 · Low 0 · Info 0", "Known exploited (CISA KEV): 3.", "…and 80 more.", "**New**",
		"[Scan in Warden](<https://warden.example/orgs/" + c.o.org.String() + "/projects/" + c.o.project.String() + "/scans?scan="} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(body, "evil.example)") || strings.Contains(body, "not-a-uuid") && !strings.Contains(body, "not\\-a\\-uuid") {
		t.Fatal("a non-UUID id became a link")
	}
	// A body that only fits with fewer rows drops rows, not the limit.
	g.Blocking = g.Blocking[:0]
	long := strings.Repeat("@", 200)
	for range 100 {
		p := strings.Repeat("`|", 200)
		g.Blocking = append(g.Blocking, issue{ID: uuid.NewString(), Key: long, Title: long, Severity: "high", RuleID: p, FilePath: &p})
	}
	checkBody(t, c, c.commentBody(g, "scan"))
}

func TestCommentBodyPassAndMarker(t *testing.T) {
	c := bodyClient()
	g := gate{Status: "completed", Finished: true, Pass: true, FailOn: "critical", Counts: map[string]int{"low": 2}}
	body := c.commentBody(g, "x")
	checkBody(t, c, body)
	if !strings.Contains(body, "### Warden: passed\n\nNo active issues at or above Critical.") || strings.Contains(body, "Scan in Warden") ||
		strings.Contains(body, "|---|") || strings.Contains(body, "KEV") {
		t.Fatal(body)
	}
	// A gate value outside the enum never reaches the body.
	g = gate{Status: "<b>failed</b>", Finished: true, FailOn: "<img>", Counts: map[string]int{}}
	body = c.commentBody(g, "x")
	checkBody(t, c, body)
	if !strings.Contains(body, "at or above High") && !strings.Contains(body, `The scan ended \<b\>failed\<\/b\>.`) {
		t.Fatal(body)
	}
	// One comment per project, and per image target.
	p := uuid.New()
	src, img, other := commentMarker(p, ""), commentMarker(p, "ghcr.io/acme/api"), commentMarker(p, "ghcr.io/acme/web")
	if src != "<!-- warden:"+p.String()+" -->" || img == src || img == other || !strings.HasPrefix(img, "<!-- warden:"+p.String()+":") ||
		strings.Contains(img, "acme") {
		t.Fatal(src, img, other)
	}
}

func FuzzCommentRow(f *testing.F) {
	for _, h := range hostile {
		f.Add(h, h, h, h)
	}
	c := bodyClient()
	f.Fuzz(func(t *testing.T, key, title, rule, path string) {
		line := 3
		row := c.commentRow(issue{ID: uuid.NewString(), Key: key, Title: title, Severity: "high", RuleID: rule, FilePath: &path, StartLine: &line},
			true, "https://warden.example", c.o.org.String())
		if !strings.HasSuffix(row, "|\n") || strings.Count(row, "\n") != 1 {
			t.Fatalf("%q", row)
		}
		checkRow(t, row)
		if len(row) > 4*(maxKey+maxTitle+maxRule+maxLocation)*2+200 {
			t.Fatal(fmt.Sprint(len(row)))
		}
	})
}
