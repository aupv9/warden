package main

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

// FuzzCommentBody renders a whole comment from hostile gate fields: the
// body stays under its cap and valid UTF-8, every table row keeps its cells,
// text is escaped (no live @mention, reference, HTML or link) and code spans
// stay closed. checkBody holds the per-line rules.
func FuzzCommentBody(f *testing.F) {
	for i, h := range hostile {
		f.Add(h, hostile[(i+1)%len(hostile)], hostile[(i+2)%len(hostile)], hostile[(i+3)%len(hostile)], h, uint8(i), i%2 == 0)
	}
	c := bodyClient()
	// Fixed ids, so a failing input reproduces exactly.
	c.o.org = uuid.MustParse("00000000-0000-4000-8000-000000000001")
	c.o.project = uuid.MustParse("00000000-0000-4000-8000-000000000002")
	f.Fuzz(func(t *testing.T, title, rule, path, pkgVersion, status string, n uint8, kev bool) {
		if len(title)+len(rule)+len(path)+len(pkgVersion)+len(status) > 16<<10 {
			return
		}
		line := 12
		g := gate{Status: status, Finished: n%7 != 0, FailOn: []string{"critical", "high", "medium", "low", "info", status}[n%6],
			FailOnKEV: kev, KEV: int(n), Counts: map[string]int{"critical": int(n), "high": 1}}
		for i := range int(n % 40) {
			is := issue{ID: uuid.NewSHA1(uuid.Nil, []byte{byte(i)}).String(), Key: title, Title: title + rule, Severity: rule,
				RuleID: rule, KEV: i%3 == 0}
			if i%3 == 1 { // imported: the tool name is hostile too
				is.ExternalTool = &pkgVersion
			}
			if i%5 == 0 {
				is.ID = path // not a UUID: never a link
			}
			if i%2 == 0 {
				is.FilePath, is.StartLine = &path, &line
			} else {
				is.PackageName, is.PackageVersion = &path, &pkgVersion
			}
			g.Blocking = append(g.Blocking, is)
			if i%4 == 0 {
				g.BlockingNew = append(g.BlockingNew, is.ID)
			}
		}
		body := c.commentBody(g, uuid.NewSHA1(uuid.Nil, []byte(status)).String())
		checkBody(t, c, body)
		// Text rendered as Markdown never reaches the comment as a raw link
		// (in code spans, which the rule and location are, nothing is linked).
		for _, s := range []string{title, status} {
			if strings.Contains(s, "://") && len(s) > 12 && strings.Contains(body, s) {
				t.Fatalf("raw input %q in the body", s)
			}
		}
	})
}
