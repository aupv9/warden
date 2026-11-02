//go:build webui

package webui

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// The real build must work under Policy.CSP without 'unsafe-inline': no inline
// script or style, no event-handler or style attributes in the HTML, and
// every script and stylesheet loaded from /assets/. The Dockerfile runs this
// test on every image build.
func TestBundleNeedsNoInlineCode(t *testing.T) {
	dist := Embedded()
	index, err := fs.ReadFile(dist, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := strings.ToLower(string(index))
	if strings.Contains(html, "<style") || regexp.MustCompile(`\s(style|on[a-z]+)\s*=`).MatchString(html) {
		t.Fatalf("index.html has inline style or event handlers:\n%s", index)
	}
	scripts := regexp.MustCompile(`<script\b[^>]*>`).FindAllString(html, -1)
	if len(scripts) == 0 {
		t.Fatal("index.html loads no script")
	}
	for _, s := range scripts {
		if !regexp.MustCompile(`\ssrc="/assets/[a-z0-9._-]+\.js"`).MatchString(s) {
			t.Errorf("inline or foreign script: %s", s)
		}
	}
	for _, l := range regexp.MustCompile(`<link\b[^>]*>`).FindAllString(html, -1) {
		if !regexp.MustCompile(`\shref="/assets/[a-z0-9._-]+\.(js|css)"`).MatchString(l) {
			t.Errorf("foreign or inline link: %s", l)
		}
	}
	// Nothing in the bundle may need a source the policy doesn't list.
	err = fs.WalkDir(dist, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if strings.HasPrefix(d.Name(), ".") {
			t.Errorf("dotfile in the bundle: %s", p)
		}
		if !strings.HasSuffix(p, ".css") {
			return nil
		}
		b, err := fs.ReadFile(dist, p)
		if err != nil {
			return err
		}
		// img-src allows data:, font-src doesn't (frontend/vite.config.ts keeps
		// fonts as files); nothing may load from another origin.
		for _, m := range regexp.MustCompile(`url\(\s*['"]?([a-z]+:[a-z]*)`).FindAllStringSubmatch(string(b), -1) {
			if m[1] != "data:image" {
				t.Errorf("%s loads from %s", p, m[1])
			}
		}
		if strings.Contains(string(b), "@import") {
			t.Errorf("%s imports another stylesheet", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
