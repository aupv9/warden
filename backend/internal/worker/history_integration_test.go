//go:build integration

package worker

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/scan/redact"
	"github.com/aupv9/warden/backend/internal/scan/sandbox"
	st "github.com/aupv9/warden/backend/internal/scan/scantest"
)

// bundleBytes is a minimal git bundle: one ref and a framed pack (bundlecheck
// reads only the framing).
func bundleBytes() ([]byte, string) {
	var p bytes.Buffer
	p.WriteString("PACK\x00\x00\x00\x02\x00\x00\x00\x01")
	p.Write(bytes.Repeat([]byte{0x78}, 16))
	sum := sha1.Sum(p.Bytes())
	p.Write(sum[:])
	data := append([]byte("# v2 git bundle\n"+strings.Repeat("ab", 20)+" refs/heads/main\n\n"), p.Bytes()...)
	s := sha256.Sum256(data)
	return data, hex.EncodeToString(s[:])
}

// historyScan inserts a queued history scan, its bundle uploaded.
func (it *itest) historyScan() (uuid.UUID, string) {
	data, sha := bundleBytes()
	id := uuid.New()
	key := "scans/" + it.org.String() + "/" + id.String() + ".bundle"
	owner(it.t, it.org, fmt.Sprintf(`INSERT INTO scan (id, org_id, project_id, created_by, status, file_name, object_key, sha256, tools, kind, target)
		VALUES ('%s', '%s', '%s', '%s', 'queued', 'repo.bundle', '%s', '%s', '{gitleaks}', 'history', '(history)')`,
		id, it.org, it.project, it.user, key, sha))
	it.store.objects[key] = data
	return id, key
}

func redacted(t *testing.T, doc st.M) st.M {
	t.Helper()
	out, err := redact.Doc(st.RoundTrip(doc), st.HMACKey)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// A history scan runs Gitleaks in git mode with the configured limits, opens
// one issue per secret at its oldest commit, records the commit count, and
// fixes only history issues; source scans never touch them. When git in the
// sandbox finds commits missing, the scan is rejected as BUNDLE_INCOMPLETE.
func TestHistoryScanEndToEnd(t *testing.T) {
	it := newITest(t)
	it.env.Images = map[string]string{"gitleaks": "ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:" + strings.Repeat("c", 64)}
	it.env.Limits.HistoryMaxBytes, it.env.Limits.HistoryMaxCommits = 1<<20, 50
	commit := func(c byte, date string) st.Commit {
		return st.Commit{SHA: strings.Repeat(string(c), 40), Date: date, Author: "Alice", Email: "alice@x.test", Message: "add " + st.FakeSecret}
	}
	historyDoc := redacted(t, st.Doc([]any{
		st.HistoryResult("aws-access-token", "src/new.py", 2, st.FakeSecret, commit('b', "2025-01-01T00:00:00Z")),
		st.HistoryResult("aws-access-token", "src/config.py", 7, st.FakeSecret, commit('a', "2023-01-01T00:00:00Z")),
	}))
	states := func() (src, hist string) {
		it.one(fmt.Sprintf(`SELECT coalesce((SELECT status::text FROM issue WHERE project_id = '%s' AND target = ''), '-'),
			coalesce((SELECT status::text FROM issue WHERE project_id = '%s' AND target = '(history)'), '-')`, it.project, it.project), &src, &hist)
		return src, hist
	}
	source := func() {
		data, sha := zipBytes()
		id, key := it.scan("queued", sha, 0, "gitleaks")
		it.store.objects[key] = data
		it.sb.docs = map[string]st.M{"gitleaks": redacted(t, st.GitleaksDoc())}
		it.run(id)
	}
	history := func(report string) uuid.UUID {
		id, key := it.historyScan()
		it.sb.docs = map[string]st.M{"gitleaks": historyDoc}
		it.sb.files = map[string]string{"history.json": report}
		it.run(id)
		if !slices.Contains(it.store.deleted, key) {
			t.Fatalf("bundle not deleted: %v", it.store.deleted)
		}
		return id
	}

	source()
	h1 := history(`{"commits":50,"truncated":true}`)
	if s, h := states(); s != "open" || h != "open" {
		t.Fatal(s, h)
	}
	spec := it.sb.specs[len(it.sb.specs)-1]
	if !slices.Equal(spec.Command, []string{"warden-gitleaks", "history", "50"}) || !spec.NeedsHMACKey ||
		spec.Artifacts[sandbox.ArtifactHistory].File != "history.json" || spec.Timeout != it.env.ScanTimeout {
		t.Fatalf("history scan ran %+v", spec)
	}
	var status, sha, path string
	var count, commits, line int
	var truncated bool
	it.one(fmt.Sprintf(`SELECT s.status::text, s.history_commits, s.history_truncated, i.commit_sha, i.commit_count, i.file_path, i.start_line
		FROM scan s JOIN issue i ON i.first_seen_scan_id = s.id WHERE s.id = '%s'`, h1), &status, &commits, &truncated, &sha, &count, &path, &line)
	if status != "completed" || commits != 50 || !truncated || sha != strings.Repeat("a", 40) || count != 2 || path != "src/config.py" || line != 7 {
		t.Fatal(status, commits, truncated, sha, count, path, line)
	}

	it.sb.empty = true
	source() // finds nothing: fixes the source issue only
	if s, h := states(); s != "fixed" || h != "open" {
		t.Fatal(s, h)
	}
	history(`{"commits":3,"truncated":false}`) // gone from every commit: fixed
	if s, h := states(); s != "fixed" || h != "fixed" {
		t.Fatal(s, h)
	}

	// git in the sandbox found commits missing (a shallow clone's bundle).
	it.sb.empty = false
	it.sb.status["gitleaks"], it.sb.exitCode = sandbox.Failed, sandbox.ExitHistoryIncomplete
	id := history(`{"commits":3,"truncated":false}`)
	var code string
	it.one(fmt.Sprintf(`SELECT status::text, error_code FROM scan WHERE id = '%s'`, id), &status, &code)
	if status != "failed" || code != "BUNDLE_INCOMPLETE" {
		t.Fatal(status, code)
	}
	if _, h := states(); h != "fixed" {
		t.Fatal(h)
	}
}
