package intel

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

// Feeds are built at test time from synthetic CVE ids.

func cve(n int) string { return fmt.Sprintf("CVE-2024-%05d", n) }

func kevEntryJSONText(id, added, due, ransomware string) string {
	return fmt.Sprintf(`{"cveID":%q,"vendorProject":"Acme","product":"Widget","dateAdded":%q,"dueDate":%q,
		"knownRansomwareCampaignUse":%q,"notes":"","cwes":["CWE-20"]}`, id, added, due, ransomware)
}

func kevDoc(entries ...string) string {
	return `{"title":"CISA Catalog of Known Exploited Vulnerabilities","catalogVersion":"2026.10.26",
		"dateReleased":"2026-10-26T22:24:24.6101Z","count":` + fmt.Sprint(len(entries)) + `,
		"vulnerabilities":[` + strings.Join(entries, ",") + `]}`
}

func TestParseKEV(t *testing.T) {
	doc := kevDoc(
		kevEntryJSONText(cve(2), "2024-03-01", "2024-03-22", "Unknown"),
		kevEntryJSONText(cve(1), "2023-11-03", "", "Known"),
	)
	k, err := ParseKEV(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if !k.Released.Equal(time.Date(2026, 10, 26, 22, 24, 24, 610100000, time.UTC)) || len(k.Entries) != 2 {
		t.Fatalf("%+v", k)
	}
	first, second := k.Entries[0], k.Entries[1] // sorted by CVE
	if first.CVE != cve(1) || !first.Ransomware || !first.Due.IsZero() || first.Added.Format(time.DateOnly) != "2023-11-03" {
		t.Fatalf("%+v", first)
	}
	if second.CVE != cve(2) || second.Ransomware || second.Due.Format(time.DateOnly) != "2024-03-22" {
		t.Fatalf("%+v", second)
	}
}

func TestParseKEVRejectsHostileInput(t *testing.T) {
	ok := kevEntryJSONText(cve(1), "2024-03-01", "2024-03-22", "Unknown")
	cases := map[string]string{
		"not json":            `<html>`,
		"array":               `[]`,
		"no entries":          kevDoc(),
		"no dateReleased":     `{"vulnerabilities":[` + ok + `]}`,
		"bad dateReleased":    strings.Replace(kevDoc(ok), "2026-10-26T22:24:24.6101Z", "yesterday", 1),
		"far future released": strings.Replace(kevDoc(ok), "2026-10-26T22", "2999-10-26T22", 1),
		"vulns not an array":  `{"dateReleased":"2026-10-26T22:24:24Z","vulnerabilities":{}}`,
		"vulns null":          `{"dateReleased":"2026-10-26T22:24:24Z","vulnerabilities":null}`,
		"entry null":          kevDoc("null"),
		"entry wrong type":    kevDoc(`{"cveID":12345,"dateAdded":"2024-03-01","knownRansomwareCampaignUse":"Unknown"}`),
		"bad cve":             kevDoc(kevEntryJSONText("CVE-24-1", "2024-03-01", "", "Unknown")),
		"cve with suffix":     kevDoc(kevEntryJSONText(cve(1)+"\n", "2024-03-01", "", "Unknown")),
		"cve injection":       kevDoc(kevEntryJSONText(cve(1)+"'; DROP TABLE issue;--", "2024-03-01", "", "Unknown")),
		"huge cve":            kevDoc(kevEntryJSONText(strings.Repeat("A", 1<<20), "2024-03-01", "", "Unknown")),
		"missing dateAdded":   kevDoc(kevEntryJSONText(cve(1), "", "", "Unknown")),
		"bad dateAdded":       kevDoc(kevEntryJSONText(cve(1), "2024-02-30", "", "Unknown")),
		"ancient dateAdded":   kevDoc(kevEntryJSONText(cve(1), "0001-01-01", "", "Unknown")),
		"bad dueDate":         kevDoc(kevEntryJSONText(cve(1), "2024-03-01", "03/22/2024", "Unknown")),
		"bad ransomware":      kevDoc(kevEntryJSONText(cve(1), "2024-03-01", "", "maybe")),
		"duplicate cve":       kevDoc(ok, ok),
		"duplicate key":       `{"dateReleased":"2026-10-26T22:24:24Z","vulnerabilities":[` + ok + `],"vulnerabilities":[]}`,
		"trailing data":       kevDoc(ok) + `{}`,
		"truncated":           kevDoc(ok)[:200],
		"deep nesting":        `{"dateReleased":"2026-10-26T22:24:24Z","x":` + strings.Repeat("[", 20000) + strings.Repeat("]", 20000) + `,"vulnerabilities":[` + ok + `]}`,
	}
	for name, doc := range cases {
		if _, err := ParseKEV(strings.NewReader(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseKEVLimits(t *testing.T) {
	// One entry more than the cap, each small: rejected by count, not size.
	entries := make([]string, MaxKEVEntries+1)
	for i := range entries {
		entries[i] = fmt.Sprintf(`{"cveID":"CVE-2024-%07d","dateAdded":"2024-03-01","knownRansomwareCampaignUse":"Unknown"}`, i)
	}
	if _, err := ParseKEV(strings.NewReader(kevDoc(entries...))); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("entries: %v", err)
	}
	if _, err := ParseKEV(strings.NewReader(kevDoc(entries[:MaxKEVEntries]...))); err != nil {
		t.Fatalf("at the cap: %v", err)
	}
	// An oversized file is cut off at the cap while streaming.
	r := &countingReader{r: io.MultiReader(strings.NewReader(`{"x":"`), zeros{})}
	if _, err := ParseKEV(r); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("size: %v", err)
	}
	if r.n > MaxKEVBytes+1<<20 {
		t.Fatalf("read %d bytes past the cap", r.n-MaxKEVBytes)
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = '0'
	}
	return len(p), nil
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func gz(t testing.TB, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := io.WriteString(w, s); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

const epssHead = "#model_version:v2026.06.15,score_date:2026-10-27T12:03:15Z\n"

func epssDoc(rows ...string) string {
	return epssHead + "cve,epss,percentile\n" + strings.Join(rows, "\n") + "\n"
}

func TestParseEPSS(t *testing.T) {
	e, err := ParseEPSS(bytes.NewReader(gz(t, epssDoc(cve(2)+",0.27183,0.98043", cve(1)+",0.04753,0.91834", cve(3)+",1,0"))))
	if err != nil {
		t.Fatal(err)
	}
	if e.ModelVersion != "v2026.06.15" || !e.ScoreDate.Equal(time.Date(2026, 10, 27, 12, 3, 15, 0, time.UTC)) || len(e.Scores) != 3 {
		t.Fatalf("%+v", e)
	}
	if s := e.Scores[0]; s.CVE != cve(1) || s.Score != float32(0.04753) || s.Percentile != float32(0.91834) {
		t.Fatalf("%+v", s)
	}
	if s := e.Scores[2]; s.CVE != cve(3) || s.Score != 1 || s.Percentile != 0 {
		t.Fatalf("%+v", s)
	}
	// Older files wrote the offset without a colon; no trailing newline is fine.
	old := strings.Replace(epssDoc(cve(1)+",0.1,0.2"), "2026-10-27T12:03:15Z", "2022-03-14T00:00:00+0000", 1)
	e, err = ParseEPSS(bytes.NewReader(gz(t, strings.TrimSuffix(old, "\n"))))
	if err != nil || !e.ScoreDate.Equal(time.Date(2022, 3, 14, 0, 0, 0, 0, time.UTC)) {
		t.Fatal(e, err)
	}
}

func TestParseEPSSRejectsHostileInput(t *testing.T) {
	ok := cve(1) + ",0.1,0.2"
	raw := map[string][]byte{
		"not gzip":      []byte(epssDoc(ok)),
		"empty":         {},
		"truncated":     gz(t, epssDoc(ok))[:30],
		"bad checksum":  func() []byte { b := gz(t, epssDoc(ok)); b[len(b)-6] ^= 0xff; return b }(),
		"gzip trailing": append(gz(t, epssDoc(ok)), "garbage"...),
	}
	text := map[string]string{
		"no comment":          "cve,epss,percentile\n" + ok + "\n",
		"no score_date":       "#model_version:v1\ncve,epss,percentile\n" + ok + "\n",
		"bad score_date":      strings.Replace(epssDoc(ok), "2026-10-27T12:03:15Z", "soon", 1),
		"future score_date":   strings.Replace(epssDoc(ok), "2026-10-27", "2626-10-27", 1),
		"control in model":    strings.Replace(epssDoc(ok), "v2026.06.15", "v1\x1b[31m", 1),
		"bad header":          epssHead + "cve,score,percentile\n" + ok + "\n",
		"header only":         epssDoc(),
		"comment only":        epssHead,
		"missing field":       epssDoc(cve(1) + ",0.1"),
		"extra field":         epssDoc(ok + ",x"),
		"empty line":          epssDoc(ok, ""),
		"bad cve":             epssDoc("CVE-2024-1,0.1,0.2"),
		"lowercase cve":       epssDoc("cve-2024-00001,0.1,0.2"),
		"quoted cve":          epssDoc(`"` + cve(1) + `",0.1,0.2`),
		"score above 1":       epssDoc(cve(1) + ",1.5,0.2"),
		"score below 0":       epssDoc(cve(1) + ",-0.1,0.2"),
		"percentile above 1":  epssDoc(cve(1) + ",0.1,2"),
		"NaN":                 epssDoc(cve(1) + ",NaN,0.2"),
		"Inf":                 epssDoc(cve(1) + ",0.1,+Inf"),
		"not a number":        epssDoc(cve(1) + ",high,0.2"),
		"empty score":         epssDoc(cve(1) + ",,0.2"),
		"long number":         epssDoc(cve(1) + ",0." + strings.Repeat("1", 100) + ",0.2"),
		"duplicate cve":       epssDoc(ok, cve(2)+",0.3,0.4", ok),
		"long line":           epssDoc(cve(1) + ",0.1,0.2" + strings.Repeat(" ", 1000)),
		"long comment":        "#" + strings.Repeat("x", 10000) + "\n",
		"binary instead":      "\x00\x01\x02",
		"score with spaces":   epssDoc(cve(1) + ", 0.1,0.2"),
		"hex float too large": epssDoc(cve(1) + ",0x1p1,0.2"),
	}
	for name, s := range text {
		raw[name] = gz(t, s)
	}
	for name, b := range raw {
		if _, err := ParseEPSS(bytes.NewReader(b)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A gzip bomb is stopped while inflating: the parser never reads far into it.
func TestParseEPSSGzipBomb(t *testing.T) {
	// 1 MiB of one byte compresses to ~1 KiB; gzip readers accept concatenated
	// members, so 400 members inflate to 400 MiB from ~400 KiB.
	member := gz(t, strings.Repeat("0", 1<<20))
	var bomb bytes.Buffer
	bomb.Write(gz(t, epssHead+"cve,epss,percentile\n"))
	for range 400 {
		bomb.Write(member)
	}
	r := &countingReader{r: bytes.NewReader(bomb.Bytes())}
	if _, err := ParseEPSS(r); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("bomb: %v", err)
	}
	if r.n > int64(bomb.Len()/10) {
		t.Fatalf("read %d of %d compressed bytes before stopping", r.n, bomb.Len())
	}

	// The same with valid-looking rows: the decompressed cap stops it (tested
	// with small limits: 300 MiB of rows would hit the row cap first).
	var rows strings.Builder
	for i := range 20_000 {
		fmt.Fprintf(&rows, "CVE-2024-%07d,0.1,0.2\n", i)
	}
	lim := epssLimits{compressed: 1 << 20, decompressed: 64 << 10, rows: 1 << 30}
	if _, err := parseEPSS(bytes.NewReader(gz(t, epssHead+"cve,epss,percentile\n"+rows.String())), lim); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("decompressed cap: %v", err)
	}
	// Row cap.
	lim = epssLimits{compressed: 1 << 20, decompressed: 1 << 30, rows: 1000}
	if _, err := parseEPSS(bytes.NewReader(gz(t, epssHead+"cve,epss,percentile\n"+rows.String())), lim); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("row cap: %v", err)
	}
	// Compressed cap, with incompressible content.
	lim = epssLimits{compressed: 1 << 10, decompressed: 1 << 30, rows: 1 << 30}
	if _, err := parseEPSS(bytes.NewReader(gz(t, epssHead+"cve,epss,percentile\n"+rows.String())), lim); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("compressed cap: %v", err)
	}
	// The same input within the limits parses.
	if e, err := ParseEPSS(bytes.NewReader(gz(t, epssHead+"cve,epss,percentile\n"+rows.String()))); err != nil || len(e.Scores) != 20_000 {
		t.Fatal(err)
	}
}

func TestParseTrivyMeta(t *testing.T) {
	got, err := ParseTrivyMeta(strings.NewReader(`{"Version":2,"NextUpdate":"2026-10-26T12:57:48.463990841Z","UpdatedAt":"2026-10-25T12:57:48.463991102Z","DownloadedAt":"2026-10-25T16:54:03.646809706Z"}`))
	if err != nil || !got.Equal(time.Date(2026, 10, 25, 12, 57, 48, 463991102, time.UTC)) {
		t.Fatal(got, err)
	}
	for name, doc := range map[string]string{
		"empty":        ``,
		"no UpdatedAt": `{"Version":2}`,
		"wrong type":   `{"UpdatedAt":20261025}`,
		"bad time":     `{"UpdatedAt":"yesterday"}`,
		"huge":         `{"UpdatedAt":"2026-10-25T12:57:48Z","x":"` + strings.Repeat("a", MaxTrivyMetaBytes) + `"}`,
	} {
		if _, err := ParseTrivyMeta(strings.NewReader(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
