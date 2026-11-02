package intel

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"errors"
	"fmt"
	"hash/crc32"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// zipEntry is one archive member for the test archives. raw entries are
// written with CreateRaw, so the header can lie about the body.
type zipEntry struct {
	name string
	body string
	mode fs.FileMode
	raw  *zip.FileHeader
	data []byte // raw compressed body
}

func buildZip(t *testing.T, entries ...zipEntry) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for _, e := range entries {
		if e.raw != nil {
			fw, err := w.CreateRaw(e.raw)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fw.Write(e.data); err != nil {
				t.Fatal(err)
			}
			continue
		}
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		if e.mode != 0 {
			h.SetMode(e.mode)
		}
		fw, err := w.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte(e.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func parseZip(t *testing.T, eco string, lim osvLimits, entries ...zipEntry) (OSVResult, error) {
	t.Helper()
	z := buildZip(t, entries...)
	return parseOSV(bytes.NewReader(z), int64(len(z)), eco, lim)
}

const modified = "2026-10-01T10:00:00Z"

// advisory builds a MAL record; affected is the raw JSON of its affected list.
func advisory(id, affected string) string {
	return fmt.Sprintf(`{"schema_version":"1.5.0","id":%q,"published":"2026-09-30T00:00:00Z","modified":%q,
		"summary":"Malicious code in pkg","details":"long text","affected":%s,"database_specific":{"x":[1,2,3]}}`,
		id, modified, affected)
}

func allVersions(eco, name string) string {
	return fmt.Sprintf(`[{"package":{"ecosystem":%q,"name":%q},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]`, eco, name)
}

func listed(eco, name string, versions ...string) string {
	q := make([]string, len(versions))
	for i, v := range versions {
		q[i] = fmt.Sprintf("%q", v)
	}
	return fmt.Sprintf(`[{"package":{"ecosystem":%q,"name":%q},"versions":[%s]}]`, eco, name, strings.Join(q, ","))
}

func mal(id, affected string) zipEntry {
	return zipEntry{name: id + ".json", body: advisory(id, affected)}
}

func TestParseOSVForms(t *testing.T) {
	res, err := parseZip(t, "npm", defaultOSVLimits,
		mal("MAL-2026-1", allVersions("npm", "evil-pkg")),
		mal("MAL-2026-2", listed("npm", "@Scope/Typo", "1.0.1", "1.0.0", "1.0.1")),
		// introduced 0 in any range means every version.
		mal("MAL-2026-3", `[{"package":{"ecosystem":"npm","name":"mixed"},"versions":["2.0.0"],
			"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"}]},{"type":"SEMVER","events":[{"introduced":"0"}]}]}]`),
		// A later introduced: never guessed; explicit versions still load.
		mal("MAL-2026-4", `[{"package":{"ecosystem":"npm","name":"later"},"ranges":[{"type":"SEMVER","events":[{"introduced":"1.2.2"}]}]}]`),
		mal("MAL-2026-5", `[{"package":{"ecosystem":"npm","name":"partial"},"versions":["3.0.0"],
			"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"3.0.1"}]}]}]`),
		zipEntry{name: "MAL-2026-6.json", body: `{"id":"MAL-2026-6","modified":"` + modified + `","withdrawn":"2026-10-02T00:00:00Z",
			"affected":` + allVersions("npm", "was-bad") + `}`},
		// GHSA and CVE entries are never opened (this one isn't even JSON).
		zipEntry{name: "GHSA-aaaa-bbbb-cccc.json", body: "not json"},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"MAL-2026-1 npm evil-pkg all=true []",
		"MAL-2026-2 npm @scope/typo all=false [1.0.0 1.0.1]",
		"MAL-2026-3 npm mixed all=true []",
		"MAL-2026-5 npm partial all=false [3.0.0]",
	}
	var got []string
	for _, p := range res.Packages {
		got = append(got, fmt.Sprintf("%s %s %s all=%v %v", p.ID, p.Ecosystem, p.MatchName, p.AllVersions, p.Versions))
		if p.Summary != "Malicious code in pkg" || p.Modified.Format(time.RFC3339) != modified || p.Published == nil {
			t.Errorf("%+v", p)
		}
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if res.Packages[1].Name != "@Scope/Typo" {
		t.Error("display name not kept")
	}
	if res.Advisories != 4 || res.Withdrawn != 1 || res.Unsupported != 1 || res.Partial != 1 || res.Skipped != 1 || res.Invalid != 0 {
		t.Fatalf("%+v", res)
	}
	if res.Updated.Format(time.RFC3339) != modified {
		t.Fatal(res.Updated)
	}
}

func TestParseOSVNormalizesForTheEcosystem(t *testing.T) {
	res, err := parseZip(t, "PyPI", defaultOSVLimits,
		mal("MAL-2026-10", `[{"package":{"ecosystem":"PyPI","name":"Requests_Toolbelt.X"},"versions":["1.0RC1"]},
			{"package":{"ecosystem":"PyPI","name":"requests-toolbelt-x"},"versions":["2.0"]}]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Packages) != 1 {
		t.Fatalf("%+v", res.Packages)
	}
	p := res.Packages[0]
	if p.MatchName != "requests-toolbelt-x" || strings.Join(p.Versions, ",") != "1.0rc1,2.0" {
		t.Fatalf("%+v", p)
	}
}

func TestParseOSVEcosystemMismatch(t *testing.T) {
	// An npm advisory in the PyPI file (or an advisory listing a package of
	// another ecosystem) never lands under the file's ecosystem.
	res, err := parseZip(t, "PyPI", defaultOSVLimits,
		mal("MAL-2026-20", allVersions("npm", "requests")),
		mal("MAL-2026-21", allVersions("pypi", "requests")), // case matters
		mal("MAL-2026-22", allVersions("PyPI", "real-one")))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Packages) != 1 || res.Packages[0].MatchName != "real-one" || res.OtherEcosystem != 2 || res.Advisories != 1 {
		t.Fatalf("%+v", res)
	}
	if _, err := parseZip(t, "npm/../x", defaultOSVLimits, mal("MAL-2026-1", allVersions("npm", "a"))); err == nil {
		t.Fatal("unknown ecosystem accepted")
	}
}

// corrupt is an entry whose body fails to inflate and whose CRC is wrong:
// opening it would count it invalid.
func corrupt(name string) zipEntry {
	if strings.HasSuffix(name, "/") { // a directory entry has no body
		return zipEntry{raw: &zip.FileHeader{Name: name, Method: zip.Store}}
	}
	return zipEntry{raw: &zip.FileHeader{Name: name, Method: zip.Deflate, CRC32: 1, CompressedSize64: 4, UncompressedSize64: 10},
		data: []byte{0xff, 0xff, 0xff, 0xff}}
}

func TestParseOSVNeverOpensOtherNames(t *testing.T) {
	names := []string{
		"../MAL-2026-1.json", "x/MAL-2026-1.json", "/MAL-2026-1.json", `..\MAL-2026-1.json`, `osv\MAL-2026-1.json`,
		"MAL-2026-1.json/", "MAL-2026-1.json.exe", "MAL-2026-1.JSON", " MAL-2026-1.json", "MAL-2026-1.json\x00",
		"MAL-26-1.json", "MAL-2026-123456789.json", "MAL-2026-1\n.json", "mal-2026-1.json", "MAL-2026-1.json ",
	}
	var entries []zipEntry
	for _, n := range names {
		entries = append(entries, corrupt(n))
	}
	entries = append(entries, mal("MAL-2026-2", allVersions("npm", "ok")))
	res, err := parseZip(t, "npm", defaultOSVLimits, entries...)
	if err != nil {
		t.Fatal(err)
	}
	if res.Skipped != len(names) || res.Invalid != 0 || len(res.Packages) != 1 {
		t.Fatalf("%+v", res)
	}
	// The same corrupt body under a MAL name is opened (and fails).
	res, err = parseZip(t, "npm", defaultOSVLimits, corrupt("MAL-2026-1.json"), mal("MAL-2026-2", allVersions("npm", "ok")))
	if err != nil || res.Invalid != 1 {
		t.Fatalf("%+v %v", res, err)
	}
}

func deflated(t *testing.T, n int) []byte {
	t.Helper()
	var b bytes.Buffer
	w, _ := flate.NewWriter(&b, flate.BestCompression)
	chunk := make([]byte, 1<<20)
	for i := 0; i < n; i += len(chunk) {
		if _, err := w.Write(chunk[:min(len(chunk), n-i)]); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestParseOSVZipBomb(t *testing.T) {
	const inflated = 200 << 20
	bomb := deflated(t, inflated)
	crc := crc32.ChecksumIEEE(make([]byte, 0)) // irrelevant: never fully read
	honest := zipEntry{raw: &zip.FileHeader{Name: "MAL-2026-1.json", Method: zip.Deflate, CRC32: crc,
		CompressedSize64: uint64(len(bomb)), UncompressedSize64: inflated}, data: bomb}
	// The header lies: small declared sizes, the body still inflates to 200 MiB.
	lying := zipEntry{raw: &zip.FileHeader{Name: "MAL-2026-2.json", Method: zip.Deflate, CRC32: crc,
		CompressedSize64: uint64(len(bomb)), UncompressedSize64: uint64(len(bomb)) * 2}, data: bomb}
	ok := mal("MAL-2026-3", allVersions("npm", "ok"))
	start := time.Now()
	res, err := parseZip(t, "npm", defaultOSVLimits, honest, lying, ok)
	if err != nil {
		t.Fatal(err)
	}
	if res.Invalid != 2 || len(res.Packages) != 1 {
		t.Fatalf("%+v", res)
	}
	if time.Since(start) > 20*time.Second {
		t.Fatal("bomb was inflated")
	}

	// A lying header within the ratio: the per-entry cap stops the read.
	lim := defaultOSVLimits
	lim.entry = 64 << 10
	big := deflated(t, 1<<20)
	res, err = parseZip(t, "npm", lim, zipEntry{raw: &zip.FileHeader{Name: "MAL-2026-4.json", Method: zip.Deflate,
		CompressedSize64: uint64(len(big)), UncompressedSize64: uint64(len(big))}, data: big}, ok)
	if err != nil || res.Invalid != 1 {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestParseOSVOversizedEntry(t *testing.T) {
	lim := defaultOSVLimits
	lim.entry = 4 << 10
	// Realistic JSON (low compression ratio) just over the cap.
	var huge strings.Builder
	for i := 0; int64(huge.Len()) <= lim.entry; i++ {
		fmt.Fprintf(&huge, `"%d.%d.%d-%x",`, i, i*7, i*13, i*104729)
	}
	body := `{"id":"MAL-2026-1","modified":"` + modified + `","affected":[{"package":{"ecosystem":"npm","name":"x"},"versions":[` +
		strings.TrimSuffix(huge.String(), ",") + `]}]}`
	res, err := parseZip(t, "npm", lim, zipEntry{name: "MAL-2026-1.json", body: body}, mal("MAL-2026-2", allVersions("npm", "ok")))
	if err != nil || res.Invalid != 1 || len(res.Packages) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestParseOSVTotalCap(t *testing.T) {
	lim := defaultOSVLimits
	lim.total = 1000
	var entries []zipEntry
	for i := range 10 {
		entries = append(entries, mal(fmt.Sprintf("MAL-2026-%d", i+1), allVersions("npm", fmt.Sprintf("p%d", i))))
	}
	if _, err := parseZip(t, "npm", lim, entries...); !errors.Is(err, ErrTooLarge) {
		t.Fatal(err)
	}
}

func TestParseOSVTooManyVersions(t *testing.T) {
	versions := make([]string, MaxOSVVersions+1)
	for i := range versions {
		versions[i] = fmt.Sprintf("1.0.%d", i)
	}
	res, err := parseZip(t, "npm", defaultOSVLimits,
		mal("MAL-2026-1", listed("npm", "many", versions...)),
		mal("MAL-2026-2", listed("npm", "enough", versions[:MaxOSVVersions]...)))
	if err != nil {
		t.Fatal(err)
	}
	if res.Invalid != 1 || len(res.Packages) != 1 || len(res.Packages[0].Versions) != MaxOSVVersions {
		t.Fatalf("invalid %d, packages %d", res.Invalid, len(res.Packages))
	}
}

func TestParseOSVMalformedEntries(t *testing.T) {
	bad := []zipEntry{
		{name: "MAL-2026-1.json", body: `{"id":"MAL-2026-1",`},
		{name: "MAL-2026-2.json", body: advisory("MAL-2026-2", allVersions("npm", "a")) + `{"id":"MAL-2026-99"}`}, // trailing record
		{name: "MAL-2026-3.json", body: advisory("MAL-2026-999", allVersions("npm", "a"))},                        // id ≠ name
		{name: "MAL-2026-4.json", body: `{"id":"MAL-2026-4","modified":"yesterday","affected":` + allVersions("npm", "a") + `}`},
		{name: "MAL-2026-5.json", body: `{"id":"MAL-2026-5","modified":"2999-01-01T00:00:00Z","affected":` + allVersions("npm", "a") + `}`},
		{name: "MAL-2026-6.json", body: `{"id":"MAL-2026-6","modified":"` + modified + `","affected":"npm"}`},
		{name: "MAL-2026-7.json", body: `[]`},
		mal("MAL-2026-8", allVersions("npm", "evil\u202egpj.exe")), // bidi override in the name
		mal("MAL-2026-9", allVersions("npm", "a\nb")),
		mal("MAL-2026-10", allVersions("npm", strings.Repeat("a", maxOSVName+1))),
		mal("MAL-2026-11", allVersions("npm", "")),
		mal("MAL-2026-12", listed("npm", "only-bad-versions", "1.0.0\x00", strings.Repeat("9", maxOSVVersion+1))),
		{name: "MAL-2026-13.json", body: advisory("MAL-2026-13", allVersions("npm", "link")), mode: fs.ModeSymlink | 0o777},
	}
	good := []zipEntry{}
	for i := range 2000 {
		good = append(good, mal(fmt.Sprintf("MAL-2025-%d", i+1), allVersions("npm", fmt.Sprintf("good-%d", i))))
	}
	res, err := parseZip(t, "npm", defaultOSVLimits, append(bad, good...)...)
	if err != nil {
		t.Fatal(err)
	}
	if res.Invalid != len(bad) || len(res.Packages) != len(good) || len(res.InvalidSamples) != 5 {
		t.Fatalf("invalid %d %v, packages %d", res.Invalid, res.InvalidSamples, len(res.Packages))
	}
	for _, s := range res.InvalidSamples {
		if len(s) > 200 {
			t.Fatalf("sample not cut: %d bytes", len(s))
		}
	}
	// More than 1% invalid: the file is rejected.
	if _, err := parseZip(t, "npm", defaultOSVLimits, append(bad, good[:100]...)...); err == nil {
		t.Fatal("mostly broken feed accepted")
	}
}

func TestParseOSVVersionsDropHostileValues(t *testing.T) {
	res, err := parseZip(t, "npm", defaultOSVLimits, mal("MAL-2026-1", listed("npm", "x", "1.0.0", "1.0.0\u202e", " 2.0.0 ", "")))
	if err != nil || len(res.Packages) != 1 || strings.Join(res.Packages[0].Versions, ",") != "1.0.0,2.0.0" {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestParseOSVSummaryIsPlainText(t *testing.T) {
	body := `{"id":"MAL-2026-1","modified":"` + modified + `","summary":"line1\n\tline2 \u202eevil\u0007 ` +
		strings.Repeat("x", 2000) + `","affected":` + allVersions("npm", "a") + `}`
	res, err := parseZip(t, "npm", defaultOSVLimits, zipEntry{name: "MAL-2026-1.json", body: body})
	if err != nil || len(res.Packages) != 1 {
		t.Fatal(res, err)
	}
	s := res.Packages[0].Summary
	if !strings.HasPrefix(s, "line1 line2 evil x") || len([]rune(s)) != maxOSVSummary || !printableName(s) {
		t.Fatalf("%q", s)
	}
}

func TestParseOSVArchiveLevelFailures(t *testing.T) {
	ok := mal("MAL-2026-1", allVersions("npm", "a"))
	if _, err := parseOSV(bytes.NewReader([]byte("<html>error</html>")), 18, "npm", defaultOSVLimits); err == nil {
		t.Error("not a zip accepted")
	}
	if _, err := parseZip(t, "npm", defaultOSVLimits); err == nil {
		t.Error("empty archive accepted")
	}
	if _, err := parseZip(t, "npm", defaultOSVLimits, ok, ok); err == nil {
		t.Error("duplicate entry accepted")
	}
	lim := defaultOSVLimits
	lim.entries = 3
	entries := []zipEntry{ok, corrupt("a"), corrupt("b"), corrupt("c")}
	if _, err := parseZip(t, "npm", lim, entries...); !errors.Is(err, ErrTooLarge) {
		t.Errorf("entry cap: %v", err)
	}
	// A central directory bigger than the budget stops zip.NewReader
	// before it has allocated a File per record.
	lim = defaultOSVLimits
	lim.directory = 64 << 10
	entries = nil
	for i := range 3000 {
		entries = append(entries, zipEntry{name: fmt.Sprintf("f%d", i)})
	}
	if _, err := parseZip(t, "npm", lim, entries...); !errors.Is(err, ErrTooLarge) {
		t.Errorf("directory budget: %v", err)
	}
	// Truncated archive.
	z := buildZip(t, ok)
	if _, err := parseOSV(bytes.NewReader(z[:len(z)-30]), int64(len(z)-30), "npm", defaultOSVLimits); err == nil {
		t.Error("truncated archive accepted")
	}
}

func TestParseOSVMaliciousFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "npm.zip")
	if err := os.WriteFile(path, buildZip(t, mal("MAL-2026-1", allVersions("npm", "a"))), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fi, _ := f.Stat()
	res, err := ParseOSVMalicious(f, fi.Size(), "npm")
	if err != nil || len(res.Packages) != 1 {
		t.Fatal(res, err)
	}
}

func TestCleanText(t *testing.T) {
	for in, want := range map[string]string{
		"":                 "",
		"  a  b ":          "a b",
		"a\u200bb":         "a b", // zero-width space is a format character
		"\xff\xfeok":       "ok",
		"ünï\tcode\r\nend": "ünï code end",
	} {
		if got := cleanText(in, 100); got != want {
			t.Errorf("cleanText(%q) = %q, want %q", in, got, want)
		}
	}
	if got := cleanText("abc def", 4); got != "abc " && got != "abc" {
		t.Errorf("%q", got)
	}
}
