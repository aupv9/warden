package intel

import (
	"archive/zip"
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/aupv9/warden/backend/internal/domain/ecosystem"
)

// FuzzParseKEV: an accepted catalog has a sane release date and only valid,
// unique entries, sorted by CVE.
func FuzzParseKEV(f *testing.F) {
	ok := kevEntryJSONText(cve(1), "2024-03-01", "2024-03-22", "Unknown")
	f.Add(kevDoc(ok, kevEntryJSONText(cve(2), "2023-11-03", "", "Known")))
	f.Add(kevDoc(ok, ok))
	f.Add(`{"dateReleased":"2026-10-26T22:24:24Z","vulnerabilities":[` + ok + `],"vulnerabilities":[]}`)
	f.Add(kevDoc(kevEntryJSONText(cve(1)+"\n", "2024-02-30", "03/22/2024", "maybe")))
	f.Fuzz(func(t *testing.T, doc string) {
		if len(doc) > 64<<10 {
			return
		}
		k, err := ParseKEV(strings.NewReader(doc))
		if err != nil {
			return
		}
		if !saneDate(k.Released) || len(k.Entries) == 0 || len(k.Entries) > MaxKEVEntries {
			t.Fatalf("catalog %v with %d entries", k.Released, len(k.Entries))
		}
		for i, e := range k.Entries {
			if !CVE.MatchString(e.CVE) || !saneDate(e.Added) || (!e.Due.IsZero() && !saneDate(e.Due)) {
				t.Fatalf("entry %+v", e)
			}
			if i > 0 && k.Entries[i-1].CVE >= e.CVE {
				t.Fatalf("entries not sorted and unique: %s, %s", k.Entries[i-1].CVE, e.CVE)
			}
		}
	})
}

// checkEPSS: scores in [0, 1], valid unique CVEs sorted, a printable model.
func checkEPSS(t *testing.T, e EPSS, err error, lim epssLimits) {
	t.Helper()
	if err != nil {
		return
	}
	if !saneDate(e.ScoreDate) || len(e.ModelVersion) > maxField || !printable(e.ModelVersion) || len(e.Scores) == 0 || len(e.Scores) > lim.rows {
		t.Fatalf("EPSS %q %v %d scores", e.ModelVersion, e.ScoreDate, len(e.Scores))
	}
	for i, s := range e.Scores {
		if !CVE.MatchString(s.CVE) || !(s.Score >= 0 && s.Score <= 1) || !(s.Percentile >= 0 && s.Percentile <= 1) {
			t.Fatalf("score %+v", s)
		}
		if i > 0 && e.Scores[i-1].CVE >= s.CVE {
			t.Fatalf("scores not sorted and unique: %s, %s", e.Scores[i-1].CVE, s.CVE)
		}
	}
}

const epssText = "#model_version:v2025.03.14,score_date:2025-10-27T12:03:15Z\ncve,epss,percentile\nCVE-2024-00001,0.5,0.9\nCVE-2024-00002,1e-3,0x1p-2\n"

// FuzzParseEPSS fuzzes the CSV (compressed in the fuzz function, so the
// fuzzer works on the text) with small caps.
func FuzzParseEPSS(f *testing.F) {
	f.Add(epssText)
	f.Add("#model_version:v1,score_date:2025-10-27\ncve,epss,percentile\nCVE-2024-00001,NaN,Inf\n")
	f.Add("#score_date:2025-10-27T12:03:15+0000\ncve,epss,percentile\nCVE-2024-00001,0.1,0.1\nCVE-2024-00001,0.1,0.1\n")
	f.Add("#model_version:\x1b[31m,score_date:2025-10-27\ncve,epss,percentile\n")
	lim := epssLimits{compressed: 32 << 10, decompressed: 64 << 10, rows: 100}
	f.Fuzz(func(t *testing.T, text string) {
		if len(text) > 128<<10 {
			return
		}
		e, err := parseEPSS(bytes.NewReader(gz(t, text)), lim)
		checkEPSS(t, e, err, lim)
	})
}

// FuzzParseEPSSRaw feeds the bytes as the file itself (gzip framing, bombs).
func FuzzParseEPSSRaw(f *testing.F) {
	f.Add(gz(f, epssText))
	f.Add(gz(f, epssText+strings.Repeat("x", 1<<16)))
	f.Add([]byte{0x1f, 0x8b})
	lim := epssLimits{compressed: 32 << 10, decompressed: 64 << 10, rows: 100}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			return
		}
		e, err := parseEPSS(bytes.NewReader(data), lim)
		checkEPSS(t, e, err, lim)
	})
}

// FuzzParseTrivyMeta: a date is returned only when it is sane.
func FuzzParseTrivyMeta(f *testing.F) {
	f.Add(`{"Version":2,"NextUpdate":"2026-10-28T06:18:21Z","UpdatedAt":"2026-10-27T06:18:21.123Z"}`)
	f.Add(`{"UpdatedAt":"0001-01-01T00:00:00Z"}`)
	f.Fuzz(func(t *testing.T, doc string) {
		if tm, err := ParseTrivyMeta(strings.NewReader(doc)); err == nil && (!saneDate(tm) || tm.Location().String() != "UTC") {
			t.Fatalf("UpdatedAt %v", tm)
		}
	})
}

func osvZip(entries map[string][]byte) []byte {
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	names := make([]string, 0, len(entries))
	for n := range entries {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		fw, err := w.CreateHeader(&zip.FileHeader{Name: n, Method: zip.Deflate})
		if err != nil {
			continue
		}
		_, _ = fw.Write(entries[n])
	}
	_ = w.Close()
	return b.Bytes()
}

// checkOSV: what the store gets is valid for the malicious_package
// constraints, normalized as ecosystem says, sorted and unique.
func checkOSV(t *testing.T, eco string, r OSVResult, err error, lim osvLimits) {
	t.Helper()
	if err != nil {
		return
	}
	for i, p := range r.Packages {
		if !MaliciousID.MatchString(p.ID) || p.Ecosystem != eco {
			t.Fatalf("package %+v", p)
		}
		if p.Name == "" || utf8.RuneCountInString(p.Name) > maxOSVName || !printableName(p.Name) ||
			p.MatchName == "" || p.MatchName != ecosystem.MatchName(eco, p.Name) || utf8.RuneCountInString(p.MatchName) > maxOSVName {
			t.Fatalf("name %q / %q", p.Name, p.MatchName)
		}
		if p.AllVersions == (len(p.Versions) > 0) || len(p.Versions) > lim.versions {
			t.Fatalf("all=%v versions=%d", p.AllVersions, len(p.Versions))
		}
		if !slices.IsSorted(p.Versions) || len(slices.Compact(slices.Clone(p.Versions))) != len(p.Versions) {
			t.Fatalf("versions %q", p.Versions)
		}
		for _, v := range p.Versions {
			if v == "" || !printableName(v) || len(v) > maxOSVVersion || ecosystem.MatchVersion(eco, v) != v && eco != ecosystem.Go {
				t.Fatalf("version %q", v)
			}
		}
		if utf8.RuneCountInString(p.Summary) > maxOSVSummary || !utf8.ValidString(p.Summary) || strings.TrimSpace(p.Summary) != p.Summary ||
			strings.Contains(p.Summary, "  ") || strings.ContainsFunc(p.Summary, func(r rune) bool { return !unicode.IsPrint(r) && r != ' ' }) {
			t.Fatalf("summary %q", p.Summary)
		}
		if !saneDate(p.Modified) || (p.Published != nil && !saneDate(*p.Published)) || p.Modified.After(r.Updated) {
			t.Fatalf("dates %v %v (updated %v)", p.Modified, p.Published, r.Updated)
		}
		if i > 0 {
			a, b := r.Packages[i-1], p
			if a.ID > b.ID || (a.ID == b.ID && a.MatchName >= b.MatchName) {
				t.Fatalf("packages not sorted and unique: %s/%s, %s/%s", a.ID, a.MatchName, b.ID, b.MatchName)
			}
		}
	}
	if r.Advisories > 0 && len(r.Packages) == 0 {
		t.Fatalf("%d advisories, no packages", r.Advisories)
	}
}

var fuzzOSVLimits = osvLimits{entries: 64, directory: 64 << 10, entry: 16 << 10, total: 256 << 10, versions: 50}

// FuzzParseOSV fuzzes one advisory's JSON inside a well-formed archive.
func FuzzParseOSV(f *testing.F) {
	f.Add("npm", "MAL-2026-1", advisory("MAL-2026-1", allVersions("npm", "evil-pkg")))
	f.Add("PyPI", "MAL-2026-2", advisory("MAL-2026-2", listed("PyPI", "Evil_Pkg", "1.0", " 1.0 ", "1.0RC1", "\x1b[31m")))
	f.Add("Go", "MAL-2026-3", advisory("MAL-2026-3", `[{"package":{"ecosystem":"Go","name":"github.com/a/b"},"versions":["v1.0.0","1.0.0"],
		"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2"}]}]},{"package":{"ecosystem":"Go","name":"GitHub.com/A/B"},"versions":["v2"]}]`))
	f.Add("crates.io", "MAL-2026-4", `{"id":"MAL-2026-4","modified":"2026-10-01T10:00:00Z","withdrawn":"2026-10-02T00:00:00Z","affected":[]}`)
	f.Add("npm", "MAL-2026-5", `{"id":"MAL-2026-5","modified":"1999-01-01T00:00:00Z","summary":"a\u202eb\n\tc   d","affected":[{"package":{"ecosystem":"npm","name":"x"},"versions":[]}]}`)
	f.Fuzz(func(t *testing.T, eco, id, body string) {
		if len(body) > 16<<10 || !ecosystem.IsOSV(eco) {
			return
		}
		z := osvZip(map[string][]byte{id + ".json": []byte(body), "GHSA-xxxx.json": []byte("{}")})
		r, err := parseOSV(bytes.NewReader(z), int64(len(z)), eco, fuzzOSVLimits)
		checkOSV(t, eco, r, err, fuzzOSVLimits)
	})
}

// FuzzParseOSVRaw feeds arbitrary bytes as the archive (forged directories,
// lying sizes, bombs).
func FuzzParseOSVRaw(f *testing.F) {
	f.Add(osvZip(map[string][]byte{"MAL-2026-1.json": []byte(advisory("MAL-2026-1", allVersions("npm", "evil-pkg"))),
		"MAL-2026-2.json": []byte(advisory("MAL-2026-2", listed("npm", "x", "1.0"))), "../MAL-2026-3.json": []byte("{}")}))
	f.Add(osvZip(map[string][]byte{"MAL-2026-1.json": bytes.Repeat([]byte(" "), 1<<15)}))
	f.Add([]byte("PK\x05\x06" + strings.Repeat("\x00", 18)))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			return
		}
		r, err := parseOSV(bytes.NewReader(data), int64(len(data)), ecosystem.Npm, fuzzOSVLimits)
		if err != nil && errors.Is(err, ErrTooLarge) {
			return
		}
		checkOSV(t, ecosystem.Npm, r, err, fuzzOSVLimits)
	})
}
