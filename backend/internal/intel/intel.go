// Package intel parses the exploit-intelligence feeds that scripts/sync-mirror.sh
// puts in the mirror: the CISA Known Exploited Vulnerabilities catalog (JSON),
// FIRST EPSS scores (csv.gz), and the Trivy DB's metadata.json.
//
// The files come from the internet, so the parsers treat them as hostile: every
// size, count and string is capped while reading (before anything is held in
// memory), every CVE id must match the regex the database checks, scores must
// be in [0, 1] and dates must be plausible. A file with a single bad record is
// rejected as a whole, so the loader keeps the previous data rather than
// loading part of a feed that someone may have tampered with.
package intel

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Limits. The real feeds are far below them (KEV ~2 MB / 2k entries, EPSS
// ~3 MB compressed / 12 MB / 300k rows in 2026).
const (
	MaxKEVBytes         = 20 << 20
	MaxKEVEntries       = 50_000
	MaxEPSSBytes        = 30 << 20 // compressed
	MaxEPSSDecompressed = 300 << 20
	MaxEPSSRows         = 1_000_000
	MaxTrivyMetaBytes   = 64 << 10

	// maxEPSSLine bounds one CSV line ("CVE-2026-1234567,0.12345,0.12345" is 34
	// bytes; the comment line is about 60).
	maxEPSSLine = 512
	// maxField bounds every string field of a KEV entry we keep.
	maxField = 64
)

// ErrTooLarge is wrapped by every size, count and length violation.
var ErrTooLarge = errors.New("too large")

// CVE matches a CVE id; the same pattern as vuln_intel's CHECK constraint, so a
// parsed feed never fails on insert.
var CVE = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,7}$`)

// Dates outside this range are rejected: KEV started in 2021 and EPSS in 2021,
// CVE ids start in 1999, and nothing legitimate is dated next century.
var (
	minDate = time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)
	maxDate = time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
)

func saneDate(t time.Time) bool { return !t.Before(minDate) && t.Before(maxDate) }

// capReader fails with err once more than max bytes have been read through it,
// so a limit holds while streaming (a gzip bomb is stopped at the cap, not
// after it has been inflated).
type capReader struct {
	r    io.Reader
	max  int64
	read int64
	err  error
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.over() {
		return 0, c.err
	}
	// Never ask for more than one byte past the cap, whatever buffer the
	// caller grew.
	if rem := c.max - c.read + 1; int64(len(p)) > rem {
		p = p[:rem]
	}
	n, err := c.r.Read(p)
	c.read += int64(n)
	if c.over() {
		return 0, c.err
	}
	return n, err
}

func (c *capReader) over() bool { return c.read > c.max }

func capped(r io.Reader, max int64, what string) *capReader {
	return &capReader{r: r, max: max, err: fmt.Errorf("%s exceeds %d bytes: %w", what, max, ErrTooLarge)}
}

// KEVEntry is one catalog entry. Due is zero when the entry has no due date.
type KEVEntry struct {
	CVE        string
	Added      time.Time
	Due        time.Time
	Ransomware bool
}

// KEV is a parsed catalog, its entries sorted by CVE.
type KEV struct {
	Released time.Time // dateReleased: when CISA published this version
	Entries  []KEVEntry
}

type kevEntryJSON struct {
	CVEID      string `json:"cveID"`
	DateAdded  string `json:"dateAdded"`
	DueDate    string `json:"dueDate"`
	Ransomware string `json:"knownRansomwareCampaignUse"`
}

// ParseKEV reads known_exploited_vulnerabilities.json. It streams the
// vulnerabilities array so the entry cap holds before entries are allocated,
// and fails on unknown types, a repeated top-level key, trailing data,
// duplicate CVEs and any invalid entry.
func ParseKEV(r io.Reader) (KEV, error) {
	var out KEV
	dec := json.NewDecoder(capped(r, MaxKEVBytes, "KEV file"))
	if err := expectDelim(dec, '{'); err != nil {
		return out, err
	}
	var released string
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return out, fmt.Errorf("KEV: %w", err)
		}
		key, _ := tok.(string)
		if seen[key] {
			return out, fmt.Errorf("KEV: duplicate key %q", key)
		}
		seen[key] = true
		switch key {
		case "dateReleased":
			if err := dec.Decode(&released); err != nil {
				return out, fmt.Errorf("KEV dateReleased: %w", err)
			}
		case "vulnerabilities":
			if out.Entries, err = kevEntries(dec); err != nil {
				return out, err
			}
		default:
			var skip json.RawMessage // bounded by the file cap
			if err := dec.Decode(&skip); err != nil {
				return out, fmt.Errorf("KEV: %w", err)
			}
		}
	}
	if err := expectDelim(dec, '}'); err != nil {
		return out, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return out, errors.New("KEV: data after the catalog")
	}
	t, err := time.Parse(time.RFC3339Nano, released)
	if err != nil || !saneDate(t) {
		return out, fmt.Errorf("KEV: dateReleased %q is not a valid timestamp", trunc(released))
	}
	out.Released = t.UTC()
	if len(out.Entries) == 0 {
		// An empty catalog would clear every KEV flag: treat it as broken.
		return out, errors.New("KEV: no vulnerabilities")
	}
	slices.SortFunc(out.Entries, func(a, b KEVEntry) int { return strings.Compare(a.CVE, b.CVE) })
	for i := 1; i < len(out.Entries); i++ {
		if out.Entries[i].CVE == out.Entries[i-1].CVE {
			return out, fmt.Errorf("KEV: duplicate %s", out.Entries[i].CVE)
		}
	}
	return out, nil
}

func kevEntries(dec *json.Decoder) ([]KEVEntry, error) {
	if err := expectDelim(dec, '['); err != nil {
		return nil, err
	}
	var out []KEVEntry
	for dec.More() {
		if len(out) == MaxKEVEntries {
			return nil, fmt.Errorf("KEV: more than %d entries: %w", MaxKEVEntries, ErrTooLarge)
		}
		var raw kevEntryJSON
		if err := dec.Decode(&raw); err != nil {
			return nil, fmt.Errorf("KEV entry %d: %w", len(out), err)
		}
		e, err := kevEntry(raw)
		if err != nil {
			return nil, fmt.Errorf("KEV entry %d: %w", len(out), err)
		}
		out = append(out, e)
	}
	return out, expectDelim(dec, ']')
}

func kevEntry(raw kevEntryJSON) (KEVEntry, error) {
	e := KEVEntry{CVE: raw.CVEID}
	if len(raw.CVEID) > maxField || !CVE.MatchString(raw.CVEID) {
		return e, fmt.Errorf("invalid cveID %q", trunc(raw.CVEID))
	}
	var err error
	if e.Added, err = date(raw.DateAdded); err != nil {
		return e, fmt.Errorf("%s dateAdded: %w", e.CVE, err)
	}
	if raw.DueDate != "" {
		if e.Due, err = date(raw.DueDate); err != nil {
			return e, fmt.Errorf("%s dueDate: %w", e.CVE, err)
		}
	}
	switch raw.Ransomware {
	case "Known":
		e.Ransomware = true
	case "Unknown":
	default:
		return e, fmt.Errorf("%s knownRansomwareCampaignUse %q is not Known or Unknown", e.CVE, trunc(raw.Ransomware))
	}
	return e, nil
}

func date(s string) (time.Time, error) {
	if len(s) != len(time.DateOnly) {
		return time.Time{}, fmt.Errorf("%q is not YYYY-MM-DD", trunc(s))
	}
	t, err := time.Parse(time.DateOnly, s)
	if err != nil || !saneDate(t) {
		return time.Time{}, fmt.Errorf("%q is not a valid date", s)
	}
	return t, nil
}

func expectDelim(dec *json.Decoder, want json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("KEV: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != want {
		return fmt.Errorf("KEV: expected %q", want)
	}
	return nil
}

// trunc keeps hostile values short in error messages (which are logged).
func trunc(s string) string {
	if len(s) > maxField {
		return s[:maxField] + "…"
	}
	return s
}

// EPSSScore is one CVE's score and percentile.
type EPSSScore struct {
	CVE        string
	Score      float32
	Percentile float32
}

// EPSS is a parsed score file, sorted by CVE.
type EPSS struct {
	ModelVersion string
	ScoreDate    time.Time
	Scores       []EPSSScore
}

const epssHeader = "cve,epss,percentile"

// ParseEPSS reads epss_scores-current.csv.gz: a comment line
// "#model_version:…,score_date:…", the header "cve,epss,percentile", then one
// row per CVE. The compressed and decompressed sizes, the line length and the
// row count are all capped while streaming.
func ParseEPSS(r io.Reader) (EPSS, error) {
	return parseEPSS(r, epssLimits{MaxEPSSBytes, MaxEPSSDecompressed, MaxEPSSRows})
}

type epssLimits struct {
	compressed, decompressed int64
	rows                     int
}

func parseEPSS(r io.Reader, lim epssLimits) (EPSS, error) {
	var out EPSS
	zr, err := gzip.NewReader(capped(r, lim.compressed, "EPSS file"))
	if err != nil {
		return out, fmt.Errorf("EPSS: %w", err)
	}
	defer zr.Close()
	dr := capped(zr, lim.decompressed, "decompressed EPSS file")
	sc := bufio.NewScanner(dr)
	sc.Buffer(make([]byte, 0, 4096), maxEPSSLine)
	line := 0
	for sc.Scan() {
		line++
		text := sc.Text()
		switch line {
		case 1:
			if out.ModelVersion, out.ScoreDate, err = epssComment(text); err != nil {
				return out, err
			}
			continue
		case 2:
			if text != epssHeader {
				return out, fmt.Errorf("EPSS: header %q is not %q", trunc(text), epssHeader)
			}
			continue
		}
		if len(out.Scores) == lim.rows {
			return out, fmt.Errorf("EPSS: more than %d rows: %w", lim.rows, ErrTooLarge)
		}
		s, err := epssRow(text)
		if dr.over() {
			// The scanner hands out the partial line it had when the cap hit.
			return out, dr.err
		}
		if err != nil {
			return out, fmt.Errorf("EPSS line %d: %w", line, err)
		}
		out.Scores = append(out.Scores, s)
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return out, fmt.Errorf("EPSS line %d: longer than %d bytes: %w", line+1, maxEPSSLine, ErrTooLarge)
		}
		return out, fmt.Errorf("EPSS: %w", err) // includes a bad gzip checksum or truncation
	}
	if line < 2 {
		return out, errors.New("EPSS: missing header")
	}
	if len(out.Scores) == 0 {
		return out, errors.New("EPSS: no scores")
	}
	slices.SortFunc(out.Scores, func(a, b EPSSScore) int { return strings.Compare(a.CVE, b.CVE) })
	for i := 1; i < len(out.Scores); i++ {
		if out.Scores[i].CVE == out.Scores[i-1].CVE {
			return out, fmt.Errorf("EPSS: duplicate %s", out.Scores[i].CVE)
		}
	}
	return out, nil
}

// epssComment parses "#model_version:v2025.03.14,score_date:2025-10-27T12:03:15Z".
// score_date is required: it is the feed date the UI shows.
func epssComment(text string) (string, time.Time, error) {
	rest, ok := strings.CutPrefix(text, "#")
	if !ok {
		return "", time.Time{}, errors.New("EPSS: first line is not the model_version/score_date comment")
	}
	var model, scoreDate string
	for _, kv := range strings.Split(rest, ",") {
		k, v, _ := strings.Cut(kv, ":")
		switch strings.TrimSpace(k) {
		case "model_version":
			model = strings.TrimSpace(v)
		case "score_date":
			scoreDate = strings.TrimSpace(v)
		}
	}
	if len(model) > maxField || !printable(model) {
		return "", time.Time{}, errors.New("EPSS: invalid model_version")
	}
	t, err := scoreTime(scoreDate)
	if err != nil {
		return "", time.Time{}, err
	}
	return model, t, nil
}

// scoreTime accepts the formats EPSS has used for score_date.
func scoreTime(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05-0700", time.DateOnly} {
		if t, err := time.Parse(layout, s); err == nil && saneDate(t) {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("EPSS: score_date %q is not a valid timestamp", trunc(s))
}

func printable(s string) bool {
	for _, r := range s {
		if r < 0x20 || r > 0x7e {
			return false
		}
	}
	return true
}

func epssRow(text string) (EPSSScore, error) {
	f := strings.Split(text, ",")
	if len(f) != 3 {
		return EPSSScore{}, fmt.Errorf("%d fields, want 3", len(f))
	}
	s := EPSSScore{CVE: f[0]}
	if !CVE.MatchString(f[0]) {
		return s, fmt.Errorf("invalid CVE %q", trunc(f[0]))
	}
	var err error
	if s.Score, err = probability(f[1]); err != nil {
		return s, fmt.Errorf("%s epss: %w", s.CVE, err)
	}
	if s.Percentile, err = probability(f[2]); err != nil {
		return s, fmt.Errorf("%s percentile: %w", s.CVE, err)
	}
	return s, nil
}

// probability parses a decimal in [0, 1]. ParseFloat also accepts "NaN",
// "Inf" and hex floats; the range check rejects the first two and the length
// cap keeps the input short.
func probability(s string) (float32, error) {
	if len(s) == 0 || len(s) > 32 {
		return 0, fmt.Errorf("%q is not a number", trunc(s))
	}
	v, err := strconv.ParseFloat(s, 32)
	if err != nil || math.IsNaN(v) || v < 0 || v > 1 {
		return 0, fmt.Errorf("%q is not a number between 0 and 1", s)
	}
	return float32(v), nil
}

// ParseTrivyMeta returns UpdatedAt from the Trivy DB's metadata.json: when
// Aqua built the vulnerability DB the mirror holds.
func ParseTrivyMeta(r io.Reader) (time.Time, error) {
	b, err := io.ReadAll(capped(r, MaxTrivyMetaBytes, "trivy metadata.json"))
	if err != nil {
		return time.Time{}, err
	}
	var m struct {
		UpdatedAt string `json:"UpdatedAt"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&m); err != nil {
		return time.Time{}, fmt.Errorf("trivy metadata.json: %w", err)
	}
	t, err := time.Parse(time.RFC3339Nano, m.UpdatedAt)
	if err != nil || !saneDate(t) {
		return time.Time{}, fmt.Errorf("trivy metadata.json: UpdatedAt %q is not a valid timestamp", trunc(m.UpdatedAt))
	}
	return t.UTC(), nil
}
