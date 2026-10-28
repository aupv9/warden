package intel

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/aupv9/warden/backend/internal/domain/ecosystem"
)

// OSV malicious-package feed: OSV publishes one all.zip per ecosystem
// (scripts/sync-mirror.sh puts it at intel/osv/<ecosystem>.zip). Next to GHSA
// and CVE entries it holds the OpenSSF malicious-packages advisories, one
// MAL-YYYY-N.json per advisory. Only those are read.
//
// The archive is read in place with archive/zip over the file (ReaderAt):
// nothing is extracted, only entries named exactly like a MAL advisory are
// decompressed, and every size and count is capped while reading.

// Limits. The real feeds are far below them, except for the per-entry size
// (npm, October 2026: 231k entries, 223k MAL advisories, 363 MB of MAL JSON,
// largest advisory 1.1 MB because of its "indicators", most versions in one
// advisory 232).
const (
	// MaxOSVEntries caps the archive's entries (all kinds).
	MaxOSVEntries = 2_000_000
	// MaxOSVDirectory caps the bytes zip.NewReader may read while loading
	// the central directory. archive/zip keeps reading directory records
	// past the count the archive declares (it only compares the count
	// modulo 65536), so a forged directory could make it allocate a File
	// for every 46 bytes of the file; this cap holds before that happens.
	MaxOSVDirectory = 128 << 20
	// MaxOSVEntryBytes caps one decompressed advisory. The plan's 256 KiB
	// would drop real advisories (up to 1.1 MB); 4 MiB keeps decoding one
	// cheap.
	MaxOSVEntryBytes = 4 << 20
	// MaxOSVTotalBytes caps the decompressed bytes of all advisories read.
	MaxOSVTotalBytes = 1 << 30
	// MaxOSVVersions caps the versions[] of one affected package.
	MaxOSVVersions = 10_000
	// maxOSVRatio: a declared compression ratio above this is a zip bomb
	// (real advisories compress about 4-6x).
	maxOSVRatio = 100
	// Stored-string caps (the malicious_package CHECK constraints).
	maxOSVName    = 256
	maxOSVVersion = 128
	maxOSVSummary = 512
	// maxInvalidShare: more than 1% of the advisories (and at least
	// minInvalid) failing validation means the file is broken or tampered
	// with; it is rejected so the previous data stays.
	maxInvalidShare = 100
	minInvalid      = 10
)

// MaliciousID matches an advisory id; the same pattern as malicious_package's
// CHECK, so a parsed feed never fails on insert.
var MaliciousID = regexp.MustCompile(`^MAL-[0-9]{4}-[0-9]{1,8}$`)

// osvEntryName: only flat entries named exactly like an advisory are opened.
// A name with a directory, "..", a backslash or anything else never matches.
var osvEntryName = regexp.MustCompile(`^(MAL-[0-9]{4}-[0-9]{1,8})\.json$`)

// MaliciousPackage is one package an advisory marks as malicious: either all
// its versions or the listed ones. Versions are ecosystem.MatchVersion-
// normalized, sorted and unique; MatchName is ecosystem.MatchName of Name.
type MaliciousPackage struct {
	ID          string
	Ecosystem   string
	Name        string
	MatchName   string
	AllVersions bool
	Versions    []string
	Summary     string
	Published   *time.Time
	Modified    time.Time
}

// OSVResult is a parsed feed. Packages are sorted by (ID, MatchName) and
// unique on that pair. The counters say what was left out and why.
type OSVResult struct {
	Packages []MaliciousPackage
	// Updated is the latest modified time of the advisories read (zero
	// when there are none).
	Updated time.Time
	// Advisories: MAL entries read and used (not withdrawn, valid).
	Advisories int
	// Withdrawn: MAL entries dropped because OSV withdrew them.
	Withdrawn int
	// Unsupported: affected packages skipped because they have neither
	// explicit versions nor an introduced-"0"-only range. Never guessed.
	Unsupported int
	// Partial: affected packages loaded from their versions[] although
	// they also have a range form that isn't supported.
	Partial int
	// OtherEcosystem: affected packages of another ecosystem (ignored).
	OtherEcosystem int
	// Invalid: MAL entries or affected packages that failed validation.
	Invalid int
	// InvalidSamples: up to 5 reasons, for the log (hostile values cut).
	InvalidSamples []string
	// Skipped: archive entries that aren't MAL advisories (never opened).
	Skipped int
}

// ParseOSVMalicious reads an OSV all.zip of size bytes for ecosystem eco
// (one of ecosystem.OSV). See parseOSV.
func ParseOSVMalicious(f *os.File, size int64, eco string) (OSVResult, error) {
	return parseOSV(f, size, eco, defaultOSVLimits)
}

type osvLimits struct {
	entries                 int
	directory, entry, total int64
	versions                int
}

var defaultOSVLimits = osvLimits{
	entries: MaxOSVEntries, directory: MaxOSVDirectory, entry: MaxOSVEntryBytes, total: MaxOSVTotalBytes,
	versions: MaxOSVVersions,
}

// budgetReaderAt fails every read once more than max bytes have been read
// through it.
type budgetReaderAt struct {
	r    io.ReaderAt
	max  int64
	read int64
}

var errOSVDirectory = fmt.Errorf("OSV: zip central directory exceeds %d bytes: %w", MaxOSVDirectory, ErrTooLarge)

func (b *budgetReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if b.read+int64(len(p)) > b.max {
		return 0, errOSVDirectory
	}
	n, err := b.r.ReadAt(p, off)
	b.read += int64(n)
	return n, err
}

// parseOSV reads the archive. Archive-level problems (not a zip, too many
// entries, the total decompressed size, a repeated advisory name, too many
// invalid advisories) fail the whole file, so the loader keeps the previous
// data. A single advisory that is malformed, too large or otherwise invalid
// is skipped and counted: OSV publishes hundreds of thousands, and dropping
// one doesn't let anyone hide another (they could as well delete it).
func parseOSV(r io.ReaderAt, size int64, eco string, lim osvLimits) (OSVResult, error) {
	var out OSVResult
	if !ecosystem.IsOSV(eco) {
		return out, fmt.Errorf("OSV: unknown ecosystem %q", trunc(eco))
	}
	budget := &budgetReaderAt{r: r, max: lim.directory}
	zr, err := zip.NewReader(budget, size)
	if err != nil {
		if errors.Is(err, ErrTooLarge) {
			return out, fmt.Errorf("OSV: zip central directory exceeds %d bytes: %w", lim.directory, ErrTooLarge)
		}
		return out, fmt.Errorf("OSV: %w", err)
	}
	// Entries are read through the file itself; the budget only guards
	// the directory.
	budget.max = 1<<63 - 1
	if len(zr.File) > lim.entries {
		return out, fmt.Errorf("OSV: more than %d archive entries: %w", lim.entries, ErrTooLarge)
	}
	if len(zr.File) == 0 {
		return out, errors.New("OSV: empty archive")
	}
	p := osvParser{eco: eco, lim: lim, out: &out, byKey: map[[2]string]int{}, seen: map[string]bool{}}
	for _, f := range zr.File {
		m := osvEntryName.FindStringSubmatch(f.Name)
		if m == nil {
			out.Skipped++
			continue
		}
		if p.seen[m[1]] {
			return out, fmt.Errorf("OSV: duplicate entry %s", m[1])
		}
		p.seen[m[1]] = true
		if err := p.entry(f, m[1]); err != nil {
			return out, err
		}
	}
	if out.Invalid > minInvalid && out.Invalid*maxInvalidShare > out.Advisories+out.Invalid {
		return out, fmt.Errorf("OSV: %d invalid advisories (e.g. %s)", out.Invalid, strings.Join(out.InvalidSamples, "; "))
	}
	slices.SortFunc(out.Packages, func(a, b MaliciousPackage) int {
		if c := strings.Compare(a.ID, b.ID); c != 0 {
			return c
		}
		return strings.Compare(a.MatchName, b.MatchName)
	})
	return out, nil
}

type osvParser struct {
	eco   string
	lim   osvLimits
	out   *OSVResult
	total int64
	byKey map[[2]string]int // (id, match name) → index in out.Packages
	seen  map[string]bool
	buf   bytes.Buffer
}

func (p *osvParser) invalid(id, why string) {
	p.out.Invalid++
	if len(p.out.InvalidSamples) < 5 {
		p.out.InvalidSamples = append(p.out.InvalidSamples, id+": "+why)
	}
}

// osvEntry is the part of an OSV record that is read. Unknown fields
// (details, references, database_specific...) are skipped by the decoder.
type osvEntry struct {
	ID        string `json:"id"`
	Summary   string `json:"summary"`
	Published string `json:"published"`
	Modified  string `json:"modified"`
	Withdrawn string `json:"withdrawn"`
	Affected  []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string     `json:"type"`
			Events []osvEvent `json:"events"`
		} `json:"ranges"`
		Versions []string `json:"versions"`
	} `json:"affected"`
}

// osvEvent is one range event; exactly one field is set in a valid record.
type osvEvent struct {
	Introduced   *string `json:"introduced"`
	Fixed        *string `json:"fixed"`
	LastAffected *string `json:"last_affected"`
	Limit        *string `json:"limit"`
}

func (p *osvParser) entry(f *zip.File, id string) error {
	if !f.Mode().IsRegular() {
		p.invalid(id, "not a regular file")
		return nil
	}
	if f.UncompressedSize64 > uint64(p.lim.entry) {
		p.invalid(id, fmt.Sprintf("larger than %d bytes", p.lim.entry))
		return nil
	}
	if f.CompressedSize64 > 0 && f.UncompressedSize64/f.CompressedSize64 > maxOSVRatio {
		p.invalid(id, "compression ratio too high")
		return nil
	}
	// The declared size is the attacker's; the cap below is ours (and
	// archive/zip also fails a body longer than declared).
	if p.total+int64(f.UncompressedSize64) > p.lim.total {
		return fmt.Errorf("OSV: advisories exceed %d bytes decompressed: %w", p.lim.total, ErrTooLarge)
	}
	rc, err := f.Open()
	if err != nil {
		p.invalid(id, err.Error())
		return nil
	}
	cr := capped(rc, p.lim.entry, id)
	// One buffer for every entry: the bodies are garbage right after decoding.
	p.buf.Reset()
	_, err = p.buf.ReadFrom(cr)
	body := p.buf.Bytes()
	rc.Close()
	p.total += cr.read
	if p.total > p.lim.total {
		return fmt.Errorf("OSV: advisories exceed %d bytes decompressed: %w", p.lim.total, ErrTooLarge)
	}
	if err != nil {
		p.invalid(id, err.Error())
		return nil
	}
	var e osvEntry
	if err := strictJSON(body, &e); err != nil {
		p.invalid(id, "malformed JSON: "+trunc(err.Error()))
		return nil
	}
	if e.ID != id {
		p.invalid(id, fmt.Sprintf("id %q doesn't match the entry name", trunc(e.ID)))
		return nil
	}
	if e.Withdrawn != "" {
		p.out.Withdrawn++
		return nil
	}
	modified, err := osvTime(e.Modified)
	if err != nil {
		p.invalid(id, "modified: "+err.Error())
		return nil
	}
	var published *time.Time
	if e.Published != "" {
		t, err := osvTime(e.Published)
		if err != nil {
			p.invalid(id, "published: "+err.Error())
			return nil
		}
		published = &t
	}
	summary := cleanText(e.Summary, maxOSVSummary)
	used := false
	for _, a := range e.Affected {
		if a.Package.Ecosystem != p.eco {
			p.out.OtherEcosystem++
			continue
		}
		name := a.Package.Name
		if name == "" || utf8.RuneCountInString(name) > maxOSVName || !printableName(name) {
			p.invalid(id, "invalid package name")
			continue
		}
		if len(a.Versions) > p.lim.versions {
			p.invalid(id, fmt.Sprintf("more than %d versions: %v", p.lim.versions, ErrTooLarge))
			continue
		}
		all, other := false, false
		for _, rg := range a.Ranges {
			if introducedZeroOnly(rg.Events) {
				all = true
			} else {
				other = true
			}
		}
		var versions []string
		if !all {
			for _, v := range a.Versions {
				// A version no component can have (components keep 128
				// printable characters) can't match: drop it.
				if v = strings.TrimSpace(v); v == "" || len(v) > maxOSVVersion || !printableName(v) {
					continue
				}
				versions = append(versions, ecosystem.MatchVersion(p.eco, v))
			}
		}
		switch {
		case all:
		case len(versions) > 0:
			if other {
				p.out.Partial++
			}
		case other || len(a.Versions) == 0:
			p.out.Unsupported++
			continue
		default:
			p.invalid(id, "no usable version")
			continue
		}
		match := ecosystem.MatchName(p.eco, name)
		if match == "" || utf8.RuneCountInString(match) > maxOSVName {
			p.invalid(id, "invalid package name")
			continue
		}
		used = true
		k := [2]string{id, match}
		if i, ok := p.byKey[k]; ok {
			// The same package twice (names differing only in case or
			// separators): one row, the union of the versions.
			mp := &p.out.Packages[i]
			mp.AllVersions = mp.AllVersions || all
			mp.Versions = append(mp.Versions, versions...)
			normVersions(mp)
			continue
		}
		mp := MaliciousPackage{ID: id, Ecosystem: p.eco, Name: name, MatchName: match, AllVersions: all,
			Versions: versions, Summary: summary, Published: published, Modified: modified}
		normVersions(&mp)
		p.byKey[k] = len(p.out.Packages)
		p.out.Packages = append(p.out.Packages, mp)
	}
	if used {
		p.out.Advisories++
		if modified.After(p.out.Updated) {
			p.out.Updated = modified
		}
	}
	return nil
}

// normVersions sorts and dedupes; an all-versions row keeps none.
func normVersions(mp *MaliciousPackage) {
	if mp.AllVersions {
		mp.Versions = nil
		return
	}
	slices.Sort(mp.Versions)
	mp.Versions = slices.Compact(mp.Versions)
}

// introducedZeroOnly: a range whose only events are introduced "0" affects
// every version. Any other event (fixed, last_affected, limit, a later
// introduced, an unknown key) makes it a range Warden doesn't evaluate.
func introducedZeroOnly(events []osvEvent) bool {
	if len(events) == 0 {
		return false
	}
	for _, ev := range events {
		if ev.Introduced == nil || *ev.Introduced != "0" || ev.Fixed != nil || ev.LastAffected != nil || ev.Limit != nil {
			return false
		}
	}
	return true
}

// strictJSON decodes one JSON value and fails on trailing data.
func strictJSON(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("data after the record")
	}
	return nil
}

func osvTime(s string) (time.Time, error) {
	if len(s) > maxField {
		return time.Time{}, errors.New("not a timestamp")
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || !saneDate(t) {
		return time.Time{}, fmt.Errorf("%q is not a valid timestamp", trunc(s))
	}
	return t.UTC(), nil
}

// printableName: no control, format (bidi) or other invisible characters, and
// no whitespace other than a plain space.
func printableName(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// cleanText keeps an advisory summary displayable as plain text: invalid
// UTF-8, control and format characters (bidi overrides) become spaces, runs
// of spaces collapse, and it is cut to max runes.
func cleanText(s string, max int) string {
	var b strings.Builder
	space, n := false, 0
	for _, r := range strings.ToValidUTF8(s, " ") {
		if n >= max {
			break
		}
		if !unicode.IsPrint(r) || unicode.IsSpace(r) {
			space = true
			continue
		}
		if space && n > 0 {
			b.WriteByte(' ')
			if n++; n >= max {
				break
			}
		}
		space = false
		b.WriteRune(r)
		n++
	}
	return b.String()
}
