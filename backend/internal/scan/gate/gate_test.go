package gate

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aupv9/warden/backend/internal/domain/severity"
	st "github.com/aupv9/warden/backend/internal/scan/scantest"
)

var today = time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)

func writeSarif(t *testing.T, level string) string {
	t.Helper()
	doc := st.Doc([]any{st.M{"ruleId": "r", "level": level, "message": st.M{"text": "m"}, "locations": []any{st.Loc("a.py", 1, "x")}}})
	b, _ := json.Marshal(doc)
	p := filepath.Join(t.TempDir(), level+".sarif")
	_ = os.WriteFile(p, b, 0o644)
	return p
}

func run(t *testing.T, opts Options) (int, string) {
	t.Helper()
	opts.Today = today
	var out bytes.Buffer
	code, err := Run(opts, &out)
	if err != nil {
		t.Fatal(err)
	}
	return code, out.String()
}

func writeBaseline(t *testing.T, entries map[string]any) string {
	t.Helper()
	b, _ := json.Marshal(entries)
	p := filepath.Join(t.TempDir(), "baseline.json")
	_ = os.WriteFile(p, b, 0o644)
	return p
}

func TestGateBlocksAndBaselineAccepts(t *testing.T) {
	f := writeSarif(t, "error")
	code, out := run(t, Options{Inputs: []Input{{"opengrep", f}}, FailOn: severity.High})
	if code != 1 {
		t.Fatalf("code %d\n%s", code, out)
	}
	var fp string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "fingerprint") {
			fs := strings.Fields(line)
			fp = fs[len(fs)-1]
		}
	}
	bl := writeBaseline(t, map[string]any{fp: map[string]string{
		"reason": "test fixture, not production code", "expires": today.AddDate(0, 0, 30).Format(time.DateOnly),
	}})
	if code, out := run(t, Options{Inputs: []Input{{"opengrep", f}}, FailOn: severity.High, Baseline: bl}); code != 0 {
		t.Fatalf("code %d\n%s", code, out)
	}
}

func fingerprintOf(t *testing.T, f string) string {
	t.Helper()
	report := filepath.Join(t.TempDir(), "r.json")
	run(t, Options{Inputs: []Input{{"opengrep", f}}, JSONOut: report})
	var rows []Row
	b, _ := os.ReadFile(report)
	if err := json.Unmarshal(b, &rows); err != nil || len(rows) != 1 {
		t.Fatal(err, rows)
	}
	return rows[0].Fingerprint
}

func TestGateIgnoresInvalidBaselineEntries(t *testing.T) {
	f := writeSarif(t, "error")
	fp := fingerprintOf(t, f)
	for name, entry := range map[string]any{
		"expired":     map[string]string{"reason": "long enough reason here....", "expires": "2020-01-01"},
		"too far out": map[string]string{"reason": "long enough reason here....", "expires": today.AddDate(0, 0, 181).Format(time.DateOnly)},
		"short":       map[string]string{"reason": "too short", "expires": today.AddDate(0, 0, 30).Format(time.DateOnly)},
		"no expiry":   map[string]string{"reason": "long enough reason here...."},
		"bad date":    map[string]string{"reason": "long enough reason here....", "expires": "soon"},
		"wrong type":  []string{"x"},
	} {
		code, out := run(t, Options{Inputs: []Input{{"opengrep", f}}, FailOn: severity.High, Baseline: writeBaseline(t, map[string]any{fp: entry})})
		if code != 1 || !strings.Contains(out, "baseline:") {
			t.Errorf("%s: code %d\n%s", name, code, out)
		}
	}
}

func TestGatePassesBelowThreshold(t *testing.T) {
	if code, out := run(t, Options{Inputs: []Input{{"opengrep", writeSarif(t, "warning")}}}); code != 0 {
		t.Fatalf("code %d\n%s", code, out)
	}
}

func TestMissingBaselineFileIsEmpty(t *testing.T) {
	acc, probs, err := LoadBaseline(filepath.Join(t.TempDir(), "nope.json"), today)
	if err != nil || len(acc) != 0 || len(probs) != 0 {
		t.Fatal(acc, probs, err)
	}
}
