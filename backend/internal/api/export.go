package api

import (
	"encoding/csv"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/aupv9/common-go/logger"
	"github.com/gin-gonic/gin"

	"github.com/aupv9/warden/backend/internal/service"
)

// exportColumns are the CSV's columns, in order (see the OpenAPI document).
var exportColumns = []string{"key", "project", "title", "severity", "status", "tool", "rule_id", "file_path", "line",
	"target", "cve", "kev", "epss", "assignee", "due_at", "created_at", "updated_at"}

// exportHeaders are the response headers set for the CSV, removed again when
// the export fails before anything was sent.
var exportHeaders = []string{"Content-Type", "Content-Disposition", "X-Warden-Truncated", "X-Content-Type-Options"}

// issueFilter reads the issue list's query (GET /issues and its export).
func issueFilter(c *gin.Context) service.IssueFilter {
	return service.IssueFilter{
		ProjectID: c.Query("project_id"), Status: c.QueryArray("status"), Severity: c.QueryArray("severity"),
		Assignee: c.Query("assignee"), Tool: c.Query("tool"), PastSLA: c.Query("past_sla"), Q: c.Query("q"),
		Kind: c.Query("kind"), KEV: c.Query("kev"), EPSSMin: c.Query("epss_min"), Source: c.Query("source"), Target: c.Query("target"),
		ExternalTool: c.Query("external_tool"), Sort: c.Query("sort"), PageParams: page(c),
	}
}

// exportEndLine is the last line of a complete export: one cell, N being the
// data rows above it. A file without it, or with another N, is incomplete:
// over HTTP/2 a failure mid-stream may just end the response, so the client
// can't tell otherwise. No data row can forge it: every row has all columns
// (so its line holds commas), csvCell keeps each on one line, and the first
// cell is the server's issue key (exportRecord).
func exportEndLine(rows int) string { return "#warden:end rows=" + strconv.Itoa(rows) }

// exportIssues streams the issue list as CSV. The service validates, rate
// limits and audits before start is called; rows are written as they are read
// (encoding/csv over the response, through a small buffer). The end line is
// written only once the last row was.
func (h handlers) exportIssues(c *gin.Context) {
	var w *csv.Writer
	rows := 0
	err := h.svc.ExportIssues(c.Request.Context(), actor(c), issueFilter(c),
		func(ex service.IssueExport) error {
			hd := c.Writer.Header()
			hd.Set("Content-Type", "text/csv; charset=utf-8")
			hd.Set("Content-Disposition", `attachment; filename="`+exportFilename(ex)+`"`)
			hd.Set("Cache-Control", "no-store")
			hd.Set("X-Content-Type-Options", "nosniff")
			if ex.Truncated {
				hd.Set("X-Warden-Truncated", "true")
			}
			c.Status(http.StatusOK)
			w = csv.NewWriter(c.Writer)
			w.UseCRLF = true // RFC 4180
			_ = w.Write(exportColumns)
			return w.Error()
		},
		func(r service.IssueExportRow) error {
			_ = w.Write(exportRecord(r))
			if err := w.Error(); err != nil {
				return err // the client went away: stop reading rows
			}
			rows++
			return nil
		})
	switch {
	case err != nil && !c.Writer.Written():
		for _, k := range exportHeaders {
			c.Writer.Header().Del(k)
		}
		fail(c, err)
	case err != nil:
		logger.FromContext(c.Request.Context()).Warn("issue export broken off", slog.Any("error", err))
		abortStream(c)
	default:
		_ = w.Write([]string{exportEndLine(rows)})
		if w.Flush(); w.Error() != nil {
			abortStream(c)
		}
	}
}

// abortStream closes the connection under a response that is already under
// way, so the client sees a failed download rather than a short file that
// looks complete. (A panic would reach common-go's Recovery, which writes a
// JSON error into the CSV.) Without HTTP/1 hijacking (HTTP/2, tests) the
// response just ends.
func abortStream(c *gin.Context) {
	var rw http.ResponseWriter = c.Writer
	if u, ok := rw.(interface{ Unwrap() http.ResponseWriter }); ok {
		rw = u.Unwrap() // gin refuses to hijack once the body has started
	}
	if conn, _, err := http.NewResponseController(rw).Hijack(); err == nil {
		_ = conn.Close()
	}
}

// exportFilename is warden-issues-<org id>-<date>.csv, restricted to
// [A-Za-z0-9._-] so it can't break out of the quoted header value.
func exportFilename(ex service.IssueExport) string {
	name := "warden-issues-" + ex.OrgID.String() + "-" + ex.At.UTC().Format(time.DateOnly) + ".csv"
	return strings.Map(func(r rune) rune {
		if r < utf8.RuneSelf && (r == '.' || r == '_' || r == '-' || unicode.IsLetter(r) || unicode.IsDigit(r)) {
			return r
		}
		return '-'
	}, name)
}

func exportRecord(r service.IssueExportRow) []string {
	opt := func(s *string) string {
		if s == nil {
			return ""
		}
		return *s
	}
	at := func(t *service.Time) string {
		if t == nil {
			return ""
		}
		return t.T().UTC().Format(time.RFC3339)
	}
	line, epss := "", ""
	if r.Line != nil {
		line = strconv.Itoa(*r.Line)
	}
	if r.EPSS != nil {
		epss = strconv.FormatFloat(*r.EPSS, 'f', -1, 64)
	}
	// An imported issue names its tool in the tool cell (external:codeql)
	// rather than in a new column, so the export's columns stay as they were.
	// The value is one of ImportTool's (checked by the database), and csvCell
	// treats it as hostile anyway.
	tool := r.Tool
	if r.ExternalTool != nil {
		tool += ":" + *r.ExternalTool
	}
	rec := []string{r.Key, r.ProjectName, r.Title, r.Severity, r.Status, tool, r.RuleID, opt(r.FilePath), line,
		r.Target, strings.Join(r.CVE, " "), strconv.FormatBool(r.KEV), epss, opt(r.Assignee), at(r.DueAt), at(&r.CreatedAt), at(&r.UpdatedAt)}
	for k, v := range rec {
		rec[k] = csvCell(v)
	}
	// The key is the project's key ([A-Z][A-Z0-9]{1,9}, checked by the
	// database too) and the issue number, never scanned text, so a row can't
	// start with the end line's "#". Kept so even if that ever changed.
	if strings.HasPrefix(rec[0], "#") {
		rec[0] = "'" + rec[0]
	}
	return rec
}

// csvCell makes one cell safe to open in a spreadsheet. Titles, paths and rule
// ids come from scanned code, so every cell is treated as hostile:
//
//   - Invalid UTF-8 becomes U+FFFD and NUL is dropped. Every other control
//     character (C0 including tab, CR and LF; DEL; C1) and the line and
//     paragraph separators become a space: each record stays on one line.
//   - Bidirectional controls and U+FEFF are dropped, so a viewer can't be made
//     to show the text reordered (Trojan Source).
//   - A cell whose first character, past spaces and invisible format
//     characters, would start a formula (= + - @, their fullwidth forms, tab or
//     CR) gets a leading apostrophe, which spreadsheets read as "text". Leading
//     spaces don't help: some spreadsheets trim them before parsing.
//
// encoding/csv then quotes cells with commas or quotes and doubles the quotes.
// The result is idempotent: escaping an escaped cell changes nothing.
func csvCell(s string) string {
	s = strings.ToValidUTF8(s, string(utf8.RuneError))
	s = strings.Map(func(r rune) rune {
		switch {
		case r == 0, isBidiControl(r), r == 0xFEFF:
			return -1
		case r < 0x20, r >= 0x7f && r < 0xa0, r == 0x2028, r == 0x2029:
			return ' '
		}
		return r
	}, s)
	for _, r := range s {
		if unicode.IsSpace(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		if formulaStart(r) {
			return "'" + s
		}
		break
	}
	return s
}

func formulaStart(r rune) bool {
	switch r {
	case '=', '+', '-', '@', '\t', '\r', 0xFF1D, 0xFF0B, 0xFF0D, 0xFF20: // the last four: fullwidth = + - @
		return true
	}
	return false
}

// isBidiControl: ALM, LRM, RLM, the embeddings and overrides (LRE…RLO) and the
// isolates (LRI…PDI).
func isBidiControl(r rune) bool {
	return r == 0x061C || r == 0x200E || r == 0x200F || (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069)
}
