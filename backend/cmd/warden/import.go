package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Imports: `warden import --tool codeql results.sarif` uploads another tool's
// SARIF file (or, --format gitlab-sast, a GitLab SAST report) as an import
// scan, then waits, applies the gate and comments exactly like `warden scan`.
// The CLI sends the file as it is: the server parses it as hostile input and
// screens every string it keeps. The CLI reads only one field of it, for the
// default category.

const (
	importSARIF      = "sarif"
	importGitLabSAST = "gitlab-sast"

	// maxCategoryScan caps what the CLI reads looking for the category: a
	// report from a scan of untrusted code is untrusted too.
	maxCategoryScan = 64 << 20
	// maxCategoryDepth caps nesting while skipping values.
	maxCategoryDepth = 64
)

// The server's patterns (OpenAPI ImportTool, ImportScanRequest.category), so
// a typo fails before the upload. The server checks again.
var (
	importToolPattern     = regexp.MustCompile(`^(codeql|gitlab-sast|semgrep|snyk-code|sonarqube|external\.[a-z0-9-]{1,32})$`)
	importCategoryPattern = regexp.MustCompile(`^[A-Za-z0-9/:._=+-]{0,100}$`)
)

// importTarget is the target the server gives an import scan (and its
// issues): '(import) <tool>' plus ' <category>' when there is one.
func importTarget(tool, category string) string {
	if category == "" {
		return "(import) " + tool
	}
	return "(import) " + tool + " " + category
}

func runImport(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer, d deps) int {
	fs := flag.NewFlagSet("warden import", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cf := addCommonFlags(fs)
	tool := fs.String("tool", "", "the tool that wrote FILE: codeql, gitlab-sast, semgrep, snyk-code, sonarqube or external.<key>")
	format := fs.String("format", importSARIF, "sarif|gitlab-sast")
	category := fs.String("category", "", "separates runs of one tool (default for SARIF: runs[0].automationDetails.id)")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(stderr, usage)
		return exitError
	}
	o := options{stdout: stdout, stderr: stderr, importTool: *tool, importFormat: *format, importCategory: *category}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	problems := cf.apply(&o, getenv)
	if !importToolPattern.MatchString(o.importTool) {
		problems = append(problems, "--tool: must be codeql, gitlab-sast, semgrep, snyk-code, sonarqube or external.<key> (a-z, 0-9, -)")
	}
	if o.importFormat != importSARIF && o.importFormat != importGitLabSAST {
		problems = append(problems, "--format: must be sarif or gitlab-sast")
	}
	if set["category"] && !importCategoryPattern.MatchString(o.importCategory) {
		problems = append(problems, "--category: at most 100 characters: letters, digits and / : . _ = + -")
	}
	switch fs.NArg() {
	case 0:
		problems = append(problems, "the report FILE is missing")
	case 1:
		o.importFile = fs.Arg(0)
		if fi, err := os.Stat(o.importFile); err != nil || !fi.Mode().IsRegular() || fi.Size() == 0 {
			problems = append(problems, "FILE: must be a non-empty file")
		}
	default:
		problems = append(problems, "give one FILE, after the flags")
	}
	if len(problems) == 0 && !set["category"] && o.importFormat == importSARIF {
		cat, err := fileCategory(o.importFile)
		if err != nil {
			problems = append(problems, err.Error())
		} else if cat != "" {
			fmt.Fprintf(stdout, "==> category %s (from runs[0].automationDetails.id)\n", clean(cat))
		}
		o.importCategory = cat
	}
	return execute(ctx, o, d, problems)
}

// importBody is the create request, without size and checksum.
func (c client) importBody() map[string]any {
	return map[string]any{"tool": c.o.importTool, "format": c.o.importFormat, "category": c.o.importCategory,
		"file_name": importFileName(c.o.importFile, c.o.importFormat)}
}

// importFileName is the name the server accepts (.sarif or .json, no path,
// tame characters), from the file's own name.
func importFileName(path, format string) string {
	base := filepath.Base(path)
	ext := strings.ToLower(filepath.Ext(base))
	if ext != ".sarif" && ext != ".json" {
		ext = ".sarif"
		if format == importGitLabSAST {
			ext = ".json"
		}
	}
	return archiveName(strings.TrimSuffix(base, filepath.Ext(base))) + ext
}

// fileCategory is the default category of a SARIF file (sarifCategory).
func fileCategory(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	id, found, err := sarifCategory(f)
	switch {
	case errors.Is(err, errCategoryScan):
		return "", fmt.Errorf("FILE: %w; pass --category (\"\" for none)", err)
	case err != nil:
		return "", fmt.Errorf("FILE: not a JSON report (%v); pass --category to skip this check", err)
	case !found:
		return "", nil
	}
	return categoryOf(id), nil
}

// categoryOf turns a SARIF runAutomationDetails.id into a category, the way
// GitHub code scanning reads it: the id up to and including its last "/",
// the rest being a run id (a date, a build number) that changes every run.
// Taking the whole id would give each run its own target, so no run would
// ever auto-fix the last one's issues. CodeQL's "/language:go/" is all
// category; an id without "/" is too. An id that isn't a valid category
// gives none.
func categoryOf(id string) string {
	if i := strings.LastIndexByte(id, '/'); i >= 0 {
		id = id[:i+1]
	}
	if !importCategoryPattern.MatchString(id) {
		return ""
	}
	return id
}

var (
	errCategoryScan = fmt.Errorf("runs[0].automationDetails.id not found in the first %d MiB", maxCategoryScan>>20)
	errCategoryJSON = errors.New("unexpected JSON")
)

// sarifCategory reads runs[0].automationDetails.id from a SARIF document,
// token by token: nothing but that string is kept, at most maxCategoryScan
// bytes are read and nesting is capped. found is false when the document
// has no such string (another type, no runs, no automationDetails). Keys
// are matched exactly and the first occurrence wins; the server doesn't
// use this value beyond checking it as a category.
func sarifCategory(r io.Reader) (id string, found bool, err error) {
	lr := &io.LimitedReader{R: r, N: maxCategoryScan}
	dec := json.NewDecoder(lr)
	defer func() {
		if err != nil && lr.N <= 0 {
			id, found, err = "", false, errCategoryScan
		}
	}()
	// The path to the value: each step is an object key, or the first
	// element of an array.
	if ok, err := enter(dec, '{'); !ok || err != nil {
		return "", false, err
	}
	if ok, err := findKey(dec, "runs"); !ok || err != nil {
		return "", false, err
	}
	if ok, err := enter(dec, '['); !ok || err != nil {
		return "", false, err
	}
	if !dec.More() {
		return "", false, nil
	}
	if ok, err := enter(dec, '{'); !ok || err != nil {
		return "", false, err
	}
	if ok, err := findKey(dec, "automationDetails"); !ok || err != nil {
		return "", false, err
	}
	if ok, err := enter(dec, '{'); !ok || err != nil {
		return "", false, err
	}
	if ok, err := findKey(dec, "id"); !ok || err != nil {
		return "", false, err
	}
	t, err := dec.Token()
	if err != nil {
		return "", false, err
	}
	s, ok := t.(string)
	return s, ok, nil
}

// enter reads the next token: ok when it opens the container delim, false
// (no error) for any other complete value.
func enter(dec *json.Decoder, delim json.Delim) (bool, error) {
	t, err := dec.Token()
	if err != nil {
		return false, err
	}
	d, ok := t.(json.Delim)
	return ok && d == delim, nil
}

// findKey reads an object's members until key, leaving the decoder at its
// value; false when the object ends without it.
func findKey(dec *json.Decoder, key string) (bool, error) {
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return false, err
		}
		k, ok := t.(string)
		if !ok {
			return false, errCategoryJSON
		}
		if k == key {
			return true, nil
		}
		if err := skipValue(dec); err != nil {
			return false, err
		}
	}
	return false, nil
}

// skipValue reads one value without keeping it.
func skipValue(dec *json.Decoder) error {
	t, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := t.(json.Delim); ok && (d == '{' || d == '[') {
		return skipRest(dec, 1)
	}
	return nil
}

// skipRest reads until depth open containers are closed.
func skipRest(dec *json.Decoder, depth int) error {
	for depth > 0 {
		if depth > maxCategoryDepth {
			return errCategoryJSON
		}
		t, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := t.(json.Delim); ok {
			if d == '{' || d == '[' {
				depth++
			} else {
				depth--
			}
		}
	}
	return nil
}
