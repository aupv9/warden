package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

const maxResponse = 4 << 20

type scanResp struct {
	ID        string  `json:"id"`
	Status    string  `json:"status"`
	ErrorCode *string `json:"error_code"`
}

type createdScan struct {
	Scan   scanResp `json:"scan"`
	Upload struct {
		Method  string            `json:"method"`
		URL     string            `json:"url"`
		Headers map[string]string `json:"headers"`
	} `json:"upload"`
}

type issue struct {
	ID        string  `json:"id"`
	Key       string  `json:"key"`
	Title     string  `json:"title"`
	Severity  string  `json:"severity"`
	FilePath  *string `json:"file_path"`
	StartLine *int    `json:"start_line"`
}

type gate struct {
	Status   string         `json:"status"`
	Finished bool           `json:"finished"`
	Pass     bool           `json:"pass"`
	FailOn   string         `json:"fail_on"`
	Counts   map[string]int `json:"counts"`
	Blocking []issue        `json:"blocking"`
}

// apiError is a failed API call, as the server described it.
type apiError struct {
	status     int
	code, msg  string
	retryAfter time.Duration
}

func (e *apiError) Error() string {
	if e.code == "" {
		return fmt.Sprintf("HTTP %d", e.status)
	}
	return fmt.Sprintf("HTTP %d %s: %s", e.status, e.code, e.msg)
}

// transient: worth retrying while polling.
func (e *apiError) transient() bool {
	return e.status == http.StatusTooManyRequests || e.status >= 500
}

type client struct {
	o options
	d deps
}

// call sends a JSON request to the API and decodes the envelope's data into out.
func (c client) call(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	// path is built from parsed UUIDs and escaped values, so plain
	// concatenation is safe; the server URL has no query (checkURL).
	target := c.o.server.String() + "/api/v1" + path
	req, err := http.NewRequestWithContext(ctx, method, target, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.o.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "warden-cli")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.d.api.Do(req)
	if err != nil {
		return netError(method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return netError(method, path, err)
	}
	var env struct {
		Data  json.RawMessage `json:"data"`
		Error *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(raw, &env)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		e := &apiError{status: resp.StatusCode}
		if env.Error != nil {
			e.code, e.msg = env.Error.Code, env.Error.Message
		}
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 && s <= 3600 {
			e.retryAfter = time.Duration(s) * time.Second
		}
		return fmt.Errorf("%s %s: %w", method, path, e)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return fmt.Errorf("%s %s: unexpected response from the server", method, path)
	}
	return nil
}

// netError drops the request URL from transport errors: for the upload it is a
// presigned URL, whose signature shouldn't end up in a CI log.
func netError(method, what string, err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	return fmt.Errorf("%s %s: %w", method, what, err)
}

func (c client) printf(format string, a ...any) { fmt.Fprintf(c.o.stdout, format, a...) }

// scan runs the whole flow and returns the exit status.
func scan(ctx context.Context, o options, d deps) (int, error) {
	c := client{o: o, d: d}
	tmp, err := os.MkdirTemp("", "warden-scan-")
	if err != nil {
		return exitError, err
	}
	defer os.RemoveAll(tmp)
	var zipPath string
	var body map[string]any
	if o.image != "" || o.imageTar != "" {
		if zipPath, body, err = c.imageArtifact(ctx, tmp); err != nil {
			return exitError, err
		}
	} else {
		dir, err := filepath.Abs(o.dir)
		if err != nil {
			return exitError, err
		}
		name := archiveName(dir)
		zipPath = filepath.Join(tmp, name+".zip")
		files, err := d.pack(dir, zipPath, name+"/")
		if err != nil {
			return exitError, fmt.Errorf("package %s: %w", dir, err)
		}
		c.printf("==> packaged %d files from %s\n", files, clean(dir))
		body = map[string]any{"file_name": name + ".zip"}
	}
	size, sum, err := digest(zipPath)
	if err != nil {
		return exitError, err
	}
	c.printf("==> %s: %d bytes\n", clean(body["file_name"].(string)), size)
	body["file_size"], body["sha256"] = size, sum
	if len(o.tools) > 0 {
		body["tools"] = o.tools
	}
	var created createdScan
	if err := c.call(ctx, "POST", "/orgs/"+o.org.String()+"/projects/"+o.project.String()+"/scans", body, &created); err != nil {
		return exitError, err
	}
	scanID := created.Scan.ID
	c.printf("==> scan %s created; uploading\n", clean(scanID))
	if err := c.upload(ctx, created, zipPath, size); err != nil {
		return exitError, err
	}
	scanPath := "/orgs/" + o.org.String() + "/scans/" + url.PathEscape(scanID)
	if err := c.call(ctx, "POST", scanPath+"/start", nil, nil); err != nil {
		return exitError, err
	}

	final, err := c.wait(ctx, scanPath)
	if err != nil {
		if ctx.Err() != nil {
			c.cancelScan(scanPath)
			return exitError, fmt.Errorf("gave up waiting for scan %s after %s; cancelled it", clean(scanID), o.timeout)
		}
		return exitError, err
	}
	if final.Status == "failed" || final.Status == "cancelled" {
		code := ""
		if final.ErrorCode != nil {
			code = " (" + *final.ErrorCode + ")"
		}
		return exitError, fmt.Errorf("scan %s %s%s", clean(scanID), final.Status, clean(code))
	}

	if o.sbomOut != "" {
		if err := c.saveSBOM(ctx, scanPath, o.sbomFormat, o.sbomOut); err != nil {
			return exitError, err
		}
	}

	gatePath := scanPath + "/gate?fail_on=" + url.QueryEscape(o.failOn)
	if o.failOnKEV {
		gatePath += "&fail_on_kev=true"
	}
	var g gate
	if err := c.call(ctx, "GET", gatePath, nil, &g); err != nil {
		return exitError, err
	}
	return c.report(g, scanID), nil
}

type sbomLink struct {
	URL        string `json:"url"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
	Components int    `json:"components"`
}

// maxSBOM matches the server's cap on stored SBOMs.
const maxSBOM = 64 << 20

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// sbomFormats names the --sbom-format values in messages.
var sbomFormats = map[string]string{"cyclonedx": "CycloneDX", "spdx": "SPDX"}

// saveSBOM downloads the scan's SBOM in format (cyclonedx or spdx) from its
// presigned link (without the API token), checks it against the size and
// SHA-256 the server recorded, and replaces dest only once the whole file is
// verified.
func (c client) saveSBOM(ctx context.Context, scanPath, format, dest string) error {
	var l sbomLink
	if err := c.call(ctx, "GET", scanPath+"/sbom?format="+url.QueryEscape(format), nil, &l); err != nil {
		var ae *apiError
		if errors.As(err, &ae) && ae.status == http.StatusNotFound {
			return fmt.Errorf("the scan has no %s SBOM: Trivy must be among the scan's tools and succeed", sbomFormats[format])
		}
		return err
	}
	u, err := parseURL(l.URL)
	if err != nil {
		return fmt.Errorf("refusing the SBOM URL the server returned: %w", err)
	}
	if l.Size < 0 || l.Size > maxSBOM || !sha256Hex.MatchString(l.SHA256) {
		return errors.New("unexpected SBOM details from the server")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	resp, err := c.d.upload.Do(req)
	if err != nil {
		return netError("GET", "SBOM", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET SBOM: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, l.Size+1))
	if err != nil {
		return netError("GET", "SBOM", err)
	}
	sum := sha256.Sum256(body)
	if int64(len(body)) != l.Size || hex.EncodeToString(sum[:]) != l.SHA256 {
		return errors.New("the downloaded SBOM doesn't match the SHA-256 the server recorded")
	}
	if err := writeFile(dest, body, 0o644); err != nil {
		return fmt.Errorf("save SBOM: %w", err)
	}
	c.printf("==> SBOM (%s, %d components) saved to %s\n", sbomFormats[format], l.Components, clean(dest))
	return nil
}

// writeFile replaces path with data through a temporary file in the same
// directory, so a failed write never leaves a truncated file behind.
func writeFile(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".warden-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after the rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func digest(path string) (int64, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return n, hex.EncodeToString(h.Sum(nil)), err
}

// upload PUTs the archive to the presigned URL, with exactly the headers the
// server asked for (never the API token).
func (c client) upload(ctx context.Context, created createdScan, path string, size int64) error {
	u, err := parseURL(created.Upload.URL)
	if err != nil {
		return fmt.Errorf("refusing the upload URL the server returned: %w", err)
	}
	if created.Upload.Method != "" && created.Upload.Method != http.MethodPut {
		return fmt.Errorf("unexpected upload method %q", clean(created.Upload.Method))
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u.String(), f)
	if err != nil {
		return err
	}
	req.ContentLength = size
	for k, v := range created.Upload.Headers {
		if strings.EqualFold(k, "Authorization") || strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "Host") {
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := c.d.upload.Do(req)
	if err != nil {
		return netError("PUT", "upload", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponse))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("PUT upload: HTTP %d", resp.StatusCode)
	}
	return nil
}

func finished(status string) bool {
	switch status {
	case "completed", "partial", "failed", "cancelled":
		return true
	}
	return false
}

// wait polls the scan with backoff until it finishes. Rate limiting and
// server errors are retried a few times; anything else ends the wait.
func (c client) wait(ctx context.Context, scanPath string) (scanResp, error) {
	delay, last, failures := c.d.poll, "", 0
	for {
		var s scanResp
		err := c.call(ctx, "GET", scanPath, nil, &s)
		var ae *apiError
		switch {
		case err == nil:
			failures = 0
			if s.Status != last {
				c.printf("==> %s\n", clean(s.Status))
				last = s.Status
			}
			if finished(s.Status) {
				return s, nil
			}
		case errors.As(err, &ae) && ae.transient() && failures < 3:
			failures++
			if ae.retryAfter > delay {
				delay = ae.retryAfter
			}
		case ctx.Err() == nil && !errors.As(err, &ae) && failures < 3: // network hiccup
			failures++
		default:
			return scanResp{}, err
		}
		if err := c.d.sleep(ctx, delay); err != nil {
			return scanResp{}, err
		}
		delay = min(delay*3/2, maxPoll)
	}
}

// cancelScan is best effort, after the overall deadline has passed.
func (c client) cancelScan(scanPath string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = c.call(ctx, "POST", scanPath+"/cancel", nil, nil)
}

func (c client) report(g gate, scanID string) int {
	counts := fmt.Sprintf("critical %d, high %d, medium %d, low %d", g.Counts["critical"], g.Counts["high"], g.Counts["medium"], g.Counts["low"])
	if g.Pass {
		c.printf("PASS: scan %s (%s); no active issues at or above %s (%s)\n", clean(scanID), clean(g.Status), clean(g.FailOn), counts)
		return exitPass
	}
	if !g.Finished { // not expected: the CLI waits for the scan to finish
		c.printf("FAIL: scan %s hasn't finished (%s)\n", clean(scanID), clean(g.Status))
		return exitGateFailed
	}
	tw := tabwriter.NewWriter(c.o.stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "KEY\tSEVERITY\tTITLE\tLOCATION\tLINK")
	web := strings.TrimRight(c.o.server.String(), "/")
	for _, i := range g.Blocking {
		loc := "-"
		if i.FilePath != nil {
			loc = *i.FilePath
			if i.StartLine != nil {
				loc += ":" + strconv.Itoa(*i.StartLine)
			}
		}
		link := web + "/orgs/" + c.o.org.String() + "/issues/" + url.PathEscape(i.ID)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", clean(i.Key), clean(i.Severity), clean(truncate(i.Title, 70)), clean(truncate(loc, 80)), clean(link))
	}
	_ = tw.Flush()
	n := 0
	for _, s := range []string{"critical", "high", "medium", "low"} {
		n += g.Counts[s]
		if s == g.FailOn {
			break
		}
	}
	which := "at or above " + clean(g.FailOn)
	if c.o.failOnKEV {
		// Known-exploited issues block whatever their severity.
		which += " or known exploited (KEV)"
		n = max(n, len(g.Blocking))
	}
	c.printf("FAIL: scan %s (%s): %d blocking issue(s) %s (%s)\n", clean(scanID), clean(g.Status), n, which, counts)
	return exitGateFailed
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
