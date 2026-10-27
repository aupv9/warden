package storage

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aupv9/warden/backend/internal/config"
)

const okSum = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" // sha256("hello")

// fakeS3 serves objects from a map; paths are path-style /bucket/key.
type fakeS3 struct {
	mu      sync.Mutex
	objects map[string]string
	status  int // forced status for every request when non-zero
	lie     int // Content-Length to claim on GET when non-zero
	reqs    []string
	puts    map[string]http.Header // request headers of each PUT, by key
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs = append(f.reqs, r.Method+" "+r.URL.Path)
	if f.status != 0 {
		w.WriteHeader(f.status)
		return
	}
	key := strings.TrimPrefix(r.URL.Path, "/bucket/")
	if r.URL.Path == "/bucket" || r.URL.Path == "/bucket/" {
		w.WriteHeader(http.StatusOK) // HeadBucket
		return
	}
	body, ok := f.objects[key]
	switch r.Method {
	case http.MethodHead, http.MethodGet:
		if !ok {
			if r.Method == http.MethodGet {
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`<Error><Code>NoSuchKey</Code><Message>missing</Message></Error>`))
				return
			}
			w.WriteHeader(http.StatusNotFound)
			return
		}
		n := len(body)
		if f.lie != 0 && r.Method == http.MethodGet {
			n = f.lie
			w.Header().Set("Content-Length", strconv.Itoa(n))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(body))
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(n))
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(body))
		}
	case http.MethodPut:
		b, _ := io.ReadAll(r.Body)
		f.objects[key] = string(b)
		if f.puts == nil {
			f.puts = map[string]http.Header{}
		}
		f.puts[key] = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	case http.MethodDelete:
		delete(f.objects, key)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func newFake(t *testing.T, objects map[string]string) (*fakeS3, *Client) {
	t.Helper()
	f := &fakeS3{objects: objects}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c, err := New(Config{Endpoint: srv.URL, Bucket: "bucket", AccessKey: "ak", SecretKey: "sk", ChecksumHeader: true, MaxObjectBytes: 10})
	if err != nil {
		t.Fatal(err)
	}
	return f, c
}

func TestNewValidates(t *testing.T) {
	for _, c := range []Config{
		{AccessKey: "a", SecretKey: "b"},
		{Bucket: "b", SecretKey: "b"},
		{Bucket: "b", AccessKey: "a"},
		{Bucket: "b", AccessKey: "a", SecretKey: "b", Endpoint: "ftp://x"},
		{Bucket: "b", AccessKey: "a", SecretKey: "b", Endpoint: "http://"},
		{Bucket: "b", AccessKey: "a", SecretKey: "b", Endpoint: "://bad"},
	} {
		if _, err := New(c); err == nil {
			t.Errorf("%+v accepted", c)
		}
	}
}

func TestAddressingAndRegion(t *testing.T) {
	ctx := context.Background()
	yes := true
	for _, c := range []struct {
		cfg        Config
		wantPrefix string
		wantRegion string
	}{
		{Config{Endpoint: "http://localhost:8333"}, "http://localhost:8333/uploads/k?", "us-east-1"},
		{Config{Endpoint: "https://s3.eu-west-1.amazonaws.com"}, "https://uploads.s3.eu-west-1.amazonaws.com/k?", "eu-west-1"},
		{Config{Endpoint: "https://s3.amazonaws.com", Region: "us-west-2"}, "https://uploads.s3.amazonaws.com/k?", "us-west-2"},
		{Config{Endpoint: "https://s3.amazonaws.com", PathStyle: &yes}, "https://s3.amazonaws.com/uploads/k?", "us-east-1"},
		{Config{Region: "ap-south-1"}, "https://uploads.s3.ap-south-1.amazonaws.com/k?", "ap-south-1"},
	} {
		cfg := c.cfg
		cfg.Bucket, cfg.AccessKey, cfg.SecretKey = "uploads", "ak", "sk"
		cl, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		u, _, err := cl.PresignPut(ctx, "k", 5, okSum, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(u, c.wantPrefix) {
			t.Errorf("%+v: url %s, want prefix %s", c.cfg, u, c.wantPrefix)
		}
		if !strings.Contains(u, "%2F"+c.wantRegion+"%2Fs3%2F") {
			t.Errorf("%+v: region not %s in %s", c.cfg, c.wantRegion, u)
		}
	}
}

func TestPresignPutPinsSizeAndChecksum(t *testing.T) {
	_, c := newFake(t, nil)
	u, headers, err := c.PresignPut(context.Background(), "scans/o/s.zip", 5, okSum, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	q, _ := url.Parse(u)
	if got := q.Query().Get("X-Amz-SignedHeaders"); got != "content-length;host;x-amz-checksum-sha256" {
		t.Fatalf("signed headers %q", got)
	}
	if q.Query().Get("X-Amz-Expires") != "900" {
		t.Fatalf("expires %q", q.Query().Get("X-Amz-Expires"))
	}
	// base64 of the raw digest of "hello"
	if len(headers) != 1 || headers["X-Amz-Checksum-Sha256"] != "LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=" {
		t.Fatalf("headers %v", headers)
	}

	c.cfg.ChecksumHeader = false
	u, headers, err = c.PresignPut(context.Background(), "scans/o/s.zip", 5, "", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	q, _ = url.Parse(u)
	if q.Query().Get("X-Amz-SignedHeaders") != "content-length;host" || len(headers) != 0 {
		t.Fatalf("%s %v", u, headers)
	}
}

func TestPresignPutRejectsBadInput(t *testing.T) {
	_, c := newFake(t, nil)
	ctx := context.Background()
	for _, tc := range []struct {
		key  string
		size int64
		sum  string
		ttl  time.Duration
	}{
		{"", 5, okSum, time.Minute},
		{"/abs", 5, okSum, time.Minute},
		{"a/../b", 5, okSum, time.Minute},
		{strings.Repeat("k", 1025), 5, okSum, time.Minute},
		{"k", 0, okSum, time.Minute},
		{"k", -1, okSum, time.Minute},
		{"k", 5, okSum, 0},
		{"k", 5, okSum, 2 * time.Hour},
		{"k", 5, "XYZ", time.Minute},
		{"k", 5, strings.ToUpper(okSum), time.Minute},
	} {
		if _, _, err := c.PresignPut(ctx, tc.key, tc.size, tc.sum, tc.ttl); err == nil {
			t.Errorf("%+v accepted", tc)
		}
	}
}

func TestHead(t *testing.T) {
	f, c := newFake(t, map[string]string{"a.zip": "hello"})
	ctx := context.Background()
	if n, err := c.Head(ctx, "a.zip"); err != nil || n != 5 {
		t.Fatal(n, err)
	}
	if _, err := c.Head(ctx, "missing.zip"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := c.Head(ctx, "../x"); err == nil {
		t.Fatal("bad key accepted")
	}
	f.status = http.StatusForbidden
	if _, err := c.Head(ctx, "a.zip"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}

func TestDownload(t *testing.T) {
	f, c := newFake(t, map[string]string{"a.zip": "hello", "big.zip": "0123456789A"})
	ctx := context.Background()
	dir := t.TempDir()

	dest := filepath.Join(dir, "a")
	if err := c.Download(ctx, "a.zip", dest); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dest); string(b) != "hello" {
		t.Fatalf("%q", b)
	}
	if st, _ := os.Stat(dest); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	// dest must not exist (O_EXCL): no clobbering or symlink following.
	if err := c.Download(ctx, "a.zip", dest); err == nil {
		t.Fatal("overwrote an existing file")
	}
	if err := c.Download(ctx, "missing.zip", filepath.Join(dir, "m")); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if err := c.Download(ctx, "big.zip", filepath.Join(dir, "big")); !errors.Is(err, ErrTooLarge) {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "big")); err == nil {
		t.Fatal("oversized download left a file")
	}
	if err := c.Download(ctx, "", filepath.Join(dir, "x")); err == nil {
		t.Fatal("empty key accepted")
	}
	f.status = http.StatusForbidden
	if err := c.Download(ctx, "a.zip", filepath.Join(dir, "f")); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}

// A store that under-reports Content-Length still can't push more than the cap.
func TestDownloadCapsStreamedBytes(t *testing.T) {
	f, c := newFake(t, map[string]string{"liar.zip": "0123456789ABCDEF"})
	f.lie = 16
	c.cfg.MaxObjectBytes = 10
	dest := filepath.Join(t.TempDir(), "l")
	if err := c.Download(context.Background(), "liar.zip", dest); !errors.Is(err, ErrTooLarge) {
		t.Fatal(err)
	}
	if _, err := os.Stat(dest); err == nil {
		t.Fatal("partial file left")
	}
}

func TestDeleteAndPing(t *testing.T) {
	f, c := newFake(t, map[string]string{"a.zip": "hello"})
	ctx := context.Background()
	if err := c.Delete(ctx, "a.zip"); err != nil {
		t.Fatal(err)
	}
	if len(f.objects) != 0 {
		t.Fatal("not deleted")
	}
	if err := c.Delete(ctx, "a.zip"); err != nil {
		t.Fatal("deleting a missing object must succeed:", err)
	}
	if err := c.Delete(ctx, "/a"); err == nil {
		t.Fatal("bad key accepted")
	}
	if err := c.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	f.status = http.StatusForbidden
	if err := c.Delete(ctx, "a.zip"); err == nil {
		t.Fatal("error swallowed")
	}
	if err := c.Ping(ctx); err == nil {
		t.Fatal("ping ignored 403")
	}
}

func TestFromSection(t *testing.T) {
	c := FromSection(config.StorageSection{Endpoint: "http://s3:8333", Bucket: "b", AccessKey: "ak", SecretKey: "sk"})
	if c.Endpoint != "http://s3:8333" || c.Bucket != "b" || c.AccessKey != "ak" || c.SecretKey != "sk" || !c.ChecksumHeader {
		t.Fatalf("%+v", c)
	}
}

func TestPut(t *testing.T) {
	f, c := newFake(t, map[string]string{})
	ctx := context.Background()
	if err := c.Put(ctx, "sboms/o/s.cdx.json", []byte("hello"), okSum, "application/vnd.cyclonedx+json"); err != nil {
		t.Fatal(err)
	}
	h := f.puts["sboms/o/s.cdx.json"]
	if f.objects["sboms/o/s.cdx.json"] != "hello" || h.Get("Content-Type") != "application/vnd.cyclonedx+json" ||
		h.Get("X-Amz-Checksum-Sha256") != "LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=" {
		t.Fatalf("%v %v", f.objects, h)
	}
	if err := c.Put(ctx, "a", []byte("x"), "nothex", "text/plain"); err == nil {
		t.Fatal("bad checksum accepted")
	}
	if err := c.Put(ctx, "../a", []byte("x"), okSum, "text/plain"); err == nil {
		t.Fatal("bad key accepted")
	}
	f.status = http.StatusForbidden
	if err := c.Put(ctx, "b", []byte("hello"), okSum, "text/plain"); err == nil {
		t.Fatal("error swallowed")
	}
}

func TestPresignGetIsAnAttachment(t *testing.T) {
	_, c := newFake(t, nil)
	ctx := context.Background()
	raw, err := c.PresignGet(ctx, "sboms/o/s.cdx.json", 5*time.Minute, "WEB-0192f0c4.cdx.json", "application/vnd.cyclonedx+json")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(raw)
	q := u.Query()
	if u.Path != "/bucket/sboms/o/s.cdx.json" || q.Get("response-content-disposition") != `attachment; filename="WEB-0192f0c4.cdx.json"` ||
		q.Get("response-content-type") != "application/vnd.cyclonedx+json" || q.Get("X-Amz-Expires") != "300" {
		t.Fatal(raw)
	}
	for _, name := range []string{"", `a"; filename="x.html`, "a\r\nX: y", "../x", strings.Repeat("a", 129)} {
		if _, err := c.PresignGet(ctx, "k", time.Minute, name, "text/plain"); err == nil {
			t.Errorf("name %q accepted", name)
		}
	}
	if _, err := c.PresignGet(ctx, "k", 2*time.Hour, "a", "text/plain"); err == nil {
		t.Fatal("long ttl accepted")
	}
	if _, err := c.PresignGet(ctx, "/k", time.Minute, "a", "text/plain"); err == nil {
		t.Fatal("bad key accepted")
	}
}
