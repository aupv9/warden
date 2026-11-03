package worker

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	dregistry "github.com/aupv9/warden/backend/internal/domain/registry"
	"github.com/aupv9/warden/backend/internal/registry"
	"github.com/aupv9/warden/backend/internal/scan/sandbox"
	"github.com/aupv9/warden/backend/internal/secretbox"
	"github.com/aupv9/warden/backend/internal/worker/dbtest"
)

// pulledKey is the object key the API gives a pulled scan.
var pulledKey = "images/org/scan.tar"

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// miniRegistry serves one single-layer image behind Basic auth.
type miniRegistry struct {
	mu       sync.Mutex
	user     string
	pass     string
	manifest []byte
	blobs    map[string][]byte
	auths    []string
}

func newMiniRegistry(t *testing.T, user, pass string) (*miniRegistry, *httptest.Server, string) {
	t.Helper()
	var tb bytes.Buffer
	tw := tar.NewWriter(&tb)
	_ = tw.WriteHeader(&tar.Header{Name: "etc/os-release", Mode: 0o644, Size: 3, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("ID\n"))
	_ = tw.Close()
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(tb.Bytes())
	_ = zw.Close()
	layer, config := gz.Bytes(), []byte(`{"architecture":"amd64","os":"linux"}`)
	m, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": sha(config), "size": len(config)},
		"layers": []any{map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": sha(layer), "size": len(layer)}}})
	r := &miniRegistry{user: user, pass: pass, manifest: m, blobs: map[string][]byte{sha(config): config, sha(layer): layer}}
	srv := httptest.NewTLSServer(r)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return r, srv, u.Host + "/team/app@" + sha(m)
}

func (r *miniRegistry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	r.auths = append(r.auths, req.Header.Get("Authorization"))
	r.mu.Unlock()
	if req.Header.Get("Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte(r.user+":"+r.pass)) {
		w.Header().Set("WWW-Authenticate", `Basic realm="r"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	d := req.URL.Path[strings.LastIndex(req.URL.Path, "/")+1:]
	switch {
	case strings.Contains(req.URL.Path, "/manifests/") && d == sha(r.manifest):
		w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
		_, _ = w.Write(r.manifest)
	case strings.Contains(req.URL.Path, "/blobs/") && r.blobs[d] != nil:
		_, _ = w.Write(r.blobs[d])
	default:
		http.NotFound(w, req)
	}
}

// pullHarness is a queued pulled image scan whose org has credentials for
// the registry, sealed under keys; password is what the org stored.
func pullHarness(t *testing.T, password string, overrides ...dbtest.Step) (*harness, *miniRegistry, *bytes.Buffer, uuid.UUID) {
	t.Helper()
	reg, srv, ref := newMiniRegistry(t, "ci", "s3cret-registry-pa55")
	keys, err := secretbox.Parse("k1:"+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)), "")
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, "queued")
	credID := uuid.New()
	sealed, kid, err := dregistry.SealPassword(keys, h.org, credID, password)
	if err != nil {
		t.Fatal(err)
	}
	h.db = dbtest.Loose(t, h.scanSteps("queued", append([]dbtest.Step{
		{Prefix: "SELECT status, project_id", Rows: row("queued", h.project, &pulledKey, nil, []string{"trivy"}, false, "WEB", "image", "127.0.0.1/team/app")},
		{Prefix: "SELECT pulled, image_ref FROM scan", Rows: row(true, &ref)},
		{Prefix: "SELECT id, username, password_enc, key_id FROM registry_credential", Rows: row(credID, "ci", sealed, kid),
			Args: func(a []any) error {
				if a[0] != h.org || a[1] != strings.Split(ref, "/")[0] {
					return fmt.Errorf("credential looked up by %v", a)
				}
				return nil
			}},
		{Prefix: "UPDATE registry_credential SET last_used_at", Affected: 1},
	}, overrides...)...)...)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	h.env.Registry = RegistrySettings{Keys: keys, Platform: registry.Platform{OS: "linux", Arch: "amd64"},
		Client: registry.NewClient(registry.Options{AllowHosts: []string{"127.0.0.1"}, RootCAs: pool})}
	h.env.Limits.PullMaxBytes = 1 << 20
	h.env.Images = map[string]string{"trivy": "docker.io/aquasec/trivy:0.75.0@sha256:" + strings.Repeat("c", 64)}
	// The fake trivy fails: what's checked here is the pull and its stamp.
	h.sb.status["trivy"] = sandbox.Failed
	var logs bytes.Buffer
	h.env.Log = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return h, reg, &logs, credID
}

func lastError(t *testing.T, h *harness) any {
	t.Helper()
	calls := h.db.Calls("UPDATE registry_credential SET last_used_at")
	if len(calls) != 1 {
		t.Fatalf("credential stamped %d times", len(calls))
	}
	return calls[0].Args[1]
}

// A pulled scan: the worker decrypts the org's credentials, pulls with them
// (Basic, to the registry only), hands imagecheck and the scanner the
// tarball, stamps the credential, and cleans up like an upload.
func TestRunScanPullsTheImage(t *testing.T) {
	h, reg, logs, _ := pullHarness(t, "s3cret-registry-pa55")
	if err := h.run(1); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.sb.mounted["src/image.tar"]; !ok {
		t.Fatalf("scanner didn't get the image: %v", h.sb.mounted)
	}
	if got := lastError(t, h); got != (*string)(nil) {
		t.Fatalf("last_error %v", got)
	}
	// The key where an upload would be is "deleted" and stamped like one.
	if !slices.Equal(h.store.deleted, []string{pulledKey}) {
		t.Fatalf("deleted %v", h.store.deleted)
	}
	if _, err := os.Stat(filepath.Join(h.env.ScratchDir, h.scan.String())); err == nil {
		t.Fatal("scratch directory left behind")
	}
	if !slices.ContainsFunc(reg.auths, func(a string) bool { return strings.HasPrefix(a, "Basic ") }) {
		t.Fatal("credentials not used")
	}
	if !strings.Contains(logs.String(), "image pulled") || strings.Contains(logs.String(), "s3cret") {
		t.Fatalf("logs: %s", logs.String())
	}
	h.assertScoped()
}

// Refused credentials fail the scan with PULL_UNAUTHORIZED and say so on
// the credential; the password appears in no log.
func TestRunScanPullUnauthorized(t *testing.T) {
	h, _, logs, _ := pullHarness(t, "wrong-registry-pa55")
	if err := h.run(1); err != nil {
		t.Fatal(err)
	}
	h.failedWith(registry.CodeUnauthorized)
	if got, ok := lastError(t, h).(*string); !ok || got == nil || *got != registry.ReasonUnauthorized {
		t.Fatalf("last_error %v", lastError(t, h))
	}
	if len(h.sb.configs) != 0 {
		t.Fatal("a scanner ran")
	}
	if strings.Contains(logs.String(), "wrong-registry") {
		t.Fatalf("password logged: %s", logs.String())
	}
	if _, err := os.Stat(filepath.Join(h.env.ScratchDir, h.scan.String())); err == nil {
		t.Fatal("scratch directory left behind")
	}
}

// Credentials that can't be decrypted fail the scan; Warden doesn't fall back
// to an anonymous pull.
func TestRunScanPullUndecryptable(t *testing.T) {
	h, reg, _, _ := pullHarness(t, "s3cret-registry-pa55")
	h.env.Registry.Keys = nil
	if err := h.run(1); err != nil {
		t.Fatal(err)
	}
	h.failedWith(registry.CodeFailed)
	if len(reg.auths) != 0 {
		t.Fatal("registry contacted")
	}
}
