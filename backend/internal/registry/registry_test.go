package registry

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aupv9/warden/backend/internal/scan/imagecheck"
)

// Host names of the test servers; all resolve to loopback through the stub
// resolver. Names in allowHosts pass the address guard (as registry.allow_hosts
// would let a laptop's registry), the others are refused at dial time.
const (
	regName      = "registry.reg.test"
	realmName    = "auth.reg.test" // same site as the registry (reg.test)
	cdnName      = "cdn.blobs.test"
	evilName     = "evil.other.test" // another site, but reachable
	internalName = "internal.test"   // not allowed: refused by the guard
)

var allowHosts = []string{regName, realmName, cdnName, evilName}

// testPKI is one self-signed certificate for every test name.
type testPKI struct {
	cert tls.Certificate
	pool *x509.CertPool
}

var (
	pkiOnce sync.Once
	pki     testPKI
)

func getPKI(t *testing.T) testPKI {
	t.Helper()
	pkiOnce.Do(func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "warden registry test"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			DNSNames:    []string{regName, realmName, cdnName, evilName, internalName},
			IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
			KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			panic(err)
		}
		leaf, _ := x509.ParseCertificate(der)
		pool := x509.NewCertPool()
		pool.AddCert(leaf)
		pki = testPKI{cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool: pool}
	})
	return pki
}

// tlsServer starts an https server for h with the test certificate.
func tlsServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	s := httptest.NewUnstartedServer(h)
	s.TLS = &tls.Config{Certificates: []tls.Certificate{getPKI(t).cert}}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

func port(s *httptest.Server) string {
	u, _ := url.Parse(s.URL)
	return u.Port()
}

// stubResolver answers every name with loopback unless answers says otherwise.
type stubResolver struct {
	mu      sync.Mutex
	answers map[string][]netip.Addr
	calls   map[string]int
}

func (r *stubResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.calls == nil {
		r.calls = map[string]int{}
	}
	r.calls[host]++
	if a, ok := r.answers[host]; ok {
		return a, nil
	}
	if strings.HasSuffix(host, ".test") {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func newTestClient(t *testing.T, r *stubResolver) *Client {
	if r == nil {
		r = &stubResolver{}
	}
	return NewClient(Options{AllowHosts: allowHosts, RootCAs: getPKI(t).pool, Resolver: r,
		DialTimeout: 2 * time.Second, HeaderTimeout: 2 * time.Second, IdleTimeout: 2 * time.Second})
}

// --- images ---

func digestOf(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

func gzipLayer(t *testing.T, name, content string) []byte {
	t.Helper()
	var tb bytes.Buffer
	tw := tar.NewWriter(&tb)
	_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte(content))
	_ = tw.Close()
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(tb.Bytes())
	_ = zw.Close()
	return gz.Bytes()
}

type desc = map[string]any

type image struct {
	config   []byte
	layers   [][]byte
	manifest []byte
	digest   string
}

func (i image) desc(mt string) desc {
	return desc{"mediaType": mt, "digest": i.digest, "size": len(i.manifest)}
}

// buildImage makes an image manifest of n layers (a repeated last layer when
// dup is set).
func buildImage(t *testing.T, arch string, n int, dup bool) image {
	t.Helper()
	img := image{config: []byte(`{"architecture":"` + arch + `","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`)}
	var ls []any
	for i := range n {
		l := gzipLayer(t, fmt.Sprintf("etc/f%d", i), fmt.Sprintf("layer %d of %s", i, arch))
		if dup && i == n-1 && i > 0 {
			l = img.layers[0]
		}
		img.layers = append(img.layers, l)
		ls = append(ls, desc{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "digest": digestOf(l), "size": len(l)})
	}
	m, _ := json.Marshal(desc{"schemaVersion": 2, "mediaType": mtDockerManifest,
		"config": desc{"mediaType": mtDockerConfig, "digest": digestOf(img.config), "size": len(img.config)}, "layers": ls})
	img.manifest, img.digest = m, digestOf(m)
	return img
}

func buildIndex(entries ...desc) ([]byte, string) {
	b, _ := json.Marshal(desc{"schemaVersion": 2, "mediaType": mtOCIIndex, "manifests": entries})
	return b, digestOf(b)
}

func withPlatform(d desc, os, arch, variant string) desc {
	p := desc{"os": os, "architecture": arch}
	if variant != "" {
		p["variant"] = variant
	}
	d["platform"] = p
	return d
}

// --- servers ---

type seen struct {
	host, path, auth string
}

// fakeRegistry serves manifests and blobs, optionally behind Basic or Bearer
// auth, and records every request.
type fakeRegistry struct {
	mu        sync.Mutex
	manifests map[string][]byte // by digest
	types     map[string]string // Content-Type by digest
	blobs     map[string][]byte
	auth      string // "", "basic", "bearer"
	realm     string // the Bearer challenge's realm
	user      string
	pass      string
	token     string
	cdn       string // blobs redirect here (base URL) when set
	hook      func(w http.ResponseWriter, r *http.Request) bool
	reqs      []seen
}

func newFake() *fakeRegistry {
	return &fakeRegistry{manifests: map[string][]byte{}, types: map[string]string{}, blobs: map[string][]byte{}}
}

func (f *fakeRegistry) addImage(img image) {
	f.manifests[img.digest] = img.manifest
	f.types[img.digest] = mtDockerManifest
	f.blobs[digestOf(img.config)] = img.config
	for _, l := range img.layers {
		f.blobs[digestOf(l)] = l
	}
}

func (f *fakeRegistry) record(r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs = append(f.reqs, seen{host: r.Host, path: r.URL.Path, auth: r.Header.Get("Authorization")})
}

func (f *fakeRegistry) requests(pathPrefix string) []seen {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []seen
	for _, s := range f.reqs {
		if strings.HasPrefix(s.path, pathPrefix) {
			out = append(out, s)
		}
	}
	return out
}

func (f *fakeRegistry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.record(r)
	if f.hook != nil && f.hook(w, r) {
		return
	}
	switch f.auth {
	case "basic":
		if r.Header.Get("Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte(f.user+":"+f.pass)) {
			w.Header().Set("WWW-Authenticate", `Basic realm="registry"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	case "bearer":
		if r.Header.Get("Authorization") != "Bearer "+f.token {
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+f.realm+`",service="reg",scope="repository:app:push,pull"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
	p := r.URL.Path
	switch {
	case p == "/v2/":
		w.WriteHeader(http.StatusOK)
	case strings.Contains(p, "/manifests/"):
		d := p[strings.LastIndex(p, "/")+1:]
		b, ok := f.manifests[d]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", f.types[d])
		_, _ = w.Write(b)
	case strings.Contains(p, "/blobs/"):
		d := p[strings.LastIndex(p, "/")+1:]
		if f.cdn != "" {
			http.Redirect(w, r, f.cdn+"/blobs/"+d+"?sig=s3cr3t-signature", http.StatusTemporaryRedirect)
			return
		}
		f.serveBlob(w, r, d)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeRegistry) serveBlob(w http.ResponseWriter, r *http.Request, d string) {
	b, ok := f.blobs[d]
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Length", fmt.Sprint(len(b)))
	_, _ = w.Write(b)
}

// cdn serves a registry's blobs at /blobs/<digest>, recording requests.
type cdn struct{ f, rec *fakeRegistry }

func (c cdn) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.rec.record(r)
	c.f.serveBlob(w, r, r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:])
}

// tokenServer issues token for user/pass (or anonymously when user is "").
type tokenServer struct {
	rec         *fakeRegistry
	user, pass  string
	token       string
	anonymousOK bool
}

func (s tokenServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.rec.record(r)
	got := r.Header.Get("Authorization")
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(s.user+":"+s.pass))
	if got != want && !(got == "" && s.anonymousOK) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.URL.Query().Get("scope") != "repository:app:pull" || r.URL.Query().Get("service") != "reg" {
		http.Error(w, "bad scope "+r.URL.RawQuery, http.StatusBadRequest)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"token": s.token, "expires_in": 300})
}

// setup is a registry at regName with one amd64 image of three layers.
type setup struct {
	f    *fakeRegistry
	srv  *httptest.Server
	img  image
	ref  Ref
	c    *Client
	r    *stubResolver
	dest string
}

func newSetup(t *testing.T) *setup {
	t.Helper()
	s := &setup{f: newFake(), img: buildImage(t, "amd64", 3, false), r: &stubResolver{}}
	s.f.addImage(s.img)
	s.srv = tlsServer(t, s.f)
	s.ref = Ref{Host: regName + ":" + port(s.srv), Repository: "app", Digest: s.img.digest}
	s.c = newTestClient(t, s.r)
	s.dest = filepath.Join(t.TempDir(), "image.tar")
	return s
}

var amd64 = Platform{OS: "linux", Arch: "amd64"}

func (s *setup) pull(creds *Credentials, maxBytes int64) (*Result, error) {
	return s.c.Pull(context.Background(), s.ref, creds, amd64, Limits{MaxBytes: maxBytes}, s.dest)
}

func wantCode(t *testing.T, err error, code string) *Error {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) || e.Code != code {
		t.Fatalf("want %s, got %v", code, err)
	}
	return e
}

// --- happy paths ---

func TestPullWritesADockerSaveTarball(t *testing.T) {
	s := newSetup(t)
	// An index: amd64, arm64/v8 and an attestation manifest.
	arm := buildImage(t, "arm64", 2, false)
	s.f.addImage(arm)
	att := buildImage(t, "unknown", 1, false)
	s.f.addImage(att)
	idx, idxDigest := buildIndex(
		withPlatform(arm.desc(mtDockerManifest), "linux", "arm64", "v8"),
		withPlatform(s.img.desc(mtDockerManifest), "linux", "amd64", ""),
		withPlatform(att.desc(mtDockerManifest), "unknown", "unknown", ""),
	)
	s.f.manifests[idxDigest], s.f.types[idxDigest] = idx, mtOCIIndex
	s.ref.Digest = idxDigest

	res, err := s.pull(nil, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if res.Manifest != s.img.digest || res.Platform != "linux/amd64" || res.Layers != 3 {
		t.Fatalf("%+v", res)
	}
	want := int64(len(idx) + len(s.img.manifest) + len(s.img.config))
	for _, l := range s.img.layers {
		want += int64(len(l))
	}
	if res.Bytes != want {
		t.Fatalf("bytes %d, want %d", res.Bytes, want)
	}
	ir, err := imagecheck.Check(s.dest, imagecheck.Limits{MaxBytes: want + TarOverhead})
	if err != nil || ir.Layout != "docker" || ir.Layers != 3 {
		t.Fatal(ir, err)
	}
	files := readTar(t, s.dest)
	var mf []struct {
		Config string
		Layers []string
	}
	if err := json.Unmarshal(files["manifest.json"], &mf); err != nil || len(mf) != 1 {
		t.Fatal(err, string(files["manifest.json"]))
	}
	if !bytes.Equal(files[mf[0].Config], s.img.config) {
		t.Fatal("config differs")
	}
	for i, l := range mf[0].Layers {
		if !bytes.Equal(files[l], s.img.layers[i]) {
			t.Fatalf("layer %d differs", i)
		}
	}
	// arm64/v8 is picked for linux/arm64 too (no variant asked).
	dest2 := filepath.Join(t.TempDir(), "arm.tar")
	res, err = s.c.Pull(context.Background(), s.ref, nil, Platform{OS: "linux", Arch: "arm64"}, Limits{MaxBytes: 1 << 20}, dest2)
	if err != nil || res.Manifest != arm.digest {
		t.Fatal(res, err)
	}
	// Nothing was ever sent with credentials.
	for _, r := range s.f.requests("/") {
		if r.auth != "" {
			t.Fatalf("anonymous pull sent %q", r.auth)
		}
	}
}

func readTar(t *testing.T, p string) map[string][]byte {
	t.Helper()
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string][]byte{}
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		if _, dup := out[h.Name]; dup {
			t.Fatalf("duplicate entry %s", h.Name)
		}
		out[h.Name] = b
	}
}

// A repeated layer is stored once (imagecheck refuses duplicate entries).
func TestPullRepeatedLayer(t *testing.T) {
	s := newSetup(t)
	img := buildImage(t, "amd64", 3, true)
	s.f.addImage(img)
	s.ref.Digest = img.digest
	if _, err := s.pull(nil, 1<<20); err != nil {
		t.Fatal(err)
	}
	if _, err := imagecheck.Check(s.dest, imagecheck.Limits{MaxBytes: 1 << 20}); err != nil {
		t.Fatal(err)
	}
}

// Bearer: the credentials go to a realm on the registry's site, the token to
// the registry, and nothing to the CDN blobs are redirected to.
func TestPullBearerSameSiteAndCDN(t *testing.T) {
	s := newSetup(t)
	tok := tlsServer(t, tokenServer{rec: s.f, user: "ci", pass: "pa55word", token: "tkn-1"})
	c := tlsServer(t, cdn{f: s.f, rec: s.f})
	s.f.auth, s.f.token = "bearer", "tkn-1"
	s.f.realm = "https://" + realmName + ":" + port(tok) + "/token"
	s.f.cdn = "https://" + cdnName + ":" + port(c)

	if _, err := s.pull(&Credentials{Username: "ci", Password: "pa55word"}, 1<<20); err != nil {
		t.Fatal(err)
	}
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("ci:pa55word"))
	var realmHits, cdnHits int
	for _, r := range s.f.requests("/") {
		h, _, _ := strings.Cut(r.host, ":")
		switch h {
		case realmName:
			realmHits++
			if r.auth != basic {
				t.Fatalf("realm got %q", r.auth)
			}
		case cdnName:
			cdnHits++
			if r.auth != "" {
				t.Fatalf("CDN got Authorization %q", r.auth)
			}
		case regName:
			if r.auth != "" && r.auth != "Bearer tkn-1" {
				t.Fatalf("registry got %q", r.auth)
			}
		}
	}
	if realmHits != 1 || cdnHits != 4 { // config + 3 layers
		t.Fatalf("realm %d, cdn %d", realmHits, cdnHits)
	}
}

func TestPullBasicOnlyToTheRegistry(t *testing.T) {
	s := newSetup(t)
	c := tlsServer(t, cdn{f: s.f, rec: s.f})
	s.f.auth, s.f.user, s.f.pass = "basic", "ci", "pa55word"
	s.f.cdn = "https://" + cdnName + ":" + port(c)
	if _, err := s.pull(&Credentials{Username: "ci", Password: "pa55word"}, 1<<20); err != nil {
		t.Fatal(err)
	}
	for _, r := range s.f.requests("/blobs/") {
		if r.auth != "" {
			t.Fatalf("CDN got %q", r.auth)
		}
	}
	// Wrong password: unauthorized, and the password is in no error.
	s.dest = filepath.Join(t.TempDir(), "x.tar")
	_, err := s.pull(&Credentials{Username: "ci", Password: "wrong-pa55"}, 1<<20)
	e := wantCode(t, err, CodeUnauthorized)
	if e.Reason() != ReasonUnauthorized || strings.Contains(err.Error(), "wrong-pa55") {
		t.Fatal(err)
	}
	// No credentials at all.
	s.dest = filepath.Join(t.TempDir(), "y.tar")
	_, err = s.pull(nil, 1<<20)
	wantCode(t, err, CodeUnauthorized)
}

// --- attacks ---

// A realm on another site never sees the org's credentials; without
// credentials an anonymous token from it is fine.
func TestRealmOnAnotherSite(t *testing.T) {
	s := newSetup(t)
	evil := &fakeRegistry{}
	tok := tlsServer(t, tokenServer{rec: evil, token: "anon", anonymousOK: true})
	s.f.auth, s.f.token = "bearer", "anon"
	s.f.realm = "https://" + evilName + ":" + port(tok) + "/token"

	_, err := s.pull(&Credentials{Username: "ci", Password: "pa55word"}, 1<<20)
	if e := wantCode(t, err, CodeBlocked); e.Reason() != ReasonBlocked {
		t.Fatal(e)
	}
	if n := len(evil.requests("/")); n != 0 {
		t.Fatalf("realm on another site got %d requests", n)
	}
	if _, err := s.pull(nil, 1<<20); err != nil {
		t.Fatal(err)
	}
	for _, r := range evil.requests("/") {
		if r.auth != "" {
			t.Fatalf("anonymous token request sent %q", r.auth)
		}
	}
	// A realm over plain http, or at an internal address, is refused too.
	for _, realm := range []string{
		"http://other.reg.test:" + port(tok) + "/token",
		"https://" + internalName + ":" + port(tok) + "/token",
		"https://169.254.169.254/token",
		"https://user:pw@" + realmName + ":" + port(tok) + "/token",
	} {
		s.f.realm = realm
		s.dest = filepath.Join(t.TempDir(), "z.tar")
		_, err := s.pull(nil, 1<<20)
		wantCode(t, err, CodeBlocked)
	}
}

// Redirects are re-checked hop by hop: internal addresses, plain http and
// endless chains are refused, and the internal server is never reached.
func TestRedirectToInternal(t *testing.T) {
	inner := newFake()
	internal := tlsServer(t, cdn{f: inner, rec: inner})
	p := port(internal)
	for _, target := range []string{
		"https://" + internalName + ":" + p,   // resolves to loopback, not allowed
		"https://127.0.0.1:" + p,              // a literal
		"https://[::ffff:127.0.0.1]:" + p,     // IPv4-mapped
		"https://169.254.169.254",             // cloud metadata
		"https://[fd00:ec2::254]",             // AWS IPv6 metadata
		"https://[64:ff9b::7f00:1]:" + p,      // NAT64 of loopback
		"http://" + internalName + ":" + p,    // plain http
		"ftp://" + cdnName + "/x",             // another scheme
		"https://user:pass@" + cdnName + "/x", // user info
	} {
		t.Run(target, func(t *testing.T) {
			s := newSetup(t)
			s.f.cdn = target
			_, err := s.pull(nil, 1<<20)
			wantCode(t, err, CodeBlocked)
		})
	}
	if n := len(inner.requests("/")); n != 0 {
		t.Fatalf("internal server reached %d times", n)
	}
}

func TestRedirectLoop(t *testing.T) {
	s := newSetup(t)
	s.f.hook = func(w http.ResponseWriter, r *http.Request) bool {
		if strings.Contains(r.URL.Path, "/blobs/") || strings.HasPrefix(r.URL.Path, "/loop") {
			http.Redirect(w, r, "/loop"+fmt.Sprint(len(r.URL.Path)), http.StatusFound)
			return true
		}
		return false
	}
	_, err := s.pull(nil, 1<<20)
	if e := wantCode(t, err, CodeFailed); !strings.Contains(e.Detail, "redirects") {
		t.Fatal(e)
	}
}

// The registry host itself at an internal address (DNS pointing there, or a
// DNS answer that changed since the credential was tested) is refused at
// dial time, for every form of an internal address.
func TestAddressGuard(t *testing.T) {
	s := newSetup(t)
	p := port(s.srv)
	for name, addrs := range map[string][]string{
		"loopback.test": {"127.0.0.1"},
		"mixed.test":    {"10.0.0.7", "127.0.0.1"},
		"mapped.test":   {"::ffff:127.0.0.1"},
		"nat64.test":    {"64:ff9b::a9fe:a9fe"},
		"sixto4.test":   {"2002:7f00:1::1"},
		"cgnat.test":    {"100.100.100.200"},
		"ula.test":      {"fd12:3456::1"},
		"meta.test":     {"169.254.169.254"},
	} {
		var as []netip.Addr
		for _, a := range addrs {
			as = append(as, netip.MustParseAddr(a))
		}
		r := &stubResolver{answers: map[string][]netip.Addr{name: as}}
		c := newTestClient(t, r)
		ref := Ref{Host: name + ":" + p, Repository: "app", Digest: s.img.digest}
		_, err := c.Pull(context.Background(), ref, &Credentials{Username: "u", Password: "p"}, amd64, Limits{MaxBytes: 1 << 20},
			filepath.Join(t.TempDir(), "x.tar"))
		if e := wantCode(t, err, CodeBlocked); e.Reason() != ReasonBlocked {
			t.Fatal(name, e)
		}
		if ok, kind := c.Check(context.Background(), name+":"+p, "u", "p"); ok || kind != ReasonBlocked {
			t.Fatal(name, ok, kind)
		}
	}
	if n := len(s.f.requests("/")); n != 0 {
		t.Fatalf("registry reached %d times through a refused name", n)
	}
	// Every pull resolves the name again and checks the answer it dials (no
	// answer is cached from a test or an earlier pull: DNS rebinding).
	r := &stubResolver{}
	c := newTestClient(t, r)
	ref := Ref{Host: "rebind.test:" + p, Repository: "app", Digest: s.img.digest}
	for range 2 {
		_, err := c.Pull(context.Background(), ref, nil, amd64, Limits{MaxBytes: 1 << 20}, filepath.Join(t.TempDir(), "x.tar"))
		wantCode(t, err, CodeBlocked)
	}
	if r.calls["rebind.test"] != 2 {
		t.Fatalf("looked up %d times", r.calls["rebind.test"])
	}
}

func TestManifestDigestMismatch(t *testing.T) {
	s := newSetup(t)
	other := buildImage(t, "amd64", 1, false)
	s.f.manifests[s.img.digest] = other.manifest // served for the wrong digest
	_, err := s.pull(nil, 1<<20)
	if e := wantCode(t, err, CodeFailed); !strings.Contains(e.Detail, "digest mismatch") {
		t.Fatal(e)
	}
	if n := len(s.f.requests("/v2/app/blobs/")); n != 0 {
		t.Fatalf("%d blobs fetched for an unverified manifest", n)
	}
	// An index entry whose manifest doesn't hash to the entry's digest.
	s = newSetup(t)
	idx, d := buildIndex(withPlatform(s.img.desc(mtDockerManifest), "linux", "amd64", ""))
	s.f.manifests[d], s.f.types[d] = idx, mtOCIIndex
	s.f.manifests[s.img.digest] = other.manifest
	s.ref.Digest = d
	_, err = s.pull(nil, 1<<20)
	wantCode(t, err, CodeFailed)
}

func TestBlobDigestMismatch(t *testing.T) {
	for name, mutate := range map[string]func(b []byte) []byte{
		"flipped": func(b []byte) []byte { c := bytes.Clone(b); c[len(c)-1] ^= 1; return c },
		"short":   func(b []byte) []byte { return b[:len(b)-1] },
		"long":    func(b []byte) []byte { return append(bytes.Clone(b), 'x') },
	} {
		t.Run(name, func(t *testing.T) {
			s := newSetup(t)
			d := digestOf(s.img.layers[1])
			s.f.blobs[d] = mutate(s.img.layers[1])
			_, err := s.pull(nil, 1<<20)
			wantCode(t, err, CodeFailed)
		})
	}
	// A body longer than its descriptor without Content-Length: only the
	// descriptor's bytes are read, and they must match.
	s := newSetup(t)
	s.f.hook = func(w http.ResponseWriter, r *http.Request) bool {
		if strings.Contains(r.URL.Path, "/blobs/") {
			d := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
			w.(http.Flusher).Flush() // chunked: no Content-Length
			_, _ = w.Write(append(bytes.Clone(s.f.blobs[d]), bytes.Repeat([]byte("A"), 4096)...))
			return true
		}
		return false
	}
	if _, err := s.pull(nil, 1<<20); err != nil {
		t.Fatal(err)
	}
	if _, err := imagecheck.Check(s.dest, imagecheck.Limits{MaxBytes: 1 << 20}); err != nil {
		t.Fatal(err)
	}
}

func TestOversize(t *testing.T) {
	s := newSetup(t)
	total := int64(len(s.img.manifest) + len(s.img.config))
	for _, l := range s.img.layers {
		total += int64(len(l))
	}
	if _, err := s.pull(nil, total); err != nil {
		t.Fatal("exactly the limit:", err)
	}
	s.dest = filepath.Join(t.TempDir(), "y.tar")
	before := len(s.f.requests("/v2/app/blobs/"))
	_, err := s.pull(nil, total-1)
	wantCode(t, err, CodeTooLarge)
	if n := len(s.f.requests("/v2/app/blobs/")) - before; n != 0 {
		t.Fatalf("%d blobs fetched for an image over the limit", n)
	}

	// A manifest over MaxManifestBytes, announced or not.
	for _, announce := range []bool{true, false} {
		s := newSetup(t)
		big := append([]byte(`{"schemaVersion":2,"x":"`), bytes.Repeat([]byte("a"), MaxManifestBytes)...)
		big = append(big, `"}`...)
		d := digestOf(big)
		s.f.hook = func(w http.ResponseWriter, r *http.Request) bool {
			if !strings.Contains(r.URL.Path, "/manifests/") {
				return false
			}
			if announce {
				w.Header().Set("Content-Length", fmt.Sprint(len(big)))
			} else {
				w.(http.Flusher).Flush()
			}
			_, _ = w.Write(big)
			return true
		}
		s.ref.Digest = d
		_, err := s.pull(nil, 1<<30)
		wantCode(t, err, CodeTooLarge)
	}

	// A descriptor that claims a huge layer is refused before any blob.
	s = newSetup(t)
	var m map[string]any
	_ = json.Unmarshal(s.img.manifest, &m)
	m["layers"].([]any)[0].(map[string]any)["size"] = int64(1) << 40
	raw, _ := json.Marshal(m)
	s.f.manifests[digestOf(raw)], s.f.types[digestOf(raw)] = raw, mtDockerManifest
	s.ref.Digest = digestOf(raw)
	_, err = s.pull(nil, 2048<<20)
	wantCode(t, err, CodeTooLarge)
	if n := len(s.f.requests("/v2/app/blobs/")); n != 0 {
		t.Fatalf("%d blobs fetched", n)
	}
}

func TestTooManyLayers(t *testing.T) {
	s := newSetup(t)
	img := buildImage(t, "amd64", MaxLayers+1, false)
	s.f.addImage(img)
	s.ref.Digest = img.digest
	_, err := s.pull(nil, 1<<30)
	wantCode(t, err, CodeTooLarge)
	if n := len(s.f.requests("/v2/app/blobs/")); n != 0 {
		t.Fatalf("%d blobs fetched", n)
	}
	img = buildImage(t, "amd64", MaxLayers, false)
	s.f.addImage(img)
	s.ref.Digest = img.digest
	if _, err := s.pull(nil, 1<<30); err != nil {
		t.Fatal(err)
	}
}

func TestIndexWithoutThePlatform(t *testing.T) {
	s := newSetup(t)
	arm := buildImage(t, "arm64", 1, false)
	s.f.addImage(arm)
	idx, d := buildIndex(
		withPlatform(arm.desc(mtDockerManifest), "linux", "arm64", "v8"),
		withPlatform(s.img.desc(mtDockerManifest), "windows", "amd64", ""),
	)
	s.f.manifests[d], s.f.types[d] = idx, mtOCIIndex
	s.ref.Digest = d
	_, err := s.pull(nil, 1<<20)
	wantCode(t, err, CodePlatform)
	// linux/arm/v7 doesn't take arm64.
	_, err = s.c.Pull(context.Background(), s.ref, nil, Platform{OS: "linux", Arch: "arm", Variant: "v7"}, Limits{MaxBytes: 1 << 20},
		filepath.Join(t.TempDir(), "a.tar"))
	wantCode(t, err, CodePlatform)
}

func TestUnsupportedManifests(t *testing.T) {
	s := newSetup(t)
	cases := map[string]string{
		"schema1":  `{"schemaVersion":1,"name":"app","fsLayers":[]}`,
		"foreign":  `{"schemaVersion":2,"mediaType":"` + mtDockerManifest + `","config":{"mediaType":"` + mtDockerConfig + `","digest":"` + digestOf(s.img.config) + `","size":` + fmt.Sprint(len(s.img.config)) + `},"layers":[{"mediaType":"application/vnd.docker.image.rootfs.foreign.diff.tar.gzip","digest":"` + digestOf([]byte("x")) + `","size":1,"urls":["https://169.254.169.254/x"]}]}`,
		"artifact": `{"schemaVersion":2,"mediaType":"` + mtOCIManifest + `","config":{"mediaType":"application/vnd.cncf.helm.config.v1+json","digest":"` + digestOf(s.img.config) + `","size":` + fmt.Sprint(len(s.img.config)) + `},"layers":[]}`,
		"nested":   `{"schemaVersion":2,"mediaType":"` + mtOCIIndex + `","manifests":[{"mediaType":"` + mtOCIIndex + `","digest":"` + s.img.digest + `","size":10,"platform":{"os":"linux","architecture":"amd64"}}]}`,
		"sha512":   `{"schemaVersion":2,"mediaType":"` + mtDockerManifest + `","config":{"mediaType":"` + mtDockerConfig + `","digest":"sha512:` + strings.Repeat("a", 128) + `","size":10},"layers":[]}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			d := digestOf([]byte(raw))
			s.f.manifests[d], s.f.types[d] = []byte(raw), "application/json"
			s.ref.Digest = d
			s.dest = filepath.Join(t.TempDir(), "x.tar")
			_, err := s.pull(nil, 1<<20)
			if name == "nested" {
				wantCode(t, err, CodePlatform)
				return
			}
			wantCode(t, err, CodeFailed)
		})
	}
	// Not found.
	s.ref.Digest = digestOf([]byte("nothing"))
	s.dest = filepath.Join(t.TempDir(), "nf.tar")
	_, err := s.pull(nil, 1<<20)
	wantCode(t, err, CodeNotFound)
}

// Slow-loris: a registry that stalls before its headers or in the middle of
// a body is given up on after the timeouts.
func TestSlowRegistry(t *testing.T) {
	var s0 *setup
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	for name, hook := range map[string]func(w http.ResponseWriter, r *http.Request) bool{
		"headers": func(w http.ResponseWriter, r *http.Request) bool {
			if !strings.Contains(r.URL.Path, "/manifests/") {
				return false
			}
			select {
			case <-release:
			case <-r.Context().Done():
			}
			return true
		},
		"body": func(w http.ResponseWriter, r *http.Request) bool {
			if !strings.Contains(r.URL.Path, "/blobs/") {
				return false
			}
			b := s0.f.blobs[r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]]
			w.Header().Set("Content-Length", fmt.Sprint(len(b)))
			_, _ = w.Write(b[:1])
			w.(http.Flusher).Flush()
			select {
			case <-release:
			case <-r.Context().Done():
			}
			return true
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := newSetup(t)
			s0 = s
			s.f.hook = hook
			s.c = NewClient(Options{AllowHosts: allowHosts, RootCAs: getPKI(t).pool, Resolver: s.r,
				HeaderTimeout: 200 * time.Millisecond, IdleTimeout: 200 * time.Millisecond})
			start := time.Now()
			_, err := s.pull(nil, 1<<20)
			wantCode(t, err, CodeFailed)
			if d := time.Since(start); d > 5*time.Second {
				t.Fatalf("took %v", d)
			}
		})
	}
}

// An allowed host that speaks plain http is used over http (development);
// any other host never is.
func TestAllowedHostOverHTTP(t *testing.T) {
	f := newFake()
	img := buildImage(t, "amd64", 1, false)
	f.addImage(img)
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	ref := Ref{Host: regName + ":" + port(srv), Repository: "app", Digest: img.digest}
	c := newTestClient(t, nil)
	if _, err := c.Pull(context.Background(), ref, nil, amd64, Limits{MaxBytes: 1 << 20}, filepath.Join(t.TempDir(), "a.tar")); err != nil {
		t.Fatal(err)
	}
	strict := NewClient(Options{RootCAs: getPKI(t).pool, Resolver: &stubResolver{answers: map[string][]netip.Addr{}}})
	ref.Host = "127.0.0.1:" + port(srv)
	_, err := strict.Pull(context.Background(), ref, nil, amd64, Limits{MaxBytes: 1 << 20}, filepath.Join(t.TempDir(), "b.tar"))
	wantCode(t, err, CodeBlocked)
}

func TestCheck(t *testing.T) {
	s := newSetup(t)
	host := regName + ":" + port(s.srv)
	ctx := context.Background()
	if ok, kind := s.c.Check(ctx, host, "u", "p"); !ok || kind != "" {
		t.Fatal(ok, kind)
	}
	s.f.auth, s.f.user, s.f.pass = "basic", "ci", "pa55word"
	if ok, kind := s.c.Check(ctx, host, "ci", "pa55word"); !ok || kind != "" {
		t.Fatal(ok, kind)
	}
	if ok, kind := s.c.Check(ctx, host, "ci", "nope"); ok || kind != ReasonUnauthorized {
		t.Fatal(ok, kind)
	}
	// Bearer with the realm on the site, then on another site.
	tok := tlsServer(t, tokenServer{rec: s.f, user: "ci", pass: "pa55word", token: "t"})
	s.f.auth, s.f.token = "bearer", "t"
	s.f.hook = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/token" { // scope-less check token
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "t"})
			return true
		}
		return false
	}
	s.f.realm = "https://" + realmName + ":" + port(s.srv) + "/token"
	if ok, kind := s.c.Check(ctx, host, "ci", "pa55word"); !ok || kind != "" {
		t.Fatal(ok, kind)
	}
	s.f.realm = "https://" + evilName + ":" + port(tok) + "/token"
	if ok, kind := s.c.Check(ctx, host, "ci", "pa55word"); ok || kind != ReasonBlocked {
		t.Fatal(ok, kind)
	}
	if ok, kind := s.c.Check(ctx, "nowhere.invalid", "ci", "pa55word"); ok || kind != ReasonUnreachable {
		t.Fatal(ok, kind)
	}
	if ok, kind := s.c.Check(ctx, internalName+":"+port(s.srv), "ci", "pa55word"); ok || kind != ReasonBlocked {
		t.Fatal(ok, kind)
	}
}

// --- units ---

func TestParseRef(t *testing.T) {
	d := "sha256:" + strings.Repeat("ab", 32)
	r, err := ParseRef("docker.io/busybox@" + d)
	if err != nil || r.Host != "docker.io" || apiHost(r.Host) != dockerHubAPI || r.apiRepository() != "library/busybox" {
		t.Fatal(r, err)
	}
	r, err = ParseRef("registry.example.com:5000/team/app@" + d)
	if err != nil || r.Host != "registry.example.com:5000" || r.apiRepository() != "team/app" || r.String() != "registry.example.com:5000/team/app@"+d {
		t.Fatal(r, err)
	}
	for _, bad := range []string{
		"busybox@" + d, "ghcr.io/app:latest", "ghcr.io/app:latest@" + d, "GHCR.io/app@" + d,
		"ghcr.io:0/app@" + d, "ghcr.io:99999/app@" + d, "ghcr.io/app@sha256:abc", "ghcr.io/../app@" + d,
		"https://ghcr.io/app@" + d, "ghcr.io/app@" + d + "\n", "user@ghcr.io/app@" + d,
	} {
		if _, err := ParseRef(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestParsePlatform(t *testing.T) {
	if p, err := ParsePlatform("linux/arm64/v8"); err != nil || p != (Platform{"linux", "arm64", "v8"}) || p.String() != "linux/arm64/v8" {
		t.Fatal(p, err)
	}
	for _, bad := range []string{"", "linux", "linux/", "Linux/amd64", "linux/amd64/v8/x", "linux/am d64"} {
		if _, err := ParsePlatform(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestSameSite(t *testing.T) {
	for _, c := range []struct {
		realm, reg string
		want       bool
	}{
		{"auth.docker.io", "docker.io", true},
		{"auth.docker.io", "registry-1.docker.io", true},
		{"gitlab.com", "registry.gitlab.com", true},
		{"ghcr.io", "ghcr.io", true},
		{"gitlab.example.com", "registry.example.com", true},
		{"evil.example.net", "registry.example.com", false},
		{"attacker.github.io", "victim.github.io", false}, // github.io is a public suffix
		{"127.0.0.1", "registry.example.com", false},
		{"10.0.0.1", "10.0.0.2", false},
		{"localhost", "localhost", true},
		{"other", "localhost", false},
		{"example.com.", "EXAMPLE.com", true},
	} {
		if got := sameSite(c.realm, c.reg); got != c.want {
			t.Errorf("sameSite(%q, %q) = %v", c.realm, c.reg, got)
		}
	}
}

func TestParseChallenges(t *testing.T) {
	cs := parseChallenges([]string{
		`Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/busybox:pull"`,
		`Negotiate abc==, Basic realm="a \"quoted\" realm" , charset=UTF-8`,
		`garbage "`, strings.Repeat("x", maxChallengeLen+1),
	})
	if len(cs) != 4 || cs[0].scheme != "bearer" || cs[0].params["realm"] != "https://auth.docker.io/token" ||
		cs[0].params["service"] != "registry.docker.io" || cs[1].scheme != "negotiate" || cs[2].scheme != "basic" ||
		cs[2].params["realm"] != `a "quoted" realm` || cs[2].params["charset"] != "UTF-8" || cs[3].scheme != "garbage" {
		t.Fatalf("%+v", cs)
	}
}

// Credentials never format with their password.
func TestCredentialsDontPrint(t *testing.T) {
	c := Credentials{Username: "ci", Password: "hunter2-pa55"}
	for _, s := range []string{fmt.Sprint(c), fmt.Sprintf("%v %+v %#v", c, &c, c), fmt.Sprint(&c)} {
		if strings.Contains(s, "hunter2") {
			t.Fatal(s)
		}
	}
}
