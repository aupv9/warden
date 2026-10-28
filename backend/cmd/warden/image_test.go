package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runImage runs `warden scan` without --dir (image flags conflict with it).
func (f *fakeServer) runImage(t *testing.T, d deps, extra ...string) result {
	t.Helper()
	args := append([]string{"scan", "--url", f.srv.URL, "--org", f.org.String(), "--project", f.prj.String()}, extra...)
	var out, errOut bytes.Buffer
	code := run(context.Background(), args, func(k string) string {
		if k == "WARDEN_TOKEN" {
			return f.token
		}
		return ""
	}, &out, &errOut, d)
	return result{code, out.String(), errOut.String()}
}

func TestImageScanWithDockerSave(t *testing.T) {
	f := newFakeServer(t)
	d := testDeps()
	var saved string
	d.save = func(_ context.Context, ref, dest string) error {
		saved = ref
		return os.WriteFile(dest, []byte("docker save of "+ref), 0o600)
	}
	d.pack = func(string, string, string) (int, error) {
		t.Fatal("packed a directory for an image scan")
		return 0, nil
	}
	r := f.runImage(t, d, "--image", "alpine:3.18.0", "--fail-on", "critical")
	if r.code != exitPass || saved != "alpine:3.18.0" || string(f.uploaded) != "docker save of alpine:3.18.0" {
		t.Fatalf("%+v saved=%q", r, saved)
	}
	c := f.created
	if c["kind"] != "image" || c["target"] != "docker.io/library/alpine" || c["image_ref"] != "alpine:3.18.0" || c["file_name"] != "alpine.tar" {
		t.Fatal(c)
	}
}

func TestImageScanWithTarball(t *testing.T) {
	f := newFakeServer(t)
	p := filepath.Join(t.TempDir(), "api.tar")
	_ = os.WriteFile(p, []byte("tarball"), 0o600)
	d := testDeps()
	d.save = func(context.Context, string, string) error { t.Fatal("docker save with --image-tar"); return nil }
	r := f.runImage(t, d, "--image-tar", p, "--target", "ghcr.io/acme/api", "--image-ref", "ghcr.io/acme/api:1.2")
	if r.code != exitPass || string(f.uploaded) != "tarball" {
		t.Fatalf("%+v", r)
	}
	if c := f.created; c["target"] != "ghcr.io/acme/api" || c["image_ref"] != "ghcr.io/acme/api:1.2" || c["file_name"] != "api.tar" || c["kind"] != "image" {
		t.Fatal(c)
	}
}

func TestImageFlagProblems(t *testing.T) {
	f := newFakeServer(t)
	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"both":           {[]string{"--image", "a", "--image-tar", "b.tar", "--target", "x"}, "give one"},
		"with dir":       {[]string{"--image", "alpine", "--dir", "."}, "--dir: not with"},
		"tar no target":  {[]string{"--image-tar", "b.tar"}, "--target: required"},
		"target alone":   {[]string{"--target", "x"}, "--target: only with"},
		"ref with image": {[]string{"--image", "alpine", "--image-ref", "x"}, "--image-ref: only with --image-tar"},
		"flag injection": {[]string{"--image", "--output=/etc/passwd"}, "--image: must be"},
	} {
		d := testDeps()
		d.save = func(context.Context, string, string) error { t.Fatal("docker save ran"); return nil }
		if r := f.runImage(t, d, c.args...); r.code != exitError || !strings.Contains(r.stderr, c.want) {
			t.Errorf("%s: %+v", name, r)
		}
	}
}

func TestImageTarget(t *testing.T) {
	for ref, want := range map[string]string{
		"alpine":                       "docker.io/library/alpine",
		"alpine:3.18.0":                "docker.io/library/alpine",
		"docker.io/alpine":             "docker.io/library/alpine",
		"index.docker.io/library/node": "docker.io/library/node",
		"acme/api:1":                   "docker.io/acme/api",
		"ghcr.io/Acme/API:1.2":         "ghcr.io/acme/api",
		"localhost:5000/api":           "localhost:5000/api",
		"localhost/api:dev":            "localhost/api",
		"registry.example:5000/a/b@sha256:" + strings.Repeat("0", 64): "registry.example:5000/a/b",
		"ghcr.io/acme/api:1.2@sha256:" + strings.Repeat("0", 64):      "ghcr.io/acme/api",
	} {
		if got, err := imageTarget(ref); err != nil || got != want {
			t.Errorf("%s: %q %v", ref, got, err)
		}
	}
	for _, bad := range []string{"", "-x", "a b", "a\nb", "a//b", strings.Repeat("a", 300)} {
		if _, err := imageTarget(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if tarName("ghcr.io/acme/api") != "api.tar" {
		t.Fatal(tarName("ghcr.io/acme/api"))
	}
}
