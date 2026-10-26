package sandbox

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const digest = "registry.internal/warden/gitleaks@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func argv(t *testing.T, spec ToolSpec, scanDir string) []string {
	t.Helper()
	a, err := DockerArgv(spec, RunConfig{ScanID: "s-1", ScanDir: scanDir, Image: digest, Runtime: "runsc", MirrorDir: "/mirror"})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestDockerArgvHasIsolationFlags(t *testing.T) {
	dir := t.TempDir()
	for name, spec := range Tools {
		a := argv(t, spec, dir)
		for _, flag := range []string{
			"--runtime=runsc", "--network=none", "--read-only", "--cap-drop=ALL",
			"--security-opt=no-new-privileges", "--pids-limit=256", "--rm",
		} {
			if !slices.Contains(a, flag) {
				t.Errorf("%s: missing %s", name, flag)
			}
		}
		if a[slices.Index(a, "--user")+1] != "65532:65532" || a[slices.Index(a, "--workdir")+1] != "/tmp" {
			t.Errorf("%s: user/workdir", name)
		}
		if !slices.Contains(a, filepath.Join(dir, "src")+":/src:ro") {
			t.Errorf("%s: src not read-only", name)
		}
		if a[slices.Index(a, "--entrypoint")+2] != digest {
			t.Errorf("%s: image must follow the entrypoint", name)
		}
		for _, s := range a {
			if strings.Contains(s, "docker.sock") || s == "--privileged" || strings.HasPrefix(s, "--network=host") {
				t.Errorf("%s: forbidden flag %s", name, s)
			}
		}
		tmp := a[slices.Index(a, "--tmpfs")+1]
		if wantExec := name == "opengrep"; strings.Contains(tmp, ",exec,") != wantExec || !strings.Contains(tmp, "nosuid") {
			t.Errorf("%s: tmpfs %s", name, tmp)
		}
	}
}

func TestOnlyGitleaksGetsHMACKey(t *testing.T) {
	for name, spec := range Tools {
		has := slices.ContainsFunc(argv(t, spec, t.TempDir()), func(s string) bool { return strings.Contains(s, "/run/warden/hmac") })
		if has != (name == "gitleaks") {
			t.Errorf("%s: hmac mounted=%v", name, has)
		}
	}
}

func TestUnpinnedImageRefused(t *testing.T) {
	for _, img := range []string{"aquasec/trivy:latest", "aquasec/trivy", "x@sha256:short", "a b@sha256:" + strings.Repeat("a", 64)} {
		if _, err := DockerArgv(Tools["trivy"], RunConfig{ScanID: "s", ScanDir: "/x", Image: img, Runtime: "runsc", MirrorDir: "/m"}); err == nil {
			t.Errorf("%q accepted", img)
		}
	}
}

func TestOnlyGitleaksScansSecrets(t *testing.T) {
	c := Tools["checkov"].Command
	i := slices.Index(c, "--skip-framework")
	if i < 0 || !slices.Contains(c[i+1:i+4], "secrets") {
		t.Fatal(c)
	}
	if !slices.Contains(Tools["opengrep"].Command, "--disable-nosem") {
		t.Fatal("opengrep honours nosemgrep comments from the upload")
	}
}

func TestToolNamesMatchTools(t *testing.T) {
	if len(ToolNames) != len(Tools) {
		t.Fatal("ToolNames out of sync")
	}
	for _, n := range ToolNames {
		if Tools[n].Name != n {
			t.Fatalf("%s: name %q", n, Tools[n].Name)
		}
	}
}

func TestTailWriterKeepsLastBytes(t *testing.T) {
	w := &tailWriter{n: 4}
	_, _ = w.Write([]byte("abc"))
	_, _ = w.Write([]byte("defg"))
	if string(w.buf) != "defg" {
		t.Fatal(string(w.buf))
	}
}
