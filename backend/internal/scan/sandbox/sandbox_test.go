package sandbox

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
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

// Trivy runs a constant script through sh: one JSON report, from which the
// SARIF and the SBOM are converted offline.
// Image scans run Trivy only, on the read-only tarball, with the same
// isolation and bigger limits.
func TestImageTrivy(t *testing.T) {
	if len(ImageTools) != 1 {
		t.Fatal("image scans run trivy only")
	}
	spec := ImageTools["trivy"]
	a := argv(t, spec, "/scan")
	for _, want := range []string{"--network=none", "--read-only", "--cap-drop=ALL", "--memory=3g", "/scan/src:/src:ro"} {
		if !slices.Contains(a, want) {
			t.Errorf("missing %s", want)
		}
	}
	if tmp := a[slices.Index(a, "--tmpfs")+1]; tmp != "/tmp:rw,noexec,nosuid,size=1g,mode=1777" {
		t.Fatal(tmp)
	}
	if spec.Name != "trivy" || spec.Timeout != 15*time.Minute || len(spec.Artifacts) != 2 ||
		!strings.Contains(spec.Command[2], "trivy image --input /src/image.tar --scanners vuln,license --list-all-pkgs") ||
		!strings.Contains(spec.Command[2], "--offline-scan") || strings.Contains(spec.Command[2], "trivy fs") {
		t.Fatal(spec.Command)
	}
	if tmp := argv(t, Tools["trivy"], "/scan")[slices.Index(argv(t, Tools["trivy"], "/scan"), "--tmpfs")+1]; !strings.Contains(tmp, "size=256m") {
		t.Fatal(tmp)
	}
}

func TestTrivyScript(t *testing.T) {
	c := Tools["trivy"].Command
	if len(c) != 3 || c[0] != "sh" || c[1] != "-c" {
		t.Fatal(c)
	}
	for _, want := range []string{"set -eu;", "trivy fs /src ", "--scanners vuln,license", "--list-all-pkgs", "--offline-scan",
		"--skip-db-update", "--format json --output /out/trivy.json",
		"trivy convert --format sarif --output /out/result.sarif /out/trivy.json",
		"trivy convert --format cyclonedx --output /out/sbom.cdx.json /out/trivy.json"} {
		if !strings.Contains(c[2], want) {
			t.Errorf("script lacks %q: %s", want, c[2])
		}
	}
	a := Tools["trivy"].Artifacts
	if a[ArtifactTrivyJSON].File != "trivy.json" || a[ArtifactSBOM].MaxBytes != 64<<20 {
		t.Fatal(a)
	}
}

func TestArtifactsAreRegularFilesWithinCaps(t *testing.T) {
	dir := t.TempDir()
	spec := ToolSpec{Artifacts: map[string]ArtifactSpec{
		"ok": {File: "ok.json", MaxBytes: 10}, "big": {File: "big.json", MaxBytes: 3},
		"link": {File: "link.json", MaxBytes: 10}, "missing": {File: "none.json", MaxBytes: 10},
		"dir": {File: "d", MaxBytes: 10},
	}}
	for name, body := range map[string]string{"ok.json": "{}", "big.json": "toolarge"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(dir, "ok.json"), filepath.Join(dir, "link.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o700); err != nil {
		t.Fatal(err)
	}
	got := artifacts(spec, dir)
	if len(got) != 1 || got["ok"] != filepath.Join(dir, "ok.json") {
		t.Fatal(got)
	}
	if artifacts(ToolSpec{}, dir) != nil {
		t.Fatal("no artifacts expected")
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
