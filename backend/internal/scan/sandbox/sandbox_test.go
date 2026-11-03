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
// Image scans run Trivy and Gitleaks, on the read-only tarball, with the
// same isolation and bigger limits.
func TestImageTrivy(t *testing.T) {
	if !slices.Equal(ImageToolNames, []string{"gitleaks", "trivy"}) {
		t.Fatal(ImageToolNames)
	}
	for _, tool := range []string{"opengrep", "checkov", "sh"} {
		if _, ok := ImageTool(tool, ImageLimits{MaxBytes: 1 << 30}); ok {
			t.Errorf("%s scans images", tool)
		}
	}
	spec, ok := ImageTool("trivy", ImageLimits{MaxBytes: 1 << 30})
	if !ok {
		t.Fatal("no image trivy")
	}
	a := argv(t, spec, "/scan")
	for _, want := range []string{"--network=none", "--read-only", "--cap-drop=ALL", "--memory=3g", "/scan/src:/src:ro"} {
		if !slices.Contains(a, want) {
			t.Errorf("missing %s", want)
		}
	}
	if tmp := a[slices.Index(a, "--tmpfs")+1]; tmp != "/tmp:rw,noexec,nosuid,size=1g,mode=1777" {
		t.Fatal(tmp)
	}
	if spec.Name != "trivy" || spec.Timeout != 15*time.Minute || len(spec.Artifacts) != 3 ||
		!strings.Contains(spec.Command[2], "trivy image --input /src/image.tar --scanners vuln,license --list-all-pkgs") ||
		!strings.Contains(spec.Command[2], "--offline-scan") || strings.Contains(spec.Command[2], "trivy fs") {
		t.Fatal(spec.Command)
	}
	if tmp := argv(t, Tools["trivy"], "/scan")[slices.Index(argv(t, Tools["trivy"], "/scan"), "--tmpfs")+1]; !strings.Contains(tmp, "size=256m") {
		t.Fatal(tmp)
	}
}

// Image scans run Gitleaks in image mode (warden-layers unpacks the layers in
// the sandbox) on the read-only tarball, with the same isolation, the key and
// the redactor; /tmp and memory don't grow with the image, the expansion cap
// does, and the timeout never exceeds the scan's.
func TestImageGitleaks(t *testing.T) {
	spec, ok := ImageTool("gitleaks", ImageLimits{MaxBytes: 2048 << 20, ScanTimeout: 30 * time.Minute})
	if !ok {
		t.Fatal("no image gitleaks")
	}
	a := argv(t, spec, "/scan")
	for _, want := range []string{"--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
		"--user", "65532:65532", "/scan/src:/src:ro", "/scan/secrets/hmac:/run/warden/hmac:ro", "--memory=2g", "--memory-swap=2g"} {
		if !slices.Contains(a, want) {
			t.Errorf("missing %s", want)
		}
	}
	if tmp := a[slices.Index(a, "--tmpfs")+1]; tmp != "/tmp:rw,noexec,nosuid,size=768m,mode=1777" {
		t.Fatal(tmp)
	}
	if got := a[slices.Index(a, "--entrypoint")+1:]; !slices.Equal(got, []string{"warden-gitleaks", digest, "image", "8589934592"}) {
		t.Fatal(got)
	}
	if spec.Name != "gitleaks" || spec.Timeout != 20*time.Minute || !spec.NeedsHMACKey ||
		spec.Artifacts[ArtifactLayers].File != "layers.json" || spec.Artifacts[ArtifactLayers].MaxBytes > 64<<10 {
		t.Fatalf("%+v", spec)
	}
	small, _ := ImageTool("gitleaks", ImageLimits{MaxBytes: 1 << 20, ScanTimeout: 10 * time.Minute})
	if small.Timeout != 10*time.Minute || small.Command[2] != "1073741824" || small.TmpfsSize != spec.TmpfsSize || small.Memory != spec.Memory {
		t.Fatalf("%+v", small)
	}
	// Org rules: the mode goes first, as for source scans.
	r, err := WithOrgRules(spec)
	if err != nil || !slices.Equal(r.Command, []string{"warden-gitleaks", "org-rules", "image", "8589934592"}) {
		t.Fatal(r.Command, err)
	}
}

// History scans run Gitleaks in git mode on the read-only bundle, with the
// same isolation; the commit limit and sizes come from the configuration,
// and the timeout never exceeds the scan's.
func TestHistoryGitleaks(t *testing.T) {
	spec := HistoryTool(HistoryLimits{MaxBytes: 1024 << 20, MaxCommits: 50_000, ScanTimeout: 30 * time.Minute})
	a := argv(t, spec, "/scan")
	for _, want := range []string{"--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
		"--user", "65532:65532", "/scan/src:/src:ro", "/scan/secrets/hmac:/run/warden/hmac:ro", "--memory=3072m"} {
		if !slices.Contains(a, want) {
			t.Errorf("missing %s", want)
		}
	}
	if tmp := a[slices.Index(a, "--tmpfs")+1]; tmp != "/tmp:rw,noexec,nosuid,size=1536m,mode=1777" {
		t.Fatal(tmp)
	}
	if got := a[slices.Index(a, "--entrypoint")+1:]; !slices.Equal(got, []string{"warden-gitleaks", digest, "history", "50000"}) {
		t.Fatal(got)
	}
	if spec.Name != "gitleaks" || spec.Timeout != 25*time.Minute || spec.Artifacts[ArtifactHistory].File != "history.json" ||
		spec.Artifacts[ArtifactHistory].MaxBytes > 1024 {
		t.Fatalf("%+v", spec)
	}
	if s := HistoryTool(HistoryLimits{MaxBytes: 1 << 20, MaxCommits: 7, ScanTimeout: 10 * time.Minute}); s.Timeout != 10*time.Minute ||
		s.Command[2] != "7" || s.TmpfsSize != "257m" {
		t.Fatalf("%+v", s)
	}
	if !slices.Equal(HistoryToolNames, []string{"gitleaks"}) {
		t.Fatal(HistoryToolNames)
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
		"trivy convert --format cyclonedx --output /out/sbom.cdx.json /out/trivy.json",
		"{ trivy convert --format spdx-json --output /out/sbom.spdx.json /out/trivy.json || rm -f /out/sbom.spdx.json; }"} {
		if !strings.Contains(c[2], want) {
			t.Errorf("script lacks %q: %s", want, c[2])
		}
	}
	a := Tools["trivy"].Artifacts
	if a[ArtifactTrivyJSON].File != "trivy.json" || a[ArtifactSBOM].MaxBytes != 64<<20 ||
		a[ArtifactSPDX].File != "sbom.spdx.json" || a[ArtifactSPDX].MaxBytes != 64<<20 {
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

func mountsRules(a []string) bool {
	return slices.ContainsFunc(a, func(s string) bool { return strings.Contains(s, ":/rules/") })
}

// Org rules run in addition to Warden's: Opengrep gets a second --config,
// warden-gitleaks the org-rules mode (history too). Each tool sees only its
// own rules file, read-only; the shared specs are never modified.
func TestWithOrgRules(t *testing.T) {
	before := slices.Clone(Tools["opengrep"].Command)
	og, err := WithOrgRules(Tools["opengrep"])
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(og.Command, []string{"opengrep", "scan", "--config", "/data/rules", "--config", "/rules/opengrep.yml",
		"--disable-nosem", "--sarif", "--output", "/out/result.sarif", "/src"}) {
		t.Fatal(og.Command)
	}
	if !slices.Equal(Tools["opengrep"].Command, before) {
		t.Fatal("Tools modified")
	}
	a := argv(t, og, "/scan")
	if !slices.Contains(a, "/scan/rules/opengrep.yml:/rules/opengrep.yml:ro") ||
		slices.ContainsFunc(a, func(s string) bool { return strings.Contains(s, "gitleaks.toml") }) {
		t.Fatal(a)
	}

	gl, err := WithOrgRules(Tools["gitleaks"])
	if err != nil {
		t.Fatal(err)
	}
	a = argv(t, gl, "/scan")
	if got := a[slices.Index(a, "--entrypoint")+1:]; !slices.Equal(got, []string{"warden-gitleaks", digest, "org-rules"}) {
		t.Fatal(got)
	}
	if !slices.Contains(a, "/scan/rules/gitleaks.toml:/rules/gitleaks.toml:ro") || !slices.Contains(a, "/scan/secrets/hmac:/run/warden/hmac:ro") {
		t.Fatal(a)
	}
	h, err := WithOrgRules(HistoryTool(HistoryLimits{MaxBytes: 1 << 20, MaxCommits: 9}))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(h.Command, []string{"warden-gitleaks", "org-rules", "history", "9"}) {
		t.Fatal(h.Command)
	}

	for _, name := range []string{"trivy", "checkov"} {
		if _, err := WithOrgRules(Tools[name]); err == nil {
			t.Errorf("%s took org rules", name)
		}
	}
	// Without org rules nothing is mounted at /rules.
	for name, spec := range Tools {
		if mountsRules(argv(t, spec, "/scan")) {
			t.Errorf("%s: rules mounted without org rules", name)
		}
	}
	// A rules file of another tool is refused.
	bad := Tools["opengrep"]
	bad.OrgRules = "gitleaks.toml"
	if _, err := DockerArgv(bad, RunConfig{ScanID: "s", ScanDir: "/x", Image: digest, Runtime: "runsc", MirrorDir: "/m"}); err == nil {
		t.Fatal("foreign rules file mounted")
	}
}

// A rule test runs the draft alone: no Warden rules, Gitleaks still redacted,
// a short timeout, the usual isolation.
func TestRuleTestTool(t *testing.T) {
	og, err := RuleTestTool("opengrep")
	if err != nil {
		t.Fatal(err)
	}
	a := argv(t, og, "/scan")
	if got := a[slices.Index(a, "--entrypoint")+1:]; !slices.Equal(got, []string{"opengrep", digest, "scan", "--config", "/rules/opengrep.yml",
		"--disable-nosem", "--sarif", "--output", "/out/result.sarif", "/src"}) {
		t.Fatal(got)
	}
	gl, err := RuleTestTool("gitleaks")
	if err != nil {
		t.Fatal(err)
	}
	a = argv(t, gl, "/scan")
	if got := a[slices.Index(a, "--entrypoint")+1:]; !slices.Equal(got, []string{"warden-gitleaks", digest, "rules-only"}) {
		t.Fatal(got)
	}
	for _, spec := range []ToolSpec{og, gl} {
		a := argv(t, spec, "/scan")
		f := OrgRulesFile(spec.Name)
		for _, want := range []string{"--network=none", "--read-only", "--cap-drop=ALL", "--runtime=runsc", "/scan/src:/src:ro",
			"/scan/rules/" + f + ":/rules/" + f + ":ro"} {
			if !slices.Contains(a, want) {
				t.Errorf("%s: missing %s", spec.Name, want)
			}
		}
		if spec.Timeout != 2*time.Minute || spec.NeedsHMACKey != (spec.Name == "gitleaks") {
			t.Errorf("%+v", spec)
		}
	}
	if _, err := RuleTestTool("trivy"); err == nil {
		t.Fatal("trivy rule test")
	}
}
