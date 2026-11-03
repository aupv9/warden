package sandbox

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

// fakeRunner answers by the docker subcommand (argv[1], or argv[1:3] for
// "image inspect") and records every argv.
type fakeRunner struct {
	out   map[string]string
	err   map[string]error
	calls [][]string
}

func (f *fakeRunner) Run(_ context.Context, argv ...string) ([]byte, error) {
	f.calls = append(f.calls, argv)
	key := argv[1]
	if key == "image" {
		key += " " + argv[2]
	}
	return []byte(f.out[key]), f.err[key]
}

func TestDockerArgvLabelsTheScan(t *testing.T) {
	a := argv(t, Tools["trivy"], t.TempDir())
	i := slices.Index(a, "--label")
	if i < 0 || a[i+1] != "warden.scan=s-1" || i > slices.Index(a, "--entrypoint") {
		t.Fatal(a)
	}
}

func TestRuntimes(t *testing.T) {
	f := &fakeRunner{out: map[string]string{"info": `{"io.containerd.runc.v2":{"path":"runc"},"runc":{"path":"runc"},"runsc":{"path":"/usr/local/bin/runsc"}}` + "\n"}}
	got, err := Runtimes(context.Background(), f)
	if err != nil || !slices.Equal(got, []string{"io.containerd.runc.v2", "runc", "runsc"}) {
		t.Fatal(got, err)
	}
	if !slices.Equal(f.calls[0], []string{"docker", "info", "--format", "{{json .Runtimes}}"}) {
		t.Fatal(f.calls)
	}
	f = &fakeRunner{out: map[string]string{"info": "Cannot connect"}}
	if _, err := Runtimes(context.Background(), f); err == nil {
		t.Fatal("garbage accepted")
	}
	f = &fakeRunner{err: map[string]error{"info": errors.New("daemon down")}}
	if _, err := Runtimes(context.Background(), f); err == nil {
		t.Fatal("error lost")
	}
}

func TestPullOnlyPinnedRegistryImages(t *testing.T) {
	f := &fakeRunner{}
	ok := "registry.internal/warden/trivy:0.1@sha256:" + strings.Repeat("a", 64)
	if err := Pull(context.Background(), f, ok); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.calls[0], []string{"docker", "pull", "--quiet", "--", ok}) {
		t.Fatal(f.calls[0])
	}
	if err := Pull(context.Background(), f, "sha256:"+strings.Repeat("b", 64)); !errors.Is(err, ErrNotPullable) {
		t.Fatal(err)
	}
	for _, bad := range []string{"aquasec/trivy:latest", "--help", "-q@sha256:" + strings.Repeat("a", 63), "x@sha256:" + strings.Repeat("a", 64) + " --all-tags"} {
		if err := Pull(context.Background(), f, bad); err == nil {
			t.Errorf("%q pulled", bad)
		}
	}
	if len(f.calls) != 1 {
		t.Fatalf("refused refs reached docker: %v", f.calls)
	}
}

func TestScannerContainersOnlyWardenScanners(t *testing.T) {
	id := "0198c0de-0000-7000-8000-000000000001"
	other := "0198c0de-0000-7000-8000-000000000002"
	f := &fakeRunner{out: map[string]string{"ps": strings.Join([]string{
		"warden-" + id + "-trivy\t" + id,
		"warden-" + other + "-gitleaks\t", // before the label existed
		"warden-api-1\t",                  // the Compose stack itself
		"warden-postgres-1\t",
		"warden-" + id + "-trivy-extra\t" + id,
		"warden-" + id + "-nmap\t" + id,
		"warden-" + id + "-opengrep\t" + other, // label disagrees: not ours
		"WARDEN-" + strings.ToUpper(id) + "-trivy\t",
		"my-warden-" + id + "-trivy\t",
		"",
	}, "\n")}}
	got, err := ScannerContainers(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	want := []Container{{Name: "warden-" + id + "-trivy", ScanID: id, Tool: "trivy"}, {Name: "warden-" + other + "-gitleaks", ScanID: other, Tool: "gitleaks"}}
	if !slices.Equal(got, want) {
		t.Fatalf("%+v", got)
	}
	if err := RemoveContainer(context.Background(), f, "warden-api-1"); err == nil {
		t.Fatal("removed a non-scanner container")
	}
	if err := RemoveContainer(context.Background(), f, want[0].Name); err != nil {
		t.Fatal(err)
	}
	if last := f.calls[len(f.calls)-1]; !slices.Equal(last, []string{"docker", "rm", "--force", "--", want[0].Name}) {
		t.Fatal(last)
	}
}

func TestImagePresent(t *testing.T) {
	f := &fakeRunner{err: map[string]error{"image inspect": errors.New("No such image")}}
	if ImagePresent(context.Background(), f, "x@sha256:"+strings.Repeat("a", 64)) {
		t.Fatal("missing image present")
	}
	f.err = nil
	if !ImagePresent(context.Background(), f, "x@sha256:"+strings.Repeat("a", 64)) {
		t.Fatal("present image missing")
	}
}

func TestExecRunnerOnlyRunsDocker(t *testing.T) {
	if _, err := (ExecRunner{}).Run(context.Background(), "sh", "-c", "true"); err == nil {
		t.Fatal("ran a non-docker command")
	}
	c := capped{n: 4}
	_, _ = c.Write([]byte("abcdef"))
	_, _ = c.Write([]byte("gh"))
	if c.String() != "abcd" {
		t.Fatal(c.String())
	}
}

// Other backends (sandbox/kube) treat a tool as Run does.
func TestBackendAccessors(t *testing.T) {
	og := Tools["opengrep"]
	tr, _ := ImageTool("trivy", ImageLimits{})
	if og.TmpSize() != "256m" || tr.TmpSize() != "1g" || Tools["checkov"].SarifFile() != "results_sarif.sarif" || og.SarifFile() != "result.sarif" {
		t.Fatal("sizes or names")
	}
	if !og.OKExit(2) || og.OKExit(1) || !Tools["trivy"].OKExit(0) || Tools["trivy"].OKExit(2) {
		t.Fatal("exit codes")
	}
	if CollectArtifacts(og, t.TempDir()) != nil {
		t.Fatal("opengrep has no artifacts")
	}
	id := "0b6f1a52-6c9e-4c52-9a7e-3f0f8c1d2e4a"
	if s, tool, ok := ParseContainerName(ContainerName(id, "trivy")); !ok || s != id || tool != "trivy" {
		t.Fatal("parse")
	}
	for _, bad := range []string{"warden-" + id + "-sh", "warden-api-1", "warden-" + id + "-trivy-x"} {
		if _, _, ok := ParseContainerName(bad); ok {
			t.Fatalf("%q parsed", bad)
		}
	}
}
