//go:build kube

// Against a real cluster made by scripts/kind-gvisor.sh (CI job `kube`):
//
//	scripts/kind-gvisor.sh
//	set -a; . .cache/kind/env; set +a
//	go -C backend test -tags kube -count=1 -v ./internal/scan/sandbox/kube/
//
// Each scanner runs through kube.Backend and through the docker backend
// (sandbox.Run, WARDEN_KUBE_TEST_DOCKER_RUNTIME) on the same scan directory;
// the findings must be the same and no SARIF may hold the raw secret. The
// canary must find the sandbox namespace isolated and warden-open not.
package kube

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/aupv9/warden/backend/internal/scan/orchestrator"
	"github.com/aupv9/warden/backend/internal/scan/sandbox"
	"github.com/aupv9/warden/backend/internal/scan/sarif"
)

func env(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv("WARDEN_KUBE_TEST_" + name)
	if v == "" {
		t.Fatalf("WARDEN_KUBE_TEST_%s is not set; run scripts/kind-gvisor.sh and source its env file", name)
	}
	return v
}

func gvisorExpected(t *testing.T) bool { return env(t, "GVISOR") == "1" }

func clientFor(kubeconfig string) (kubernetes.Interface, error) {
	rc, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(rc)
}

func liveBackend(t *testing.T, namespace string) *Backend {
	t.Helper()
	b, err := New(Config{
		Namespace: namespace, RuntimeClass: env(t, "RUNTIME_CLASS"), MirrorPVC: env(t, "MIRROR_PVC"),
		IOImage: env(t, "IO_IMAGE"), MaxInputBytes: 1 << 30, MaxInputEntries: 100_000,
	}, env(t, "KUBECONFIG"), slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// awsKey is an AWS access key id made at run time (CLAUDE.md: no real-looking
// secret is committed). scantest.FakeSecret won't do here: it contains
// "EXAMPLE", which Gitleaks's default allowlist skips, so a real Gitleaks finds
// nothing in it through either backend.
var awsKey = func() string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return "AKIA" + string(b)
}()

// sampleScan lays out a scan directory as the orchestrator does: a source
// tree each scanner finds something in, with a fake AWS key built at run time
// (awsKey), and the HMAC key Gitleaks' redaction uses.
func sampleScan(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"app/config.py": "import subprocess\n\nAWS_ACCESS_KEY_ID = \"" + awsKey + "\"\n\n" +
			"def run(cmd):\n    return subprocess.call(cmd, shell=True)\n",
		"requirements.txt": "django==3.2.0\nrequests==2.19.0\n",
		"Dockerfile":       "FROM ubuntu:latest\nRUN apt-get update && apt-get install -y curl\nADD http://example.com/x.tgz /opt/\n",
	}
	for name, body := range files {
		p := filepath.Join(dir, "src", filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o444); err != nil {
			t.Fatal(err)
		}
	}
	key, err := orchestrator.NewHMACKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "secrets"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secrets", "hmac"), key, 0o444); err != nil {
		t.Fatal(err)
	}
	return dir
}

// copyScan copies a scan directory's input (src, secrets), so each backend
// writes its own out/.
func copyScan(t *testing.T, from string) string {
	t.Helper()
	to := t.TempDir()
	err := filepath.WalkDir(from, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, p)
		if rel == "out" || strings.HasPrefix(rel, "out"+string(filepath.Separator)) {
			return filepath.SkipDir
		}
		target := filepath.Join(to, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o444)
	})
	if err != nil {
		t.Fatal(err)
	}
	return to
}

type finding struct{ rule, path, content string }

func findings(t *testing.T, tool, scanDir string, r sandbox.ToolRun) []finding {
	t.Helper()
	if r.Status != sandbox.Succeeded {
		t.Fatalf("%s: %s: %s (exit %d)", tool, r.Status, r.Error, r.ExitCode)
	}
	doc, err := sarif.Load(r.Sarif)
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	fs, err := sarif.Parse(doc, tool, sarif.Options{SourceRoot: filepath.Join(scanDir, "src")})
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	var out []finding
	for _, f := range fs {
		line := 0
		if f.StartLine != nil {
			line = *f.StartLine
		}
		out = append(out, finding{f.RuleID, fmt.Sprintf("%s:%d", f.FilePath, line), f.ContentKey})
	}
	slices.SortFunc(out, func(a, b finding) int { return strings.Compare(a.rule+a.path+a.content, b.rule+b.path+b.content) })
	return out
}

// noRawSecret: nothing a scanner hands back holds the fake key.
func noRawSecret(t *testing.T, outDir string) {
	t.Helper()
	_ = filepath.WalkDir(outDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err == nil && bytes.Contains(b, []byte(awsKey)) {
			t.Errorf("raw secret in %s", p)
		}
		return nil
	})
}

func TestKubeMatchesDocker(t *testing.T) {
	b := liveBackend(t, env(t, "NAMESPACE"))
	dockerRuntime := os.Getenv("WARDEN_KUBE_TEST_DOCKER_RUNTIME")
	tools := sandbox.ToolNames
	if v := os.Getenv("WARDEN_KUBE_TEST_TOOLS"); v != "" {
		tools = strings.Split(v, ",")
	}
	base := sampleScan(t)
	for _, tool := range tools {
		t.Run(tool, func(t *testing.T) {
			image := env(t, "IMAGE_"+strings.ToUpper(tool))
			spec := sandbox.Tools[tool]
			kubeDir, dockerDir := copyScan(t, base), copyScan(t, base)
			scanID := uuid.NewString()

			var kr, dr sandbox.ToolRun
			var wg sync.WaitGroup
			wg.Go(func() {
				kr = b.Run(context.Background(), spec, sandbox.RunConfig{ScanID: scanID, ScanDir: kubeDir, Image: image})
			})
			if dockerRuntime != "" {
				wg.Go(func() {
					dr = sandbox.Run(context.Background(), spec, sandbox.RunConfig{ScanID: scanID, ScanDir: dockerDir, Image: image,
						Runtime: dockerRuntime, MirrorDir: env(t, "MIRROR_DIR")})
				})
			}
			wg.Wait()
			got := findings(t, tool, kubeDir, kr)
			t.Logf("%s: %d findings through kubernetes in %dms", tool, len(got), kr.DurationMS)
			noRawSecret(t, filepath.Join(kubeDir, "out"))
			if tool == "gitleaks" && len(got) == 0 {
				t.Fatal("gitleaks found nothing: the input didn't arrive")
			}
			if len(spec.Artifacts) > 0 && len(kr.Artifacts) == 0 {
				t.Errorf("%s: no artifacts fetched", tool)
			}
			if dockerRuntime == "" {
				t.Log("WARDEN_KUBE_TEST_DOCKER_RUNTIME unset: not compared with the docker backend")
				return
			}
			want := findings(t, tool, dockerDir, dr)
			noRawSecret(t, filepath.Join(dockerDir, "out"))
			if !slices.Equal(got, want) {
				t.Fatalf("%s: kubernetes found %v\ndocker found %v", tool, got, want)
			}
			if len(kr.Artifacts) != len(dr.Artifacts) {
				t.Errorf("%s: artifacts %v vs %v", tool, kr.Artifacts, dr.Artifacts)
			}
		})
	}
	// Every run deleted its Pod.
	pods, err := b.ScannerPods(context.Background())
	if err != nil || len(pods) != 0 {
		t.Fatalf("scanner pods left: %v %v", pods, err)
	}
}

// A cancelled run (the orchestrator's cancel) deletes its Pod.
func TestKubeCancel(t *testing.T) {
	b := liveBackend(t, env(t, "NAMESPACE"))
	dir := sampleScan(t)
	scanID := uuid.NewString()
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		// Once the Pod exists, cancel as RunScan does: context, then Kill.
		for i := 0; i < 600; i++ {
			if _, err := b.Client.CoreV1().Pods(b.Namespace).Get(ctx, sandbox.ContainerName(scanID, "trivy"), metav1.GetOptions{}); err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		cancel()
		b.Kill(scanID, "trivy")
	}()
	r := b.Run(ctx, sandbox.Tools["trivy"], sandbox.RunConfig{ScanID: scanID, ScanDir: dir, Image: env(t, "IMAGE_TRIVY")})
	if r.Status != sandbox.Failed || r.Error != "cancelled" {
		t.Fatalf("run %+v", r)
	}
	if _, err := b.Client.CoreV1().Pods(b.Namespace).Get(context.Background(), sandbox.ContainerName(scanID, "trivy"), metav1.GetOptions{}); err == nil {
		t.Fatal("pod left after cancel")
	}
}

func TestKubeCanaryAndRuntimeClass(t *testing.T) {
	ctx := context.Background()
	b := liveBackend(t, env(t, "NAMESPACE"))
	// The worker's Role is namespaced: RuntimeClasses are not its to read,
	// and the canary's own gVisor check stands in.
	if st, err := b.RuntimeClass(ctx); st != RuntimeClassUnknown {
		t.Fatalf("RuntimeClass as the worker: %v %v", st, err)
	}
	if err := b.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	admin := *b
	var err error
	if admin.Client, err = clientFor(env(t, "ADMIN_KUBECONFIG")); err != nil {
		t.Fatal(err)
	}
	st, err := admin.RuntimeClass(ctx)
	if gvisorExpected(t) && st != RuntimeClassGVisor {
		t.Fatalf("RuntimeClass: %v %v", st, err)
	}
	if !gvisorExpected(t) && st != RuntimeClassBad {
		t.Fatalf("RuntimeClass on runc: %v %v", st, err)
	}

	res, err := b.Canary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("isolated namespace: %+v", res)
	if len(res.Reached) != 0 {
		t.Fatalf("the sandbox namespace is not isolated: %v", res.Reached)
	}
	if res.GVisor != gvisorExpected(t) {
		t.Fatalf("canary gVisor=%v, want %v", res.GVisor, gvisorExpected(t))
	}

	// Without a NetworkPolicy the canary reaches the API server's service
	// (and the internet where the runner has it): the worker refuses that.
	open := liveBackend(t, env(t, "OPEN_NAMESPACE"))
	res, err = open.Canary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("open namespace: %+v", res)
	if len(res.Reached) == 0 {
		t.Fatalf("the canary reached nothing from a namespace without a NetworkPolicy: %+v", res)
	}
}
