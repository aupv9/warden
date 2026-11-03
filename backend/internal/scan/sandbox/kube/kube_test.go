package kube

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	utilexec "k8s.io/client-go/util/exec"

	"github.com/aupv9/warden/backend/internal/scan/sandbox"
	"github.com/aupv9/warden/backend/internal/scan/sandbox/sandboxio"
)

const ns = "warden-sandbox"

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func running(name string) corev1.ContainerStatus {
	return corev1.ContainerStatus{Name: name, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}
}

func waiting(name, reason string) corev1.ContainerStatus {
	return corev1.ContainerStatus{Name: name, State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: reason, Message: "details"}}}
}

func terminated(name string, code int32, reason, msg string) corev1.ContainerStatus {
	return corev1.ContainerStatus{Name: name, State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: code, Reason: reason, Message: msg}}}
}

// cluster is a fake API server plus a fake kubelet and exec: each Pod gets a
// directory standing for its volumes (in/, ctl/, out/), and exec runs the
// real warden-sandbox-io commands (sandboxio.Main) against it.
type cluster struct {
	t  *testing.T
	cs *fake.Clientset
	b  *Backend

	mu sync.Mutex
	// onCreate sets a new Pod's status (default: io-in running).
	onCreate func(p *corev1.Pod)
	// scanner plays the tool once the input is sealed: it may write
	// <pod>/out and returns the scanner's and io-out's statuses.
	scanner func(podDir string) []corev1.ContainerStatus
	// send replaces io-out's `send` (a compromised Pod).
	send   func(stdout io.Writer) error
	pods   map[string]string // pod name -> its directory
	execs  []string
	podUID map[string]types.UID
}

func newCluster(t *testing.T, objs ...runtime.Object) *cluster {
	t.Helper()
	c := &cluster{t: t, cs: fake.NewClientset(objs...), pods: map[string]string{}, podUID: map[string]types.UID{}}
	c.onCreate = func(p *corev1.Pod) {
		p.Status = corev1.PodStatus{Phase: corev1.PodPending,
			InitContainerStatuses: []corev1.ContainerStatus{running(containerIn)},
			ContainerStatuses:     []corev1.ContainerStatus{waiting(containerScanner, "PodInitializing"), waiting(containerOut, "PodInitializing")}}
	}
	c.scanner = func(dir string) []corev1.ContainerStatus {
		must(t, os.WriteFile(filepath.Join(dir, "out", "result.sarif"), []byte(`{"runs":[]}`), 0o644))
		return []corev1.ContainerStatus{terminated(containerScanner, 0, "Completed", ""), running(containerOut)}
	}
	c.cs.PrependReactor("create", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		p := a.(k8stesting.CreateAction).GetObject().(*corev1.Pod)
		p.UID = types.UID(uuid.NewString())
		c.mu.Lock()
		c.onCreate(p)
		dir := filepath.Join(t.TempDir(), "pod")
		for _, d := range []string{"in/src", "in/secrets", "in/rules", "ctl", "out"} {
			must(t, os.MkdirAll(filepath.Join(dir, d), 0o755))
		}
		c.pods[p.Name] = dir
		c.podUID[p.Name] = p.UID
		c.mu.Unlock()
		return false, nil, nil
	})
	// The fake tracker ignores delete preconditions; the API server doesn't.
	c.cs.PrependReactor("delete", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		d := a.(k8stesting.DeleteAction)
		pre := d.GetDeleteOptions().Preconditions
		if pre == nil || pre.UID == nil {
			return false, nil, nil
		}
		obj, err := c.cs.Tracker().Get(a.GetResource(), ns, d.GetName())
		if err == nil && obj.(*corev1.Pod).UID != *pre.UID {
			return true, nil, apierrors.NewConflict(a.GetResource().GroupResource(), d.GetName(), errors.New("UID precondition failed"))
		}
		return false, nil, nil
	})
	c.b = &Backend{Client: c.cs, Exec: c, Config: Config{Namespace: ns, RuntimeClass: "gvisor", MirrorPVC: "m", IOImage: testIO,
		MaxInputBytes: 1 << 20, MaxInputEntries: 100}, Log: quiet()}
	return c
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// setStatus replaces the named containers' statuses (and the phase).
func (c *cluster) setStatus(name string, phase corev1.PodPhase, reason string, init, main []corev1.ContainerStatus) {
	ctx := context.Background()
	p, err := c.cs.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
	must(c.t, err)
	p.Status.Phase, p.Status.Reason = phase, reason
	if init != nil {
		p.Status.InitContainerStatuses = init
	}
	if main != nil {
		p.Status.ContainerStatuses = main
	}
	_, err = c.cs.CoreV1().Pods(ns).UpdateStatus(ctx, p, metav1.UpdateOptions{})
	must(c.t, err)
}

// Exec runs warden-sandbox-io with the Pod's paths mapped to its directory.
func (c *cluster) Exec(ctx context.Context, namespace, pod, container string, cmd []string, stdin io.Reader, stdout, stderr io.Writer) error {
	c.mu.Lock()
	dir := c.pods[pod]
	c.execs = append(c.execs, container+" "+strings.Join(cmd[1:2], " "))
	send := c.send
	c.mu.Unlock()
	if namespace != ns || dir == "" || cmd[0] != ioBinary {
		return fmt.Errorf("exec into %s/%s: %v", namespace, pod, cmd)
	}
	args := make([]string, len(cmd)-1)
	for i, a := range cmd[1:] {
		switch a {
		case inDir, "/out", readyMarker:
			a = filepath.Join(dir, a)
		}
		args[i] = a
	}
	switch {
	case container == containerIn && args[0] == "receive":
	case container == containerOut && args[0] == "send":
		if send != nil {
			return send(stdout)
		}
	default:
		return fmt.Errorf("%s may not run %s", container, args[0])
	}
	if code := sandboxio.Main(ctx, args, stdin, stdout, stderr); code != 0 {
		return utilexec.CodeExitError{Err: fmt.Errorf("command terminated with exit code %d", code), Code: code}
	}
	if args[0] == "receive" {
		c.mu.Lock()
		statuses := c.scanner(dir)
		c.mu.Unlock()
		if statuses != nil {
			c.setStatus(pod, corev1.PodRunning, "", []corev1.ContainerStatus{terminated(containerIn, 0, "Completed", "")}, statuses)
		}
	}
	return nil
}

// scanDir lays out a scan directory as the orchestrator does.
func scanDir(t *testing.T, withKey, withRules bool) string {
	t.Helper()
	d := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(d, "src", "app"), 0o755))
	must(t, os.WriteFile(filepath.Join(d, "src", "app", "config.py"), []byte("key = 'x'\n"), 0o444))
	if withKey {
		must(t, os.MkdirAll(filepath.Join(d, "secrets"), 0o700))
		must(t, os.WriteFile(filepath.Join(d, "secrets", "hmac"), bytes.Repeat([]byte("k"), 64), 0o400))
	}
	if withRules {
		must(t, os.MkdirAll(filepath.Join(d, "rules"), 0o755))
		must(t, os.WriteFile(filepath.Join(d, "rules", "gitleaks.toml"), []byte("[[rules]]\n"), 0o444))
		must(t, os.WriteFile(filepath.Join(d, "rules", "opengrep.yml"), []byte("rules: []\n"), 0o444))
	}
	return d
}

func runConfig(dir string) sandbox.RunConfig {
	return sandbox.RunConfig{ScanID: testScan, ScanDir: dir, Image: testImage}
}

func (c *cluster) podGone(t *testing.T, name string) {
	t.Helper()
	if _, err := c.cs.CoreV1().Pods(ns).Get(context.Background(), name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("pod %s not deleted: %v", name, err)
	}
}

func TestRunGitleaks(t *testing.T) {
	c := newCluster(t)
	dir := scanDir(t, true, true)
	var podDir string
	c.scanner = func(d string) []corev1.ContainerStatus {
		podDir = d
		// The input arrived complete before the scanner "started".
		if _, err := os.Stat(filepath.Join(d, "ctl", "ready")); err != nil {
			t.Error("scanner started before the input was sealed")
		}
		must(t, os.WriteFile(filepath.Join(d, "out", "result.sarif"), []byte(`{"runs":[]}`), 0o644))
		// What isn't the tool's SARIF stays in the Pod.
		must(t, os.WriteFile(filepath.Join(d, "out", "raw.sarif"), []byte("raw secret"), 0o644))
		return []corev1.ContainerStatus{terminated(containerScanner, 0, "Completed", ""), running(containerOut)}
	}
	spec := gitleaksWithRules(t)
	r := c.b.Run(context.Background(), spec, runConfig(dir))
	if r.Status != sandbox.Succeeded {
		t.Fatalf("run %+v", r)
	}
	if r.Sarif != filepath.Join(dir, "out", "gitleaks", "result.sarif") {
		t.Fatalf("sarif %q", r.Sarif)
	}
	got, _ := sandboxio.FileNames(filepath.Join(dir, "out", "gitleaks"))
	if strings.Join(got, ",") != "result.sarif" {
		t.Fatalf("fetched %v", got)
	}
	for _, f := range []string{"in/src/app/config.py", "in/secrets/hmac", "in/rules/gitleaks.toml"} {
		if _, err := os.Stat(filepath.Join(podDir, f)); err != nil {
			t.Errorf("%s not sent", f)
		}
	}
	// Only this tool's rules file goes in.
	if _, err := os.Stat(filepath.Join(podDir, "in/rules/opengrep.yml")); !errors.Is(err, fs.ErrNotExist) {
		t.Error("another tool's rules were sent")
	}
	if strings.Join(c.execs, ";") != "io-in receive;io-out send" {
		t.Errorf("execs %v", c.execs)
	}
	c.podGone(t, sandbox.ContainerName(testScan, "gitleaks"))
}

func TestRunTrivyArtifacts(t *testing.T) {
	c := newCluster(t)
	c.scanner = func(d string) []corev1.ContainerStatus {
		must(t, os.WriteFile(filepath.Join(d, "out", "result.sarif"), []byte(`{"runs":[]}`), 0o644))
		must(t, os.WriteFile(filepath.Join(d, "out", "trivy.json"), []byte(`{}`), 0o644))
		must(t, os.Symlink("/etc/passwd", filepath.Join(d, "out", "sbom.cdx.json")))
		return []corev1.ContainerStatus{terminated(containerScanner, 0, "Completed", ""), running(containerOut)}
	}
	dir := scanDir(t, false, false)
	r := c.b.Run(context.Background(), sandbox.Tools["trivy"], runConfig(dir))
	if r.Status != sandbox.Succeeded || len(r.Artifacts) != 1 || r.Artifacts[sandbox.ArtifactTrivyJSON] == "" {
		t.Fatalf("run %+v", r)
	}
}

func TestRunFailures(t *testing.T) {
	for _, c := range []struct {
		name     string
		onCreate func(p *corev1.Pod)
		scanner  []corev1.ContainerStatus
		phase    corev1.PodPhase
		reason   string
		status   sandbox.ToolStatus
		errHas   string
		exit     int
	}{
		{name: "exit code", scanner: []corev1.ContainerStatus{terminated(containerScanner, 7, "Error", "boom: config error"), running(containerOut)},
			status: sandbox.Failed, errHas: "boom: config error", exit: 7},
		{name: "exit code, no message", scanner: []corev1.ContainerStatus{terminated(containerScanner, 1, "Error", ""), running(containerOut)},
			status: sandbox.Failed, errHas: "exit 1", exit: 1},
		{name: "oom", scanner: []corev1.ContainerStatus{terminated(containerScanner, 137, "OOMKilled", ""), running(containerOut)},
			status: sandbox.Failed, errHas: "OOMKilled", exit: 137},
		{name: "deadline", scanner: []corev1.ContainerStatus{terminated(containerScanner, 137, "Error", ""), terminated(containerOut, 137, "Error", "")},
			phase: corev1.PodFailed, reason: "DeadlineExceeded", status: sandbox.Timeout, errHas: "timeout"},
		{name: "image pull", scanner: []corev1.ContainerStatus{waiting(containerScanner, "ImagePullBackOff"), running(containerOut)},
			status: sandbox.Failed, errHas: "scanner: ImagePullBackOff"},
		{name: "results container gone", scanner: []corev1.ContainerStatus{terminated(containerScanner, 0, "Completed", ""), terminated(containerOut, 1, "Error", "")},
			status: sandbox.Failed, errHas: "results container exited"},
		{name: "evicted", scanner: []corev1.ContainerStatus{running(containerScanner), running(containerOut)},
			phase: corev1.PodFailed, reason: "Evicted", status: sandbox.Failed, errHas: "Evicted"},
		{name: "io image", onCreate: func(p *corev1.Pod) {
			p.Status.InitContainerStatuses = []corev1.ContainerStatus{waiting(containerIn, "InvalidImageName")}
		}, status: sandbox.Failed, errHas: "io-in: InvalidImageName"},
		{name: "io-in exits early", onCreate: func(p *corev1.Pod) {
			p.Status.InitContainerStatuses = []corev1.ContainerStatus{terminated(containerIn, 1, "Error", "")}
		}, status: sandbox.Failed, errHas: "input container exited"},
	} {
		t.Run(c.name, func(t *testing.T) {
			cl := newCluster(t)
			if c.onCreate != nil {
				cl.onCreate = c.onCreate
			}
			cl.scanner = func(string) []corev1.ContainerStatus { return nil }
			if c.scanner != nil {
				phase := c.phase
				if phase == "" {
					phase = corev1.PodRunning
				}
				cl.scanner = func(d string) []corev1.ContainerStatus {
					// A failed tool may leave a SARIF; it isn't fetched.
					must(t, os.WriteFile(filepath.Join(d, "out", "result.sarif"), []byte(`{"runs":[]}`), 0o644))
					go cl.setStatus(sandbox.ContainerName(testScan, "opengrep"), phase, c.reason,
						[]corev1.ContainerStatus{terminated(containerIn, 0, "Completed", "")}, c.scanner)
					return nil
				}
			}
			dir := scanDir(t, false, false)
			r := cl.b.Run(context.Background(), sandbox.Tools["opengrep"], runConfig(dir))
			if r.Status != c.status || !strings.Contains(r.Error, c.errHas) || r.ExitCode != c.exit {
				t.Fatalf("run %+v", r)
			}
			if names, _ := sandboxio.FileNames(filepath.Join(dir, "out", "opengrep")); len(names) != 0 {
				t.Fatalf("results of a failed run fetched: %v", names)
			}
			cl.podGone(t, sandbox.ContainerName(testScan, "opengrep"))
		})
	}
}

// What io-out sends back is hostile: a compromised Pod's stream is refused
// whole and nothing of it is kept.
func TestRunHostileResults(t *testing.T) {
	tarOf := func(add func(tw *tar.Writer)) []byte {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		add(tw)
		tw.Close()
		return buf.Bytes()
	}
	file := func(tw *tar.Writer, name, body string) {
		tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Size: int64(len(body)), Mode: 0o644})
		io.WriteString(tw, body)
	}
	for name, stream := range map[string][]byte{
		"symlink to a host file": tarOf(func(tw *tar.Writer) {
			tw.WriteHeader(&tar.Header{Name: "result.sarif", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"})
		}),
		"hard link": tarOf(func(tw *tar.Writer) {
			tw.WriteHeader(&tar.Header{Name: "result.sarif", Typeflag: tar.TypeLink, Linkname: "/etc/passwd"})
		}),
		"traversal": tarOf(func(tw *tar.Writer) { file(tw, "../../escape.sarif", "{}") }),
		"another file": tarOf(func(tw *tar.Writer) {
			file(tw, "result.sarif", `{"runs":[]}`)
			file(tw, "raw.sarif", "secret")
		}),
		"duplicate": tarOf(func(tw *tar.Writer) {
			file(tw, "result.sarif", `{"runs":[]}`)
			file(tw, "result.sarif", `{"runs":[{}]}`)
		}),
		"device": tarOf(func(tw *tar.Writer) {
			tw.WriteHeader(&tar.Header{Name: "result.sarif", Typeflag: tar.TypeChar, Devmajor: 1, Devminor: 3})
		}),
		"oversize": tarOf(func(tw *tar.Writer) {
			tw.WriteHeader(&tar.Header{Name: "result.sarif", Typeflag: tar.TypeReg, Size: 256<<20 + 1, Mode: 0o644})
		}),
		"garbage": bytes.Repeat([]byte{0xee}, 4096),
		"trailing data": append(tarOf(func(tw *tar.Writer) { file(tw, "result.sarif", `{"runs":[]}`) }),
			bytes.Repeat([]byte("x"), 1<<20)...),
	} {
		t.Run(name, func(t *testing.T) {
			c := newCluster(t)
			c.send = func(stdout io.Writer) error {
				_, err := stdout.Write(stream)
				return err
			}
			dir := scanDir(t, false, false)
			r := c.b.Run(context.Background(), sandbox.Tools["opengrep"], runConfig(dir))
			if r.Status != sandbox.Failed || (!strings.Contains(r.Error, "results rejected") && !strings.Contains(r.Error, "fetching results")) {
				t.Fatalf("run %+v", r)
			}
			if names, _ := os.ReadDir(filepath.Join(dir, "out", "opengrep")); len(names) != 0 {
				t.Fatalf("kept %v", names)
			}
			if _, err := os.Lstat(filepath.Join(dir, "escape.sarif")); err == nil {
				t.Fatal("escaped")
			}
		})
	}
}

func TestRunInputRefusals(t *testing.T) {
	c := newCluster(t)
	dir := scanDir(t, false, false)
	// Gitleaks without its key: refused before any Pod.
	if r := c.b.Run(context.Background(), sandbox.Tools["gitleaks"], runConfig(dir)); r.Status != sandbox.Failed || !strings.Contains(r.Error, "secrets/hmac") {
		t.Fatalf("run %+v", r)
	}
	// A symlink in place of the key is not followed.
	must(t, os.MkdirAll(filepath.Join(dir, "secrets"), 0o700))
	must(t, os.Symlink("/etc/passwd", filepath.Join(dir, "secrets", "hmac")))
	if r := c.b.Run(context.Background(), sandbox.Tools["gitleaks"], runConfig(dir)); r.Status != sandbox.Failed {
		t.Fatalf("run %+v", r)
	}
	c.b.MaxInputBytes = 3
	if r := c.b.Run(context.Background(), sandbox.Tools["opengrep"], runConfig(dir)); r.Status != sandbox.Failed || !strings.Contains(r.Error, "byte limit") {
		t.Fatalf("run %+v", r)
	}
	c.b.MaxInputBytes, c.b.MaxInputEntries = 1<<20, 2
	if r := c.b.Run(context.Background(), sandbox.Tools["opengrep"], runConfig(dir)); r.Status != sandbox.Failed || !strings.Contains(r.Error, "entries") {
		t.Fatalf("run %+v", r)
	}
	if len(c.pods) != 0 {
		t.Fatalf("pods made: %v", c.pods)
	}
	c.b.MaxInputEntries = 100
	rc := runConfig(dir)
	rc.Image = "sha256:" + strings.Repeat("a", 64)
	if r := c.b.Run(context.Background(), sandbox.Tools["opengrep"], rc); r.Status != sandbox.Failed || !strings.Contains(r.Error, "pinned") {
		t.Fatalf("run %+v", r)
	}
}

func TestRunCancelAndTimeout(t *testing.T) {
	old := workerGrace
	workerGrace = 0
	defer func() { workerGrace = old }()

	// The scanner never ends; the caller cancels.
	c := newCluster(t)
	c.scanner = func(string) []corev1.ContainerStatus {
		return []corev1.ContainerStatus{running(containerScanner), running(containerOut)}
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(300 * time.Millisecond); cancel() }()
	r := c.b.Run(ctx, sandbox.Tools["opengrep"], runConfig(scanDir(t, false, false)))
	if r.Status != sandbox.Failed || r.Error != "cancelled" {
		t.Fatalf("cancel: %+v", r)
	}
	c.podGone(t, sandbox.ContainerName(testScan, "opengrep"))

	// Never scheduled: the worker's deadline, with the reason.
	c = newCluster(t)
	c.onCreate = func(p *corev1.Pod) {
		p.Status = corev1.PodStatus{Phase: corev1.PodPending, Conditions: []corev1.PodCondition{{
			Type: corev1.PodScheduled, Status: corev1.ConditionFalse, Reason: "Unschedulable", Message: "0/1 nodes: insufficient memory"}}}
	}
	spec := sandbox.Tools["opengrep"]
	spec.Timeout = 300 * time.Millisecond
	r = c.b.Run(context.Background(), spec, runConfig(scanDir(t, false, false)))
	if r.Status != sandbox.Timeout || !strings.Contains(r.Error, "insufficient memory") {
		t.Fatalf("timeout: %+v", r)
	}
	c.podGone(t, sandbox.ContainerName(testScan, "opengrep"))
}

// A Pod deleted or replaced under the run is never used.
func TestRunPodReplacedOrDeleted(t *testing.T) {
	for _, replace := range []bool{false, true} {
		c := newCluster(t)
		name := sandbox.ContainerName(testScan, "opengrep")
		c.onCreate = func(p *corev1.Pod) {
			p.Status = corev1.PodStatus{Phase: corev1.PodPending}
			go func() {
				time.Sleep(100 * time.Millisecond)
				must(t, c.cs.CoreV1().Pods(ns).Delete(context.Background(), name, metav1.DeleteOptions{}))
				if replace {
					q := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}}
					c.mu.Lock()
					c.onCreate = func(p *corev1.Pod) { p.Status.InitContainerStatuses = []corev1.ContainerStatus{running(containerIn)} }
					c.mu.Unlock()
					_, err := c.cs.CoreV1().Pods(ns).Create(context.Background(), q, metav1.CreateOptions{})
					must(t, err)
				}
			}()
		}
		r := c.b.Run(context.Background(), sandbox.Tools["opengrep"], runConfig(scanDir(t, false, false)))
		if r.Status != sandbox.Failed || !(strings.Contains(r.Error, "replaced") || strings.Contains(r.Error, "deleted")) {
			t.Fatalf("replace=%v: %+v", replace, r)
		}
		if replace {
			// The newer Pod is not this run's to delete.
			if _, err := c.cs.CoreV1().Pods(ns).Get(context.Background(), name, metav1.GetOptions{}); err != nil {
				t.Fatalf("the replacement was deleted: %v", err)
			}
		}
	}
}

func TestRunReplacesLeftoverAndKill(t *testing.T) {
	name := sandbox.ContainerName(testScan, "opengrep")
	left := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, UID: "old"}}
	c := newCluster(t, left)
	r := c.b.Run(context.Background(), sandbox.Tools["opengrep"], runConfig(scanDir(t, false, false)))
	if r.Status != sandbox.Succeeded {
		t.Fatalf("run %+v", r)
	}
	_, err := c.cs.CoreV1().Pods(ns).Create(context.Background(), &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}}, metav1.CreateOptions{})
	must(t, err)
	c.b.Kill(testScan, "opengrep")
	c.podGone(t, name)
	c.b.Kill(testScan, "opengrep") // gone already: fine
	var graces []int64
	for _, a := range c.cs.Actions() {
		if d, ok := a.(k8stesting.DeleteAction); ok {
			if g := d.GetDeleteOptions().GracePeriodSeconds; g != nil {
				graces = append(graces, *g)
			}
		}
	}
	for _, g := range graces {
		if g != 0 {
			t.Fatalf("delete with grace %d", g)
		}
	}
}

func TestExitCode(t *testing.T) {
	if ExitCode(utilexec.CodeExitError{Code: 3}) != 3 || ExitCode(&utilexec.CodeExitError{Code: 4}) != 4 || ExitCode(errors.New("x")) != -1 {
		t.Fatal("ExitCode")
	}
	w := &tail{n: 4}
	w.Write([]byte("abcdef"))
	if w.String() != "cdef" {
		t.Fatal(w.String())
	}
}
