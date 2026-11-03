// Package kube runs each scanner as a gVisor Pod in a namespace of its own
// (scan.sandbox_backend=kubernetes), for a worker that holds no Docker
// socket. It implements the worker's Sandbox exactly like the docker backend:
// the same ToolSpec and argv, the same <ScanDir>/out/<tool> results, so the
// orchestrator, parsers and results don't change.
//
// The worker's access is a Role in that namespace: pods create, get, list,
// watch, delete and pods/exec create. Input goes in and /out comes back only
// as tar streams over pods/exec, through warden-sandbox-io in the Pod
// (sandboxio): no volume is shared with the worker, and the namespace's
// NetworkPolicy denies all traffic (the preflight's canary checks that).
// See scannerPod for the Pod and Run for the sequence.
package kube

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/aupv9/warden/backend/internal/scan/sandbox"
	"github.com/aupv9/warden/backend/internal/scan/sandbox/sandboxio"
	"github.com/aupv9/warden/backend/internal/scan/zipcheck"
)

// Config is scan.kube plus the scan limits.
type Config struct {
	Namespace    string
	RuntimeClass string // "" only in development: the cluster's default runtime
	MirrorPVC    string // "" only in development: an empty /data
	IOImage      string
	// MaxInputBytes and MaxInputEntries bound what one run sends into a Pod
	// (the largest upload's content, plus the key and rules); a larger input
	// is refused before a Pod is made.
	MaxInputBytes   int64
	MaxInputEntries int
}

// Backend implements the worker's Sandbox with Pods.
type Backend struct {
	Client kubernetes.Interface
	Exec   Execer
	Config
	Log *slog.Logger
	// InCluster: the worker runs in the cluster (its /etc/resolv.conf names
	// the cluster DNS, which the canary also tries).
	InCluster bool
}

// New connects with the in-cluster service account, or kubeconfig
// (development only).
func New(cfg Config, kubeconfig string, log *slog.Logger) (*Backend, error) {
	if errs := validation.IsDNS1123Label(cfg.Namespace); len(errs) > 0 {
		return nil, fmt.Errorf("scan.kube.namespace: %s", strings.Join(errs, "; "))
	}
	if cfg.IOImage == "" {
		return nil, errors.New("scan.kube.io_image is required for the kubernetes backend")
	}
	var rc *rest.Config
	var err error
	if kubeconfig == "" {
		rc, err = rest.InClusterConfig()
	} else {
		rc, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	if err != nil {
		return nil, fmt.Errorf("kubernetes client: %w", err)
	}
	rc.UserAgent = "warden-worker"
	// One run makes a handful of calls; several slots run at once.
	rc.QPS, rc.Burst = 20, 40
	cs, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return nil, fmt.Errorf("kubernetes client: %w", err)
	}
	return &Backend{Client: cs, Exec: RemoteExecer{Config: rc, Client: cs}, Config: cfg, Log: log, InCluster: kubeconfig == ""}, nil
}

// workerGrace: the worker's own deadline is the tool's timeout plus this. The
// Pod's activeDeadlineSeconds (the tool's timeout, from the Pod's start)
// normally ends a run that is too slow, and the worker reports what the
// kubelet saw; this timer covers an API server that stops answering.
var workerGrace = 30 * time.Second

// opTimeout bounds the API calls made outside a run's context (deletes).
const opTimeout = 30 * time.Second

// runError is a run's outcome other than success.
type runError struct {
	status sandbox.ToolStatus
	msg    string
	code   int
}

func (e *runError) Error() string { return e.msg }

func failed(format string, args ...any) *runError {
	return &runError{status: sandbox.Failed, msg: fmt.Sprintf(format, args...)}
}

// Run runs one tool in a Pod:
//
//  1. create the Pod (scannerPod); a leftover of the same name (an earlier
//     attempt) is deleted first;
//  2. wait for io-in to run, then exec `warden-sandbox-io receive` in it
//     with the input as tar (src/, secrets/hmac for Gitleaks, the tool's
//     org rules); receive seals the input, io-in exits, the scanner starts;
//  3. wait for the scanner to terminate (its exit code, OOMKilled, the
//     deadline, an image that can't be pulled);
//  4. exec `warden-sandbox-io send` in io-out, which is still running, and
//     receive /out into <ScanDir>/out/<tool> as hostile input: only the
//     SARIF and the tool's artifacts, each within its cap;
//  5. delete the Pod (always; by UID, so a newer Pod of the same name is
//     never removed).
//
// Every step watches the Pod's UID: a Pod replaced under the same name fails
// the run instead of being used.
func (b *Backend) Run(ctx context.Context, spec sandbox.ToolSpec, c sandbox.RunConfig) sandbox.ToolRun {
	started := time.Now()
	result := func(e *runError) sandbox.ToolRun {
		return sandbox.ToolRun{Tool: spec.Name, Status: e.status, DurationMS: time.Since(started).Milliseconds(), Error: e.msg, ExitCode: e.code}
	}
	outDir := filepath.Join(c.ScanDir, "out", spec.Name)
	if err := freshDir(outDir); err != nil {
		return result(failed("%v", err))
	}
	in, err := b.planInput(spec, c.ScanDir)
	if err != nil {
		return result(failed("input: %v", err))
	}
	pod, err := scannerPod(spec, c, b.Config, in)
	if err != nil {
		return result(failed("%v", err))
	}

	runCtx, cancel := context.WithTimeout(ctx, spec.Timeout+workerGrace)
	defer cancel()
	uid, err := b.create(runCtx, pod)
	if err != nil {
		return result(b.classify(runCtx, err))
	}
	defer b.remove(pod.Name, uid)

	term, err := b.drive(runCtx, spec, pod.Name, uid, in, c.ScanDir, outDir)
	if err != nil {
		_ = zipcheck.RemoveAll(outDir) // nothing of a failed fetch is read
		_ = os.MkdirAll(outDir, 0o700)
		return result(b.classify(runCtx, err))
	}
	if term.Reason == "OOMKilled" {
		return result(&runError{status: sandbox.Failed, code: int(term.ExitCode),
			msg: fmt.Sprintf("OOMKilled: the scanner exceeded its memory limit (%s)", spec.Memory)})
	}
	code := int(term.ExitCode)
	sarifPath := filepath.Join(outDir, spec.SarifFile())
	st, statErr := os.Lstat(sarifPath)
	if !spec.OKExit(code) || statErr != nil || !st.Mode().IsRegular() {
		msg := strings.TrimSpace(term.Message)
		if msg == "" {
			msg = fmt.Sprintf("exit %d", code)
		}
		return result(&runError{status: sandbox.Failed, msg: msg, code: code})
	}
	return sandbox.ToolRun{Tool: spec.Name, Status: sandbox.Succeeded, DurationMS: time.Since(started).Milliseconds(),
		Sarif: sarifPath, Artifacts: sandbox.CollectArtifacts(spec, outDir)}
}

// drive is steps 2 to 4; it returns the scanner's terminated state, with
// /out fetched when the exit code is one the tool succeeds with.
func (b *Backend) drive(ctx context.Context, spec sandbox.ToolSpec, name string, uid types.UID, in input, scanDir, outDir string) (*corev1.ContainerStateTerminated, error) {
	if _, err := b.waitFor(ctx, name, uid, inputReady); err != nil {
		return nil, err
	}
	if err := b.sendInput(ctx, name, in, scanDir); err != nil {
		return nil, err
	}
	// A failed tool's /out isn't read, as with docker.
	fetch := func(t *corev1.ContainerStateTerminated) bool {
		return t.Reason != "OOMKilled" && spec.OKExit(int(t.ExitCode))
	}
	pod, err := b.waitFor(ctx, name, uid, scannerDone(fetch))
	if err != nil {
		return nil, err
	}
	term := containerStatus(pod.Status.ContainerStatuses, containerScanner).State.Terminated
	if !fetch(term) {
		return term, nil
	}
	if err := b.fetchOutput(ctx, name, outCaps(spec), outDir); err != nil {
		return nil, err
	}
	return term, nil
}

// planInput lists what goes into the Pod and sizes it.
func (b *Backend) planInput(spec sandbox.ToolSpec, scanDir string) (input, error) {
	in := input{names: []string{"src"}}
	if spec.NeedsHMACKey {
		in.names = append(in.names, "secrets/hmac")
	}
	if spec.OrgRules != "" {
		in.names = append(in.names, sandbox.RulesDir+"/"+spec.OrgRules)
	}
	for _, n := range in.names[1:] {
		// Lstat: a file, not a symlink, as docker's bind mount would need.
		st, err := os.Lstat(filepath.Join(scanDir, filepath.FromSlash(n)))
		if err != nil || !st.Mode().IsRegular() {
			return in, fmt.Errorf("%s is missing", n)
		}
		if strings.HasPrefix(n, sandbox.RulesDir+"/") {
			in.rulesBytes = st.Size()
		}
	}
	_, disk, err := sandboxio.Plan(scanDir, in.names[:1])
	if err != nil {
		return in, err
	}
	all, _, err := sandboxio.Plan(scanDir, in.names)
	if err != nil {
		return in, err
	}
	in.srcDisk, in.bytes, in.entries = disk, all.Bytes, all.Entries()
	if b.MaxInputBytes > 0 && in.bytes > b.MaxInputBytes {
		return in, fmt.Errorf("%d bytes, over the %d byte limit", in.bytes, b.MaxInputBytes)
	}
	if b.MaxInputEntries > 0 && in.entries > b.MaxInputEntries {
		return in, fmt.Errorf("%d entries, over the limit of %d", in.entries, b.MaxInputEntries)
	}
	return in, nil
}

// create makes the Pod and returns its UID. A Pod of the same name is what a
// crashed attempt left (names are per scan and tool): it is deleted first.
func (b *Backend) create(ctx context.Context, pod *corev1.Pod) (types.UID, error) {
	pods := b.Client.CoreV1().Pods(b.Namespace)
	for attempt := 0; ; attempt++ {
		got, err := pods.Create(ctx, pod, metav1.CreateOptions{})
		if err == nil {
			return got.UID, nil
		}
		if !apierrors.IsAlreadyExists(err) || attempt == 2 {
			return "", fmt.Errorf("creating the pod: %w", err)
		}
		if err := b.deletePod(ctx, pod.Name, nil); err != nil {
			return "", fmt.Errorf("removing an earlier pod: %w", err)
		}
		if err := b.waitGone(ctx, pod.Name); err != nil {
			return "", err
		}
	}
}

// remove deletes the run's Pod on the way out, whatever happened; the
// worker's context may be gone, so it has its own deadline.
func (b *Backend) remove(name string, uid types.UID) {
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	if err := b.deletePod(ctx, name, &uid); err != nil && b.Log != nil {
		b.Log.Warn("scanner pod not deleted; the worker's next start removes it", "pod", name, "err", err)
	}
}

// deletePod deletes at once (grace 0): a scanner has nothing to save. With
// uid, only that Pod. Gone already is fine.
func (b *Backend) deletePod(ctx context.Context, name string, uid *types.UID) error {
	opts := metav1.DeleteOptions{GracePeriodSeconds: ptr(int64(0))}
	if uid != nil {
		opts.Preconditions = &metav1.Preconditions{UID: uid}
	}
	err := b.Client.CoreV1().Pods(b.Namespace).Delete(ctx, name, opts)
	if err == nil || apierrors.IsNotFound(err) || (uid != nil && apierrors.IsConflict(err)) {
		return nil
	}
	return err
}

func (b *Backend) waitGone(ctx context.Context, name string) error {
	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()
	for {
		_, err := b.Client.CoreV1().Pods(b.Namespace).Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

// Kill deletes the tool's Pod at once; used on cancel and before a retry.
func (b *Backend) Kill(scanID, tool string) {
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	name := sandbox.ContainerName(scanID, tool)
	if err := b.deletePod(ctx, name, nil); err != nil && b.Log != nil {
		b.Log.Warn("scanner pod not deleted", "pod", name, "err", err)
	}
}

// classify turns an error into the run's status: the worker's deadline is a
// timeout, the caller's cancellation is "cancelled" (as with docker).
func (b *Backend) classify(ctx context.Context, err error) *runError {
	var re *runError
	if errors.As(err, &re) {
		return re
	}
	if ctx.Err() != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return &runError{status: sandbox.Timeout, msg: "timeout"}
		}
		return failed("cancelled")
	}
	return failed("%v", err)
}

// sendInput streams the input into io-in (step 2).
func (b *Backend) sendInput(ctx context.Context, name string, in input, scanDir string) error {
	pr, pw := io.Pipe()
	go func() {
		_, _, err := sandboxio.SendTree(pw, scanDir, in.names, sandboxio.Limits{MaxBytes: in.bytes, MaxEntries: in.entries})
		pw.CloseWithError(err)
	}()
	stderr := &tail{n: 1024}
	err := b.Exec.Exec(ctx, b.Namespace, name, containerIn, receiveCmd(in), pr, io.Discard, stderr)
	pr.CloseWithError(errors.New("input stream closed")) // unblocks the sender if receive stopped early
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return failed("%v", execErr("sending input", err, stderr))
	}
	return nil
}

// fetchOutput receives /out from io-out (step 4). The stream is hostile:
// sandboxio.Receive with the tool's files and caps, into outDir only.
func (b *Backend) fetchOutput(ctx context.Context, name string, caps map[string]int64, outDir string) error {
	pr, pw := io.Pipe()
	type received struct{ err error }
	done := make(chan received, 1)
	go func() {
		_, err := sandboxio.Receive(pr, outDir, sandboxio.Limits{MaxBytes: sumCaps(caps), MaxEntries: len(caps), Files: caps})
		// Anything after the end of the archive is refused: the sender's
		// writes fail and its exec ends.
		pr.CloseWithError(errors.New("results stream closed"))
		done <- received{err}
	}()
	stderr := &tail{n: 1024}
	execErrV := b.Exec.Exec(ctx, b.Namespace, name, containerOut, sendCmd(caps), nil, pw, stderr)
	pw.CloseWithError(execErrV) // nil: a clean end of stream
	r := <-done
	if r.err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return failed("results rejected: %v", r.err)
	}
	if execErrV != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return failed("%v", execErr("fetching results", execErrV, stderr))
	}
	return nil
}

// freshDir makes dir empty: <ScanDir>/out/<tool> holds only what this run
// fetched.
func freshDir(dir string) error {
	if err := zipcheck.RemoveAll(dir); err != nil {
		return err
	}
	return os.MkdirAll(dir, 0o700)
}
