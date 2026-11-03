package kube

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/aupv9/warden/backend/internal/scan/sandbox"
	"github.com/aupv9/warden/backend/internal/scan/sandbox/sandboxio"
)

// GVisorHandler is the containerd runtime handler of gVisor.
const GVisorHandler = "runsc"

// RuntimeClassState is what the API says of scan.kube.runtime_class.
type RuntimeClassState int

const (
	// RuntimeClassGVisor: it exists with handler runsc.
	RuntimeClassGVisor RuntimeClassState = iota
	// RuntimeClassUnknown: the worker may not read RuntimeClasses (they are
	// cluster-scoped; the chart's Role is namespaced). The canary then
	// checks from inside a Pod that it runs on gVisor.
	RuntimeClassUnknown
	// RuntimeClassBad: missing, or another handler.
	RuntimeClassBad
)

// RuntimeClass checks scan.kube.runtime_class. err explains a Bad state or
// an Unknown one.
func (b *Backend) RuntimeClass(ctx context.Context) (RuntimeClassState, error) {
	if b.Config.RuntimeClass == "" {
		return RuntimeClassBad, errors.New("scan.kube.runtime_class is empty: scanner pods use the cluster's default runtime, not gVisor")
	}
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	rc, err := b.Client.NodeV1().RuntimeClasses().Get(ctx, b.Config.RuntimeClass, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		return RuntimeClassBad, fmt.Errorf("RuntimeClass %q does not exist (scan.kube.runtime_class)", b.Config.RuntimeClass)
	case apierrors.IsForbidden(err):
		return RuntimeClassUnknown, fmt.Errorf("may not read RuntimeClass %q: %w", b.Config.RuntimeClass, err)
	case err != nil:
		return RuntimeClassUnknown, fmt.Errorf("reading RuntimeClass %q: %w", b.Config.RuntimeClass, err)
	case rc.Handler != GVisorHandler:
		return RuntimeClassBad, fmt.Errorf("RuntimeClass %q has handler %q, not %q (gVisor)", rc.Name, rc.Handler, GVisorHandler)
	}
	return RuntimeClassGVisor, nil
}

// Ready is the worker's "sandbox" readiness check: the API server answers
// for the namespace (the Role works) and the RuntimeClass, if readable, is
// still gVisor.
func (b *Backend) Ready(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	if _, err := b.Client.CoreV1().Pods(b.Namespace).List(ctx, metav1.ListOptions{Limit: 1}); err != nil {
		return fmt.Errorf("listing pods in %s: %w", b.Namespace, err)
	}
	if st, err := b.RuntimeClass(ctx); st == RuntimeClassBad {
		return err
	}
	return nil
}

// ScannerPods lists the Pods named and labelled like scanner Pods
// (sandbox.ParseContainerName; a warden.scan label that disagrees with the
// name is not one the worker made).
func (b *Backend) ScannerPods(ctx context.Context) ([]sandbox.Container, error) {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	sel := labels.SelectorFromSet(labels.Set{labelManagedBy: managedBy}).String() + "," + LabelScan
	list, err := b.Client.CoreV1().Pods(b.Namespace).List(ctx, metav1.ListOptions{LabelSelector: sel})
	if err != nil {
		return nil, err
	}
	var out []sandbox.Container
	for _, p := range list.Items {
		id, tool, ok := sandbox.ParseContainerName(p.Name)
		if !ok || p.Labels[LabelScan] != id {
			continue
		}
		out = append(out, sandbox.Container{Name: p.Name, ScanID: id, Tool: tool})
	}
	return out, nil
}

// RemovePod deletes a scanner Pod by name (only a scanner Pod's name).
func (b *Backend) RemovePod(ctx context.Context, name string) error {
	if _, _, ok := sandbox.ParseContainerName(name); !ok {
		return errors.New("not a scanner pod name")
	}
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	return b.deletePod(ctx, name, nil)
}

// CanaryResult is what the canary Pod found.
type CanaryResult struct {
	// Reached are the targets it could open a TCP connection to: the
	// namespace's traffic is not denied.
	Reached []string
	Tried   []string
	// GVisor: it ran on gVisor's kernel.
	GVisor bool
}

// Canary runs a Pod with the io image and every scanner Pod's settings that
// tries to reach the internet (1.1.1.1:443), the API server's service and
// extra targets, and reports whether it runs on gVisor. A canary that can't
// run or report is an error: isolation is unknown. Leftover canaries (of a
// crashed start) are removed first.
func (b *Backend) Canary(ctx context.Context, extra []string) (CanaryResult, error) {
	var res CanaryResult
	b.removeCanaries(ctx)
	suffix := make([]byte, 4)
	_, _ = rand.Read(suffix)
	pod := canaryPod(b.Config, "warden-canary-"+hex.EncodeToString(suffix), extra)
	ctx, cancel := context.WithTimeout(ctx, canaryTimeout+workerGrace)
	defer cancel()
	created, err := b.Client.CoreV1().Pods(b.Namespace).Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		return res, fmt.Errorf("creating the canary pod: %w", err)
	}
	defer b.remove(pod.Name, created.UID)
	done, err := b.waitFor(ctx, pod.Name, created.UID, func(p *corev1.Pod) (bool, error) {
		if t := containerStatus(p.Status.ContainerStatuses, containerCanary).State.Terminated; t != nil {
			return true, nil
		}
		return false, podFailure(p)
	})
	if err != nil {
		return res, fmt.Errorf("canary pod: %w", err)
	}
	t := containerStatus(done.Status.ContainerStatuses, containerCanary).State.Terminated
	if t.ExitCode != sandboxio.ExitOK && t.ExitCode != sandboxio.ExitReached {
		return res, fmt.Errorf("canary exited %d: %s", t.ExitCode, clip(t.Reason+" "+t.Message))
	}
	var r sandboxio.ProbeReport
	if len(t.Message) > 4096 || json.Unmarshal([]byte(t.Message), &r) != nil {
		return res, fmt.Errorf("canary exited %d without a readable report", t.ExitCode)
	}
	res = CanaryResult{Reached: r.Reached, Tried: r.Tried, GVisor: r.GVisor}
	if (t.ExitCode == sandboxio.ExitOK) != (len(r.Reached) == 0 && r.GVisor) {
		return res, fmt.Errorf("canary exit %d disagrees with its report", t.ExitCode)
	}
	return res, nil
}

func (b *Backend) removeCanaries(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	sel := labels.SelectorFromSet(labels.Set{labelManagedBy: managedBy, LabelRole: "canary"}).String()
	list, err := b.Client.CoreV1().Pods(b.Namespace).List(ctx, metav1.ListOptions{LabelSelector: sel})
	if err != nil {
		return
	}
	for _, p := range list.Items {
		if strings.HasPrefix(p.Name, "warden-canary-") {
			_ = b.deletePod(ctx, p.Name, nil)
		}
	}
}

// ClusterDNS is the worker's first nameserver as host:53, when the worker
// runs in the cluster (it is then the cluster DNS, which a NetworkPolicy
// often lets through); "" otherwise.
func (b *Backend) ClusterDNS() string {
	if !b.InCluster {
		return ""
	}
	return firstNameserver("/etc/resolv.conf")
}

func firstNameserver(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" {
			if ip := net.ParseIP(fields[1]); ip != nil && !ip.IsLoopback() {
				return net.JoinHostPort(ip.String(), "53")
			}
		}
	}
	return ""
}

// PreflightTimeout bounds the whole kubernetes preflight.
const PreflightTimeout = canaryTimeout + 2*time.Minute
