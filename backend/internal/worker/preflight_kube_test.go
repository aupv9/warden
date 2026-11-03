package worker

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	nodev1 "k8s.io/api/node/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/aupv9/warden/backend/internal/scan/sandbox"
	"github.com/aupv9/warden/backend/internal/scan/sandbox/kube"
)

const (
	sandboxNS = "warden-sandbox"
	ioImage   = "ghcr.io/aupv9/warden:0.6.0@sha256:" + "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	isolated  = `{"tried":["1.1.1.1:443"],"reached":[],"gvisor":true}`
)

// kubeEnv is preflightEnv on the kubernetes backend: a fake API server whose
// canary Pods "exit" with code and report.
func kubeEnv(t *testing.T, active []uuid.UUID, code int32, report string, objs ...runtime.Object) (*Env, *fake.Clientset) {
	t.Helper()
	env, _ := preflightEnv(t, active, nil)
	cs := fake.NewClientset(objs...)
	cs.PrependReactor("create", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		p := a.(k8stesting.CreateAction).GetObject().(*corev1.Pod)
		p.UID = types.UID("uid-" + p.Name)
		if p.Labels[kube.LabelRole] == "canary" {
			p.Status = corev1.PodStatus{Phase: corev1.PodFailed, ContainerStatuses: []corev1.ContainerStatus{{Name: "canary",
				State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: code, Message: report}}}}}
		}
		return false, nil, nil
	})
	env.Kube = &kube.Backend{Client: cs, Config: kube.Config{Namespace: sandboxNS, RuntimeClass: "gvisor", MirrorPVC: "m", IOImage: ioImage,
		IsolationTargets: kube.ProbeTargets}, Log: quietLog()}
	env.Sandbox = env.Kube
	return env, cs
}

var gvisorRC = &nodev1.RuntimeClass{ObjectMeta: metav1.ObjectMeta{Name: "gvisor"}, Handler: "runsc"}

func scannerPod(scan, tool string) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: sandbox.ContainerName(scan, tool), Namespace: sandboxNS,
		Labels: map[string]string{sandbox.LabelScan: scan, "app.kubernetes.io/managed-by": "warden-worker"}}}
}

func TestPreflightKubeOK(t *testing.T) {
	running, orphan := uuid.New(), uuid.New()
	env, cs := kubeEnv(t, []uuid.UUID{running}, 0, isolated, gvisorRC,
		scannerPod(running.String(), "trivy"), scannerPod(orphan.String(), "opengrep"))
	if err := env.Preflight(context.Background(), nil, true); err != nil {
		t.Fatal(err)
	}
	pods, _ := cs.CoreV1().Pods(sandboxNS).List(context.Background(), metav1.ListOptions{})
	if len(pods.Items) != 1 || pods.Items[0].Name != sandbox.ContainerName(running.String(), "trivy") {
		t.Fatalf("pods left %v", pods.Items)
	}
}

func TestPreflightKubeRefusals(t *testing.T) {
	forbidRC := func(cs *fake.Clientset) {
		cs.PrependReactor("get", "runtimeclasses", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "node.k8s.io", Resource: "runtimeclasses"}, "gvisor", errors.New("rbac"))
		})
	}
	for _, c := range []struct {
		name   string
		objs   []runtime.Object
		code   int32
		report string
		mutate func(*Env, *fake.Clientset)
		want   string
	}{
		{"internet reachable", []runtime.Object{gvisorRC}, 10, `{"tried":["1.1.1.1:443"],"reached":["1.1.1.1:443"],"gvisor":true}`, nil, "not isolated: a canary pod connected to 1.1.1.1:443"},
		{"api reachable", []runtime.Object{gvisorRC}, 10, `{"tried":["10.96.0.1:443"],"reached":["10.96.0.1:443"],"gvisor":true}`, nil, "10.96.0.1:443"},
		{"no runtime class", nil, 0, isolated, nil, `RuntimeClass "gvisor" does not exist`},
		{"runc handler", []runtime.Object{&nodev1.RuntimeClass{ObjectMeta: metav1.ObjectMeta{Name: "gvisor"}, Handler: "runc"}}, 0, isolated, nil, `handler "runc"`},
		{"not gvisor, rc unreadable", nil, 10, `{"tried":["1.1.1.1:443"],"reached":[],"gvisor":false}`,
			func(_ *Env, cs *fake.Clientset) { forbidRC(cs) }, "did not run on gVisor"},
		{"canary fails", []runtime.Object{gvisorRC}, 2, "usage", nil, "isolation is unknown"},
		{"local image", []runtime.Object{gvisorRC}, 0, isolated, func(e *Env, _ *fake.Clientset) {
			e.Images = map[string]string{"trivy": "sha256:" + strings.Repeat("d", 64)}
		}, "scan.images.trivy"},
		{"io image tag", []runtime.Object{gvisorRC}, 0, isolated, func(e *Env, _ *fake.Clientset) { e.Kube.IOImage = "warden:dev" }, "scan.kube.io_image"},
	} {
		t.Run(c.name, func(t *testing.T) {
			for _, strict := range []bool{true, false} {
				env, cs := kubeEnv(t, nil, c.code, c.report, c.objs...)
				if c.mutate != nil {
					c.mutate(env, cs)
				}
				err := env.Preflight(context.Background(), nil, strict)
				if strict && (err == nil || !strings.Contains(err.Error(), c.want)) {
					t.Fatalf("got %v, want %q", err, c.want)
				}
				// Outside prod the same problems only warn.
				if !strict && err != nil {
					t.Fatalf("dev: %v", err)
				}
			}
		})
	}
}

// With the RuntimeClass verified, a canary that doesn't recognize gVisor
// only warns: the RuntimeClass is the authority.
func TestPreflightKubeTrustsAVerifiedRuntimeClass(t *testing.T) {
	env, _ := kubeEnv(t, nil, 10, `{"tried":["1.1.1.1:443"],"reached":[],"gvisor":false}`, gvisorRC)
	if err := env.Preflight(context.Background(), nil, true); err != nil {
		t.Fatal(err)
	}
}

// A policy that applies only after a pod started (k3s) passes once the
// canary is cut off; GKE Sandbox's handler is "gvisor".
func TestPreflightKubeLatePolicyAndGKE(t *testing.T) {
	gke := &nodev1.RuntimeClass{ObjectMeta: metav1.ObjectMeta{Name: "gvisor"}, Handler: "gvisor"}
	env, _ := kubeEnv(t, nil, 0, `{"tried":["1.1.1.1:443"],"reached":[],"early":["1.1.1.1:443"],"gvisor":true}`, gke)
	if err := env.Preflight(context.Background(), nil, true); err != nil {
		t.Fatal(err)
	}
	if len(env.Kube.IsolationTargets) == 0 {
		t.Fatal("scanner pods lost their isolation gate")
	}
}

// In development an open namespace only warns, and scanner pods then don't
// wait for a cut-off that would never come; in prod the gate stays.
func TestPreflightKubeOpenNamespace(t *testing.T) {
	open := `{"tried":["1.1.1.1:443"],"reached":["1.1.1.1:443"],"gvisor":true}`
	env, _ := kubeEnv(t, nil, 10, open, gvisorRC)
	if err := env.Preflight(context.Background(), nil, false); err != nil {
		t.Fatal(err)
	}
	if env.Kube.IsolationTargets != nil {
		t.Fatal("gate kept in development")
	}
	env, _ = kubeEnv(t, nil, 10, open, gvisorRC)
	if err := env.Preflight(context.Background(), nil, true); err == nil || len(env.Kube.IsolationTargets) == 0 {
		t.Fatal("prod: open namespace accepted or gate removed:", err)
	}
}
