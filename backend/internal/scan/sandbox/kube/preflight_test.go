package kube

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	nodev1 "k8s.io/api/node/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stesting "k8s.io/client-go/testing"

	"github.com/aupv9/warden/backend/internal/scan/sandbox/sandboxio"
)

func runtimeClass(name, handler string) *nodev1.RuntimeClass {
	return &nodev1.RuntimeClass{ObjectMeta: metav1.ObjectMeta{Name: name}, Handler: handler}
}

func TestRuntimeClass(t *testing.T) {
	ctx := context.Background()
	c := newCluster(t, runtimeClass("gvisor", "runsc"))
	if st, err := c.b.RuntimeClass(ctx); st != RuntimeClassGVisor || err != nil {
		t.Fatalf("gvisor: %v %v", st, err)
	}
	if err := c.b.Ready(ctx); err != nil {
		t.Fatal(err)
	}

	// GKE Sandbox's handler.
	c = newCluster(t, runtimeClass("gvisor", "gvisor"))
	if st, err := c.b.RuntimeClass(ctx); st != RuntimeClassGVisor || err != nil {
		t.Fatalf("gke: %v %v", st, err)
	}

	c = newCluster(t, runtimeClass("gvisor", "runc"))
	if st, err := c.b.RuntimeClass(ctx); st != RuntimeClassBad || !strings.Contains(err.Error(), `handler "runc"`) {
		t.Fatalf("runc: %v %v", st, err)
	}
	if err := c.b.Ready(ctx); err == nil {
		t.Fatal("ready with a runc RuntimeClass")
	}

	c = newCluster(t)
	if st, err := c.b.RuntimeClass(ctx); st != RuntimeClassBad || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("missing: %v %v", st, err)
	}
	c.b.Config.RuntimeClass = ""
	if st, _ := c.b.RuntimeClass(ctx); st != RuntimeClassBad {
		t.Fatal("empty runtime class")
	}

	// The Role is namespaced: reading the RuntimeClass may be forbidden.
	c = newCluster(t)
	c.cs.PrependReactor("get", "runtimeclasses", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "node.k8s.io", Resource: "runtimeclasses"}, "gvisor", errors.New("rbac"))
	})
	if st, _ := c.b.RuntimeClass(ctx); st != RuntimeClassUnknown {
		t.Fatalf("forbidden: %v", st)
	}
	if err := c.b.Ready(ctx); err != nil {
		t.Fatalf("ready without RuntimeClass access: %v", err)
	}
	c.cs.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("connection refused")
	})
	if err := c.b.Ready(ctx); err == nil {
		t.Fatal("ready without the API")
	}
}

func TestScannerPodsAndRemove(t *testing.T) {
	ctx := context.Background()
	mk := func(name string, lbl map[string]string) runtime.Object {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: lbl}}
	}
	id := "0b6f1a52-6c9e-4c52-9a7e-3f0f8c1d2e4a"
	ours := map[string]string{labelManagedBy: managedBy, LabelScan: id}
	c := newCluster(t,
		mk("warden-"+id+"-trivy", ours),
		mk("warden-"+id+"-bogus", ours), // not a tool
		mk("warden-"+id+"-checkov", map[string]string{labelManagedBy: managedBy, LabelScan: "x"}), // label disagrees
		mk("warden-"+id+"-opengrep", map[string]string{LabelScan: id}),                            // not managed by the worker
		mk("unrelated", nil),
	)
	pods, err := c.b.ScannerPods(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pods) != 1 || pods[0].Tool != "trivy" || pods[0].ScanID != id {
		t.Fatalf("pods %+v", pods)
	}
	if err := c.b.RemovePod(ctx, "unrelated"); err == nil {
		t.Fatal("removed a pod that isn't a scanner's")
	}
	if err := c.b.RemovePod(ctx, pods[0].Name); err != nil {
		t.Fatal(err)
	}
	c.podGone(t, pods[0].Name)
}

func TestCanary(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name    string
		code    int32
		msg     string
		reached int
		gvisor  bool
		errHas  string
	}{
		{"isolated", 0, `{"tried":["1.1.1.1:443","10.96.0.1:443"],"reached":[],"gvisor":true}`, 0, true, ""},
		{"internet", sandboxio.ExitReached, `{"tried":["1.1.1.1:443"],"reached":["1.1.1.1:443"],"gvisor":true}`, 1, true, ""},
		{"not gvisor", sandboxio.ExitReached, `{"tried":["1.1.1.1:443"],"reached":[],"gvisor":false}`, 0, false, ""},
		{"no report", sandboxio.ExitReached, ``, 0, false, "without a readable report"},
		{"lying exit", 0, `{"tried":["1.1.1.1:443"],"reached":["1.1.1.1:443"],"gvisor":true}`, 1, true, "disagrees"},
		{"crashed", 2, `usage`, 0, false, "canary exited 2"},
	} {
		t.Run(c.name, func(t *testing.T) {
			cl := newCluster(t)
			// A leftover canary of a crashed start is removed.
			_, err := cl.cs.CoreV1().Pods(ns).Create(ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "warden-canary-old", Namespace: ns,
				Labels: map[string]string{labelManagedBy: managedBy, LabelRole: "canary"}}}, metav1.CreateOptions{})
			must(t, err)
			cl.onCreate = func(p *corev1.Pod) {
				if p.Labels[LabelRole] == "canary" && p.Name != "warden-canary-old" {
					assertHardened(t, p)
					p.Status = corev1.PodStatus{Phase: corev1.PodFailed,
						ContainerStatuses: []corev1.ContainerStatus{terminated(containerCanary, c.code, "", c.msg)}}
				}
			}
			res, err := cl.b.Canary(ctx)
			if c.errHas != "" {
				if err == nil || !strings.Contains(err.Error(), c.errHas) {
					t.Fatalf("err %v", err)
				}
			} else if err != nil || len(res.Reached) != c.reached || res.GVisor != c.gvisor {
				t.Fatalf("res %+v err %v", res, err)
			}
			list, _ := cl.cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
			if len(list.Items) != 0 {
				t.Fatalf("canary pods left: %d", len(list.Items))
			}
		})
	}

	cl := newCluster(t)
	cl.onCreate = func(p *corev1.Pod) {
		p.Status.ContainerStatuses = []corev1.ContainerStatus{waiting(containerCanary, "ImagePullBackOff")}
	}
	if _, err := cl.b.Canary(ctx); err == nil || !strings.Contains(err.Error(), "ImagePullBackOff") {
		t.Fatalf("image: %v", err)
	}
}

func TestClusterDNS(t *testing.T) {
	p := filepath.Join(t.TempDir(), "resolv.conf")
	must(t, os.WriteFile(p, []byte("search svc.cluster.local\nnameserver 127.0.0.53\nnameserver 10.96.0.10\noptions ndots:5\n"), 0o644))
	if got := firstNameserver(p); got != "10.96.0.10:53" {
		t.Fatalf("got %q", got)
	}
	if firstNameserver(filepath.Join(t.TempDir(), "none")) != "" {
		t.Fatal("missing file")
	}
	b := &Backend{}
	if b.ClusterDNS() != "" {
		t.Fatal("outside the cluster")
	}
}

func TestNewValidates(t *testing.T) {
	if _, err := New(Config{Namespace: "Bad_NS", IOImage: testIO}, "", quiet()); err == nil {
		t.Fatal("bad namespace")
	}
	if _, err := New(Config{Namespace: "ns"}, "", quiet()); err == nil {
		t.Fatal("no io image")
	}
	if _, err := New(Config{Namespace: "ns", IOImage: testIO}, filepath.Join(t.TempDir(), "missing"), quiet()); err == nil {
		t.Fatal("missing kubeconfig")
	}
	kc := filepath.Join(t.TempDir(), "kubeconfig")
	must(t, os.WriteFile(kc, []byte(`apiVersion: v1
kind: Config
clusters: [{name: c, cluster: {server: "https://127.0.0.1:6443"}}]
contexts: [{name: c, context: {cluster: c, user: u}}]
current-context: c
users: [{name: u, user: {token: t}}]
`), 0o600))
	b, err := New(Config{Namespace: "ns", IOImage: testIO}, kc, quiet())
	if err != nil {
		t.Fatal(err)
	}
	if b.InCluster || b.Exec == nil {
		t.Fatalf("%+v", b)
	}
}
