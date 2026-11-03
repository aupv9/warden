package kube

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/aupv9/warden/backend/internal/scan/sandbox"
)

var update = flag.Bool("update", false, "rewrite the golden files")

const (
	testScan  = "0b6f1a52-6c9e-4c52-9a7e-3f0f8c1d2e4a"
	testImage = "registry.example/warden-gitleaks:8.30@sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testIO    = "ghcr.io/aupv9/warden:0.6.0@sha256:" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

var testConfig = Config{Namespace: "warden-sandbox", RuntimeClass: "gvisor", MirrorPVC: "warden-mirror", IOImage: testIO,
	IsolationTargets: append(slices.Clone(ProbeTargets), "10.96.0.10:53")}

func gitleaksWithRules(t *testing.T) sandbox.ToolSpec {
	t.Helper()
	spec, err := sandbox.WithOrgRules(sandbox.Tools["gitleaks"])
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

func testInput() input {
	return input{names: []string{"src", "secrets/hmac", "rules/gitleaks.toml"}, bytes: 12345, entries: 7, srcDisk: 40960, rulesBytes: 300}
}

// The scanner Pod as the API server gets it, field by field: any change to a
// security setting shows up here (go test ./internal/scan/sandbox/kube -update).
func TestScannerPodGolden(t *testing.T) {
	pod, err := scannerPod(gitleaksWithRules(t), sandbox.RunConfig{ScanID: testScan, Image: testImage}, testConfig, testInput())
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.MarshalIndent(pod, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "scanner-pod.golden.json")
	if *update {
		if err := os.WriteFile(golden, append(got, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(want)) != strings.TrimSpace(string(got)) {
		t.Fatalf("scanner pod differs from %s (rerun with -update after reviewing):\n%s", golden, got)
	}
}

// assertHardened checks every security setting of a Pod the worker makes.
func assertHardened(t *testing.T, p *corev1.Pod) {
	t.Helper()
	s := p.Spec
	if s.RuntimeClassName == nil || *s.RuntimeClassName != "gvisor" {
		t.Error("runtimeClassName")
	}
	if s.AutomountServiceAccountToken == nil || *s.AutomountServiceAccountToken {
		t.Error("service account token mounted")
	}
	if s.EnableServiceLinks == nil || *s.EnableServiceLinks {
		t.Error("service links")
	}
	if s.HostNetwork || s.HostPID || s.HostIPC || s.ShareProcessNamespace == nil || *s.ShareProcessNamespace {
		t.Error("host or shared namespaces")
	}
	if s.RestartPolicy != corev1.RestartPolicyNever {
		t.Error("restartPolicy")
	}
	if s.ActiveDeadlineSeconds == nil || *s.ActiveDeadlineSeconds <= 0 {
		t.Error("activeDeadlineSeconds")
	}
	if s.DNSPolicy != corev1.DNSNone || s.DNSConfig == nil || !slices.Equal(s.DNSConfig.Nameservers, []string{"127.0.0.1"}) {
		t.Error("DNS")
	}
	if s.ServiceAccountName != "" || len(s.ImagePullSecrets) != 0 || s.NodeName != "" || len(s.HostAliases) != 0 {
		t.Error("unexpected pod field")
	}
	ps := s.SecurityContext
	if ps == nil || ps.RunAsNonRoot == nil || !*ps.RunAsNonRoot || *ps.RunAsUser != SandboxUID || *ps.RunAsGroup != SandboxUID ||
		*ps.FSGroup != SandboxUID || ps.SeccompProfile == nil || ps.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Error("pod security context")
	}
	for _, v := range s.Volumes {
		vs := v.VolumeSource
		switch {
		case vs.EmptyDir != nil:
			if vs.EmptyDir.SizeLimit == nil || vs.EmptyDir.SizeLimit.Sign() <= 0 {
				t.Errorf("volume %s has no size limit", v.Name)
			}
		case vs.PersistentVolumeClaim != nil:
			if !vs.PersistentVolumeClaim.ReadOnly || v.Name != "data" {
				t.Errorf("volume %s: writable claim", v.Name)
			}
		default:
			t.Errorf("volume %s: not an emptyDir or the mirror", v.Name)
		}
	}
	for _, c := range append(slices.Clone(s.InitContainers), s.Containers...) {
		sc := c.SecurityContext
		if sc == nil || sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot || *sc.RunAsUser != SandboxUID || *sc.RunAsGroup != SandboxUID {
			t.Errorf("%s: user", c.Name)
		}
		if sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
			t.Errorf("%s: writable root", c.Name)
		}
		if sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation || sc.Privileged == nil || *sc.Privileged {
			t.Errorf("%s: privilege", c.Name)
		}
		if sc.Capabilities == nil || !slices.Equal(sc.Capabilities.Drop, []corev1.Capability{"ALL"}) || len(sc.Capabilities.Add) != 0 {
			t.Errorf("%s: capabilities", c.Name)
		}
		if sc.SeccompProfile == nil || sc.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
			t.Errorf("%s: seccomp", c.Name)
		}
		if !Pinned(c.Image) || c.ImagePullPolicy != corev1.PullIfNotPresent {
			t.Errorf("%s: image %q", c.Name, c.Image)
		}
		for _, r := range []corev1.ResourceName{corev1.ResourceCPU, corev1.ResourceMemory, corev1.ResourceEphemeralStorage} {
			l, ok := c.Resources.Limits[r]
			if !ok || l.Sign() <= 0 || !l.Equal(c.Resources.Requests[r]) {
				t.Errorf("%s: %s limit", c.Name, r)
			}
		}
		if len(c.Ports) != 0 || c.Stdin || c.TTY || c.RestartPolicy != nil {
			t.Errorf("%s: ports, stdin or a sidecar restart policy", c.Name)
		}
	}
}

func mountsOf(p *corev1.Pod, container string) map[string]corev1.VolumeMount {
	out := map[string]corev1.VolumeMount{}
	for _, c := range append(slices.Clone(p.Spec.InitContainers), p.Spec.Containers...) {
		if c.Name == container {
			for _, m := range c.VolumeMounts {
				out[m.MountPath] = m
			}
		}
	}
	return out
}

func TestScannerPodSecurity(t *testing.T) {
	cases := map[string]sandbox.ToolSpec{"gitleaks+rules": gitleaksWithRules(t)}
	for name, spec := range sandbox.Tools {
		cases[name] = spec
	}
	for _, tool := range sandbox.ImageToolNames {
		cases["image "+tool], _ = sandbox.ImageTool(tool, sandbox.ImageLimits{MaxBytes: 1 << 30, ScanTimeout: time.Hour})
	}
	cases["history"] = sandbox.HistoryTool(sandbox.HistoryLimits{MaxBytes: 1 << 30, MaxCommits: 10, ScanTimeout: time.Hour})
	for name, spec := range cases {
		t.Run(name, func(t *testing.T) {
			pod, err := scannerPod(spec, sandbox.RunConfig{ScanID: testScan, Image: testImage}, testConfig, testInput())
			if err != nil {
				t.Fatal(err)
			}
			assertHardened(t, pod)
			if pod.Name != "warden-"+testScan+"-"+spec.Name || pod.Labels[LabelScan] != testScan || pod.Labels[LabelTool] != spec.Name {
				t.Errorf("name/labels %s %v", pod.Name, pod.Labels)
			}
			if got := *pod.Spec.ActiveDeadlineSeconds; got != int64(spec.Timeout.Seconds()) {
				t.Errorf("deadline %d, timeout %s", got, spec.Timeout)
			}
			sc := pod.Spec.Containers[0]
			if sc.Name != containerScanner || sc.Command[0] != spec.Command[0] || !slices.Equal(sc.Args, spec.Command[1:]) ||
				sc.WorkingDir != "/tmp" || len(sc.Env) != 1 || sc.Env[0] != (corev1.EnvVar{Name: "HOME", Value: "/tmp"}) {
				t.Errorf("scanner command/env: %v %v", sc.Command, sc.Args)
			}
			m := mountsOf(pod, containerScanner)
			for path, ro := range map[string]bool{"/src": true, "/out": false, "/tmp": false, "/data": true} {
				if mm, ok := m[path]; !ok || mm.ReadOnly != ro {
					t.Errorf("scanner mount %s: %+v", path, mm)
				}
			}
			if m["/data"].SubPath != spec.Name {
				t.Errorf("mirror subPath %q", m["/data"].SubPath)
			}
			if _, ok := m["/run/warden"]; ok != spec.NeedsHMACKey || (ok && !m["/run/warden"].ReadOnly) {
				t.Errorf("hmac mount: %v", ok)
			}
			if _, ok := m["/rules"]; ok != (spec.OrgRules != "") || (ok && !m["/rules"].ReadOnly) {
				t.Errorf("rules mount: %v", ok)
			}
			// io-out reads /out only; io-in never sees /out, the mirror or /tmp.
			if out := mountsOf(pod, containerOut); len(out) != 1 || !out["/out"].ReadOnly {
				t.Errorf("io-out mounts %v", out)
			}
			for p := range mountsOf(pod, containerIn) {
				if !strings.HasPrefix(p, "/in/") && p != "/ctl" {
					t.Errorf("io-in mounts %s", p)
				}
			}
			// The scanner starts only after io-in saw the network cut off.
			want := ioBinary + " wait -marker /ctl/ready -within 1m0s -connect 1.1.1.1:443 -connect $KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT -connect 10.96.0.10:53"
			if got := strings.Join(pod.Spec.InitContainers[0].Command, " "); got != want {
				t.Errorf("io-in command %q", got)
			}
			// Gitleaks' log never becomes the Pod's termination message.
			if spec.NeedsHMACKey && sc.TerminationMessagePolicy != corev1.TerminationMessageReadFile {
				t.Error("gitleaks termination message from logs")
			}
			mem, _ := dockerBytes(spec.Memory)
			if q := sc.Resources.Limits[corev1.ResourceMemory]; q.Value() != mem {
				t.Errorf("memory %s for %s", q.String(), spec.Memory)
			}
			for _, v := range pod.Spec.Volumes {
				if v.Name == "tmp" {
					tmp, _ := dockerBytes(spec.TmpSize())
					if v.EmptyDir.Medium != corev1.StorageMediumMemory || v.EmptyDir.SizeLimit.Value() != tmp {
						t.Errorf("tmp volume %+v", v.EmptyDir)
					}
				}
			}
		})
	}
}

func TestCanaryPodSecurity(t *testing.T) {
	pod := canaryPod(testConfig, "warden-canary-0011aabb", testConfig.IsolationTargets)
	assertHardened(t, pod)
	if len(pod.Spec.Volumes) != 0 || pod.Labels[LabelScan] != "" || pod.Labels[LabelRole] != "canary" {
		t.Errorf("canary %+v", pod.ObjectMeta)
	}
	args := strings.Join(pod.Spec.Containers[0].Args, " ")
	for _, want := range []string{"-connect 1.1.1.1:443", "-connect $KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT", "-connect 10.96.0.10:53", "-report /dev/termination-log"} {
		if !strings.Contains(args, want) {
			t.Errorf("canary args %q lack %q", args, want)
		}
	}
}

func TestScannerPodRefusals(t *testing.T) {
	spec := sandbox.Tools["opengrep"]
	for name, c := range map[string]struct {
		spec sandbox.ToolSpec
		rc   sandbox.RunConfig
	}{
		"image ID":       {spec, sandbox.RunConfig{ScanID: testScan, Image: "sha256:" + strings.Repeat("a", 64)}},
		"tag":            {spec, sandbox.RunConfig{ScanID: testScan, Image: "aquasec/trivy:0.75.0"}},
		"bad pod name":   {spec, sandbox.RunConfig{ScanID: "Not_A_Name", Image: testImage}},
		"long pod name":  {spec, sandbox.RunConfig{ScanID: strings.Repeat("a", 60), Image: testImage}},
		"no command":     {sandbox.ToolSpec{Name: "x", CPUs: "1", Memory: "1g"}, sandbox.RunConfig{ScanID: testScan, Image: testImage}},
		"bad cpus":       {sandbox.ToolSpec{Name: "x", CPUs: "lots", Memory: "1g", Command: []string{"x"}}, sandbox.RunConfig{ScanID: testScan, Image: testImage}},
		"bad memory":     {sandbox.ToolSpec{Name: "x", CPUs: "1", Memory: "1t", Command: []string{"x"}}, sandbox.RunConfig{ScanID: testScan, Image: testImage}},
		"bad tmp":        {sandbox.ToolSpec{Name: "x", CPUs: "1", Memory: "1g", TmpfsSize: "-1m", Command: []string{"x"}}, sandbox.RunConfig{ScanID: testScan, Image: testImage}},
		"another's rule": {func() sandbox.ToolSpec { s := spec; s.OrgRules = "gitleaks.toml"; return s }(), sandbox.RunConfig{ScanID: testScan, Image: testImage}},
	} {
		if _, err := scannerPod(c.spec, c.rc, testConfig, testInput()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestScannerPodDevelopmentDefaults(t *testing.T) {
	cfg := testConfig
	cfg.RuntimeClass, cfg.MirrorPVC, cfg.IsolationTargets = "", "", nil
	pod, err := scannerPod(sandbox.Tools["trivy"], sandbox.RunConfig{ScanID: testScan, Image: testImage}, cfg, testInput())
	if err != nil {
		t.Fatal(err)
	}
	if got := pod.Spec.InitContainers[0].Command; len(got) != 4 {
		t.Errorf("isolation gate without targets: %v", got)
	}
	if pod.Spec.RuntimeClassName != nil {
		t.Error("runtime class set")
	}
	for _, v := range pod.Spec.Volumes {
		if v.Name == "data" && v.EmptyDir == nil {
			t.Error("mirror without a claim")
		}
	}
	if m := mountsOf(pod, containerScanner)["/data"]; m.SubPath != "" || !m.ReadOnly {
		t.Errorf("data mount %+v", m)
	}
}

func TestDockerBytes(t *testing.T) {
	for in, want := range map[string]int64{"512m": 512 << 20, "2g": 2 << 30, "1536m": 1536 << 20, "64k": 64 << 10, "100b": 100, "7": 7, "1G": 1 << 30} {
		if got, err := dockerBytes(in); err != nil || got != want {
			t.Errorf("%s = %d, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "m", "0m", "-1g", "1t", "1.5g", "99999999999999g"} {
		if _, err := dockerBytes(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	// Kubernetes would read docker's "512m" as millibytes.
	if q := resource.MustParse("512m"); q.Value() > 1 {
		t.Fatal("assumption about quantities")
	}
}

func TestPinned(t *testing.T) {
	d := "@sha256:" + strings.Repeat("0", 64)
	for ref, want := range map[string]bool{
		"ghcr.io/aupv9/warden" + d:           true,
		"ghcr.io/aupv9/warden:0.6.0" + d:     true,
		"localhost:5001/warden-gitleaks" + d: true,
		"sha256:" + strings.Repeat("0", 64):  false,
		"ghcr.io/aupv9/warden:0.6.0":         false,
		"ghcr.io/aupv9/warden@sha256:abc":    false,
		"Upper/case" + d:                     false,
		"x y" + d:                            false,
	} {
		if Pinned(ref) != want {
			t.Errorf("Pinned(%q) != %v", ref, want)
		}
	}
}

func TestCommands(t *testing.T) {
	in := testInput()
	if got := strings.Join(receiveCmd(in), " "); got != ioBinary+" receive -dir /in -max-bytes 12345 -max-entries 7 -seal /ctl/ready" {
		t.Errorf("receive %q", got)
	}
	caps := outCaps(sandbox.Tools["trivy"])
	if len(caps) != 4 || caps["result.sarif"] != 256<<20 || caps["trivy.json"] != 256<<20 {
		t.Errorf("trivy caps %v", caps)
	}
	if got := strings.Join(sendCmd(map[string]int64{"b": 2, "a": 1}), " "); got != ioBinary+" send -dir /out -file a=1 -file b=2" {
		t.Errorf("send %q", got)
	}
	if c := outCaps(sandbox.Tools["checkov"]); len(c) != 1 || c["results_sarif.sarif"] == 0 {
		t.Errorf("checkov caps %v", c)
	}
}
