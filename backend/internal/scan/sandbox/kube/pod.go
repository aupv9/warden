package kube

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/aupv9/warden/backend/internal/scan/sandbox"
	"github.com/aupv9/warden/backend/internal/scan/sarif"
)

// Labels on every Pod the worker makes. warden.scan is the docker backend's
// label too (sandbox.LabelScan): the startup cleanup lists Pods by it.
const (
	LabelScan = sandbox.LabelScan
	LabelTool = "warden.tool"
	// LabelRole is "scanner" or "canary".
	LabelRole      = "warden.role"
	labelManagedBy = "app.kubernetes.io/managed-by"
	managedBy      = "warden-worker"
)

// Container names and the paths warden-sandbox-io works on. The binary's
// path is absolute: the io image has no shell and PATH is not relied on.
const (
	containerIn      = "io-in"
	containerScanner = "scanner"
	containerOut     = "io-out"
	containerCanary  = "canary"

	ioBinary    = "/usr/local/bin/warden-sandbox-io"
	inDir       = "/in"
	readyMarker = "/ctl/ready"
)

// SandboxUID is the user (and group) every container runs as, the docker
// backend's sandbox.SandboxUID.
const SandboxUID int64 = 65532

// Sizes besides what a run computes. The io containers only copy streams.
const (
	slack         = 64 << 20 // per volume, for file system overhead and temporaries
	ioCPU         = "100m"
	ioMemory      = 64 << 20
	ioEphemeral   = 16 << 20
	ctlSize       = 1 << 20 // the ready marker
	secretsSize   = 1 << 20 // the HMAC key
	canaryTimeout = 3 * time.Minute
)

// pinnedRef is an image a kubelet can pull by content: name@sha256:<digest>.
// A bare image ID (sha256:…, the docker backend's locally built scanners)
// names no registry location, so it is refused here.
var pinnedRef = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}$`)

// Pinned reports whether ref is name@sha256:<digest>.
func Pinned(ref string) bool { return pinnedRef.MatchString(ref) }

// input sizes what goes into a Pod (sandboxio.Plan of the scan directory).
type input struct {
	names      []string // relative to the scan directory: src, secrets/hmac, rules/<file>
	bytes      int64
	entries    int
	srcDisk    int64 // space src/ takes (4 KiB blocks)
	rulesBytes int64
}

// outCaps are the files a tool may hand back from /out and the largest size
// of each: its SARIF (sarif.MaxFileBytes, what sarif.Load reads) and its
// artifacts. Nothing else leaves the Pod.
func outCaps(spec sandbox.ToolSpec) map[string]int64 {
	caps := map[string]int64{spec.SarifFile(): sarif.MaxFileBytes}
	for _, a := range spec.Artifacts {
		caps[a.File] = a.MaxBytes
	}
	return caps
}

func sumCaps(caps map[string]int64) int64 {
	var n int64
	for _, c := range caps {
		n += c
	}
	return n
}

// dockerBytes parses a docker size ("512m", "2g", "1536m"; b, k, m, g are
// powers of 1024). Kubernetes reads "512m" as 0.512 bytes, so ToolSpec's
// sizes are converted, never passed through.
func dockerBytes(s string) (int64, error) {
	if s == "" {
		return 0, errors.New("empty size")
	}
	unit := int64(1)
	num := s
	switch s[len(s)-1] {
	case 'b', 'B':
		num = s[:len(s)-1]
	case 'k', 'K':
		unit, num = 1<<10, s[:len(s)-1]
	case 'm', 'M':
		unit, num = 1<<20, s[:len(s)-1]
	case 'g', 'G':
		unit, num = 1<<30, s[:len(s)-1]
	}
	n, err := strconv.ParseInt(num, 10, 64)
	if err != nil || n <= 0 || n > math.MaxInt64/unit {
		return 0, fmt.Errorf("bad size %q", s)
	}
	return n * unit, nil
}

func bytesQ(n int64) resource.Quantity { return *resource.NewQuantity(n, resource.BinarySI) }

func ptr[T any](v T) *T { return &v }

// containerSecurity is every container's security context: non-root
// 65532, read-only root file system, no capabilities, no privilege
// escalation, the runtime's default seccomp profile. With the Pod's
// settings this passes the "restricted" Pod Security Standard.
func containerSecurity() *corev1.SecurityContext {
	return &corev1.SecurityContext{
		RunAsNonRoot:             ptr(true),
		RunAsUser:                ptr(SandboxUID),
		RunAsGroup:               ptr(SandboxUID),
		ReadOnlyRootFilesystem:   ptr(true),
		AllowPrivilegeEscalation: ptr(false),
		Privileged:               ptr(false),
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}
}

func emptyDir(size int64, memory bool) corev1.VolumeSource {
	ed := &corev1.EmptyDirVolumeSource{SizeLimit: ptr(bytesQ(size))}
	if memory {
		ed.Medium = corev1.StorageMediumMemory
	}
	return corev1.VolumeSource{EmptyDir: ed}
}

func ioResources(ephemeral int64) corev1.ResourceRequirements {
	l := corev1.ResourceList{
		corev1.ResourceCPU:              resource.MustParse(ioCPU),
		corev1.ResourceMemory:           bytesQ(ioMemory),
		corev1.ResourceEphemeralStorage: bytesQ(ephemeral),
	}
	return corev1.ResourceRequirements{Requests: l, Limits: l}
}

// podShell is what every Pod of the worker shares (scanner and canary):
// gVisor's RuntimeClass, no service account token, no service links, no
// host namespaces, no DNS (a nameserver nothing listens on: scanners are
// offline, and a query would carry data out wherever a NetworkPolicy lets
// DNS through), never restarted, and a deadline.
func podShell(cfg Config, name string, labels map[string]string, deadline time.Duration) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: cfg.Namespace, Labels: labels},
		Spec: corev1.PodSpec{
			RestartPolicy:                 corev1.RestartPolicyNever,
			ActiveDeadlineSeconds:         ptr(int64(math.Ceil(deadline.Seconds()))),
			TerminationGracePeriodSeconds: ptr(int64(1)),
			AutomountServiceAccountToken:  ptr(false),
			EnableServiceLinks:            ptr(false),
			HostNetwork:                   false,
			HostPID:                       false,
			HostIPC:                       false,
			ShareProcessNamespace:         ptr(false),
			DNSPolicy:                     corev1.DNSNone,
			DNSConfig:                     &corev1.PodDNSConfig{Nameservers: []string{"127.0.0.1"}},
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot:   ptr(true),
				RunAsUser:      ptr(SandboxUID),
				RunAsGroup:     ptr(SandboxUID),
				FSGroup:        ptr(SandboxUID),
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
		},
	}
	if cfg.RuntimeClass != "" {
		p.Spec.RuntimeClassName = ptr(cfg.RuntimeClass)
	}
	return p
}

// scannerPod builds the Pod of one tool run. Its design (see also Run):
//
//   - io-in, an init container (warden-sandbox-io wait), holds the input
//     volumes read-write and blocks until /ctl/ready exists. The worker
//     execs `warden-sandbox-io receive` into it, streaming src/,
//     secrets/hmac and rules/<file> as tar; receive writes /ctl/ready only
//     after a complete, accepted stream, and refuses a second one. Init
//     containers run to completion before any regular container starts, so
//     the scanner never sees partial input.
//   - scanner runs ToolSpec's command, as `docker run --entrypoint` would,
//     with src, secrets and rules read-only, /out writable, /tmp and the
//     mirror (scan.kube.mirror_pvc, subPath <tool>, read-only) at /data.
//   - io-out (warden-sandbox-io hold) has /out read-only and never exits on
//     its own: it is a regular container, not a native sidecar, because the
//     kubelet stops sidecars as soon as the last regular container exits,
//     which would race the worker's fetch. So the Pod can't finish before
//     the worker has exec'd `warden-sandbox-io send` into io-out and read
//     the results back; then the worker deletes it. If the worker is gone,
//     activeDeadlineSeconds ends the Pod, and the next worker start removes
//     it.
//
// Volumes are emptyDirs sized from what this run holds (none is shared with
// the worker or another Pod). Memory-backed: /tmp (as docker's tmpfs, so its
// pages count against the scanner's memory limit as ToolSpec assumes), the
// HMAC key and the ready marker. Kubernetes can't mount an emptyDir noexec,
// so /tmp is executable for every tool, not only Opengrep's (TmpExec);
// gVisor still confines whatever runs there.
func scannerPod(spec sandbox.ToolSpec, c sandbox.RunConfig, cfg Config, in input) (*corev1.Pod, error) {
	name := sandbox.ContainerName(c.ScanID, spec.Name)
	if errs := validation.IsDNS1123Label(name); len(errs) > 0 {
		return nil, fmt.Errorf("pod name %q: %s", name, strings.Join(errs, "; "))
	}
	if !Pinned(c.Image) {
		return nil, errors.New("scanner image must be pinned as name@sha256:<digest> for the kubernetes backend")
	}
	if len(spec.Command) == 0 {
		return nil, errors.New("tool has no command")
	}
	if spec.OrgRules != "" && spec.OrgRules != sandbox.OrgRulesFile(spec.Name) {
		return nil, fmt.Errorf("%s: unexpected org rules file %q", spec.Name, spec.OrgRules)
	}
	cpu, err := resource.ParseQuantity(spec.CPUs)
	if err != nil {
		return nil, fmt.Errorf("cpus %q: %w", spec.CPUs, err)
	}
	mem, err := dockerBytes(spec.Memory)
	if err != nil {
		return nil, fmt.Errorf("memory: %w", err)
	}
	tmp, err := dockerBytes(spec.TmpSize())
	if err != nil {
		return nil, fmt.Errorf("tmp: %w", err)
	}
	caps := outCaps(spec)
	outSize := sumCaps(caps) + slack
	srcSize := in.srcDisk + slack
	rulesSize := in.rulesBytes + 1<<20

	p := podShell(cfg, name, map[string]string{
		LabelScan: c.ScanID, LabelTool: spec.Name, LabelRole: "scanner", labelManagedBy: managedBy,
	}, spec.Timeout)

	vols := []corev1.Volume{
		{Name: "src", VolumeSource: emptyDir(srcSize, false)},
		{Name: "out", VolumeSource: emptyDir(outSize, false)},
		{Name: "tmp", VolumeSource: emptyDir(tmp, true)},
		{Name: "ctl", VolumeSource: emptyDir(ctlSize, true)},
	}
	if cfg.MirrorPVC != "" {
		vols = append(vols, corev1.Volume{Name: "data", VolumeSource: corev1.VolumeSource{
			PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: cfg.MirrorPVC, ReadOnly: true}}})
	} else {
		// Development without a mirror: an empty /data, so the tools that
		// need their data fail visibly (config refuses this in prod).
		vols = append(vols, corev1.Volume{Name: "data", VolumeSource: emptyDir(1<<20, false)})
	}
	inMounts := []corev1.VolumeMount{
		{Name: "src", MountPath: inDir + "/src"},
		{Name: "ctl", MountPath: "/ctl"},
	}
	scanMounts := []corev1.VolumeMount{
		{Name: "src", MountPath: "/src", ReadOnly: true},
		{Name: "out", MountPath: "/out"},
		{Name: "tmp", MountPath: "/tmp"},
		{Name: "data", MountPath: "/data", ReadOnly: true},
	}
	if cfg.MirrorPVC != "" {
		scanMounts[3].SubPath = spec.Name
	}
	if spec.NeedsHMACKey {
		vols = append(vols, corev1.Volume{Name: "secrets", VolumeSource: emptyDir(secretsSize, true)})
		inMounts = append(inMounts, corev1.VolumeMount{Name: "secrets", MountPath: inDir + "/secrets"})
		// The directory holds only hmac: /run/warden/hmac, as with docker.
		scanMounts = append(scanMounts, corev1.VolumeMount{Name: "secrets", MountPath: "/run/warden", ReadOnly: true})
	}
	if spec.OrgRules != "" {
		vols = append(vols, corev1.Volume{Name: "rules", VolumeSource: emptyDir(rulesSize, false)})
		inMounts = append(inMounts, corev1.VolumeMount{Name: "rules", MountPath: inDir + "/" + sandbox.RulesDir})
		// Only this tool's file is sent: /rules/<file>, as with docker.
		scanMounts = append(scanMounts, corev1.VolumeMount{Name: "rules", MountPath: "/rules", ReadOnly: true})
	}
	p.Spec.Volumes = vols

	// Gitleaks' output may echo what it found: its log never becomes the
	// termination message (stored in the Pod's status). Other tools' last
	// lines of stderr explain a failure, like the docker backend's tail.
	msgPolicy := corev1.TerminationMessageFallbackToLogsOnError
	if spec.NeedsHMACKey {
		msgPolicy = corev1.TerminationMessageReadFile
	}
	inEphemeral := in.srcDisk + in.rulesBytes + ioEphemeral
	// io-in exits, and so lets the scanner start, only once the input is
	// sealed and (with IsolationTargets) none of the targets connects from
	// this Pod: a NetworkPolicy may take effect only after a Pod started.
	inCmd := []string{ioBinary, "wait", "-marker", readyMarker}
	if len(cfg.IsolationTargets) > 0 {
		inCmd = append(inCmd, "-within", isolationWithin.String())
		for _, t := range cfg.IsolationTargets {
			inCmd = append(inCmd, "-connect", t)
		}
	}
	p.Spec.InitContainers = []corev1.Container{{
		Name: containerIn, Image: cfg.IOImage, ImagePullPolicy: corev1.PullIfNotPresent,
		Command:         inCmd,
		VolumeMounts:    inMounts,
		Resources:       ioResources(inEphemeral),
		SecurityContext: containerSecurity(),
		// Only warden-sandbox-io's own messages ("still reaches …").
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
	}}
	scanRes := corev1.ResourceList{
		corev1.ResourceCPU:    cpu,
		corev1.ResourceMemory: bytesQ(mem),
		// The kubelet compares the Pod's whole disk use (every emptyDir that
		// isn't memory, logs) with the sum of its regular containers'
		// limits, and src stays after io-in is done: the scanner's limit
		// carries src and /out.
		corev1.ResourceEphemeralStorage: bytesQ(srcSize + rulesSize + outSize),
	}
	p.Spec.Containers = []corev1.Container{
		{
			Name: containerScanner, Image: c.Image, ImagePullPolicy: corev1.PullIfNotPresent,
			Command:                  []string{spec.Command[0]},
			Args:                     slices.Clone(spec.Command[1:]),
			WorkingDir:               "/tmp",
			Env:                      []corev1.EnvVar{{Name: "HOME", Value: "/tmp"}},
			VolumeMounts:             scanMounts,
			Resources:                corev1.ResourceRequirements{Requests: scanRes, Limits: scanRes},
			SecurityContext:          containerSecurity(),
			TerminationMessagePolicy: msgPolicy,
		},
		{
			Name: containerOut, Image: cfg.IOImage, ImagePullPolicy: corev1.PullIfNotPresent,
			Command:                  []string{ioBinary, "hold"},
			VolumeMounts:             []corev1.VolumeMount{{Name: "out", MountPath: "/out", ReadOnly: true}},
			Resources:                ioResources(ioEphemeral),
			SecurityContext:          containerSecurity(),
			TerminationMessagePolicy: corev1.TerminationMessageReadFile,
		},
	}
	return p, nil
}

// receiveCmd is what the worker execs in io-in; the limits are exactly what
// it is about to send.
func receiveCmd(in input) []string {
	return []string{ioBinary, "receive", "-dir", inDir,
		"-max-bytes", strconv.FormatInt(in.bytes, 10), "-max-entries", strconv.Itoa(in.entries), "-seal", readyMarker}
}

// sendCmd is what the worker execs in io-out: the tool's files and caps.
func sendCmd(caps map[string]int64) []string {
	cmd := []string{ioBinary, "send", "-dir", "/out"}
	names := make([]string, 0, len(caps))
	for n := range caps {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		cmd = append(cmd, "-file", n+"="+strconv.FormatInt(caps[n], 10))
	}
	return cmd
}

// ProbeTargets are what a sandboxed Pod must not reach: the internet and the
// API server's service (KUBERNETES_SERVICE_HOST/PORT, which the kubelet sets
// even without service links). The cluster DNS is added when the worker
// knows it (Backend.ClusterDNS).
var ProbeTargets = []string{"1.1.1.1:443", "$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT"}

// isolationWithin: how long a new Pod's network may take to be cut off.
// canaryWithin is shorter: the canary only proves the policy works.
const (
	isolationWithin = time.Minute
	canaryWithin    = 30 * time.Second
)

// canaryPod is the preflight's probe: the io image with every scanner Pod's
// settings, trying TCP connections to targets in rounds until none connects
// (for at most canaryWithin), and checking it runs on gVisor.
func canaryPod(cfg Config, name string, targets []string) *corev1.Pod {
	p := podShell(cfg, name, map[string]string{LabelRole: "canary", labelManagedBy: managedBy}, canaryTimeout)
	args := []string{"probe", "-timeout", "3s", "-within", canaryWithin.String()}
	for _, t := range targets {
		args = append(args, "-connect", t)
	}
	args = append(args, "-report", corev1.TerminationMessagePathDefault)
	p.Spec.Containers = []corev1.Container{{
		Name: containerCanary, Image: cfg.IOImage, ImagePullPolicy: corev1.PullIfNotPresent,
		Command:                  []string{ioBinary},
		Args:                     args,
		Resources:                ioResources(ioEphemeral),
		SecurityContext:          containerSecurity(),
		TerminationMessagePolicy: corev1.TerminationMessageReadFile,
	}}
	return p
}
