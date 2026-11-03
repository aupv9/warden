#!/usr/bin/env bash
# A kind cluster for the kubernetes sandbox backend's integration test
# (CI job `kube`, build tag `kube`):
#
#   - kind with a pinned node image; gVisor (runsc and its containerd shim,
#     pinned and checksummed) installed in the node and registered with
#     containerd as the handler "runsc"; a RuntimeClass "gvisor" for it;
#   - a local registry (pinned) the node pulls from: the warden image
#     (scan.kube.io_image) and the Gitleaks and Opengrep images built from
#     scanners/ are pushed there and referenced by digest, like any image a
#     kubelet pulls; Trivy and Checkov come from scanners/images.lock.json;
#   - kube-network-policies (pinned), which enforces NetworkPolicy next to
#     kindnet. kindnet alone did not: on kind v0.33 a runc pod and a gVisor
#     pod both reached 1.1.1.1:443 and the API server under a default-deny
#     policy (found by the canary). The canary test proves enforcement;
#   - namespace warden-sandbox: Pod Security "restricted", a default-deny
#     NetworkPolicy, and the mirror as a read-only claim (a hostPath volume
#     of the node, mounted from $MIRROR);
#   - namespace warden-open: no policy, for the canary's negative test.
#
# It writes the test's settings to $OUT (default .cache/kind/env) and prints
# how to run the test. Needs docker, kubectl, curl, jq, and the mirror
# (scripts/sync-mirror.sh). Linux x86_64 (CI) and arm64 (e.g. Colima).
#
#   scripts/kind-gvisor.sh            create (or reuse) the cluster
#   scripts/kind-gvisor.sh cluster    only the cluster, the registry and
#                                     NetworkPolicy enforcement (no mirror,
#                                     namespaces or images): for the chart's
#                                     deploy/helm/test/cluster-smoke.sh
#   scripts/kind-gvisor.sh delete     delete the cluster and the registry
#
# KIND_RUNTIME=runc skips gVisor and maps the RuntimeClass "gvisor" to runc
# instead: for a laptop whose VM can't run runsc. The test then only checks
# the Pod lifecycle; it says so and the canary's gVisor check is expected to
# fail. Never use it to judge isolation.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLUSTER="${KIND_CLUSTER:-warden-kube}"
STATE="$ROOT/.cache/kind"
OUT="${OUT:-$STATE/env}"
MIRROR="${MIRROR:-$ROOT/.cache/mirror}"
KIND_RUNTIME="${KIND_RUNTIME:-runsc}"
MODE="${1:-}"
case "$MODE" in ""|cluster|delete) ;; *) echo "usage: $0 [cluster|delete]" >&2; exit 2 ;; esac
LOCK="$ROOT/scanners/images.lock.json"

# kind v0.33.0 (2026-08-26) and its Kubernetes 1.37.0 node image.
KIND_VERSION=v0.33.0
KIND_SHA256_LINUX_AMD64=aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d
KIND_SHA256_LINUX_ARM64=20022bee6cfcd5086cb7234d218e3454e6090022f2a8f55d1fa7fcf42c3867a2
KIND_SHA256_DARWIN_ARM64=0c8c7dbe5e23594a198b786c4bc13dacc101fa6196b0cb0b23a1ca44e61f4b4f
NODE_IMAGE=kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5
# gVisor release 20261005.0 (as in ci.yml), SHA-512 of the release tarballs.
GVISOR_RELEASE="${GVISOR_RELEASE:-20261005.0}"
GVISOR_SHA512_X86_64=79869ae9a589355a46d46fdac068d9a954e741741ffe77c64e38c56ea955498c1cb04e9bce44e1cce5155333e6b76bee72347c6661bb7c78fd2fe3aad198c8fe
GVISOR_SHA512_AARCH64=1bc58be6f881264ced1df8ff61db0205531abedcace005585ac5637c5c987831062b365f99f270ef0939849f130344b84e0f1a663294406f798b8f7c8cd326ac
# distribution (registry) 3.1.2, 2026-09-24.
REGISTRY_IMAGE=registry:3.1.2@sha256:d4032d4cc323c1731c707931ecada07a53076eac38e3b61ae57533f170f2c6c3
# kube-network-policies v1.1.1 (2026-07-28), the image its v1.1.2 install.yaml names.
NETPOL_IMAGE=registry.k8s.io/networking/kube-network-policies:v1.1.1@sha256:fa4a8a823da474dd6efa3bb80347b5ac58376370e1c179c5d3fa462e14b0e465
REGISTRY_NAME="${CLUSTER}-registry"
REGISTRY_PORT="${REGISTRY_PORT:-5001}"

die() { echo "kind-gvisor: $*" >&2; exit 1; }
for c in docker kubectl curl jq; do command -v "$c" >/dev/null || die "needs $c"; done

mkdir -p "$STATE/bin"
KIND="$(command -v kind || true)"
if [ -z "$KIND" ] || [ "$("$KIND" version | awk '{print $2}')" != "$KIND_VERSION" ]; then
  KIND="$STATE/bin/kind"
  if [ ! -x "$KIND" ]; then
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    arch="$(uname -m)"; case "$arch" in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; esac
    var="KIND_SHA256_$(tr '[:lower:]' '[:upper:]' <<<"${os}_${arch}")"
    sum="${!var:-}"
    [ -n "$sum" ] || die "no checksum pinned for kind on ${os}-${arch}; install kind $KIND_VERSION yourself"
    curl -fsSL --proto '=https' -o "$KIND.tmp" "https://github.com/kubernetes-sigs/kind/releases/download/${KIND_VERSION}/kind-${os}-${arch}"
    echo "${sum}  $KIND.tmp" | { sha256sum -c - 2>/dev/null || shasum -a 256 -c -; } >/dev/null || die "kind checksum mismatch"
    chmod +x "$KIND.tmp" && mv "$KIND.tmp" "$KIND"
  fi
fi

if [ "$MODE" = delete ]; then
  "$KIND" delete cluster --name "$CLUSTER" || true
  docker rm -f "$REGISTRY_NAME" >/dev/null 2>&1 || true
  exit 0
fi

[ "$MODE" = cluster ] || [ -d "$MIRROR/trivy" ] || die "mirror missing at $MIRROR; run scripts/sync-mirror.sh first"

echo "==> registry $REGISTRY_NAME on 127.0.0.1:$REGISTRY_PORT"
if [ "$(docker inspect -f '{{.State.Running}}' "$REGISTRY_NAME" 2>/dev/null || true)" != true ]; then
  docker rm -f "$REGISTRY_NAME" >/dev/null 2>&1 || true
  docker run -d --restart=always -p "127.0.0.1:${REGISTRY_PORT}:5000" --name "$REGISTRY_NAME" "$REGISTRY_IMAGE" >/dev/null
fi

echo "==> kind cluster $CLUSTER ($NODE_IMAGE)"
if ! "$KIND" get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  cfg="$(mktemp)"
  mounts=""
  [ "$MODE" = cluster ] || mounts="    extraMounts:
      - hostPath: ${MIRROR}
        containerPath: /warden-mirror
        readOnly: true"
  cat >"$cfg" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: ${NODE_IMAGE}
${mounts}
containerdConfigPatches:
  - |-
    [plugins."io.containerd.grpc.v1.cri".registry]
      config_path = "/etc/containerd/certs.d"
    [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc]
      runtime_type = "io.containerd.runsc.v1"
      [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc.options]
        TypeUrl = "io.containerd.runsc.v1.options"
        ConfigPath = "/etc/containerd/runsc.toml"
EOF
  "$KIND" create cluster --name "$CLUSTER" --config "$cfg" --wait 120s
  rm -f "$cfg"
fi
NODE="${CLUSTER}-control-plane"
CTX="kind-${CLUSTER}"
KUBECONFIG_FILE="$STATE/kubeconfig"
"$KIND" get kubeconfig --name "$CLUSTER" >"$KUBECONFIG_FILE"
chmod 600 "$KUBECONFIG_FILE"
k() { kubectl --kubeconfig "$KUBECONFIG_FILE" --context "$CTX" "$@"; }

# The node pulls localhost:$REGISTRY_PORT/... from the registry container.
docker network connect kind "$REGISTRY_NAME" >/dev/null 2>&1 || true
docker exec "$NODE" mkdir -p "/etc/containerd/certs.d/localhost:${REGISTRY_PORT}"
docker exec -i "$NODE" tee "/etc/containerd/certs.d/localhost:${REGISTRY_PORT}/hosts.toml" >/dev/null <<EOF
[host."http://${REGISTRY_NAME}:5000"]
EOF

handler=runsc
if [ "$KIND_RUNTIME" = runsc ]; then
  echo "==> gVisor $GVISOR_RELEASE in the node"
  arch="$(docker exec "$NODE" uname -m)"
  case "$arch" in
    x86_64) sum="$GVISOR_SHA512_X86_64" ;;
    aarch64) sum="$GVISOR_SHA512_AARCH64" ;;
    *) die "no gVisor checksum for $arch" ;;
  esac
  tarball="$STATE/gvisor-${GVISOR_RELEASE}-${arch}.tar.bz2"
  if [ ! -f "$tarball" ]; then
    curl -fsSL --proto '=https' -o "$tarball.tmp" "https://storage.googleapis.com/gvisor/releases/release/${GVISOR_RELEASE}/${arch}/gvisor.tar.bz2"
    mv "$tarball.tmp" "$tarball"
  fi
  echo "${sum}  $tarball" | { sha512sum -c - 2>/dev/null || shasum -a 512 -c -; } >/dev/null || { rm -f "$tarball"; die "gVisor checksum mismatch"; }
  bins="$STATE/gvisor-${GVISOR_RELEASE}-${arch}"
  mkdir -p "$bins"
  # runsc, the shim, and gvisor-bin/ (the Sentry and helpers runsc starts
  # beside itself; containerd's runsc refuses to start a sandbox without it).
  tar -xjf "$tarball" -C "$bins"
  for b in runsc containerd-shim-runsc-v1 gvisor-bin; do
    docker cp "$bins/$b" "$NODE:/usr/local/bin/$b"
  done
  docker exec "$NODE" chmod -R a+rX,go-w /usr/local/bin/runsc /usr/local/bin/containerd-shim-runsc-v1 /usr/local/bin/gvisor-bin
  # The kubelet uses the systemd cgroup driver in kind.
  docker exec -i "$NODE" tee /etc/containerd/runsc.toml >/dev/null <<'EOF'
[runsc_config]
  systemd-cgroup = "true"
EOF
  docker exec "$NODE" systemctl restart containerd
else
  echo "==> KIND_RUNTIME=$KIND_RUNTIME: no gVisor; RuntimeClass gvisor maps to runc (lifecycle tests only)"
  handler=runc
fi
k wait --for=condition=Ready node --all --timeout=120s >/dev/null

echo "==> kube-network-policies (NetworkPolicy enforcement)"
# From kube-network-policies' install.yaml at v1.1.2, image pinned by digest.
k apply -f - >/dev/null <<EOF
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata: {name: kube-network-policies}
rules:
  - apiGroups: [""]
    resources: [pods, namespaces]
    verbs: [list, watch]
  - apiGroups: [networking.k8s.io]
    resources: [networkpolicies]
    verbs: [list, watch]
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata: {name: kube-network-policies}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: kube-network-policies}
subjects:
  - {kind: ServiceAccount, name: kube-network-policies, namespace: kube-system}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: kube-network-policies, namespace: kube-system}
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: kube-network-policies
  namespace: kube-system
  labels: {app: kube-network-policies}
spec:
  selector:
    matchLabels: {app: kube-network-policies}
  template:
    metadata:
      labels: {app: kube-network-policies}
    spec:
      hostNetwork: true
      nodeSelector: {kubernetes.io/os: linux}
      tolerations: [{operator: Exists, effect: NoSchedule}]
      serviceAccountName: kube-network-policies
      containers:
        - name: kube-network-policies
          image: ${NETPOL_IMAGE}
          args: [/bin/netpol, "--hostname-override=\$(MY_NODE_NAME)", --v=2, --nfqueue-id=98]
          volumeMounts:
            - {name: nri-plugin, mountPath: /var/run/nri}
            - {name: netns, mountPath: /var/run/netns, mountPropagation: HostToContainer}
          resources:
            requests: {cpu: 100m, memory: 50Mi}
          securityContext:
            privileged: true
            capabilities: {add: [NET_ADMIN]}
          env:
            - name: MY_NODE_NAME
              valueFrom: {fieldRef: {fieldPath: spec.nodeName}}
      volumes:
        - {name: nri-plugin, hostPath: {path: /var/run/nri}}
        - {name: netns, hostPath: {path: /var/run/netns}}
EOF
k -n kube-system rollout status ds/kube-network-policies --timeout=180s >/dev/null

if [ "$MODE" = cluster ]; then
  echo "==> ready: KUBECONFIG=$KUBECONFIG_FILE, registry localhost:$REGISTRY_PORT (the node pulls from it), node $NODE"
  exit 0
fi

echo "==> RuntimeClass, namespaces, NetworkPolicy, mirror claim"
k apply -f - >/dev/null <<EOF
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata: {name: gvisor}
handler: ${handler}
---
apiVersion: v1
kind: Namespace
metadata:
  name: warden-sandbox
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: default-deny, namespace: warden-sandbox}
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
---
apiVersion: v1
kind: Namespace
metadata:
  name: warden-open
  labels:
    pod-security.kubernetes.io/enforce: restricted
---
apiVersion: v1
kind: PersistentVolume
metadata: {name: warden-mirror}
spec:
  capacity: {storage: 10Gi}
  accessModes: [ReadOnlyMany]
  persistentVolumeReclaimPolicy: Retain
  storageClassName: ""
  claimRef: {namespace: warden-sandbox, name: warden-mirror}
  hostPath: {path: /warden-mirror, type: Directory}
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata: {name: warden-mirror, namespace: warden-sandbox}
spec:
  accessModes: [ReadOnlyMany]
  storageClassName: ""
  volumeName: warden-mirror
  resources: {requests: {storage: 10Gi}}
EOF

echo "==> the worker's identity: the chart's Role, nothing cluster-wide"
for ns in warden-sandbox warden-open; do
  k apply -f - >/dev/null <<EOF
apiVersion: v1
kind: ServiceAccount
metadata: {name: warden-worker, namespace: ${ns}}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: warden-worker, namespace: ${ns}}
rules:
  - apiGroups: [""]
    resources: [pods]
    verbs: [create, get, list, watch, delete]
  - apiGroups: [""]
    resources: [pods/exec]
    verbs: [create]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: warden-worker, namespace: ${ns}}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: warden-worker}
subjects:
  - {kind: ServiceAccount, name: warden-worker, namespace: warden-sandbox}
EOF
done
WORKER_KUBECONFIG="$STATE/kubeconfig-worker"
server="$(k config view --raw --minify -o jsonpath='{.clusters[0].cluster.server}')"
k config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d >"$STATE/ca.crt"
token="$(k -n warden-sandbox create token warden-worker --duration=4h)"
rm -f "$WORKER_KUBECONFIG"
kw() { kubectl --kubeconfig "$WORKER_KUBECONFIG" "$@" >/dev/null; }
kw config set-cluster kind --server="$server" --certificate-authority="$STATE/ca.crt" --embed-certs=true
kw config set-credentials warden-worker --token="$token"
kw config set-context worker --cluster=kind --user=warden-worker
kw config use-context worker
chmod 600 "$WORKER_KUBECONFIG"

# push builds an image, pushes it to the local registry and prints name@digest.
push() { # name dockerfile
  local ref="localhost:${REGISTRY_PORT}/$1:kube-test"
  docker build -q -f "$2" -t "$ref" "$ROOT" >/dev/null
  docker push -q "$ref" >/dev/null
  docker image inspect -f '{{range .RepoDigests}}{{println .}}{{end}}' "$ref" | grep -m1 "^localhost:${REGISTRY_PORT}/$1@"
}
echo "==> images (warden, gitleaks, opengrep) into the local registry"
IO_IMAGE="$(push warden "$ROOT/backend/Dockerfile")"
GITLEAKS="$(push warden-gitleaks "$ROOT/scanners/gitleaks/Dockerfile")"
OPENGREP="$(push warden-opengrep "$ROOT/scanners/opengrep/Dockerfile")"
TRIVY="$(jq -er .trivy.upstream "$LOCK")"
CHECKOV="$(jq -er .checkov.upstream "$LOCK")"

mkdir -p "$(dirname "$OUT")"
cat >"$OUT" <<EOF
WARDEN_KUBE_TEST_KUBECONFIG=$WORKER_KUBECONFIG
WARDEN_KUBE_TEST_ADMIN_KUBECONFIG=$KUBECONFIG_FILE
WARDEN_KUBE_TEST_NAMESPACE=warden-sandbox
WARDEN_KUBE_TEST_OPEN_NAMESPACE=warden-open
WARDEN_KUBE_TEST_RUNTIME_CLASS=gvisor
WARDEN_KUBE_TEST_GVISOR=$([ "$handler" = runsc ] && echo 1 || echo 0)
WARDEN_KUBE_TEST_MIRROR_PVC=warden-mirror
WARDEN_KUBE_TEST_MIRROR_DIR=$MIRROR
WARDEN_KUBE_TEST_IO_IMAGE=$IO_IMAGE
WARDEN_KUBE_TEST_IMAGE_GITLEAKS=$GITLEAKS
WARDEN_KUBE_TEST_IMAGE_OPENGREP=$OPENGREP
WARDEN_KUBE_TEST_IMAGE_TRIVY=$TRIVY
WARDEN_KUBE_TEST_IMAGE_CHECKOV=$CHECKOV
EOF
echo "==> ready; settings in $OUT. Run the test with:"
echo "    set -a; . $OUT; set +a; go -C backend test -tags kube -count=1 -v ./internal/scan/sandbox/kube/"
