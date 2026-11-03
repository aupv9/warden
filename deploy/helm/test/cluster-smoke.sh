#!/usr/bin/env bash
# Installs the chart into a throwaway cluster (kind, k3d) and checks what only
# a cluster can: the migrate hook, the api becoming ready under Pod Security
# "restricted" in its namespace, the NetworkPolicies (needs a CNI that
# enforces them), including the worker's egress to the API server's addresses
# as the chart looks them up, the Pod Security check of an existing sandbox
# namespace and Pod Security in it, and the worker's RBAC. The worker is not
# started (replicas 0): it needs gVisor nodes; probe Pods with its labels
# stand in for it on the network. With MIRROR_IMAGE it also runs the mirror
# CronJob once (Trivy DB, rules, feeds: about 1 GB on the node). CI (job
# helm-cluster) runs it on kind with kube-network-policies
# (scripts/kind-gvisor.sh cluster); KEEP=1 leaves everything in place.
#
# Usage: IMAGE_REPO=… IMAGE_DIGEST=sha256:… [MIRROR_IMAGE=repo@sha256:…] \
#        deploy/helm/test/cluster-smoke.sh
# Uses the current kubectl context; needs helm, kubectl, openssl, jq. The
# probe image needs busybox nc (-z, -l -p).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CHART="$HERE/../warden"
ROOT="$(cd "$HERE/../../.." && pwd)"
: "${IMAGE_REPO:?set IMAGE_REPO}" "${IMAGE_DIGEST:?set IMAGE_DIGEST}"
NS=warden-smoke
SANDBOX=warden-smoke-sandbox
DB=warden-smoke-db
CLIENT=warden-smoke-client     # stands in for the ingress controller's namespace
OTHER=warden-smoke-other       # any other namespace
REL=t
API="$REL-warden-api"
# Same pin as docker-compose.yml.
PG_IMAGE="postgres:16-alpine@sha256:f4610795587492cd4fb887c2dc3de301b813278bb6f616992061141b5f15ac36"
# Only for the in-cluster probes below (busybox wget); never part of the chart.
PROBE_IMAGE="${PROBE_IMAGE:-$PG_IMAGE}"
pw() { openssl rand -hex 16; }
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "    ok  $*"; }

cleanup() {
  [ "${KEEP:-0}" = 1 ] && return
  helm uninstall "$REL" -n "$NS" --wait >/dev/null 2>&1 || true
  kubectl delete ns "$NS" "$SANDBOX" "$DB" "$CLIENT" "$OTHER" --wait=false >/dev/null 2>&1 || true
  kubectl delete pv warden-smoke-mirror --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT
debug() {
  kubectl -n "$NS" get pods,jobs -o wide >&2 || true
  kubectl -n "$NS" logs -l app.kubernetes.io/instance=$REL --all-containers --tail=30 >&2 || true
  kubectl -n "$NS" get events --sort-by=.lastTimestamp | tail -20 >&2 || true
}

restricted='{"runAsNonRoot":true,"runAsUser":65532,"seccompProfile":{"type":"RuntimeDefault"}}'
csc='{"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"]}}'
# probe NS NAME CMD...: runs CMD in a restricted Pod in NS; returns its exit
# status. CMD starts after 5 seconds: some CNIs (k3s's kube-router) apply
# NetworkPolicy to a new Pod only after it has started. PROBE_LABELS gives the
# Pod labels (so the policies of a component select it).
probe() {
  local ns="$1" name="$2"; shift 2
  local overrides labels=()
  [ -n "${PROBE_LABELS:-}" ] && labels=(--labels="$PROBE_LABELS")
  overrides="$(printf '{"spec":{"securityContext":%s,"automountServiceAccountToken":false,"containers":[{"name":"p","image":"%s","command":%s,"securityContext":%s}]}}' \
    "$restricted" "$PROBE_IMAGE" "$(printf '%s\n' sh -c 'sleep 5; exec "$0" "$@"' "$@" | jq -R . | jq -s -c .)" "$csc")"
  kubectl -n "$ns" run "$name" --image="$PROBE_IMAGE" --restart=Never ${labels[@]+"${labels[@]}"} --overrides="$overrides" >/dev/null
  kubectl -n "$ns" wait --for=jsonpath='{.status.phase}'=Succeeded "pod/$name" --timeout=60s >/dev/null 2>&1 \
    || { kubectl -n "$ns" delete pod "$name" --wait=false >/dev/null 2>&1; return 1; }
  kubectl -n "$ns" delete pod "$name" --wait=false >/dev/null 2>&1
}

echo "==> namespaces"
for n in "$NS" "$SANDBOX" "$DB" "$CLIENT" "$OTHER"; do kubectl create ns "$n" >/dev/null; done
# The release namespace runs restricted too: every Pod of the chart complies.
kubectl label ns "$NS" pod-security.kubernetes.io/enforce=restricted >/dev/null
# The sandbox namespace exists beforehand (sandbox.createNamespace=false); it
# gets its Pod Security label only after the chart has refused it without.

echo "==> Postgres"
PG_OWNER="$(pw)"; PG_APP="$(pw)"
kubectl -n "$DB" create configmap init-roles --from-file=10-roles.sh="$ROOT/deploy/postgres/init-roles.sh" >/dev/null
kubectl -n "$DB" create secret generic pg --from-literal=owner="$PG_OWNER" --from-literal=app="$PG_APP" >/dev/null
kubectl -n "$DB" apply -f - >/dev/null <<EOF
apiVersion: apps/v1
kind: Deployment
metadata: { name: postgres }
spec:
  selector: { matchLabels: { app: postgres } }
  template:
    metadata: { labels: { app: postgres } }
    spec:
      containers:
        - name: postgres
          image: $PG_IMAGE
          env:
            - { name: POSTGRES_DB, value: warden }
            - { name: POSTGRES_USER, value: warden_owner }
            - { name: POSTGRES_PASSWORD, valueFrom: { secretKeyRef: { name: pg, key: owner } } }
            - { name: WARDEN_APP_PASSWORD, valueFrom: { secretKeyRef: { name: pg, key: app } } }
          ports: [{ containerPort: 5432 }]
          readinessProbe: { exec: { command: [pg_isready, -U, warden_owner, -d, warden, -h, 127.0.0.1] }, periodSeconds: 2 }
          volumeMounts: [{ name: init, mountPath: /docker-entrypoint-initdb.d }]
      volumes: [{ name: init, configMap: { name: init-roles } }]
---
apiVersion: v1
kind: Service
metadata: { name: postgres }
spec: { selector: { app: postgres }, ports: [{ port: 5432 }] }
EOF
kubectl -n "$DB" rollout status deploy/postgres --timeout=180s >/dev/null
ok "postgres ready"

echo "==> Secret and mirror claims (created by the operator, not the chart)"
dsn() { printf 'postgres://%s:%s@postgres.%s.svc:5432/warden?sslmode=disable' "$1" "$2" "$DB"; }
kubectl -n "$NS" create secret generic warden-secrets \
  --from-literal=WARDEN_DATABASE__DSN="$(dsn warden_app "$PG_APP")" \
  --from-literal=WARDEN_MIGRATE__DSN="$(dsn warden_owner "$PG_OWNER")" \
  --from-literal=WARDEN_STORAGE__ACCESS_KEY="$(pw)" \
  --from-literal=WARDEN_STORAGE__SECRET_KEY="$(pw)" \
  --from-literal=WARDEN_SECRETS__KEY="k1:$(openssl rand -base64 32)" \
  --from-literal=WARDEN_SCAN__HMAC_KEY="$(openssl rand -hex 32)" >/dev/null
# A test cluster has no shared storage: two independent claims stand in for
# the two claims on one volume (the worker isn't started). MIRROR_HOSTPATH
# (a directory on the node, writable by 65532) backs the one the mirror job
# writes, for a test node short of disk.
if [ -n "${MIRROR_HOSTPATH:-}" ]; then
  kubectl apply -f - >/dev/null <<EOF
apiVersion: v1
kind: PersistentVolume
metadata: { name: warden-smoke-mirror }
spec:
  capacity: { storage: 2Gi }
  accessModes: [ReadWriteOnce]
  storageClassName: ""
  persistentVolumeReclaimPolicy: Delete
  claimRef: { namespace: $NS, name: $REL-warden-mirror }
  hostPath: { path: $MIRROR_HOSTPATH, type: Directory }
EOF
fi
for c in "$NS/$REL-warden-mirror" "$SANDBOX/warden-mirror"; do
  class=""
  [ -n "${MIRROR_HOSTPATH:-}" ] && [ "${c%%/*}" = "$NS" ] && class='storageClassName: "", volumeName: warden-smoke-mirror,'
  kubectl -n "${c%%/*}" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: PersistentVolumeClaim
metadata: { name: ${c##*/} }
spec: { $class accessModes: [ReadWriteOnce], resources: { requests: { storage: 2Gi } } }
EOF
done

args=(
  -f "$HERE/values/required.yaml"
  --set image.repository="$IMAGE_REPO" --set image.digest="$IMAGE_DIGEST"
  --set image.pullPolicy=IfNotPresent
  --set api.replicas=1 --set worker.replicas=0
  --set sandbox.namespace="$SANDBOX" --set sandbox.createNamespace=false
  --set storage.endpoint=http://s3:8333
  --set "networkPolicy.ingressFrom[0].namespaceSelector.matchLabels.kubernetes\.io/metadata\.name=$CLIENT"
  # The API server's addresses: looked up by the chart, as on a real install.
  --set networkPolicy.egress.kubeAPI.cidrs=null
  --set sandbox.resourceQuota.hard.pods=10
)
if [ -n "${MIRROR_IMAGE:-}" ]; then
  args+=(--set mirror.cronjob.image="$MIRROR_IMAGE" --set-string mirror.cronjob.feeds.osvEcosystems=Go)
else
  args+=(--set mirror.cronjob.enabled=false)
fi

echo "==> the Pod Security label of an existing sandbox namespace is checked"
# refused WANT helm-args...: a server-side dry run must fail with WANT.
refused() {
  local want="$1" err; shift
  if err="$(helm install "$REL" "$CHART" -n "$NS" "${args[@]}" "$@" --dry-run=server 2>&1)"; then
    fail "helm accepted: $*"
  fi
  grep -qF -- "$want" <<<"$err" || fail "helm refused, but not with '$want': $err"
}
refused "must carry the label pod-security.kubernetes.io/enforce=restricted"
# Read from the cluster, the label wins over the operator's word.
refused "must carry the label pod-security.kubernetes.io/enforce=restricted" --set sandbox.podSecurityConfirmed=true
refused "sandbox.podSecurityConfirmed=true" --set sandbox.namespace=warden-smoke-missing
ok "an unlabelled or unreadable sandbox namespace is refused"
kubectl label ns "$SANDBOX" pod-security.kubernetes.io/enforce=restricted >/dev/null

echo "==> helm install (migrate hook, then the api must become ready)"
helm install "$REL" "$CHART" -n "$NS" "${args[@]}" --wait --timeout 5m >/dev/null || { debug; fail "helm install"; }
ok "migrations applied, api ready"

echo "==> network policies"
probe "$CLIENT" c1 wget -q -T 5 -O /dev/null "http://$API.$NS.svc/readyz" || { debug; fail "the ingress namespace can't reach the API"; }
ok "the ingress namespace reaches the API"
probe "$OTHER" o1 wget -q -T 5 -O /dev/null "http://$API.$NS.svc/readyz" && fail "another namespace reached the API"
ok "other namespaces don't"
probe "$CLIENT" c2 wget -q -T 5 -O /dev/null "http://$REL-warden-api-metrics.$NS.svc:9090/metrics" && fail "the ingress namespace reached /metrics"
ok "the admin port isn't reachable from the ingress namespace"
probe "$SANDBOX" s1 wget -q -T 5 -O /dev/null "http://$API.$NS.svc/readyz" && fail "a sandbox Pod reached the API"
probe "$SANDBOX" s2 nslookup kubernetes.default.svc.cluster.local && fail "a sandbox Pod resolved DNS"
ok "sandbox Pods reach nothing (not the API, not DNS)"

echo "==> the worker's egress: the API server, no other address on its ports"
# The chart read the endpoints of default/kubernetes and its ClusterIP.
want="$( { kubectl get endpointslice -n default kubernetes -o json | jq -r '.endpoints[].addresses[]'
           kubectl get service -n default kubernetes -o json | jq -r '.spec.clusterIPs[]'; } \
         | awk '{ print $0 (index($0, ":") ? "/128" : "/32") }' | sort -u)"
got="$(kubectl -n "$NS" get networkpolicy "$REL-warden-worker" -o json \
  | jq -r '.spec.egress[] | select(any(.ports[]; .port == 6443)) | .to[].ipBlock.cidr' | sort -u)"
[ -n "$want" ] && [ "$want" = "$got" ] || fail "worker policy allows [$(tr '\n' ' ' <<<"$got")] for the API server; the cluster has [$(tr '\n' ' ' <<<"$want")]"
ok "the worker's kubeAPI rule is the API server's addresses: $(tr '\n' ' ' <<<"$got")"
# Something else listening on 6443 at a private address: another namespace
# reaches it, the worker must not (it could before 0.7: kubeAPI was "anywhere").
kubectl -n "$OTHER" run listener --image="$PROBE_IMAGE" --restart=Never --overrides="$(printf '{"spec":{"securityContext":%s,"automountServiceAccountToken":false,"containers":[{"name":"listener","image":"%s","command":["sh","-c","while true; do nc -l -p 6443 </dev/null >/dev/null 2>&1; done"],"securityContext":%s}]}}' "$restricted" "$PROBE_IMAGE" "$csc")" >/dev/null
kubectl -n "$OTHER" wait --for=condition=Ready pod/listener --timeout=120s >/dev/null || { debug; fail "listener Pod"; }
LISTENER="$(kubectl -n "$OTHER" get pod listener -o jsonpath='{.status.podIP}')"
probe "$OTHER" o2 nc -z -w 5 "$LISTENER" 6443 || fail "the listener on $LISTENER:6443 isn't reachable even without a policy"
W_LABELS="app.kubernetes.io/name=warden,app.kubernetes.io/instance=$REL,app.kubernetes.io/component=worker"
PROBE_LABELS="$W_LABELS" probe "$NS" w1 nc -z -w 5 kubernetes.default.svc.cluster.local 443 || { debug; fail "the worker can't reach the API server"; }
ok "the worker reaches the API server"
PROBE_LABELS="$W_LABELS" probe "$NS" w2 nc -z -w 5 "$LISTENER" 6443 && fail "the worker reached $LISTENER:6443"
ok "the worker doesn't reach another address on 6443"
kubectl -n "$OTHER" delete pod listener --wait=false >/dev/null 2>&1 || true

echo "==> Pod Security in the sandbox namespace"
if kubectl -n "$SANDBOX" run root --image="$PROBE_IMAGE" --restart=Never --dry-run=server \
     --overrides='{"spec":{"containers":[{"name":"root","image":"'"$PROBE_IMAGE"'","securityContext":{"privileged":true}}]}}' >/dev/null 2>&1; then
  fail "the sandbox namespace admitted a privileged Pod"
fi
ok "a privileged Pod is refused"

echo "==> the worker's rights"
SA="system:serviceaccount:$NS:$REL-warden-worker"
can() { kubectl auth can-i "$@" --as="$SA" 2>/dev/null; }
for want in "create pods -n $SANDBOX" "delete pods -n $SANDBOX" "watch pods -n $SANDBOX" "create pods --subresource=exec -n $SANDBOX" \
            "get runtimeclasses.node.k8s.io/gvisor"; do
  # shellcheck disable=SC2086
  [ "$(can $want)" = yes ] || fail "worker can't: $want"
done
for deny in "get secrets -n $SANDBOX" "create pods -n $NS" "get secrets -n $NS" "create pods --subresource=attach -n $SANDBOX" "get pods --subresource=exec -n $SANDBOX" \
            "get pods --subresource=log -n $SANDBOX" "update pods -n $SANDBOX" "update pods --subresource=ephemeralcontainers -n $SANDBOX" \
            "list runtimeclasses.node.k8s.io" "get runtimeclasses.node.k8s.io/runc" "create pods -n default" \
            "create persistentvolumeclaims -n $SANDBOX" "list nodes"; do
  # shellcheck disable=SC2086
  [ "$(can $deny)" = no ] || fail "worker can: $deny"
done
ok "pods and pods/exec in the sandbox namespace, get on one RuntimeClass, nothing else"

if [ -n "${MIRROR_IMAGE:-}" ]; then
  echo "==> mirror CronJob (Trivy DB without Docker, then sync-mirror.sh)"
  kubectl -n "$NS" create job --from="cronjob/$REL-warden-mirror" mirror-once >/dev/null
  kubectl -n "$NS" wait --for=condition=complete job/mirror-once --timeout=15m >/dev/null || {
    kubectl -n "$NS" logs job/mirror-once --all-containers --tail=40 >&2; fail "mirror job"; }
  kubectl -n "$NS" logs job/mirror-once -c sync | grep -qF "Trivy DB: skipped (WARDEN_MIRROR_SKIP_TRIVY=1)" || fail "mirror: sync-mirror.sh didn't leave the Trivy DB to the init container"
  kubectl -n "$NS" logs job/mirror-once -c sync | grep -q "mirror ready at /mirror" || fail "mirror: sync-mirror.sh didn't finish"
  ok "mirror filled"
fi
echo "cluster smoke passed"
