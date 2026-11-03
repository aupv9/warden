#!/usr/bin/env bash
# Static checks of deploy/helm/warden (CI job `helm`): helm lint --strict,
# renders that must fail (missing digests, unsafe settings), renders that must
# pass, kubeconform against the oldest and a current Kubernetes, and the
# security properties of every render (check-security.sh).
#
# Usage: deploy/helm/test/run.sh   (needs helm 3, kubeconform, yq v4, jq)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CHART="$HERE/../warden"
ROOT="$(cd "$HERE/../../.." && pwd)"
V="$HERE/values"
NS=warden
# The chart's kubeVersion floor and a current release.
K8S_VERSIONS="${K8S_VERSIONS:-1.29.0 1.36.0}"
# JSON schemas, pinned by commit (a commit ≥ 2 weeks old when pinned):
# Kubernetes' own, and the CRDs catalog for ServiceMonitor and HTTPRoute.
K8S_SCHEMAS="https://raw.githubusercontent.com/yannh/kubernetes-json-schema/817113f21a2643311cbc3e992bb44ffe1c416c54/{{.NormalizedKubernetesVersion}}-standalone-strict/{{.ResourceKind}}{{.KindSuffix}}.json"
CRD_SCHEMAS="https://raw.githubusercontent.com/datreeio/CRDs-catalog/63669a570e231d4f1f8396d229a1de512bcf0a34/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json"

out="$(mktemp -d)"; trap 'rm -rf "$out"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

echo "==> scanner image defaults match scanners/images.lock.json"
for t in trivy checkov; do
  want="$(jq -er ".$t.upstream" "$ROOT/scanners/images.lock.json")"
  got="$(yq -e ".scannerImages.$t" "$CHART/values.yaml")"
  [ "$want" = "$got" ] || fail "values.yaml scannerImages.$t is $got; the lock file pins $want"
done

echo "==> renders that must fail"
# must_fail NAME EXPECTED_MESSAGE helm-args...
must_fail() {
  local name="$1" want="$2"; shift 2
  local err
  if err="$(helm template t "$CHART" -n "$NS" "$@" 2>&1 >/dev/null)"; then
    fail "$name: rendered, but should have been refused"
  fi
  grep -qiF -- "$want" <<<"$err" || fail "$name: refused, but not with '$want':
$err"
  echo "    ok  $name"
}
R=(-f "$V/required.yaml")
must_fail "defaults alone" "image.digest is required"
must_fail "no existingSecret" "existingSecret is required" "${R[@]}" --set existingSecret=
must_fail "image by tag" "image/digest" "${R[@]}" --set image.digest=latest
must_fail "scanner image by tag" "scannerImages/trivy" "${R[@]}" --set scannerImages.trivy=docker.io/aquasec/trivy:0.75.0
must_fail "no gitleaks image" "scannerImages.gitleaks is required" "${R[@]}" --set scannerImages.gitleaks=
must_fail "mirror image by tag" "mirror/cronjob/image" "${R[@]}" --set mirror.cronjob.image=registry.example.com/warden/mirror:latest
must_fail "unknown value" "additional properties" "${R[@]}" --set api.hostNetwork=true
must_fail "http issuer" "oidc/issuer" "${R[@]}" --set oidc.issuer=http://sso.example.com/realms/warden
must_fail "public http storage" "storage/endpoint" "${R[@]}" --set storage.endpoint=http://s3.example.com
must_fail "root user" "podSecurityContext/runAsUser" "${R[@]}" --set podSecurityContext.runAsUser=0
must_fail "RWO mirror" "mirror/storage/accessMode" "${R[@]}" --set mirror.storage.accessMode=ReadWriteOnce
must_fail "ingress and gateway" "choose one" "${R[@]}" --set ingress.enabled=true --set ingress.tls.secretName=tls --set gateway.enabled=true --set "gateway.parentRefs[0].name=gw"
must_fail "ingress without TLS" "ingress.tls" "${R[@]}" --set ingress.enabled=true
must_fail "sandbox is the release namespace" "must differ" "${R[@]}" --set sandbox.namespace="$NS"
must_fail "short grace period" "at least scan.timeout + 10m" "${R[@]}" --set worker.terminationGracePeriodSeconds=1800
must_fail "secret in extraEnv" "looks like a secret" "${R[@]}" --set extraEnv.WARDEN_SCAN__HMAC_KEY=x
must_fail "managed key in extraEnv" "set by the chart" "${R[@]}" --set extraEnv.WARDEN_APP__ENV=local
must_fail "dev webhook hosts in extraEnv" "can't be set" "${R[@]}" --set extraEnv.WARDEN_WEBHOOK__ALLOW_HOSTS=localhost
must_fail "bad timeout" "scan/timeout" "${R[@]}" --set-string scan.timeout=30
must_fail "nfs without server" "mirror.storage.nfs" "${R[@]}" --set mirror.storage.type=nfs
# The worker's way to the API server: its addresses, never "anywhere on 443".
# helm template can't look them up, so without cidrs the render must fail.
must_fail "kubeAPI egress without addresses" "kubeAPI.cidrs is required" "${R[@]}" --set networkPolicy.egress.kubeAPI.cidrs=null
must_fail "kubeAPI egress to a network" "wider than /16" "${R[@]}" --set 'networkPolicy.egress.kubeAPI.cidrs={172.18.0.2/32,10.0.0.0/8}'
must_fail "kubeAPI egress to any IPv6" "wider than /48" "${R[@]}" --set 'networkPolicy.egress.kubeAPI.cidrs={::/0}'
must_fail "kubeAPI egress by name" "kubeAPI/cidrs" "${R[@]}" --set 'networkPolicy.egress.kubeAPI.cidrs={kubernetes.default.svc}'
must_fail "kubeAPI egress as peers (pre-0.7)" "replaced by networkPolicy.egress.kubeAPI.cidrs" "${R[@]}" \
  --set 'networkPolicy.egress.kubeAPI.to[0].ipBlock.cidr=0.0.0.0/0'
# An existing sandbox namespace whose Pod Security label can't be read here.
must_fail "unchecked sandbox namespace" "sandbox.podSecurityConfirmed=true" "${R[@]}" --set sandbox.createNamespace=false

echo "==> renders that must pass (helm lint --strict, helm template)"
# must_pass NAME helm-args...
must_pass() {
  local name="$1"; shift
  helm lint --strict "$CHART" -n "$NS" "$@" >"$out/lint.log" 2>&1 || { cat "$out/lint.log" >&2; fail "helm lint: $name"; }
  helm template t "$CHART" -n "$NS" "$@" >"$out/$name.yaml"
  echo "    ok  $name"
}
must_pass required "${R[@]}"
must_pass prod-example -f "$CHART/values-prod-example.yaml"
must_pass variants "${R[@]}" -f "$V/variants.yaml"
must_pass ingress-secret "${R[@]}" --set ingress.enabled=true --set ingress.tls.secretName=warden-tls \
  --set mirror.cronjob.enabled=false --set networkPolicy.enabled=false --set networkPolicy.egress.kubeAPI.cidrs=null
rm -f "$out/lint.log"

echo "==> kubeconform"
for k in $K8S_VERSIONS; do
  kubeconform -strict -summary -kubernetes-version "$k" \
    -schema-location "$K8S_SCHEMAS" -schema-location "$CRD_SCHEMAS" "$out"/*.yaml
done

echo "==> security properties"
"$HERE/check-security.sh" "$out"/*.yaml

echo "==> the security check catches a weakened render"
mkdir "$out/mutants"
# mutant NAME YQ_EXPRESSION: the required render, changed by one expression,
# must fail check-security.sh.
mutant() {
  local name="$1" expr="$2" f="$out/mutants/$1.yaml"
  yq "$expr" "$out/required.yaml" >"$f"
  # Compared as data: yq also reformats what it doesn't change.
  [ "$(yq -o=json -I=0 "$f")" = "$(yq -o=json -I=0 "$out/required.yaml")" ] && fail "mutant $name: the expression changed nothing"
  if "$HERE/check-security.sh" "$f" >/dev/null 2>&1; then
    fail "mutant $name: check-security.sh accepted it"
  fi
  echo "    ok  $name"
}
W='select(.kind == "Deployment" and .metadata.labels."app.kubernetes.io/component" == "worker")'
A='select(.kind == "Deployment" and .metadata.labels."app.kubernetes.io/component" == "api")'
mutant writable-rootfs "($A | .spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem) = false"
mutant escalation "($W | .spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation) = true"
mutant capability "($W | .spec.template.spec.containers[0].securityContext.capabilities.add) = [\"NET_RAW\"]"
mutant root-pod "($A | .spec.template.spec.securityContext.runAsUser) = 0"
mutant no-seccomp "del($A | .spec.template.spec.securityContext.seccompProfile)"
mutant docker-socket "($W | .spec.template.spec.volumes) += [{\"name\": \"sock\", \"hostPath\": {\"path\": \"/var/run/docker.sock\"}}]"
mutant host-network "($W | .spec.template.spec.hostNetwork) = true"
mutant api-token "($A | .spec.template.spec.automountServiceAccountToken) = true"
mutant tag-image "(select(.kind == \"CronJob\") | .spec.jobTemplate.spec.template.spec.initContainers[0].image) = \"aquasec/trivy:latest\""
mutant secret-in-env "($A | .spec.template.spec.containers[0].env) += [{\"name\": \"WARDEN_SECRETS__KEY\", \"value\": \"k1:abc\"}]"
mutant owner-dsn-in-api "($A | .spec.template.spec.volumes[0].secret.items) += [{\"key\": \"WARDEN_MIGRATE__DSN\", \"path\": \"m\"}]"
mutant role-secrets "(select(.kind == \"Role\") | .rules) += [{\"apiGroups\": [\"\"], \"resources\": [\"secrets\"], \"verbs\": [\"get\"]}]"
mutant role-attach "(select(.kind == \"Role\") | .rules[1].resources) = [\"pods/exec\", \"pods/attach\"]"
mutant clusterrole-list "(select(.kind == \"ClusterRole\") | .rules[0].verbs) = [\"get\", \"list\"]"
mutant clusterrole-any "del(select(.kind == \"ClusterRole\") | .rules[0].resourceNames)"
mutant sandbox-egress "(select(.kind == \"NetworkPolicy\" and .metadata.namespace == \"warden-sandbox\") | .spec.egress) = [{}]"
mutant sandbox-ingress-only "(select(.kind == \"NetworkPolicy\" and .metadata.namespace == \"warden-sandbox\") | .spec.policyTypes) = [\"Ingress\"]"
mutant sandbox-psa "(select(.kind == \"Namespace\") | .metadata.labels.\"pod-security.kubernetes.io/enforce\") = \"baseline\""
mutant no-quota "del(select(.kind == \"ResourceQuota\"))"
mutant docker-backend "(($W | .spec.template.spec.containers[0].env[] | select(.name == \"WARDEN_SCAN__SANDBOX_BACKEND\")).value) = \"docker\""
WNP='select(.kind == "NetworkPolicy" and .metadata.name == "t-warden-worker")'
KAPI="$WNP | .spec.egress[] | select(.ports | any_c(.port == 6443))"
mutant kubeapi-open "del($KAPI | .to)"
mutant kubeapi-split "($KAPI | .to) = [{\"ipBlock\": {\"cidr\": \"0.0.0.0/1\"}}, {\"ipBlock\": {\"cidr\": \"128.0.0.0/1\"}}]"
mutant kubeapi-any-pod "($KAPI | .to) += [{\"namespaceSelector\": {}}]"
mutant webhook-private "del($WNP | .spec.egress[].to[]?.ipBlock.except)"
mutant webhook-partial-except "($WNP | .spec.egress[].to[]?.ipBlock.except[]? | select(. == \"10.0.0.0/8\")) = \"10.0.0.0/9\""
mutant webhook-ipv6-private "($WNP | .spec.egress[].to[]?.ipBlock.except) |= ((. // []) - [\"fe80::/10\"])"
mutant https-rules-open "($WNP | .spec.egress[] | select((.ports | length) == 1 and .ports[0].port == 443) | .to) = []"
mutant public-service "(select(.kind == \"Service\" and .metadata.name == \"t-warden-api\") | .spec.type) = \"LoadBalancer\""
{ cat "$out/required.yaml"; printf -- '---\napiVersion: v1\nkind: Secret\nmetadata: {name: leaked}\nstringData: {k: v}\n'; } >"$out/mutants/secret.yaml"
"$HERE/check-security.sh" "$out/mutants/secret.yaml" >/dev/null 2>&1 && fail "mutant secret: check-security.sh accepted it"
echo "    ok  secret"
echo "all chart checks passed"
