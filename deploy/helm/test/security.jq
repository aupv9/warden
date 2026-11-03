# Security properties of a rendered chart. Input: every rendered object, as
# one JSON array (yq -o=json | jq -s). Output: one line per violation; none
# means the render passes. Run by check-security.sh.

def podspec:
  if .kind == "CronJob" then .spec.jobTemplate.spec.template.spec
  elif (.kind | IN("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job")) then .spec.template.spec
  elif .kind == "Pod" then .spec
  else null end;
def id: "\(.kind)/\(.metadata.name)";
def component: .metadata.labels["app.kubernetes.io/component"];
def is_worker: .kind == "Deployment" and component == "worker";
def env($k): [.[] | select(is_worker) | podspec.containers[0].env[]? | select(.name == $k) | .value][0];

. as $all
| ($all | env("WARDEN_SCAN__KUBE__NAMESPACE")) as $sandbox
| ($all | env("WARDEN_SCAN__KUBE__RUNTIME_CLASS")) as $rc
| ($all | env("WARDEN_SCAN__SANDBOX_BACKEND")) as $backend
| (
    # The chart never renders secret values.
    ($all[] | select(.kind == "Secret") | "\(id): the chart must not render Secrets"),

    # The worker runs scanners as Pods: no Docker, gVisor RuntimeClass.
    (if $sandbox == null then "worker: WARDEN_SCAN__KUBE__NAMESPACE not set" else empty end),
    (if $backend != "kubernetes" then "worker: sandbox backend is \($backend), want kubernetes" else empty end),
    (if ($rc // "") == "" then "worker: no RuntimeClass" else empty end),

    # Every Pod template.
    ($all[] | select(podspec != null) | . as $o | podspec as $p | id as $n |
      (if $p.securityContext.runAsNonRoot != true then "\($n): pod securityContext.runAsNonRoot is not true" else empty end),
      (if (($p.securityContext.runAsUser // 0) == 0) then "\($n): pod runAsUser is unset or 0" else empty end),
      (if $p.securityContext.seccompProfile.type != "RuntimeDefault" then "\($n): pod seccompProfile is not RuntimeDefault" else empty end),
      (if ($p.hostNetwork or $p.hostPID or $p.hostIPC) then "\($n): uses a host namespace" else empty end),
      (if any($p.volumes[]?; has("hostPath")) then "\($n): mounts a hostPath" else empty end),
      (if $p.enableServiceLinks != false then "\($n): enableServiceLinks is not false" else empty end),
      (if ($o | is_worker) then
         (if $p.automountServiceAccountToken != true then "\($n): the worker needs its token" else empty end)
       elif $p.automountServiceAccountToken != false then "\($n): automountServiceAccountToken is not false"
       else empty end),
      (($p.containers + ($p.initContainers // []))[] | . as $c | "\($n) container \($c.name)" as $cn | $c.securityContext as $s |
        (if $s.allowPrivilegeEscalation != false then "\($cn): allowPrivilegeEscalation is not false" else empty end),
        (if $s.readOnlyRootFilesystem != true then "\($cn): readOnlyRootFilesystem is not true" else empty end),
        (if $s.runAsNonRoot != true then "\($cn): runAsNonRoot is not true" else empty end),
        (if (($s.capabilities.drop // []) | index("ALL")) == null then "\($cn): capabilities not dropped" else empty end),
        (if (($s.capabilities.add // []) | length) > 0 then "\($cn): adds capabilities" else empty end),
        (if $s.privileged == true then "\($cn): privileged" else empty end),
        (if $s.seccompProfile.type != "RuntimeDefault" then "\($cn): seccompProfile is not RuntimeDefault" else empty end),
        (if ($c.image | test("@sha256:[0-9a-f]{64}$") | not) then "\($cn): image \($c.image) is not pinned by digest" else empty end),
        (if $c.resources.limits.memory == null then "\($cn): no memory limit" else empty end),
        (if any($c.ports[]?; .hostPort != null) then "\($cn): hostPort" else empty end),
        (if any($c.volumeMounts[]?; (.mountPath | test("docker.sock|containerd.sock|crio.sock"))) then "\($cn): mounts a container runtime socket" else empty end),
        (if any($c.env[]?; (.name | test("DSN|PASSWORD|SECRET|_KEY")) and has("value") and ((.value | startswith("file:/run/secrets/")) | not)) then "\($cn): a secret setting is not read from a file" else empty end)
      )
    ),

    # Only the migrate Job sees the owner DSN; only the worker the HMAC key.
    ($all[] | select(podspec != null) | . as $o | podspec as $p | id as $n |
      [$p.volumes[]?.secret.items[]?.key] as $keys |
      (if ($o | component) != "migrate" and ($keys | index("WARDEN_MIGRATE__DSN")) then "\($n): mounts WARDEN_MIGRATE__DSN" else empty end),
      (if ($o | is_worker | not) and ($keys | index("WARDEN_SCAN__HMAC_KEY")) then "\($n): mounts WARDEN_SCAN__HMAC_KEY" else empty end)
    ),

    # No secret in a ConfigMap's keys.
    ($all[] | select(.kind == "ConfigMap") | id as $n | (.data // {}) | keys[] | select(test("DSN|PASSWORD|SECRET|_KEY")) | "\($n): \(.) in a ConfigMap"),

    # RBAC: exactly the worker's Role in the sandbox namespace, and at most a
    # get on the one RuntimeClass.
    ($all[] | select(.kind == "Role") | id as $n |
      (if .metadata.namespace != $sandbox then "\($n): Role outside the sandbox namespace (\(.metadata.namespace))" else empty end),
      (if .rules != [
          {apiGroups: [""], resources: ["pods"], verbs: ["create", "get", "list", "watch", "delete"]},
          {apiGroups: [""], resources: ["pods/exec"], verbs: ["create"]}
        ] then "\($n): rules differ from pods create/get/list/watch/delete + pods/exec create: \(.rules)" else empty end)
    ),
    ($all[] | select(.kind == "ClusterRole") | id as $n |
      if .rules != [{apiGroups: ["node.k8s.io"], resources: ["runtimeclasses"], resourceNames: [$rc], verbs: ["get"]}]
      then "\($n): a ClusterRole may only get the RuntimeClass \($rc): \(.rules)" else empty end
    ),
    ($all[] | select(.kind == "RoleBinding" or .kind == "ClusterRoleBinding") | id as $n |
      (if (.subjects | length) != 1 or .subjects[0].kind != "ServiceAccount" or (.subjects[0].name | endswith("-worker") | not)
       then "\($n): binds something other than the worker's ServiceAccount" else empty end),
      (if (.roleRef.kind == "ClusterRole" and .kind == "RoleBinding") then "\($n): binds a ClusterRole" else empty end)
    ),
    (if ([$all[] | select(.kind == "Role")] | length) != 1 then "want exactly one Role" else empty end),

    # The sandbox namespace: restricted Pod Security, deny-all both ways.
    ($all[] | select(.kind == "Namespace" and .metadata.name == $sandbox) | id as $n |
      if .metadata.labels["pod-security.kubernetes.io/enforce"] != "restricted"
      then "\($n): Pod Security enforce is not restricted" else empty end
    ),
    (if ([$all[] | select(.kind == "NetworkPolicy" and .metadata.namespace == $sandbox
          and .spec.podSelector == {} and (.spec.policyTypes | sort) == ["Egress", "Ingress"]
          and (.spec.ingress == null) and (.spec.egress == null))] | length) != 1
     then "sandbox namespace \($sandbox): no deny-all NetworkPolicy (ingress and egress)" else empty end),
    ($all[] | select(.kind == "NetworkPolicy" and .metadata.namespace == $sandbox and ((.spec.ingress != null) or (.spec.egress != null)))
      | "\(id): allows traffic in the sandbox namespace"),
    ($all[] | select(.kind != "Namespace" and .metadata.namespace == $sandbox and podspec != null)
      | "\(id): the chart runs a workload in the sandbox namespace"),
    (if ([$all[] | select(.kind == "ResourceQuota" and .metadata.namespace == $sandbox)] | length) != 1 then "sandbox namespace: no ResourceQuota" else empty end),
    (if ([$all[] | select(.kind == "LimitRange" and .metadata.namespace == $sandbox)] | length) != 1 then "sandbox namespace: no LimitRange" else empty end),

    # The admin port (/metrics) is never routed from outside.
    ($all[] | select(.kind == "Ingress") | id as $n | .spec.rules[].http.paths[].backend.service |
      if .port.name != "http" or (.name | endswith("-api") | not) then "\($n): routes to \(.name):\(.port)" else empty end),
    ($all[] | select(.kind == "HTTPRoute") | id as $n | .spec.rules[].backendRefs[] |
      if (.name | endswith("-api") | not) then "\($n): routes to \(.name)" else empty end),
    ($all[] | select(.kind == "Service" and (.spec.type // "ClusterIP") != "ClusterIP") | "\(id): Service type \(.spec.type)")
  )
