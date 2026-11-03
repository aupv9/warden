{{/* Names */}}
{{- define "warden.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "warden.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 40 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 40 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 40 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Cluster-scoped objects (PersistentVolumes, ClusterRole) carry the release namespace. */}}
{{- define "warden.clusterName" -}}
{{- printf "%s-%s" .Release.Namespace (include "warden.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "warden.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: {{ include "warden.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: warden
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/* (dict "ctx" $ "component" "api") */}}
{{- define "warden.componentLabels" -}}
{{ include "warden.labels" .ctx }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "warden.selectorLabels" -}}
app.kubernetes.io/name: {{ include "warden.name" .ctx }}
app.kubernetes.io/instance: {{ .ctx.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/* Images: only digest-pinned references. */}}
{{- define "warden.image" -}}
{{- $d := required "image.digest is required: the Warden image is pinned by digest (sha256:…, from the release notes)" .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository $d -}}
{{- end -}}

{{- define "warden.ioImage" -}}
{{- default (include "warden.image" .) .Values.sandbox.ioImage -}}
{{- end -}}

{{- define "warden.scannerImage" -}}
{{- $ref := index .ctx.Values.scannerImages .tool -}}
{{- required (printf "scannerImages.%s is required: a registry reference pinned by @sha256 digest" .tool) $ref -}}
{{- end -}}

{{- define "warden.trivyMirrorImage" -}}
{{- default (include "warden.scannerImage" (dict "ctx" . "tool" "trivy")) .Values.mirror.cronjob.trivyImage -}}
{{- end -}}

{{/* Mirror claims: one in the release namespace, one in the sandbox namespace. */}}
{{- define "warden.mirrorClaim" -}}
{{- default (printf "%s-mirror" (include "warden.fullname" .)) .Values.mirror.storage.claimName -}}
{{- end -}}

{{- define "warden.sandboxMirrorClaim" -}}
{{- required "mirror.storage.sandboxClaimName is required" .Values.mirror.storage.sandboxClaimName -}}
{{- end -}}

{{/* Pod and container security contexts. The values may add to the pod's;
     these fields always win. */}}
{{- define "warden.podSecurityContext" -}}
{{- $sc := deepCopy .Values.podSecurityContext -}}
{{- $_ := set $sc "runAsNonRoot" true -}}
{{- $_ := set $sc "seccompProfile" (dict "type" "RuntimeDefault") -}}
{{- toYaml $sc -}}
{{- end -}}

{{- define "warden.containerSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
runAsNonRoot: true
privileged: false
capabilities:
  drop: [ALL]
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{/* Secret keys each component mounts from existingSecret. */}}
{{- define "warden.secretKeys" -}}
{{- $v := .ctx.Values -}}
{{- $keys := list -}}
{{- if eq .component "migrate" -}}
{{- $keys = list "WARDEN_MIGRATE__DSN" -}}
{{- else -}}
{{- $keys = list "WARDEN_DATABASE__DSN" "WARDEN_STORAGE__ACCESS_KEY" "WARDEN_STORAGE__SECRET_KEY" "WARDEN_SECRETS__KEY" -}}
{{- if eq .component "worker" -}}{{- $keys = append $keys "WARDEN_SCAN__HMAC_KEY" -}}{{- end -}}
{{- if $v.existingSecretOptional.secretsOldKeys -}}{{- $keys = append $keys "WARDEN_SECRETS__OLD_KEYS" -}}{{- end -}}
{{- if $v.existingSecretOptional.smtpPassword -}}{{- $keys = append $keys "WARDEN_SMTP__PASSWORD" -}}{{- end -}}
{{- end -}}
{{- toJson $keys -}}
{{- end -}}

{{/* env entries pointing each secret setting at its file. */}}
{{- define "warden.secretEnv" -}}
{{- range (include "warden.secretKeys" . | fromJsonArray) }}
- name: {{ . }}
  value: file:/run/secrets/warden/{{ . }}
{{- end }}
{{- end -}}

{{- define "warden.secretVolume" -}}
- name: secrets
  secret:
    secretName: {{ required "existingSecret is required: the name of a Secret holding Warden's keys (see values.yaml)" .ctx.Values.existingSecret }}
    defaultMode: 0440
    items:
{{- range (include "warden.secretKeys" . | fromJsonArray) }}
      - key: {{ . }}
        path: {{ . }}
{{- end }}
{{- end -}}

{{/* Settings shared by api and worker, as a YAML map of env vars. */}}
{{- define "warden.commonEnv" -}}
{{- $v := .Values -}}
WARDEN_APP__ENV: prod
WARDEN_LOG__FORMAT: json
WARDEN_LOG__LEVEL: {{ $v.logLevel | quote }}
WARDEN_ADMIN__ADDR: {{ printf "0.0.0.0:%d" (int $v.admin.port) | quote }}
WARDEN_OIDC__ISSUER: {{ required "oidc.issuer is required (https)" $v.oidc.issuer | quote }}
WARDEN_OIDC__AUDIENCE: {{ $v.oidc.audience | quote }}
WARDEN_OIDC__ALGORITHMS: {{ join "," $v.oidc.algorithms | quote }}
WARDEN_OIDC__REQUIRE_MFA_ROLES: {{ join "," $v.oidc.requireMfaRoles | quote }}
{{- with $v.oidc.jwksUrl }}
WARDEN_OIDC__JWKS_URL: {{ . | quote }}
{{- end }}
{{- with $v.oidc.mfaAmr }}
WARDEN_OIDC__MFA_AMR: {{ join "," . | quote }}
{{- end }}
{{- with $v.oidc.mfaAcr }}
WARDEN_OIDC__MFA_ACR: {{ join "," . | quote }}
{{- end }}
{{- with $v.oidc.consoleUrl }}
WARDEN_OIDC__CONSOLE_URL: {{ . | quote }}
{{- end }}
WARDEN_WEB__OIDC_CLIENT_ID: {{ $v.web.oidcClientId | quote }}
WARDEN_WEB__OIDC_SCOPE: {{ $v.web.oidcScope | quote }}
{{- with $v.web.oidcAudience }}
WARDEN_WEB__OIDC_AUDIENCE: {{ . | quote }}
{{- end }}
WARDEN_STORAGE__ENDPOINT: {{ required "storage.endpoint is required" $v.storage.endpoint | quote }}
{{- with $v.storage.publicEndpoint }}
WARDEN_STORAGE__PUBLIC_ENDPOINT: {{ . | quote }}
{{- end }}
WARDEN_STORAGE__BUCKET: {{ $v.storage.bucket | quote }}
WARDEN_SMTP__HOST: {{ required "smtp.host is required" $v.smtp.host | quote }}
WARDEN_SMTP__PORT: {{ $v.smtp.port | quote }}
WARDEN_SMTP__FROM: {{ required "smtp.from is required" $v.smtp.from | quote }}
{{- with $v.smtp.username }}
WARDEN_SMTP__USERNAME: {{ . | quote }}
{{- end }}
WARDEN_SMTP__IMPLICIT_TLS: {{ $v.smtp.implicitTls | quote }}
WARDEN_SMTP__DIGEST_HOUR: {{ $v.smtp.digestHour | quote }}
WARDEN_SMTP__PUBLIC_BASE_URL: {{ printf "https://%s" (required "domain is required" $v.domain) | quote }}
WARDEN_NOTIFY__READ_RETENTION: {{ $v.notify.readRetention | quote }}
WARDEN_NOTIFY__UNREAD_RETENTION: {{ $v.notify.unreadRetention | quote }}
WARDEN_WEBHOOK__FAILURE_LIMIT: {{ $v.webhook.failureLimit | quote }}
WARDEN_SCAN__TIMEOUT: {{ $v.scan.timeout | quote }}
{{- end -}}

{{/* Variables only the worker gets (also refused in extraEnv). */}}
{{- define "warden.workerEnv" -}}
WARDEN_SCAN__SANDBOX_BACKEND: kubernetes
WARDEN_SCAN__SANDBOX_RUNTIME: runsc
WARDEN_SCAN__KUBE__NAMESPACE: {{ .Values.sandbox.namespace | quote }}
WARDEN_SCAN__KUBE__RUNTIME_CLASS: {{ .Values.sandbox.runtimeClassName | quote }}
WARDEN_SCAN__KUBE__MIRROR_PVC: {{ include "warden.sandboxMirrorClaim" . | quote }}
WARDEN_SCAN__KUBE__IO_IMAGE: {{ include "warden.ioImage" . | quote }}
WARDEN_SCAN__SCRATCH_DIR: /scratch
WARDEN_SCAN__MIRROR_DIR: /mirror
WARDEN_SCAN__SLOTS_PER_NODE: {{ .Values.scan.slotsPerNode | quote }}
{{- range $t := list "gitleaks" "opengrep" "trivy" "checkov" }}
WARDEN_SCAN__IMAGES__{{ upper $t }}: {{ include "warden.scannerImage" (dict "ctx" $ "tool" $t) | quote }}
{{- end }}
{{- end -}}

{{/* extraEnv, after refusing what the chart manages or what is secret. */}}
{{- define "warden.extraEnv" -}}
{{- $managed := merge (include "warden.commonEnv" . | fromYaml) (include "warden.workerEnv" . | fromYaml) -}}
{{- range $k, $val := .Values.extraEnv -}}
{{- if hasKey $managed $k -}}
{{- fail (printf "extraEnv.%s: set by the chart; use its value instead" $k) -}}
{{- end -}}
{{- if regexMatch "(DSN|PASSWORD|SECRET|_KEY|_KEYS|TOKEN)" $k -}}
{{- fail (printf "extraEnv.%s looks like a secret: put it in existingSecret, never in values" $k) -}}
{{- end -}}
{{- if regexMatch "^WARDEN_(SERVER__|SCAN__KUBE__|SCAN__SANDBOX_|WEBHOOK__ALLOW_HOSTS|CONFIG_FILE|DATABASE__)" $k -}}
{{- fail (printf "extraEnv.%s can't be set through this chart" $k) -}}
{{- end -}}
{{- end -}}
{{- with .Values.extraEnv }}
{{- toYaml . }}
{{- end }}
{{- end -}}

{{/* Seconds in a Go duration made of h, m and s parts ("30m", "1h30m"). */}}
{{- define "warden.seconds" -}}
{{- $s := toString . -}}
{{- if or (eq $s "") (not (regexMatch "^([0-9]+h)?([0-9]+m)?([0-9]+s)?$" $s)) -}}
{{- fail (printf "scan.timeout %q: use hours, minutes and seconds, like 30m or 1h30m" $s) -}}
{{- end -}}
{{- $total := 0 -}}
{{- range $part := regexFindAll "[0-9]+[hms]" $s -1 -}}
{{- $n := regexFind "[0-9]+" $part | atoi -}}
{{- $u := regexFind "[hms]" $part -}}
{{- if eq $u "h" -}}{{- $total = add $total (mul $n 3600) -}}
{{- else if eq $u "m" -}}{{- $total = add $total (mul $n 60) -}}
{{- else -}}{{- $total = add $total $n -}}{{- end -}}
{{- end -}}
{{- $total -}}
{{- end -}}

{{- define "warden.workerGraceSeconds" -}}
{{- $timeout := include "warden.seconds" .Values.scan.timeout | int -}}
{{- $g := .Values.worker.terminationGracePeriodSeconds -}}
{{- if kindIs "invalid" $g -}}
{{- add $timeout 900 -}}
{{- else if lt (int $g) (add $timeout 600 | int) -}}
{{- fail (printf "worker.terminationGracePeriodSeconds (%d) must be at least scan.timeout + 10m (%d): a stopping worker finishes its scans, which always delete their source" (int $g) (add $timeout 600)) -}}
{{- else -}}
{{- int $g -}}
{{- end -}}
{{- end -}}

{{/* A NetworkPolicy egress rule from {to, ports}. */}}
{{- define "warden.egressRule" -}}
- ports:
{{- toYaml .ports | nindent 4 }}
{{- with .to }}
  to:
{{- toYaml . | nindent 4 }}
{{- end }}
{{- end -}}

{{/* The addresses the worker may reach the Kubernetes API server on, as a
     JSON list of CIDRs: networkPolicy.egress.kubeAPI.cidrs, or else what the
     cluster says at install/upgrade (the endpoints of default/kubernetes, and
     its ClusterIP for CNIs that match before Service translation). Never an
     open rule: with neither, the render fails. */}}
{{- define "warden.kubeAPICIDRs" -}}
{{- $k := .Values.networkPolicy.egress.kubeAPI -}}
{{- if $k.to -}}
{{- fail "networkPolicy.egress.kubeAPI.to was replaced by networkPolicy.egress.kubeAPI.cidrs: list the API server's addresses (e.g. [172.18.0.2/32])" -}}
{{- end -}}
{{- $cidrs := list -}}
{{- if $k.cidrs -}}
{{- $cidrs = $k.cidrs -}}
{{- else -}}
{{- $slice := lookup "discovery.k8s.io/v1" "EndpointSlice" "default" "kubernetes" -}}
{{- range $ep := dig "endpoints" (list) $slice -}}
{{- range $a := $ep.addresses | default list -}}
{{- $cidrs = append $cidrs (printf "%s/%s" $a (ternary "128" "32" (contains ":" $a))) -}}
{{- end -}}
{{- end -}}
{{- if not $cidrs -}}
{{- $eps := lookup "v1" "Endpoints" "default" "kubernetes" -}}
{{- range $sub := dig "subsets" (list) $eps -}}
{{- range $a := $sub.addresses | default list -}}
{{- $cidrs = append $cidrs (printf "%s/%s" $a.ip (ternary "128" "32" (contains ":" $a.ip))) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if not $cidrs -}}
{{- fail "networkPolicy.egress.kubeAPI.cidrs is required: the Kubernetes API server's addresses, e.g. [172.18.0.2/32] (kubectl get endpointslice -n default kubernetes -o jsonpath='{.endpoints[*].addresses[*]}'). helm install/upgrade reads them from the cluster when it can; helm template and offline renders can't. The worker's egress is never left open to every address" -}}
{{- end -}}
{{- $svc := lookup "v1" "Service" "default" "kubernetes" -}}
{{- range $ip := dig "spec" "clusterIPs" (list) $svc -}}
{{- $cidrs = append $cidrs (printf "%s/%s" $ip (ternary "128" "32" (contains ":" $ip))) -}}
{{- end -}}
{{- end -}}
{{- range $c := $cidrs -}}
{{- $bits := regexReplaceAll "^.*/" $c "" | int -}}
{{- $min := ternary 48 16 (contains ":" $c) -}}
{{- if or (not (contains "/" $c)) (lt $bits $min) -}}
{{- fail (printf "networkPolicy.egress.kubeAPI.cidrs: %s is wider than /%d: list the API server's addresses, not a network" $c $min) -}}
{{- end -}}
{{- end -}}
{{- $cidrs | uniq | toJson -}}
{{- end -}}

{{- define "warden.kubeAPIRule" -}}
{{- $to := list -}}
{{- range (include "warden.kubeAPICIDRs" . | fromJsonArray) -}}
{{- $to = append $to (dict "ipBlock" (dict "cidr" .)) -}}
{{- end -}}
{{- include "warden.egressRule" (dict "to" $to "ports" .Values.networkPolicy.egress.kubeAPI.ports) -}}
{{- end -}}

{{/* Checks that need more than the schema. */}}
{{- define "warden.validate" -}}
{{- $v := .Values -}}
{{- $_ := include "warden.image" . -}}
{{- $_ := required "existingSecret is required: the name of a Secret holding Warden's keys (see values.yaml)" $v.existingSecret -}}
{{- if and $v.ingress.enabled $v.gateway.enabled -}}
{{- fail "ingress.enabled and gateway.enabled: choose one" -}}
{{- end -}}
{{- if $v.ingress.enabled -}}
{{- $t := $v.ingress.tls -}}
{{- $n := 0 -}}
{{- if $t.secretName }}{{ $n = add1 $n }}{{ end -}}
{{- if $t.certManager.clusterIssuer }}{{ $n = add1 $n }}{{ end -}}
{{- if $t.certManager.issuer }}{{ $n = add1 $n }}{{ end -}}
{{- if ne (int $n) 1 -}}
{{- fail "ingress.tls: set exactly one of secretName, certManager.clusterIssuer or certManager.issuer" -}}
{{- end -}}
{{- end -}}
{{- if and $v.gateway.enabled (not $v.gateway.parentRefs) -}}
{{- fail "gateway.parentRefs: name the Gateway (and listener) the HTTPRoute attaches to" -}}
{{- end -}}
{{- if eq $v.sandbox.namespace .Release.Namespace -}}
{{- fail "sandbox.namespace must differ from the release namespace: everything in it is denied all network access" -}}
{{- end -}}
{{- if and $v.serviceMonitor.enabled (not $v.metrics.enabled) -}}
{{- fail "serviceMonitor.enabled needs metrics.enabled" -}}
{{- end -}}
{{- $st := $v.mirror.storage -}}
{{- if and (eq $st.type "nfs") (or (not $st.nfs.server) (not $st.nfs.path)) -}}
{{- fail "mirror.storage.type=nfs needs mirror.storage.nfs.server and .path" -}}
{{- end -}}
{{- if and (eq $st.type "csi") (or (not $st.csi.driver) (not $st.csi.volumeHandle)) -}}
{{- fail "mirror.storage.type=csi needs mirror.storage.csi.driver and .volumeHandle" -}}
{{- end -}}
{{- if and $v.mirror.cronjob.enabled (not $v.mirror.cronjob.image) -}}
{{- fail "mirror.cronjob.image is required: an image with bash, curl, jq and Warden's scripts under /opt/warden, pinned by digest (deploy/helm/mirror/Dockerfile)" -}}
{{- end -}}
{{- /* A sandbox namespace the chart doesn't create: read it and check its
     Pod Security label. Fail closed when it can't be read (helm template,
     offline GitOps renders, not created yet), unless the operator states
     that they own the label (sandbox.podSecurityConfirmed). */ -}}
{{- if not $v.sandbox.createNamespace -}}
{{- $ns := lookup "v1" "Namespace" "" $v.sandbox.namespace -}}
{{- if $ns -}}
{{- $labels := dig "metadata" "labels" (dict) $ns -}}
{{- if ne (index $labels "pod-security.kubernetes.io/enforce" | default "") "restricted" -}}
{{- fail (printf "namespace %s must carry the label pod-security.kubernetes.io/enforce=restricted" $v.sandbox.namespace) -}}
{{- end -}}
{{- else if not $v.sandbox.podSecurityConfirmed -}}
{{- fail (printf "sandbox.createNamespace=false, and namespace %s can't be read to check its Pod Security label (helm template, an offline render, or it doesn't exist yet). Label it pod-security.kubernetes.io/enforce=restricted and set sandbox.podSecurityConfirmed=true: you then own that label" $v.sandbox.namespace) -}}
{{- end -}}
{{- end -}}
{{- if $v.networkPolicy.enabled -}}
{{- $_ := include "warden.kubeAPICIDRs" . -}}
{{- end -}}
{{- $_ := include "warden.workerGraceSeconds" . -}}
{{- $_ := include "warden.extraEnv" . -}}
{{- end -}}
