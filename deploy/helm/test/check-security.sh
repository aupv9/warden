#!/usr/bin/env bash
# Fails when a rendered chart breaks one of its security properties
# (security.jq: Pod security fields, digests, RBAC, the sandbox namespace,
# secrets, routing). Usage: check-security.sh RENDERED.yaml...
# Needs yq (mikefarah, v4) and jq.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
status=0
for f in "$@"; do
  problems="$(yq -o=json -I=0 'select(. != null)' "$f" | jq -s -r -f "$HERE/security.jq")"
  pods="$(yq -o=json -I=0 'select(. != null)' "$f" | jq -s '[.[] | select(.kind | IN("Deployment","Job","CronJob","StatefulSet","DaemonSet","Pod"))] | length')"
  if [ -n "$problems" ]; then
    echo "FAIL $f:" >&2
    sed 's/^/  /' <<<"$problems" >&2
    status=1
  elif [ "$pods" -eq 0 ]; then
    echo "FAIL $f: no workloads rendered" >&2
    status=1
  else
    echo "ok   $f ($pods workloads)"
  fi
done
exit "$status"
