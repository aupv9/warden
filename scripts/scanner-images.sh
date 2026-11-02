#!/usr/bin/env bash
# Prepares the scanner images on the host that runs warden-worker and prints
# the WARDEN_SCAN__IMAGES__* settings for them:
#   scripts/scanner-images.sh [ENV_FILE]   (with ENV_FILE, also writes them there)
#
# Gitleaks and Opengrep are built from scanners/ (pinned bases, checksummed
# downloads) and referenced by their content-addressed image ID; Trivy and
# Checkov are pulled at the digests in scanners/images.lock.json. Run it again
# after upgrading Warden: the lock file may have moved.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOCK="$ROOT/scanners/images.lock.json"
ENV_FILE="${1:-}"
command -v jq >/dev/null || { echo "scanner-images: needs jq" >&2; exit 1; }

for t in gitleaks opengrep; do
  echo "==> building $t" >&2
  docker build -q -f "$ROOT/scanners/$t/Dockerfile" -t "warden/$t:local" "$ROOT" >/dev/null
  printf -v "img_$t" "%s" "$(docker image inspect -f "{{.Id}}" "warden/$t:local")"
done
for t in trivy checkov; do
  ref="$(jq -er ".$t.upstream" "$LOCK")"
  [[ "$ref" == *@sha256:* ]] || { echo "scanner-images: $t is not pinned by digest in $LOCK" >&2; exit 1; }
  echo "==> pulling $ref" >&2
  docker pull -q "$ref" >/dev/null
  printf -v "img_$t" "%s" "$ref"
done

for t in gitleaks opengrep trivy checkov; do
  var="img_$t"; img="${!var}"
  key="WARDEN_SCAN__IMAGES__$(tr '[:lower:]' '[:upper:]' <<<"$t")"
  echo "$key=${img}"
  if [ -n "$ENV_FILE" ]; then
    if grep -q "^$key=" "$ENV_FILE"; then
      tmp="$(mktemp "$ENV_FILE.XXXXXX")"
      # Image references hold no '|' (digests and repository names), so it is a safe delimiter.
      sed "s|^$key=.*|$key=${img}|" "$ENV_FILE" > "$tmp" && chmod 600 "$tmp" && mv -f "$tmp" "$ENV_FILE"
    else
      echo "$key=${img}" >> "$ENV_FILE"
    fi
  fi
done
[ -z "$ENV_FILE" ] || echo "updated $ENV_FILE" >&2
