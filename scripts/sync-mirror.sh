#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MIRROR="${MIRROR:-$ROOT/.cache/mirror}"
LOCK="$ROOT/scanners/images.lock.json"
lock() { jq -er ".$1" "$LOCK"; }

TRIVY_IMAGE="$(lock trivy.upstream)"
RULES_REPO="$(lock opengrep.rules.repo)"
RULES_COMMIT="$(lock opengrep.rules.commit)"

mkdir -p "$MIRROR"/{trivy,opengrep,gitleaks,checkov}

echo "==> Trivy DB"
# Run as the caller so the DB isn't root-owned on Linux (the chmod below would fail).
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$MIRROR/trivy:/data" "$TRIVY_IMAGE" \
  --cache-dir /data image --download-db-only --no-progress

echo "==> opengrep-rules @ ${RULES_COMMIT:0:12}"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
curl -fsSL "${RULES_REPO}/archive/${RULES_COMMIT}.tar.gz" | tar -xz -C "$tmp"
src="$(find "$tmp" -mindepth 1 -maxdepth 1 -type d | head -1)"
rm -rf "$MIRROR/opengrep/rules" && mkdir -p "$MIRROR/opengrep/rules"
for lang in python go javascript typescript dockerfile yaml generic bash; do
  [ -d "$src/$lang" ] || continue
  (cd "$src" && find "$lang" -type f \( -name '*.yaml' -o -name '*.yml' \) \
     -path '*/security/*' ! -path '*secret*' ! -name '*.test.yaml' ! -name '*.test.yml' ! -path '*/fixtures/*' -print0 \
   | xargs -0 -I{} sh -c 'mkdir -p "$1/$(dirname "$2")" && cp "$2" "$1/$2"' _ "$MIRROR/opengrep/rules" {})
done
cp "$ROOT"/rules/opengrep/*.yml "$MIRROR/opengrep/rules/"

echo "==> gitleaks config"
cp "$ROOT/scanners/gitleaks/gitleaks.toml" "$MIRROR/gitleaks/gitleaks.toml"

chmod -R a+rX "$MIRROR"
echo "mirror ready at $MIRROR"
