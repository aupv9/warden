#!/usr/bin/env bash
set -euo pipefail

# Usage: sync-mirror.sh [intel]   ("intel" refreshes only the KEV/EPSS/OSV feeds)
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MIRROR="${MIRROR:-$ROOT/.cache/mirror}"
LOCK="$ROOT/scanners/images.lock.json"
lock() { jq -er ".$1" "$LOCK"; }
ONLY="${1:-}"
case "$ONLY" in ""|intel) ;; *) echo "usage: $0 [intel]" >&2; exit 2 ;; esac

KEV_URL="${WARDEN_KEV_URL:-https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json}"
# FIRST publishes EPSS through Empirical Security (epss.cyentia.com redirects here).
EPSS_URL="${WARDEN_EPSS_URL:-https://epss.empiricalsecurity.com/epss_scores-current.csv.gz}"
# OSV publishes one all.zip per ecosystem; the worker loads its MAL- (malicious
# package) advisories. The names must be OSV's (and Warden's, domain/ecosystem).
OSV_URL="${WARDEN_OSV_URL:-https://osv-vulnerabilities.storage.googleapis.com}"
OSV_ECOSYSTEMS="${WARDEN_OSV_ECOSYSTEMS:-npm PyPI Go Maven crates.io RubyGems NuGet Packagist}"

mkdir -p "$MIRROR"/{trivy,opengrep,gitleaks,checkov,intel,intel/osv}
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

if [ -z "$ONLY" ]; then
TRIVY_IMAGE="$(lock trivy.upstream)"
RULES_REPO="$(lock opengrep.rules.repo)"
RULES_COMMIT="$(lock opengrep.rules.commit)"

echo "==> Trivy DB"
# Run as the caller so the DB isn't root-owned on Linux (the chmod below would fail).
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$MIRROR/trivy:/data" "$TRIVY_IMAGE" \
  --cache-dir /data image --download-db-only --no-progress

echo "==> opengrep-rules @ ${RULES_COMMIT:0:12}"
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
fi

# Exploit intelligence, loaded by the worker's load_vuln_intel job. Each feed is
# downloaded next to its final name, given a quick sanity check, then moved into
# place, so a failed download keeps the previous file. The worker validates
# everything again (backend/internal/intel); this check only catches an error
# page or a truncated download early.
echo "==> CISA KEV + FIRST EPSS + OSV malicious packages"
INTEL="$MIRROR/intel"
[ -f "$INTEL/sources.json" ] || echo '[]' > "$INTEL/sources.json"
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
kev_ok() { jq -e '(.vulnerabilities | type == "array" and length > 0) and (.dateReleased | type == "string")' "$1" >/dev/null; }
epss_ok() { gzip -t "$1" && [ "$(gzip -dc "$1" | sed -n '2{p;q;}')" = "cve,epss,percentile" ]; }
# A zip starts with a local file header (PK\3\4); the worker reads the archive
# with its own caps (backend/internal/intel/osv.go) and never extracts it.
zip_ok() { [ "$(head -c 4 "$1" | od -An -tx1 | tr -d ' \n')" = "504b0304" ]; }
intel_failed=""
# fetch NAME URL FILE MAX_BYTES CHECK [MAX_SECONDS]
fetch() {
  local name="$1" url="$2" file="$INTEL/$3" max="$4" check="$5" secs="${6:-600}" part sum
  part="$(mktemp "$file.XXXXXX")"
  if curl -fsSL --proto '=https' --proto-redir '=https' --retry 3 --max-time "$secs" --max-filesize "$max" -o "$part" "$url" \
     && "$check" "$part"; then
    sum="$(sha256 "$part")"
    chmod 644 "$part" && mv -f "$part" "$file"
    jq --arg n "$name" --arg u "$url" --arg t "$(date -u +%FT%TZ)" --arg s "$sum" \
      '[.[] | select(.name != $n)] + [{name: $n, url: $u, fetched_at: $t, sha256: $s}] | sort_by(.name)' \
      "$INTEL/sources.json" > "$tmp/sources.json" && mv -f "$tmp/sources.json" "$INTEL/sources.json"
    echo "    $name: $3 sha256 ${sum:0:16}"
  else
    rm -f "$part"
    echo "ERROR: $name: download from $url failed or isn't a valid feed; kept the previous $3" >&2
    intel_failed="$intel_failed $name"
  fi
}
# Size caps match the worker's (internal/intel).
fetch kev "$KEV_URL" kev.json $((20 << 20)) kev_ok
fetch epss "$EPSS_URL" epss.csv.gz $((30 << 20)) epss_ok
for eco in $OSV_ECOSYSTEMS; do
  case "$eco" in
    npm) max=$((512 << 20)) ;;
    PyPI|Go|Maven|crates.io|RubyGems|NuGet|Packagist) max=$((128 << 20)) ;;
    *) echo "ERROR: WARDEN_OSV_ECOSYSTEMS: unknown ecosystem '$eco'" >&2; intel_failed="$intel_failed osv_mal:?"; continue ;;
  esac
  fetch "osv_mal:$eco" "$OSV_URL/$eco/all.zip" "osv/$eco.zip" "$max" zip_ok 1800
done

chmod -R a+rX "$MIRROR"
if [ -n "$intel_failed" ]; then
  echo "mirror at $MIRROR is ready except for:$intel_failed" >&2
  exit 1
fi
echo "mirror ready at $MIRROR"
