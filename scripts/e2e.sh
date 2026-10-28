#!/usr/bin/env bash
# End-to-end smoke test against the local dev stack (make up, make migrate,
# make api, make worker, make mirror). Not run in CI: it needs Docker,
# Keycloak and a mirror. Every run creates a new org, so it can be repeated.
#
#   make e2e                    # or: scripts/e2e.sh
#   E2E_ENV=path/to/env.sh      # sourced instead of .env (must export WARDEN_*)
#
# It refuses any non-local API or Keycloak URL. Credentials it creates (a
# Keycloak client and two users with random passwords, user and API tokens)
# live in .cache/e2e with mode 600 and are never printed. Test data (an AWS-style
# key, lockfiles) is generated at run time; nothing secret is in the repo.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ -n "${E2E_ENV:-}" ]; then source "$E2E_ENV"; elif [ -f .env ]; then set -a; source .env; set +a; fi
: "${KEYCLOAK_ADMIN_PASSWORD:?run make env (or set E2E_ENV)}"
API="${WARDEN_URL:-http://localhost:${WARDEN_SERVER__PORT:-8010}}"
ISSUER="${WARDEN_OIDC__ISSUER:-http://localhost:8180/realms/warden}"
KC="${ISSUER%/realms/*}"
REALM="${ISSUER##*/realms/}"
for u in "$API" "$KC"; do
  case "$u" in http://localhost:*|http://127.0.0.1:*) ;; *) echo "refusing non-local URL $u"; exit 2 ;; esac
done
for c in jq curl git docker; do command -v "$c" >/dev/null || { echo "$c is required"; exit 2; }; done

BIN="$ROOT/backend/bin"
if [ ! -x "$BIN/warden" ] || [ ! -x "$BIN/warden-admin" ]; then make -s build >/dev/null; fi
STATE="$ROOT/.cache/e2e"
mkdir -p "$STATE"
chmod 700 "$STATE"
umask 077
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0 FAIL=0 SKIP=0
ok()   { PASS=$((PASS + 1)); printf '  ok    %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); printf '  FAIL  %s\n' "$1"; }
skip() { SKIP=$((SKIP + 1)); printf '  skip  %s\n' "$1"; }
check() { local name=$1; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi; }
step() { printf '\n== %s\n' "$1"; }

curl -fsS "$API/readyz" >/dev/null || { echo "API not ready at $API (make api)"; exit 2; }

# --- Keycloak: dev-only client and users -------------------------------------
step "Keycloak (dev realm $REALM)"
rnd() { openssl rand -base64 24 | tr '+/' '-_' | tr -d '=\n'; } # no newline: curl @file sends it all
for f in client admin-pass sec-pass; do [ -s "$STATE/$f" ] || rnd > "$STATE/$f"; done
ADMIN_TOKEN=$(curl -fsS -d client_id=admin-cli -d username=admin --data-urlencode "password=$KEYCLOAK_ADMIN_PASSWORD" \
  -d grant_type=password "$KC/realms/master/protocol/openid-connect/token" | jq -r .access_token)
KH=(-H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json")
R="$KC/admin/realms/$REALM"
client=$(jq -n --rawfile s "$STATE/client" '{clientId:"warden-e2e", publicClient:false, directAccessGrantsEnabled:true,
  standardFlowEnabled:false, secret:($s|rtrimstr("\n")), protocolMappers:[{name:"aud", protocol:"openid-connect",
  protocolMapper:"oidc-audience-mapper", config:{"included.custom.audience":"warden-api","access.token.claim":"true"}}]}')
cid=$(curl -fsS "${KH[@]}" "$R/clients?clientId=warden-e2e" | jq -r '.[0].id // empty')
if [ -z "$cid" ]; then
  curl -fsS "${KH[@]}" -X POST "$R/clients" -d "$client"
else
  curl -fsS "${KH[@]}" -X PUT "$R/clients/$cid" -d "$client"
fi
for u in admin sec; do
  uid=$(curl -fsS "${KH[@]}" "$R/users?username=e2e-$u&exact=true" | jq -r '.[0].id // empty')
  if [ -z "$uid" ]; then
    curl -fsS "${KH[@]}" -X POST "$R/users" -d "{\"username\":\"e2e-$u\",\"email\":\"e2e-$u@example.com\",\"emailVerified\":true,
      \"firstName\":\"E2E\",\"lastName\":\"$u\",\"enabled\":true,\"requiredActions\":[]}"
    uid=$(curl -fsS "${KH[@]}" "$R/users?username=e2e-$u&exact=true" | jq -r '.[0].id')
  fi
  jq -n --rawfile p "$STATE/$u-pass" '{type:"password", temporary:false, value:($p|rtrimstr("\n"))}' |
    curl -fsS "${KH[@]}" -X PUT "$R/users/$uid/reset-password" -d @-
done
user_token() {
  curl -fsS -d client_id=warden-e2e --data-urlencode "client_secret@$STATE/client" -d grant_type=password \
    -d "username=e2e-$1" --data-urlencode "password@$STATE/$1-pass" -d scope=openid \
    "$ISSUER/protocol/openid-connect/token" | jq -r .access_token > "$STATE/$1.token"
}
user_token admin && user_token sec
ok "client warden-e2e and users e2e-admin, e2e-sec"

# api USER METHOD PATH [BODY]: the response's data, or exit on an HTTP error.
api() {
  local tok=$1 method=$2 path=$3 body=${4:-}
  local args=(-sS -X "$method" -H "Authorization: Bearer $(cat "$STATE/$tok.token")" -o "$WORK/resp" -w '%{http_code}')
  [ -n "$body" ] && args+=(-H "Content-Type: application/json" -d "$body")
  local code
  code=$(curl "${args[@]}" "$API$path")
  if [ "${code:0:1}" != 2 ]; then echo "  $method $path -> $code $(jq -c .error "$WORK/resp" 2>/dev/null)" >&2; return 1; fi
  jq .data "$WORK/resp"
}

# --- Org, project, token ------------------------------------------------------
step "Org, project and API token"
api admin GET /me >/dev/null && api sec GET /me >/dev/null # first sign-in creates the users
ORG=$("$BIN/warden-admin" org create --name "E2E $(date -u +%Y%m%dT%H%M%S)" --admin e2e-admin@example.com | grep -Eo '[0-9a-f-]{36}' | head -1)
"$BIN/warden-admin" org add-member --org "$ORG" --email e2e-sec@example.com --role security_lead >/dev/null
user_token sec # roles are read per request, but refresh anyway
PRJ=$(api sec POST "/orgs/$ORG/projects" '{"key":"E2E","name":"E2E smoke"}' | jq -r .id)
api sec POST "/orgs/$ORG/projects/$PRJ/tokens" '{"name":"e2e","scopes":["scan:write","issues:read"],"expires_in_days":1}' |
  jq -r .secret > "$STATE/scan.token"
ok "org $ORG, project $PRJ"

# --- Fixture repository --------------------------------------------------------
step "Source scan"
MAL_PKG="${E2E_MAL_PKG:-}" MAL_VER="${E2E_MAL_VERSION:-}"
REPO="$WORK/repo"
mkdir -p "$REPO"
deps='"lodash":"4.17.15","gpl-thing":"1.0.0"'
pkgs='"node_modules/lodash":{"version":"4.17.15","license":"MIT"},"node_modules/gpl-thing":{"version":"1.0.0","license":"GPL-3.0-only"}'
if [ -n "$MAL_PKG" ]; then
  deps+=",\"$MAL_PKG\":\"$MAL_VER\""
  pkgs+=",\"node_modules/$MAL_PKG\":{\"version\":\"$MAL_VER\",\"license\":\"MIT\"}"
fi
echo "{\"name\":\"e2e\",\"version\":\"1.0.0\",\"lockfileVersion\":3,\"requires\":true,\"packages\":{\"\":{\"name\":\"e2e\",\"version\":\"1.0.0\",\"dependencies\":{$deps}},$pkgs}}" |
  jq . > "$REPO/package-lock.json"
cat > "$REPO/pom.xml" <<'EOF'
<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>
  <groupId>example</groupId><artifactId>e2e</artifactId><version>1.0.0</version>
  <dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId>
    <version>2.14.1</version></dependency></dependencies></project>
EOF
# An AWS-style access key id made up now, so Gitleaks has something to find.
FAKE_KEY="AKIA$(LC_ALL=C tr -dc 'A-Z2-7' </dev/urandom | head -c 16)"
printf 'aws_access_key_id = %s\n' "$FAKE_KEY" > "$REPO/config.ini"
git -C "$REPO" init -q && git -C "$REPO" add -A && git -C "$REPO" -c user.email=e2e@example.com -c user.name=e2e commit -qm fixture

curl -fsS -X PUT -H "Authorization: Bearer $(cat "$STATE/sec.token")" -H "Content-Type: application/json" \
  -d '{"categories":{"forbidden":"block","restricted":"review","reciprocal":"allow","notice":"allow","permissive":"allow","unencumbered":"allow","unknown":"allow"},"deny":[],"allow":[]}' \
  "$API/orgs/$ORG/license-policy" >/dev/null && ok "license preset applied"

set +e
WARDEN_TOKEN=$(cat "$STATE/scan.token") "$BIN/warden" scan --url "$API" --org "$ORG" --project "$PRJ" --dir "$REPO" \
  --fail-on critical --fail-on-kev --sbom-out "$WORK/bom.cdx.json" > "$WORK/scan1.log" 2>&1
code=$?
set -e
check "warden scan --fail-on-kev exits 1 (log4j is in KEV)" test "$code" = 1
SCAN=$(api sec GET "/orgs/$ORG/projects/$PRJ/scans" | jq -r '.items[0].id')
issues() { api sec GET "/orgs/$ORG/issues?project_id=$PRJ&limit=200$1"; }
issues "" > "$WORK/issues.json"
check "KEV issue for CVE-2021-44228" jq -e '[.items[] | select(.kev)] | length > 0' "$WORK/issues.json"
check "license issue with category restricted" jq -e '[.items[] | select(.license_category == "restricted")] | length == 1' "$WORK/issues.json"
check "Gitleaks found the generated key" jq -e '[.items[] | select(.tool == "gitleaks")] | length > 0' "$WORK/issues.json"
for id in $(jq -r '.items[] | select(.tool == "gitleaks") | .id' "$WORK/issues.json"); do api sec GET "/orgs/$ORG/issues/$id"; done > "$WORK/secret-issues.json"
check "the raw key appears in no issue" bash -c "! grep -qF '$FAKE_KEY' '$WORK/issues.json' '$WORK/secret-issues.json'"
check "CLI saved the CycloneDX SBOM" jq -e '.bomFormat == "CycloneDX" and (.components | length > 0)' "$WORK/bom.cdx.json"

step "SBOM downloads"
for f in cyclonedx spdx; do
  if url=$(api sec GET "/orgs/$ORG/scans/$SCAN/sbom?format=$f" | jq -r .url) && curl -fsS -o "$WORK/sbom.$f.json" "$url"; then
    ok "$f download"
  else
    bad "$f download"
  fi
done
check "CycloneDX names the project" jq -e '.metadata.component.name == "E2E"' "$WORK/sbom.cyclonedx.json"
check "SPDX document is SPDX-2.x" jq -e '.spdxVersion | startswith("SPDX-2.")' "$WORK/sbom.spdx.json"

step "Component inventory"
api sec GET "/orgs/$ORG/components?q=log4j" > "$WORK/comp.json" || true
check "search finds log4j-core 2.14.1" jq -e '[.items[] | select(.name == "org.apache.logging.log4j:log4j-core" and .version == "2.14.1")] | length == 1' "$WORK/comp.json"
api sec GET "/orgs/$ORG/components/usage?ecosystem=Maven&name=org.apache.logging.log4j:log4j-core&version=2.14.1" > "$WORK/usage.json" || true
check "usage lists the project" jq -e --arg p "$PRJ" '[.items[] | select(.project_id == $p)] | length == 1' "$WORK/usage.json"
check "API token reads project components" bash -c "curl -fsS -H \"Authorization: Bearer \$(cat '$STATE/scan.token')\" '$API/orgs/$ORG/projects/$PRJ/components?q=lodash' | jq -e '.data.items | length == 1'"

step "Malicious packages"
osv=$(api sec GET "/orgs/$ORG/vuln-data" | jq -r '[.sources[] | select(.name == "osv_mal:npm" and .loaded_at != null)] | length')
if [ -z "$MAL_PKG" ]; then
  skip "set E2E_MAL_PKG and E2E_MAL_VERSION to a MAL-listed npm package to test detection"
elif [ "$osv" != 1 ]; then
  skip "OSV npm feed not loaded (make mirror, then restart the worker)"
else
  check "malicious package is a Critical issue" jq -e --arg n "$MAL_PKG" \
    '[.items[] | select((.rule_id | startswith("malicious:")) and .package_name == $n and .severity == "critical")] | length == 1' "$WORK/issues.json"
  api sec GET "/orgs/$ORG/components?malicious=true" > "$WORK/mal.json" || true
  check "inventory marks it malicious" jq -e --arg n "$MAL_PKG" '[.items[] | select(.name == $n and .malicious)] | length == 1' "$WORK/mal.json"
fi

step "Image scan"
before=$(jq '[.items[] | select(.target == "")] | length' "$WORK/issues.json")
set +e
WARDEN_TOKEN=$(cat "$STATE/scan.token") "$BIN/warden" scan --url "$API" --org "$ORG" --project "$PRJ" \
  --image alpine:3.18.0 --fail-on critical > "$WORK/scan2.log" 2>&1
set -e
issues "" > "$WORK/issues2.json"
check "image issues under docker.io/library/alpine" jq -e '[.items[] | select(.target == "docker.io/library/alpine")] | length > 0' "$WORK/issues2.json"
check "source issues stay open" test "$(jq '[.items[] | select(.target == "")] | length' "$WORK/issues2.json")" = "$before"
api sec GET "/orgs/$ORG/projects/$PRJ/targets" > "$WORK/targets.json" || true
check "targets lists source and the image" jq -e '[.items[].target] | sort == ["", "docker.io/library/alpine"]' "$WORK/targets.json"

printf '\n%d passed, %d failed, %d skipped (org %s)\n' "$PASS" "$FAIL" "$SKIP" "$ORG"
[ "$FAIL" = 0 ]
