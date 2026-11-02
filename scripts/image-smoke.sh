#!/usr/bin/env bash
# Smoke test for a built Warden image (CI job `image`, `make image-smoke`):
# migrations apply, warden-api serves the bundled web UI with its own CSP and
# the API with its deny-all one, /api/v1/web-config answers, and the docker
# CLI the worker needs runs in the scratch image.
#
# Usage: image-smoke.sh IMAGE   (needs docker, curl, jq, openssl)
set -euo pipefail
IMAGE="${1:?usage: $0 IMAGE}"
# Same pin as docker-compose.yml.
PG_IMAGE="postgres:16-alpine@sha256:f4610795587492cd4fb887c2dc3de301b813278bb6f616992061141b5f15ac36"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ID="warden-smoke-$$"
PORT="${SMOKE_PORT:-18010}"
ISSUER="https://sso.smoke.example/realms/warden"
pw() { openssl rand -hex 16; }
PG_OWNER="$(pw)"; PG_APP="$(pw)"

cleanup() {
  docker rm -f "$ID-api" "$ID-db" >/dev/null 2>&1 || true
  docker network rm "$ID" >/dev/null 2>&1 || true
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; docker logs "$ID-api" 2>&1 | tail -20 >&2 || true; exit 1; }

docker network create "$ID" >/dev/null
docker run -d --name "$ID-db" --network "$ID" --network-alias db \
  -e POSTGRES_DB=warden -e POSTGRES_USER=warden_owner -e POSTGRES_PASSWORD="$PG_OWNER" -e WARDEN_APP_PASSWORD="$PG_APP" \
  -v "$ROOT/deploy/postgres/init-roles.sh:/docker-entrypoint-initdb.d/10-roles.sh:ro" "$PG_IMAGE" >/dev/null
for _ in $(seq 60); do
  docker exec "$ID-db" pg_isready -U warden_owner -d warden -h 127.0.0.1 >/dev/null 2>&1 && break
  sleep 1
done

echo "==> the docker CLI runs in the image (read-only rootfs, no HOME)"
v="$(docker run --rm --read-only --entrypoint docker "$IMAGE" version --format '{{.Client.Version}}' 2>/dev/null)" || true
[[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "docker CLI: got '$v'"
echo "    docker $v"

echo "==> warden-migrate"
docker run --rm --network "$ID" -e WARDEN_APP__ENV=local \
  -e WARDEN_MIGRATE__DSN="postgres://warden_owner:$PG_OWNER@db:5432/warden?sslmode=disable" \
  --entrypoint /usr/local/bin/warden-migrate "$IMAGE"

echo "==> warden-api"
# app.env=local: this checks serving, not the production guardrails (which
# want real https endpoints and secrets); the compose smoke runs prod.
docker run -d --name "$ID-api" --network "$ID" --read-only -p "127.0.0.1:$PORT:8000" \
  -e WARDEN_APP__ENV=local -e WARDEN_OIDC__ISSUER="$ISSUER" \
  -e WARDEN_DATABASE__DSN="postgres://warden_app:$PG_APP@db:5432/warden?sslmode=disable" \
  -e WARDEN_STORAGE__ENDPOINT=http://s3:8333 -e WARDEN_STORAGE__PUBLIC_ENDPOINT=https://s3.smoke.example \
  -e WARDEN_STORAGE__ACCESS_KEY="$(pw)" -e WARDEN_STORAGE__SECRET_KEY="$(pw)" "$IMAGE" >/dev/null
BASE="http://127.0.0.1:$PORT"
for _ in $(seq 30); do curl -fsS "$BASE/healthz" >/dev/null 2>&1 && break; sleep 1; done
curl -fsS "$BASE/healthz" >/dev/null || fail "/healthz"

tmp="$(mktemp -d)"; trap 'cleanup; rm -rf "$tmp"' EXIT
header() { grep -i "^$1:" "$2" | head -1 | cut -d' ' -f2- | tr -d '\r'; }

echo "==> GET / is the web UI with the UI's CSP"
curl -fsS -D "$tmp/h" -o "$tmp/index.html" "$BASE/projects/x"
grep -q '<div id="root"></div>' "$tmp/index.html" || fail "index.html not served"
csp="$(header content-security-policy "$tmp/h")"
for want in "script-src 'self';" "style-src 'self';" "font-src 'self';" "frame-ancestors 'none';" \
            "connect-src 'self' https://sso.smoke.example https://s3.smoke.example;"; do
  [[ "$csp" == *"$want"* ]] || fail "UI CSP lacks \"$want\": $csp"
done
[[ "$csp" != *unsafe-* ]] || fail "UI CSP has unsafe-*: $csp"
[ "$(header cache-control "$tmp/h")" = "no-store" ] || fail "index.html is cacheable"

asset="$(grep -o '/assets/[A-Za-z0-9._-]*\.js' "$tmp/index.html" | head -1)"
curl -fsS -D "$tmp/ah" -o /dev/null "$BASE$asset" || fail "GET $asset"
[ "$(header cache-control "$tmp/ah")" = "public, max-age=31536000, immutable" ] || fail "$asset cache headers"
[[ "$(header content-type "$tmp/ah")" == text/javascript* ]] || fail "$asset content type"
code="$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/assets/missing-0000.js")"
[ "$code" = 404 ] || fail "missing asset: $code"
code="$(curl -sS -o /dev/null -w '%{http_code}' --path-as-is "$BASE/assets/../index.html")"
[ "$code" = 404 ] || fail "dot segment: $code"

echo "==> /api/v1/web-config, and the API keeps its deny-all CSP"
curl -fsS -D "$tmp/wh" -o "$tmp/wc.json" "$BASE/api/v1/web-config"
jq -e --arg iss "$ISSUER" '.data.issuer == $iss and .data.client_id == "warden-web" and .data.audience == null' "$tmp/wc.json" >/dev/null \
  || fail "web-config: $(cat "$tmp/wc.json")"
[ "$(header content-security-policy "$tmp/wh")" = "default-src 'none'; frame-ancestors 'none'" ] || fail "API CSP"
code="$(curl -sS -o "$tmp/nf.json" -w '%{http_code}' "$BASE/api/v1/no-such-route")"
[ "$code" = 404 ] && jq -e '.error.code == "NOT_FOUND"' "$tmp/nf.json" >/dev/null || fail "API 404 fell back to the UI"

echo "image smoke OK"
