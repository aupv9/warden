#!/usr/bin/env bash
# Starts deploy/compose/docker-compose.prod.yml (profiles core and s3, plus
# scanner with SMOKE_SCANNER=1) with app.env=prod, behind Caddy using its
# internal CA, and checks it end to end through TLS: /readyz, the web UI with
# HSTS and its CSP, /api/v1/web-config, and the object store's public name.
# Then tears everything down, volumes included.
#
# Usage: compose-smoke.sh IMAGE   (needs docker compose, curl, jq, openssl)
# SMOKE_SCANNER=1 also runs the worker: the Docker daemon needs runsc, and
# SMOKE_SCRATCH / SMOKE_MIRROR must be directories owned by 65532.
set -euo pipefail
IMAGE="${1:?usage: $0 IMAGE}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export SMOKE_DIR; SMOKE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/warden-smoke.XXXXXX")"
HTTPS_PORT="${SMOKE_HTTPS_PORT:-18443}"
DOMAIN=warden.localhost S3_DOMAIN=s3.warden.localhost
project="warden-smoke-$$"
compose() {
  docker compose -p "$project" --env-file "$SMOKE_DIR/.env" -f "$ROOT/deploy/compose/docker-compose.prod.yml" \
    -f "$ROOT/deploy/compose/test/docker-compose.smoke.yml" "${profiles[@]}" "$@"
}
profiles=(--profile core --profile s3)
[ "${SMOKE_SCANNER:-}" = 1 ] && profiles+=(--profile scanner)
cleanup() {
  status=$?
  if [ "$status" != 0 ]; then compose ps -a || true; compose logs --tail 40 || true; fi
  compose down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$SMOKE_DIR"
  exit "$status"
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

cp "$ROOT/deploy/compose/.env.example" "$SMOKE_DIR/.env.example"
"$ROOT/scripts/gen-secrets.sh" "$SMOKE_DIR" >/dev/null
set_env() { # set_env KEY VALUE: replace or append, keeping mode 600
  local tmp; tmp="$(mktemp "$SMOKE_DIR/.env.XXXXXX")"
  grep -v "^$1=" "$SMOKE_DIR/.env" > "$tmp" || true
  printf '%s=%s\n' "$1" "$2" >> "$tmp"
  mv -f "$tmp" "$SMOKE_DIR/.env"
}
set_env WARDEN_IMAGE "$IMAGE"
set_env WARDEN_DOMAIN "$DOMAIN"
set_env WARDEN_S3_DOMAIN "$S3_DOMAIN"
set_env ACME_EMAIL "smoke@example.com"
# Never contacted during the smoke test; https because prod requires it.
set_env WARDEN_OIDC__ISSUER "https://sso.smoke.example/realms/warden"
set_env WARDEN_SMTP__HOST "smtp.smoke.example"
set_env HTTP_BIND "127.0.0.1:${SMOKE_HTTP_PORT:-18080}"
set_env HTTPS_BIND "127.0.0.1:$HTTPS_PORT"
if [ "${SMOKE_SCANNER:-}" = 1 ]; then
  set_env WARDEN_SCRATCH_DIR "${SMOKE_SCRATCH:?}"
  set_env WARDEN_MIRROR_DIR "${SMOKE_MIRROR:?}"
  set_env DOCKER_GID "$(stat -c %g /var/run/docker.sock)"
  # The real scanner images, as an operator prepares them: in prod the
  # worker's preflight refuses to start without every image present.
  "$ROOT/scripts/scanner-images.sh" "$SMOKE_DIR/.env" >/dev/null
fi

echo "==> compose up (${profiles[*]})"
compose up -d --wait --wait-timeout 300

curl_tls() { curl -sS --cacert "$SMOKE_DIR/root.crt" --resolve "$1:$HTTPS_PORT:127.0.0.1" "${@:2}"; }
compose exec -T caddy cat /data/caddy/pki/authorities/local/root.crt > "$SMOKE_DIR/root.crt"

echo "==> https://$DOMAIN/readyz"
ok=""
for _ in $(seq 30); do
  if [ "$(curl_tls "$DOMAIN" -o /dev/null -w '%{http_code}' "https://$DOMAIN:$HTTPS_PORT/readyz")" = 200 ]; then ok=1; break; fi
  sleep 2
done
[ -n "$ok" ] || fail "/readyz: $(curl_tls "$DOMAIN" "https://$DOMAIN:$HTTPS_PORT/readyz" || true)"

echo "==> web UI through Caddy"
curl_tls "$DOMAIN" -fsS -D "$SMOKE_DIR/h" -o "$SMOKE_DIR/index.html" "https://$DOMAIN:$HTTPS_PORT/"
grep -q '<div id="root"></div>' "$SMOKE_DIR/index.html" || fail "index.html"
grep -qi '^strict-transport-security: max-age=31536000' "$SMOKE_DIR/h" || fail "no HSTS"
grep -qi "^content-security-policy: .*connect-src 'self' https://sso.smoke.example https://$S3_DOMAIN;" "$SMOKE_DIR/h" \
  || fail "UI CSP: $(grep -i '^content-security-policy' "$SMOKE_DIR/h")"

echo "==> /api/v1/web-config"
curl_tls "$DOMAIN" -fsS "https://$DOMAIN:$HTTPS_PORT/api/v1/web-config" \
  | jq -e '.data.issuer == "https://sso.smoke.example/realms/warden" and .data.client_id == "warden-web"' >/dev/null || fail "web-config"

echo "==> object store at https://$S3_DOMAIN (anonymous request refused by SeaweedFS)"
code="$(curl_tls "$S3_DOMAIN" -o /dev/null -w '%{http_code}' "https://$S3_DOMAIN:$HTTPS_PORT/warden-uploads/x")"
[[ "$code" =~ ^4[0-9][0-9]$ ]] || fail "s3: $code"

if [ "${SMOKE_SCANNER:-}" = 1 ]; then
  echo "==> worker healthy, docker CLI reaches the daemon"
  [ "$(docker inspect -f '{{.State.Health.Status}}' "$(compose ps -q worker)")" = healthy ] || fail "worker not healthy"
  compose exec -T worker docker info -f '{{json .Runtimes}}' | grep -q '"runsc"' || fail "worker: no runsc"
fi
echo "compose smoke OK"
