#!/usr/bin/env bash
# Adds "Sign in with GitHub / Google" to the dev Keycloak realm (idempotent).
#
# Client IDs and secrets come from the environment (or .env), never from the repo:
#   GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET   (GitHub → Settings → Developer settings → OAuth Apps)
#   GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET   (Google Cloud → APIs & Services → Credentials)
#   GOOGLE_HOSTED_DOMAIN                      optional: only accounts of this Workspace domain
# Register this callback URL at the provider:
#   http://localhost:8180/realms/warden/broker/<github|google>/endpoint
# A provider whose ID or secret is missing is skipped. `--remove` deletes both.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
if [ -f .env ]; then set -a; source .env; set +a; fi
: "${KEYCLOAK_ADMIN_PASSWORD:?run make env}"
KC="${KEYCLOAK_URL:-http://localhost:8180}"
REALM="${KEYCLOAK_REALM:-warden}"
command -v jq >/dev/null || { echo "jq is required"; exit 1; }

ADMIN=$(curl -fsS -d client_id=admin-cli -d username=admin --data-urlencode "password=$KEYCLOAK_ADMIN_PASSWORD" \
  -d grant_type=password "$KC/realms/master/protocol/openid-connect/token" | jq -r .access_token)
H=(-H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json")
API="$KC/admin/realms/$REALM/identity-provider/instances"

if [ "${1:-}" = "--remove" ]; then
  for alias in github google; do
    curl -fsS -o /dev/null -X DELETE "${H[@]}" "$API/$alias" && echo "removed $alias" || true
  done
  exit 0
fi

# upsert ALIAS JSON: create the provider, or update it in place.
upsert() {
  if curl -fs -o /dev/null "${H[@]}" "$API/$1"; then
    curl -fsS -X PUT "${H[@]}" "$API/$1" -d "$2" && echo "updated $1"
  else
    curl -fsS -X POST "${H[@]}" "$API" -d "$2" && echo "added $1"
  fi
}

# trustEmail: both providers only hand over verified addresses, so Keycloak marks
# them verified. An address that already belongs to a Keycloak user is not merged
# silently: the default "first broker login" flow asks that user to prove it by
# signing in first. (Warden itself never links two accounts by email either.)
if [ -n "${GITHUB_CLIENT_ID:-}" ] && [ -n "${GITHUB_CLIENT_SECRET:-}" ]; then
  upsert github "$(jq -n --arg id "$GITHUB_CLIENT_ID" --arg secret "$GITHUB_CLIENT_SECRET" '{
    alias: "github", providerId: "github", displayName: "GitHub", enabled: true, trustEmail: true,
    firstBrokerLoginFlowAlias: "first broker login",
    config: {clientId: $id, clientSecret: $secret, defaultScope: "user:email", syncMode: "IMPORT"}}')"
else
  echo "skip github (set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET)"
fi

if [ -n "${GOOGLE_CLIENT_ID:-}" ] && [ -n "${GOOGLE_CLIENT_SECRET:-}" ]; then
  upsert google "$(jq -n --arg id "$GOOGLE_CLIENT_ID" --arg secret "$GOOGLE_CLIENT_SECRET" --arg hd "${GOOGLE_HOSTED_DOMAIN:-}" '{
    alias: "google", providerId: "google", displayName: "Google", enabled: true, trustEmail: true,
    firstBrokerLoginFlowAlias: "first broker login",
    config: ({clientId: $id, clientSecret: $secret, defaultScope: "openid profile email", syncMode: "IMPORT"}
             + (if $hd != "" then {hostedDomain: $hd} else {} end))}')"
else
  echo "skip google (set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)"
fi
