#!/usr/bin/env bash
# Upgrade test (Docker Compose): proves that upgrading a running deployment
# from a released Warden to IMAGE keeps the data, by following README
# "Upgrading" on deploy/compose/docker-compose.prod.yml (profiles core and s3,
# app.env=prod, behind Caddy with its internal CA, as scripts/compose-smoke.sh):
#
#   1. installs the previous release: its own compose files (git archive of
#      UPGRADE_FROM_REF) and image (UPGRADE_FROM_IMAGE, by digest), an .env
#      from its gen-secrets.sh;
#   2. seeds it: two users, an org through warden-admin (audited: create,
#      add-member, set-role), and as the schema owner a project, a scan, three
#      issues and an issues:read API token; reads the issues back through the
#      API with that token;
#   3. backs up with scripts/backup.sh (the manifest must name the old schema);
#   4. upgrades: this tree's compose files, WARDEN_IMAGE=IMAGE, `migrate`, then
#      the stack;
#   5. checks: /readyz, `warden-migrate status` up to date, `warden-admin audit
#      verify`, the row count of every table that existed before unchanged, the
#      API returning the same issues (list and detail);
#   6. schema gate: the old `warden-migrate status` must call the database
#      newer, and the old API must refuse to start on it (if IMAGE added
#      migrations); the new API must still be ready afterwards;
#   7. tears everything down, volumes included.
#
# warden-admin is in neither the image nor the release archives, so the test
# builds it (Go) from UPGRADE_FROM_REF for the old release and from this tree
# for IMAGE, and runs it in the api service's container (its env, its network).
#
# Usage: upgrade-test.sh IMAGE   (needs git, go, docker compose, curl, jq, openssl)
#   UPGRADE_FROM_IMAGE  the release upgraded from, by digest (default below)
#   UPGRADE_FROM_REF    its git tag, for its compose files; empty = this tree's
#   UPGRADE_HTTPS_PORT, UPGRADE_HTTP_PORT   Caddy on 127.0.0.1 (18444, 18081)
# To move the baseline to a newer release, change both defaults together
# (`gh release view vX.Y.Z` lists the image digest). The test writes nothing
# but its work directory under .cache/ (Colima shares only $HOME with its VM).
set -euo pipefail
IMAGE="${1:?usage: $0 IMAGE}"
FROM_IMAGE="${UPGRADE_FROM_IMAGE-ghcr.io/aupv9/warden@sha256:95eeb7678c444ae8197e776092e7414c55230d29cd223dc00d7c12967af11e4c}"
FROM_REF="${UPGRADE_FROM_REF-v0.5.0-alpha.1}"
HTTPS_PORT="${UPGRADE_HTTPS_PORT:-18444}"
HTTP_PORT="${UPGRADE_HTTP_PORT:-18081}"
DOMAIN=warden.localhost S3_DOMAIN=s3.warden.localhost
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
for tool in git go docker curl jq openssl; do
  command -v "$tool" >/dev/null || { echo "upgrade-test: needs $tool" >&2; exit 2; }
done
[[ "$FROM_IMAGE" == *@sha256:* ]] || { echo "upgrade-test: UPGRADE_FROM_IMAGE must be pinned by digest" >&2; exit 2; }

umask 077
mkdir -p "$ROOT/.cache"
WORK="$(mktemp -d "$ROOT/.cache/upgrade-test.XXXXXX")"
# docker-compose.smoke.yml reads the SeaweedFS identity from $SMOKE_DIR/secrets.
export SMOKE_DIR="$WORK"
project="warden-upgrade-$$"
oldapi="$project-oldapi"
profiles=(--profile core --profile s3)
SRC="$ROOT" # the compose files in use: the old release's, then this tree's
compose() {
  docker compose -p "$project" --env-file "$WORK/.env" -f "$SRC/deploy/compose/docker-compose.prod.yml" \
    -f "$SRC/deploy/compose/test/docker-compose.smoke.yml" "${profiles[@]}" "$@"
}
cleanup() {
  status=$?
  if [ "$status" != 0 ]; then
    compose ps -a || true
    for c in $(compose ps -aq 2>/dev/null); do
      docker inspect -f '{{.Name}} image={{.Config.Image}} restarts={{.RestartCount}} exit={{.State.ExitCode}} health={{if .State.Health}}{{.State.Health.Status}}{{end}}' "$c" || true
    done
    compose logs --tail 40 || true
    docker logs --tail 20 "$oldapi" 2>&1 | sed 's/^/[old api] /' || true
  fi
  docker rm -f -v "$oldapi" >/dev/null 2>&1 || true
  compose down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
  [ "$status" = 0 ] && echo "upgrade test: OK" || echo "upgrade test: FAILED" >&2
  exit "$status"
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
step() { echo "== $*"; }
set_env() { # set_env KEY VALUE: replace or append, keeping mode 600
  local tmp; tmp="$(mktemp "$WORK/.env.XXXXXX")"
  grep -v "^$1=" "$WORK/.env" > "$tmp" || true
  printf '%s=%s\n' "$1" "$2" >> "$tmp"
  mv -f "$tmp" "$WORK/.env"
}
# sql: psql as the schema owner over the postgres container's socket (a
# superuser in Compose, so RLS doesn't hide or refuse rows).
sql() { compose exec -T postgres psql -X -A -t -q -v ON_ERROR_STOP=1 -U warden_owner -d warden; }
# admin ARGS: warden-admin ($ADMIN, the binary matching the running release).
admin() {
  compose run --rm --no-deps -T -v "$ADMIN:/usr/local/bin/warden-admin:ro" \
    --entrypoint /usr/local/bin/warden-admin api "$@"
}
# build_admin SRC OUT: a static linux warden-admin for the Docker daemon's arch.
build_admin() {
  CGO_ENABLED=0 GOOS=linux GOARCH="$(docker version -f '{{.Server.Arch}}')" \
    go -C "$1/backend" build -trimpath -o "$2" ./cmd/warden-admin
  chmod 755 "$2" # the container runs as 65532
}
migrate_status() { compose run --rm --no-deps -T migrate status; }
# counts: every table's exact row count, but goose's own and River's (jobs the
# API may enqueue or prune between two counts).
counts() {
  sql <<'SQL'
SELECT format('SELECT %L || ''='' || count(*) FROM %I', tablename, tablename)
FROM pg_tables WHERE schemaname = 'public' AND tablename <> 'goose_db_version' AND tablename NOT LIKE 'river\_%'
ORDER BY tablename \gexec
SQL
}
curl_tls() { curl -sS --cacert "$WORK/root.crt" --resolve "$DOMAIN:$HTTPS_PORT:127.0.0.1" "$@"; }
ready() {
  compose exec -T caddy cat /data/caddy/pki/authorities/local/root.crt > "$WORK/root.crt"
  local code=""
  for _ in $(seq 60); do
    code="$(curl_tls -o "$WORK/readyz" -w '%{http_code}' "https://$DOMAIN:$HTTPS_PORT/readyz" || true)"
    [ "$code" = 200 ] && return 0
    sleep 2
  done
  fail "/readyz: $code $(cat "$WORK/readyz" 2>/dev/null || true)"
}
# api PATH: GET through Caddy with the API token (from a file, not argv).
api() { curl_tls -f -H @"$WORK/auth" "https://$DOMAIN:$HTTPS_PORT/api/v1/orgs/$org$1"; }
# issues: the seeded issues as the API lists them, fields every version has.
issues() {
  api "/issues" | jq -S '[.data.items[] | {id, key, project_id, title, severity, status, tool, rule_id, file_path}] | sort_by(.key)'
}
issue_detail() { api "/issues/$1" | jq -S '.data | {id, key, title, severity, status, first_seen_scan: .first_seen_scan.id, last_seen_scan: .last_seen_scan.id}'; }
schema_of() { sed -nE "s/^$1 schema: *([0-9]+)$/\1/p"; }

step "previous release: ${FROM_REF:-this tree} ($FROM_IMAGE)"
if [ -n "$FROM_REF" ]; then
  git -C "$ROOT" rev-parse -q --verify "$FROM_REF^{commit}" >/dev/null ||
    fail "$FROM_REF is not in this clone (git fetch --tags, or a full clone in CI)"
  mkdir "$WORK/old"
  git -C "$ROOT" archive "$FROM_REF" deploy/compose deploy/postgres scripts/gen-secrets.sh backend | tar -x -C "$WORK/old"
  SRC="$WORK/old"
fi
mkdir -p "$WORK/bin"
build_admin "$SRC" "$WORK/bin/warden-admin-old"
build_admin "$ROOT" "$WORK/bin/warden-admin-new"
ADMIN="$WORK/bin/warden-admin-old"
for img in "$FROM_IMAGE" "$IMAGE"; do # quietly; IMAGE may exist only locally
  docker image inspect "$img" >/dev/null 2>&1 || docker pull -q "$img" >/dev/null
done
cp "$SRC/deploy/compose/.env.example" "$WORK/.env.example"
"$SRC/scripts/gen-secrets.sh" "$WORK" >/dev/null
set_env WARDEN_IMAGE "$FROM_IMAGE"
set_env WARDEN_DOMAIN "$DOMAIN"
set_env WARDEN_S3_DOMAIN "$S3_DOMAIN"
set_env ACME_EMAIL "upgrade@example.com"
# Never contacted: the test signs in with an API token. https because prod requires it.
set_env WARDEN_OIDC__ISSUER "https://sso.upgrade.example/realms/warden"
set_env WARDEN_SMTP__HOST "smtp.upgrade.example"
set_env HTTP_BIND "127.0.0.1:$HTTP_PORT"
set_env HTTPS_BIND "127.0.0.1:$HTTPS_PORT"
compose up -d --quiet-pull --wait --wait-timeout 300
ready
old_schema="$(migrate_status | schema_of binary)"
[[ "$old_schema" =~ ^[0-9]+$ ]] || fail "old warden-migrate status printed no schema"

step "seed (schema $old_schema)"
sql <<'SQL'
INSERT INTO app_user (id, keycloak_sub, email, display_name) VALUES
  (gen_random_uuid(), 'upgrade-admin', 'admin@upgrade.test', 'Upgrade Admin'),
  (gen_random_uuid(), 'upgrade-lead', 'lead@upgrade.test', 'Upgrade Lead');
SQL
org="$(admin org create --name "Upgrade" --admin admin@upgrade.test | sed -nE 's/^created organization .*: ([0-9a-f-]{36})\r?$/\1/p')"
[[ "$org" =~ ^[0-9a-f-]{36}$ ]] || fail "org create printed no id"
admin org add-member --org "$org" --email lead@upgrade.test --role member >/dev/null
admin org set-role --org "$org" --email lead@upgrade.test --role security_lead >/dev/null
# An API token of the security lead (tokens are exempt from MFA; the lead may
# run scans in every project, which a token needs). Only its sha256 is stored;
# the secret is [a-p]{52}, inside the token alphabet [a-z2-7].
prefix="$(openssl rand -hex 4 | tr '0-9a-f' 'a-p')"
secret="$(openssl rand -hex 26 | tr '0-9a-f' 'a-p')"
hash="$(printf '%s' "$secret" | openssl dgst -sha256 -r | cut -d' ' -f1)"
printf 'Authorization: Bearer wdn_%s_%s\n' "$prefix" "$secret" > "$WORK/auth"
unset secret
sql <<SQL
WITH p AS (INSERT INTO project (id, org_id, key, name) VALUES (gen_random_uuid(), '$org', 'WEB', 'Web') RETURNING id),
     u AS (SELECT id FROM app_user WHERE email = 'lead@upgrade.test'),
     t AS (INSERT INTO api_token (id, org_id, project_id, user_id, created_by, name, prefix, token_hash, scopes, expires_at)
           SELECT gen_random_uuid(), '$org', p.id, u.id, u.id, 'upgrade test', '$prefix', '$hash', '{issues:read}', now() + interval '1 day'
           FROM p, u),
     s AS (INSERT INTO scan (id, org_id, project_id, created_by, status, file_name, sha256, tools, finished_at)
           SELECT gen_random_uuid(), '$org', p.id, u.id, 'completed', 'web.zip', repeat('a', 64), '{opengrep}', now()
           FROM p, u RETURNING id, project_id)
INSERT INTO issue (id, org_id, project_id, number, fingerprint, tool, rule_id, title, severity, status,
                   first_seen_scan_id, last_seen_scan_id, file_path)
SELECT gen_random_uuid(), '$org', s.project_id, n, lpad(n::text, 64, '0'), 'opengrep', 'upgrade.rule', 'Upgrade issue ' || n,
       (ARRAY['critical','high','low']::severity[])[n], 'open', s.id, s.id, 'app/main.py'
FROM s, generate_series(1, 3) AS n;
SQL
admin audit verify --org "$org"
issues > "$WORK/issues.before"
[ "$(jq length "$WORK/issues.before")" = 3 ] || { cat "$WORK/issues.before" >&2; fail "the old API lists $(jq length "$WORK/issues.before") issues, want 3"; }
first="$(jq -r '.[0].id' "$WORK/issues.before")"
issue_detail "$first" > "$WORK/detail.before"
counts > "$WORK/counts.before"
for t in organization org_member app_user project scan issue api_token audit_log; do
  grep -Eq "^$t=[1-9]" "$WORK/counts.before" || fail "$t is empty after seeding"
done

step "back up (scripts/backup.sh)"
"$ROOT/scripts/backup.sh" --container "$(compose ps -q postgres)" --warden-version "${FROM_REF:-old}" "$WORK/backups" >/dev/null
manifest="$(ls "$WORK"/backups/warden-*.manifest)"
grep -qx "schema_version=$old_schema" "$manifest" || fail "backup manifest: $(grep schema_version "$manifest")"
[ -s "${manifest%.manifest}.dump" ] || fail "backup: empty dump"

step "upgrade to $IMAGE (this tree's compose files)"
SRC="$ROOT" ADMIN="$WORK/bin/warden-admin-new"
set_env WARDEN_IMAGE "$IMAGE"
compose run --rm -T migrate
compose up -d --quiet-pull --wait --wait-timeout 300
ready

step "check the upgraded deployment"
status_out="$(migrate_status)" || { echo "$status_out" >&2; fail "warden-migrate status"; }
grep -qx 'status: up to date' <<<"$status_out" || fail "warden-migrate status: $status_out"
new_schema="$(schema_of database <<<"$status_out")"
[ "$new_schema" -ge "$old_schema" ] || fail "schema went from $old_schema to $new_schema"
admin audit verify --org "$org"
counts > "$WORK/counts.after"
# Tables that existed before keep their row counts; new tables may have rows.
while IFS= read -r line; do
  grep -qxF "$line" "$WORK/counts.after" || fail "row count changed: $line before, $(grep "^${line%%=*}=" "$WORK/counts.after" || echo missing) after"
done < "$WORK/counts.before"
issues > "$WORK/issues.after"
diff "$WORK/issues.before" "$WORK/issues.after" >&2 || fail "the API lists other issues after the upgrade"
issue_detail "$first" > "$WORK/detail.after"
diff "$WORK/detail.before" "$WORK/detail.after" >&2 || fail "issue detail changed after the upgrade"
tr '\n' ' ' < "$WORK/counts.after"; echo

step "schema gate: the old release refuses schema $new_schema"
set_env WARDEN_IMAGE "$FROM_IMAGE"
rc=0; old_status="$(migrate_status)" || rc=$?
if [ "$rc" != 1 ] || ! grep -q 'newer than this binary' <<<"$old_status"; then
  fail "old warden-migrate status (exit $rc): $old_status"
fi
if [ "$new_schema" -gt "$old_schema" ]; then
  compose run -d --no-deps --name "$oldapi" api >/dev/null
  state=""
  for _ in $(seq 60); do
    state="$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$oldapi")"
    [[ "$state" == exited* ]] && break
    sleep 1
  done
  [[ "$state" == exited* ]] || fail "the old API is still running on schema $new_schema"
  [ "${state#exited }" != 0 ] || fail "the old API exited 0"
  docker logs "$oldapi" 2>&1 | grep -q "database schema $new_schema is newer than this binary ($old_schema)" ||
    { docker logs --tail 20 "$oldapi" >&2; fail "the old API stopped for another reason"; }
  docker rm -f -v "$oldapi" >/dev/null
else
  echo "no new migrations ($old_schema): nothing for the old API to refuse"
fi
set_env WARDEN_IMAGE "$IMAGE"
ready
issues | diff "$WORK/issues.before" - >&2 || fail "issues changed after the old API's attempt"
