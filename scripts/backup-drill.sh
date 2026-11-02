#!/usr/bin/env bash
# Restore drill (make backup-drill): proves that a backup restores into a new
# database and that Warden accepts it. Needs Docker and Go only.
#
#   1. starts a throwaway PostgreSQL A (the image pinned in docker-compose.yml,
#      with deploy/postgres/init-roles.sh), migrates it and seeds an org
#      through warden-admin (audited), plus a project, a scan and issues;
#   2. checks the refusals: backup into a directory others can read, restore
#      of a dump that doesn't match its manifest or has none;
#   3. backs A up with scripts/backup.sh and restores into a second throwaway
#      PostgreSQL B (another warden_app password: roles are not in the dump)
#      with scripts/restore.sh, which runs warden-migrate;
#   4. on B: warden-migrate status must be up to date, warden-admin audit
#      verify (as warden_app) must pass, and every table's row count must
#      equal A's; a second restore must be refused, and --force must work;
#   5. removes the containers and the work directory.
#
# BACKUP_DRILL_CLIENT=container (default) runs the PostgreSQL tools inside the
# containers; =local uses the host's pg_dump/pg_restore/psql through
# WARDEN_MIGRATE__DSN. The work directory is under the repo's .cache (Colima
# only shares $HOME with its VM).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLIENT="${BACKUP_DRILL_CLIENT:-container}"
[ "$CLIENT" = container ] || [ "$CLIENT" = local ] || { echo "BACKUP_DRILL_CLIENT: container or local" >&2; exit 2; }
IMAGE="$(grep -m1 -oE 'postgres:[0-9a-z.-]+@sha256:[0-9a-f]{64}' "$ROOT/docker-compose.yml")"
umask 077
mkdir -p "$ROOT/.cache"
WORK="$(mktemp -d "$ROOT/.cache/backup-drill.XXXXXX")"
run_id="warden-drill-$$"
cleanup() {
  status=$?
  if [ "$status" != 0 ]; then
    for c in a b; do docker logs --tail 20 "$run_id-$c" 2>&1 | sed "s/^/[$c] /" || true; done
  fi
  docker rm -f -v "$run_id-a" "$run_id-b" >/dev/null 2>&1 || true
  rm -rf "$WORK"
  [ "$status" = 0 ] && echo "backup drill: OK" || echo "backup drill: FAILED" >&2
  exit "$status"
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
step() { echo "== $*"; }
# refuses WHAT PATTERN CMD...: CMD must fail with PATTERN in its error output,
# and print no password of the drill.
refuses() {
  local what="$1" pattern="$2" out; shift 2
  if out="$("$@" 2>&1)"; then fail "$what: accepted"; fi
  grep -qE "$pattern" <<<"$out" || { echo "$out" >&2; fail "$what: refused for another reason"; }
  for pw in "${a_OWNER_PW:-}" "${b_OWNER_PW:-}" "${a_APP_PW:-}" "${b_APP_PW:-}"; do
    [ -z "$pw" ] || ! grep -qF "$pw" <<<"$out" || fail "$what: printed a password"
  done
}

step "DSN parsing (scripts/pg-client.sh)"
dsn() { # dsn DSN: the PG* variables pg_dsn_env sets, or its error
  (PROG=check; . "$ROOT/scripts/pg-client.sh"; unset PGSSLMODE PGPASSWORD
   WARDEN_MIGRATE__DSN="$1" pg_dsn_env 2>&1 && echo "$PGUSER|${PGPASSWORD-unset}|$PGHOST|$PGPORT|$PGDATABASE|${PGSSLMODE:-}")
}
[ "$(dsn 'postgres://warden_owner:p%40ss%2Fw%25rd@db.internal:6432/warden?sslmode=verify-full')" = \
  'warden_owner|p@ss/w%rd|db.internal|6432|warden|verify-full' ] || fail "percent-encoded DSN"
[ "$(dsn 'postgresql://u@[fd00::5]/warden')" = 'u|unset|fd00::5|5432|warden|' ] || fail "IPv6 DSN without password"
for bad in 'postgres://u:secret-pw@h/db?host=/tmp' 'mysql://u:secret-pw@h/db' 'postgres://u:secret-pw@h' ''; do
  out="$(dsn "$bad" || true)"
  grep -q 'check: ' <<<"$out" || fail "DSN accepted: ${bad%%:*}"
  ! grep -q 'secret-pw' <<<"$out" || fail "DSN error printed the password"
done

step "build warden-migrate and warden-admin"
go -C "$ROOT/backend" build -o "$WORK/bin/" ./cmd/warden-migrate ./cmd/warden-admin
export PATH="$WORK/bin:$PATH"
export WARDEN_LOG__LEVEL=warn

# start NAME: a PostgreSQL like Compose's, with fresh passwords in an env file
# (not on a command line); prints nothing, sets <NAME>_PORT, <NAME>_OWNER_PW,
# <NAME>_APP_PW.
start() {
  local name="$1" owner_pw app_pw
  owner_pw="$(openssl rand -hex 16)"; app_pw="$(openssl rand -hex 16)"
  printf 'POSTGRES_DB=warden\nPOSTGRES_USER=warden_owner\nPOSTGRES_PASSWORD=%s\nWARDEN_APP_PASSWORD=%s\n' \
    "$owner_pw" "$app_pw" > "$WORK/$name.env"
  docker run -d --name "$run_id-$name" --env-file "$WORK/$name.env" -p 127.0.0.1::5432 \
    -v "$ROOT/deploy/postgres/init-roles.sh:/docker-entrypoint-initdb.d/10-roles.sh:ro" "$IMAGE" >/dev/null
  printf -v "${name}_OWNER_PW" '%s' "$owner_pw"
  printf -v "${name}_APP_PW" '%s' "$app_pw"
}
# ready NAME: TCP inside the container answers only after init scripts ran.
ready() {
  local name="$1" port i
  for i in $(seq 1 90); do
    if docker exec "$run_id-$name" pg_isready -q -h 127.0.0.1 -U warden_owner -d warden 2>/dev/null; then
      port="$(docker port "$run_id-$name" 5432/tcp | head -n 1)"
      printf -v "${name}_PORT" '%s' "${port##*:}"
      return 0
    fi
    sleep 1
  done
  fail "PostgreSQL $name did not start"
}
owner_dsn() { local pw="${1}_OWNER_PW" port="${1}_PORT"; echo "postgres://warden_owner:${!pw}@127.0.0.1:${!port}/warden?sslmode=disable"; }
app_dsn() { local pw="${1}_APP_PW" port="${1}_PORT"; echo "postgres://warden_app:${!pw}@127.0.0.1:${!port}/warden?sslmode=disable"; }
sql() { docker exec -i "$run_id-$1" psql -X -A -t -q -v ON_ERROR_STOP=1 -U warden_owner -d warden; }
# migrate NAME ARGS: warden-migrate against NAME; waits for the published port
# (Colima forwards it a moment after the server is up).
migrate() {
  local name="$1"; shift
  local i rc
  for i in $(seq 1 30); do
    rc=0; WARDEN_MIGRATE__DSN="$(owner_dsn "$name")" warden-migrate status >/dev/null 2>&1 || rc=$?
    [ "$rc" != 2 ] && break
    sleep 1
  done
  WARDEN_MIGRATE__DSN="$(owner_dsn "$name")" warden-migrate "$@"
}
admin() { local name="$1"; shift; WARDEN_DATABASE__DSN="$(app_dsn "$name")" warden-admin "$@"; }
# counts NAME: every public table with its exact row count.
counts() {
  sql "$1" <<'SQL'
SELECT format('SELECT %L || ''='' || count(*) FROM %I', tablename, tablename)
FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename \gexec
SQL
}
# acls NAME: grants on every table, sequence and function, row-security flags
# and policies: what keeps warden_app inside its org.
acls() {
  sql "$1" <<'SQL'
SELECT format('%s %s %s rls=%s force=%s', c.relname, c.relkind, coalesce(c.relacl::text, '-'), c.relrowsecurity, c.relforcerowsecurity)
FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'S', 'v') ORDER BY 1;
SELECT format('%s(%s) %s definer=%s', p.proname, pg_get_function_identity_arguments(p.oid), coalesce(p.proacl::text, '-'), p.prosecdef) FROM pg_proc p
WHERE p.pronamespace = 'public'::regnamespace ORDER BY 1;
SELECT format('%s %s %s %s using(%s) check(%s)', tablename, policyname, roles, cmd, qual, with_check)
FROM pg_policies WHERE schemaname = 'public' ORDER BY 1;
SQL
}
# same WHAT FUNC: FUNC's output on A and B must be equal, and not empty.
same() {
  local x y
  x="$("$2" a)"; y="$("$2" b)"
  [ -n "$x" ] || fail "$1: no output"
  [ "$x" = "$y" ] || { diff <(echo "$x") <(echo "$y") >&2 || true; fail "$1 differ between A and B"; }
}
# client NAME SCRIPT ARGS: backup.sh / restore.sh against NAME.
client() {
  local name="$1" script="$2"; shift 2
  if [ "$CLIENT" = container ]; then
    "$ROOT/scripts/$script" --container "$run_id-$name" "$@"
  else
    WARDEN_MIGRATE__DSN="$(owner_dsn "$name")" "$ROOT/scripts/$script" "$@"
  fi
}

step "start PostgreSQL A and B ($IMAGE)"
start a; start b
ready a; ready b

step "migrate and seed A"
migrate a up >/dev/null
sql a <<'SQL'
INSERT INTO app_user (id, keycloak_sub, email, display_name) VALUES
  (gen_random_uuid(), 'drill-admin', 'admin@drill.test', 'Drill Admin'),
  (gen_random_uuid(), 'drill-lead', 'lead@drill.test', 'Drill Lead');
SQL
org="$(admin a org create --name "Drill" --admin admin@drill.test | sed -nE 's/^created organization .*: ([0-9a-f-]{36})$/\1/p')"
[ -n "$org" ] || fail "org create printed no id"
admin a org add-member --org "$org" --email lead@drill.test --role member >/dev/null
admin a org set-role --org "$org" --email lead@drill.test --role security_lead >/dev/null
sql a <<SQL
WITH p AS (INSERT INTO project (id, org_id, key, name) VALUES (gen_random_uuid(), '$org', 'WEB', 'Web') RETURNING id),
     u AS (SELECT id FROM app_user WHERE email = 'admin@drill.test'),
     s AS (INSERT INTO scan (id, org_id, project_id, created_by, status, file_name, sha256, tools, finished_at)
           SELECT gen_random_uuid(), '$org', p.id, u.id, 'completed', 'web.zip', repeat('a', 64), '{opengrep}', now()
           FROM p, u RETURNING id, project_id)
INSERT INTO issue (id, org_id, project_id, number, fingerprint, tool, rule_id, title, severity, status,
                   first_seen_scan_id, last_seen_scan_id, file_path)
SELECT gen_random_uuid(), '$org', s.project_id, n, lpad(n::text, 64, '0'), 'opengrep', 'drill.rule', 'Drill issue ' || n,
       (ARRAY['critical','high','low']::severity[])[n], 'open', s.id, s.id, 'app/main.py'
FROM s, generate_series(1, 3) AS n;
SQL
admin a audit verify --org "$org"

step "refusals"
mkdir -m 755 "$WORK/open"
refuses "backup into a directory others can read" 'accessible to other users' client a backup.sh "$WORK/open"
[ -z "$(ls -A "$WORK/open")" ] || fail "backup left files in a refused directory"

step "back up A"
client a backup.sh --warden-version drill "$WORK/backups"
dump="$(ls "$WORK"/backups/warden-*.dump)"
[ "$(stat -c %a "$dump" 2>/dev/null || stat -f %Lp "$dump")" = 600 ] || fail "dump is not mode 600"
[ "$(stat -c %a "$WORK/backups" 2>/dev/null || stat -f %Lp "$WORK/backups")" = 700 ] || fail "backup directory is not mode 700"

mkdir -m 700 "$WORK/bad"
cp "$dump" "${dump%.dump}.manifest" "$WORK/bad/"
bad="$WORK/bad/$(basename "$dump")"
printf 'x' >> "$bad"
refuses "restore of a dump that doesn't match its manifest" 'does not match the manifest' client b restore.sh "$bad"
rm "${bad%.dump}.manifest"
cp "$dump" "$bad"
refuses "restore without a manifest" 'no manifest' client b restore.sh "$bad"
[ "$(sql b <<<"SELECT count(*) FROM pg_tables WHERE schemaname = 'public'")" = 0 ] || fail "a refused restore touched B"

step "restore into B"
WARDEN_MIGRATE__DSN="$(owner_dsn b)" client b restore.sh "$dump"

step "check B"
migrate b status
admin b audit verify --org "$org"
same "row counts" counts
same "grants, RLS and policies" acls
for t in organization org_member project scan issue audit_log; do
  n="$(sql b <<<"SELECT count(*) FROM $t")"
  [ "$n" -gt 0 ] || fail "$t is empty on B"
done
counts b | grep -E '^(organization|project|scan|issue|audit_log)=' | tr '\n' ' '; echo

step "restore refuses a non-empty database; --force replaces it"
refuses "restore over a database with tables" 'restore into an empty database' client b restore.sh "$dump"
WARDEN_MIGRATE__DSN="$(owner_dsn b)" client b restore.sh --force "$dump" >/dev/null
admin b audit verify --org "$org"
same "row counts after --force" counts
same "grants, RLS and policies after --force" acls
