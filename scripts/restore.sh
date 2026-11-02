#!/usr/bin/env bash
# Restores a backup made by scripts/backup.sh:
#
#   scripts/restore.sh [--container NAME] [--force] DIR/warden-<timestamp>.dump
#
# Restores into an EMPTY database: a fresh PostgreSQL whose warden_app role
# already exists (in Compose, a new pgdata volume: deploy/postgres/init-roles.sh
# creates the role on first start; start only the postgres service). Stop the
# API and worker first. Steps:
#   1. the manifest next to the dump must exist and its sha256 must match;
#   2. the database must have no tables in schema public, unless --force
#      (which drops the dump's objects before recreating them, and keeps any
#      others; prefer a fresh database);
#   3. pg_restore in a single transaction, stopping at the first error, so a
#      failed restore leaves the database as it was;
#   4. warden-migrate (WARDEN_MIGRATE, default warden-migrate on PATH) when
#      WARDEN_MIGRATE__DSN is set: it re-applies the warden_app grants
#      (grants.sql runs after every migrate) and migrates a dump from an older
#      Warden; then warden-migrate status. Otherwise run it yourself: in
#      Compose, starting the core profile runs the migrate service before the
#      API and worker.
# The connection is --container or WARDEN_MIGRATE__DSN, as in backup.sh.
set -euo pipefail
PROG=restore.sh
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/pg-client.sh
. "$ROOT/scripts/pg-client.sh"

usage() { echo "usage: $PROG [--container NAME] [--force] DUMP" >&2; exit 2; }
force=""
while [ $# -gt 0 ]; do
  case "$1" in
    --container) [ $# -ge 2 ] || usage; PG_CONTAINER="$2"; shift 2 ;;
    --force) force=1; shift ;;
    -h|--help) usage ;;
    -*) usage ;;
    *) break ;;
  esac
done
[ $# -eq 1 ] || usage
dump="$1"
manifest="${dump%.dump}.manifest"
[ "$manifest" != "$dump" ] && [ -f "$dump" ] || { echo "$PROG: $dump is not a .dump file" >&2; exit 1; }
[ -f "$manifest" ] || { echo "$PROG: no manifest $manifest; refusing an unverified dump" >&2; exit 1; }

field() { sed -n "s/^$1=//p" "$manifest" | head -n 1; }
[ "$(field format)" = "warden-backup/1" ] || { echo "$PROG: $manifest: unknown format" >&2; exit 1; }
want="$(field sha256)"
[[ "$want" =~ ^[0-9a-f]{64}$ ]] || { echo "$PROG: $manifest: no sha256" >&2; exit 1; }
got="$(pg_sha256 "$dump")"
[ "$got" = "$want" ] || { echo "$PROG: $dump: sha256 $got does not match the manifest ($want); refusing" >&2; exit 1; }
schema="$(field schema_version)"
echo "dump verified: schema $schema, Warden $(field warden_version), sha256 $got"

pg_setup
role="$(pg_query "SELECT count(*) FROM pg_roles WHERE rolname = 'warden_app'")"
[ "$role" = 1 ] || { echo "$PROG: role warden_app does not exist; create it first (deploy/postgres/init-roles.sh)" >&2; exit 1; }
tables="$(pg_query "SELECT count(*) FROM pg_tables WHERE schemaname = 'public'")"
clean=()
if [ "$tables" != 0 ]; then
  if [ -z "$force" ]; then
    echo "$PROG: the database has $tables tables in schema public; restore into an empty database (or --force)" >&2
    exit 1
  fi
  echo "$PROG: --force: replacing the dump's objects in a database with $tables tables" >&2
  clean=(--clean --if-exists)
fi
server="$(pg_query 'SHOW server_version_num')"
from="$(field postgres_version)"
if [[ "$from" =~ ^[0-9]+$ ]] && [ $((server / 10000)) -lt $((from / 10000)) ]; then
  echo "$PROG: the dump comes from PostgreSQL $((from / 10000)), this server is $((server / 10000)); refusing" >&2
  exit 1
fi

# Ownership and grants come from the dump (the owner role must be warden_owner,
# as in the source); grants.sql re-applies the app's grants below anyway.
pg pg_restore --exit-on-error --single-transaction --no-password ${clean[@]+"${clean[@]}"} < "$dump"
echo "restored $dump"

if [ -z "${WARDEN_MIGRATE__DSN:-}" ]; then
  cat <<'EOF'
Next: run warden-migrate (it re-applies the warden_app grants and migrates an
older schema). In Compose, starting the core profile runs the migrate service
before the API and worker. Then check `warden-migrate status` and
`warden-admin audit verify --org <id>`.
EOF
  exit 0
fi
migrate="${WARDEN_MIGRATE:-warden-migrate}"
command -v "$migrate" >/dev/null || { echo "$PROG: $migrate not found; set WARDEN_MIGRATE or run warden-migrate yourself" >&2; exit 1; }
"$migrate" up
"$migrate" status
