# Sourced by backup.sh and restore.sh: how to reach Warden's database as the
# schema owner. Two ways, so neither needs a password on a command line:
#
#   --container NAME   run the PostgreSQL tools inside that container (the
#                      Compose `postgres` service, e.g. warden-postgres-1) over
#                      its local socket, as WARDEN_PG_USER (default
#                      warden_owner) on WARDEN_PG_DB (default warden). No
#                      password is involved and the host needs only docker.
#   (default)          the host's pg_dump / pg_restore / psql, connecting with
#                      WARDEN_MIGRATE__DSN from the environment. The DSN is split
#                      into PG* variables (libpq reads them from the
#                      environment), never printed and never put in argv.
#
# Either way the role must bypass row-level security (a superuser, as
# POSTGRES_USER is in the Compose deployment, or BYPASSRLS): every business
# table has FORCEd RLS, which applies to the table owner too, and pg_dump
# refuses to dump such a table rather than dump part of it.

PG_CONTAINER=""

# pg_url_decode decodes %XX escapes (a DSN's user and password may hold them).
pg_url_decode() {
  local s="${1//\\/\\\\}"
  printf '%b' "${s//%/\\x}"
}

# pg_dsn_env exports PGHOST, PGPORT, PGUSER, PGPASSWORD, PGDATABASE and the
# supported query parameters from WARDEN_MIGRATE__DSN. Errors name the
# problem, never the value.
pg_dsn_env() {
  local dsn="${WARDEN_MIGRATE__DSN:-}"
  [ -n "$dsn" ] || { echo "$PROG: set WARDEN_MIGRATE__DSN (schema owner) or use --container" >&2; return 1; }
  local re='^postgres(ql)?://([^:@/?]+)(:([^@/?]*))?@(\[[0-9A-Fa-f:.]+\]|[^:/?@]+)(:([0-9]+))?/([^/?]+)(\?(.*))?$'
  [[ "$dsn" =~ $re ]] || { echo "$PROG: WARDEN_MIGRATE__DSN is not a postgres://user[:password]@host[:port]/db URL" >&2; return 1; }
  PGUSER="$(pg_url_decode "${BASH_REMATCH[2]}")"
  PGPASSWORD="$(pg_url_decode "${BASH_REMATCH[4]}")"
  PGHOST="${BASH_REMATCH[5]}"; PGHOST="${PGHOST#[}"; PGHOST="${PGHOST%]}"
  PGPORT="${BASH_REMATCH[7]:-5432}"
  PGDATABASE="$(pg_url_decode "${BASH_REMATCH[8]}")"
  export PGUSER PGPASSWORD PGHOST PGPORT PGDATABASE
  [ -n "$PGPASSWORD" ] || unset PGPASSWORD # then ~/.pgpass or another method
  local query="${BASH_REMATCH[10]}" kv k v parts=()
  [ -z "$query" ] || IFS='&' read -r -a parts <<< "$query"
  for kv in ${parts[@]+"${parts[@]}"}; do
    k="${kv%%=*}"; v="$(pg_url_decode "${kv#*=}")"
    case "$k" in
      sslmode) export PGSSLMODE="$v" ;;
      sslrootcert) export PGSSLROOTCERT="$v" ;;
      sslcert) export PGSSLCERT="$v" ;;
      sslkey) export PGSSLKEY="$v" ;;
      connect_timeout) export PGCONNECT_TIMEOUT="$v" ;;
      application_name) export PGAPPNAME="$v" ;;
      "") ;;
      *) echo "$PROG: WARDEN_MIGRATE__DSN: unsupported parameter $k" >&2; return 1 ;;
    esac
  done
}

# pg_setup takes the connection from the parsed options.
pg_setup() {
  if [ -n "$PG_CONTAINER" ]; then
    command -v docker >/dev/null || { echo "$PROG: --container needs docker" >&2; return 1; }
    docker inspect -f '{{.State.Running}}' "$PG_CONTAINER" 2>/dev/null | grep -qx true ||
      { echo "$PROG: container $PG_CONTAINER is not running" >&2; return 1; }
    return 0
  fi
  local tool
  for tool in pg_dump pg_restore psql; do
    command -v "$tool" >/dev/null || { echo "$PROG: $tool not found; install the PostgreSQL client or use --container" >&2; return 1; }
  done
  pg_dsn_env
}

# pg TOOL ARGS...: run a PostgreSQL tool against the database; stdin and
# stdout pass through.
pg() {
  local tool="$1"; shift
  if [ -n "$PG_CONTAINER" ]; then
    docker exec -i "$PG_CONTAINER" "$tool" -U "${WARDEN_PG_USER:-warden_owner}" -d "${WARDEN_PG_DB:-warden}" "$@"
  else
    # The database name is not secret; pg_restore needs it (without -d it
    # would print SQL instead of restoring).
    "$tool" -d "$PGDATABASE" "$@"
  fi
}

# pg_query SQL: one value, unaligned, no psqlrc.
pg_query() {
  pg psql -X -A -t -q -v ON_ERROR_STOP=1 -c "$1"
}

pg_sha256() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

pg_mode() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }
pg_owner() { stat -c %u "$1" 2>/dev/null || stat -f %u "$1"; }
