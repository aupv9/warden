#!/usr/bin/env bash
# Backs up Warden's database:
#
#   scripts/backup.sh [--container NAME] [--warden-version V] DIR
#
# Writes DIR/warden-<UTC timestamp>.dump (pg_dump custom format, as the schema
# owner) and DIR/warden-<UTC timestamp>.manifest (schema version, Warden
# version, PostgreSQL version, sha256 of the dump), both mode 600. DIR is
# created with mode 700; an existing DIR must be ours and not accessible to
# other users, since a dump holds every org's findings. The connection is
# --container or WARDEN_MIGRATE__DSN (see scripts/pg-client.sh); the DSN is
# never printed. pg_dump takes a consistent snapshot, so Warden can keep
# running.
#
# Not in the dump, back them up separately (and not next to the dump: the
# dump's webhook URLs and secrets are encrypted under WARDEN_SECRETS__KEY):
#   WARDEN_SCAN__HMAC_KEY      per-org secret fingerprints derive from it; a new
#                              key gives every known secret a new fingerprint
#   WARDEN_SECRETS__KEY (+ WARDEN_SECRETS__OLD_KEYS)
#                              without it stored webhooks can't be decrypted
#   OIDC settings (WARDEN_OIDC__*, WARDEN_WEB__OIDC_*): accounts are bound to
#                              the provider's subjects
#   role passwords (POSTGRES_OWNER_PASSWORD, WARDEN_APP_PASSWORD): roles are
#                              cluster-wide and not in a database dump
# In the Compose deployment all of them are in deploy/compose/.env.
#
# Object storage is not backed up: uploads are deleted when their scan ends,
# and SBOMs (sboms/<org>/<scan>.*.json) are kept for scan.sbom_retention only
# and are produced again by scanning again. To keep them anyway, copy the
# bucket's sboms/ prefix with your S3 tool.
set -euo pipefail
PROG=backup.sh
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/pg-client.sh
. "$ROOT/scripts/pg-client.sh"
umask 077

usage() { echo "usage: $PROG [--container NAME] [--warden-version V] DIR" >&2; exit 2; }
version=""
while [ $# -gt 0 ]; do
  case "$1" in
    --container) [ $# -ge 2 ] || usage; PG_CONTAINER="$2"; shift 2 ;;
    --warden-version) [ $# -ge 2 ] || usage; version="$2"; shift 2 ;;
    -h|--help) usage ;;
    -*) usage ;;
    *) break ;;
  esac
done
[ $# -eq 1 ] || usage
dir="$1"
[[ "$version" =~ ^[A-Za-z0-9._+-]{0,64}$ ]] || { echo "$PROG: --warden-version: letters, digits and ._+- only" >&2; exit 2; }

[ ! -L "$dir" ] || { echo "$PROG: $dir is a symlink; refusing" >&2; exit 1; }
if [ ! -e "$dir" ]; then
  mkdir -p -m 700 "$dir"
fi
[ -d "$dir" ] || { echo "$PROG: $dir is not a directory" >&2; exit 1; }
[ "$(pg_owner "$dir")" = "$(id -u)" ] || { echo "$PROG: $dir is not owned by $(id -un); refusing" >&2; exit 1; }
mode="$(pg_mode "$dir")"
if [ $((8#$mode & 8#007)) -ne 0 ]; then
  echo "$PROG: $dir is accessible to other users (mode $mode); chmod 700 it first" >&2
  exit 1
fi
[ $((8#$mode & 8#070)) -eq 0 ] || echo "$PROG: warning: $dir is accessible to its group (mode $mode)" >&2

pg_setup
schema="$(pg_query 'SELECT max(version_id) FROM goose_db_version')" ||
  { echo "$PROG: can't read the schema version; is this Warden's database?" >&2; exit 1; }
[[ "$schema" =~ ^[0-9]+$ ]] || { echo "$PROG: no schema version recorded; is this database migrated?" >&2; exit 1; }
server="$(pg_query 'SHOW server_version_num')"

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
base="$dir/warden-$stamp"
[ ! -e "$base.dump" ] || { echo "$PROG: $base.dump exists" >&2; exit 1; }
tmp="$(mktemp "$dir/.warden-$stamp.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
# Custom format (compressed, selective restore); ownership and grants are kept,
# so the restored functions keep EXECUTE revoked from PUBLIC.
pg pg_dump --format=custom --no-password > "$tmp"
[ -s "$tmp" ] || { echo "$PROG: pg_dump wrote nothing" >&2; exit 1; }
sum="$(pg_sha256 "$tmp")"
mv "$tmp" "$base.dump"
trap - EXIT
cat > "$base.manifest" <<EOF
format=warden-backup/1
created_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
dump=warden-$stamp.dump
sha256=$sum
schema_version=$schema
warden_version=$version
postgres_version=$server
EOF
chmod 600 "$base.dump" "$base.manifest"

echo "wrote $base.dump (schema $schema, sha256 $sum)"
echo "wrote $base.manifest"
cat <<'EOF'
Not in the dump; keep these backed up separately, away from it:
  WARDEN_SCAN__HMAC_KEY, WARDEN_SECRETS__KEY, WARDEN_SECRETS__OLD_KEYS,
  WARDEN_OIDC__* and WARDEN_WEB__OIDC_* settings,
  POSTGRES_OWNER_PASSWORD, WARDEN_APP_PASSWORD (deploy/compose/.env in Compose)
SBOMs in object storage are not included; scanning again recreates them.
EOF
