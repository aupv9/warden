#!/usr/bin/env bash
# Fills the production compose settings with random secrets:
#   scripts/gen-secrets.sh [DIR]   (default: deploy/compose)
#
# Creates DIR/.env from DIR/.env.example if it doesn't exist, then replaces
# every value that is exactly CHANGE_ME with a fresh random one, in a format
# that suits the variable. Existing values are kept, so running it again only
# fills what is still a placeholder. Also writes DIR/secrets/s3.json (the
# bundled SeaweedFS identity) from the storage keys, and DOCKER_GID when it is
# empty and this host has a Docker socket.
#
# Secrets go only into files created with mode 600 (directory 700); the
# script prints variable names, never values, and passes no secret on a
# command line.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="${1:-$ROOT/deploy/compose}"
ENV="$DIR/.env"
umask 077
command -v openssl >/dev/null || { echo "gen-secrets: needs openssl" >&2; exit 1; }
[ ! -L "$ENV" ] || { echo "gen-secrets: $ENV is a symlink; refusing" >&2; exit 1; }
if [ ! -e "$ENV" ]; then
  cp "$DIR/.env.example" "$ENV"
  echo "created $ENV from .env.example"
fi
chmod 600 "$ENV"

b64url() { openssl rand -base64 "$1" | tr '+/' '-_' | tr -d '=\n'; }
secret_for() {
  case "$1" in
    WARDEN_SECRETS__KEY) printf 'k1:%s' "$(openssl rand -base64 32 | tr -d '\n')" ;; # <key id>:<base64 of 32 bytes>
    WARDEN_SCAN__HMAC_KEY) openssl rand -hex 32 ;;
    WARDEN_STORAGE__ACCESS_KEY) printf 'warden%s' "$(openssl rand -hex 10)" ;;
    *) b64url 32 ;; # passwords: URL-safe, so they can sit in a DSN as is
  esac
}

docker_gid() {
  local sock=/var/run/docker.sock
  [ -S "$sock" ] || return 0
  stat -c %g "$sock" 2>/dev/null || stat -f %g "$sock"
}

tmp="$(mktemp "$ENV.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
filled=()
while IFS= read -r line || [ -n "$line" ]; do
  if [[ "$line" =~ ^([A-Z0-9_]+)=CHANGE_ME$ ]]; then
    name="${BASH_REMATCH[1]}"
    printf '%s=%s\n' "$name" "$(secret_for "$name")" >> "$tmp"
    filled+=("$name")
  elif [[ "$line" == "DOCKER_GID=" ]] && gid="$(docker_gid)" && [ -n "$gid" ]; then
    printf 'DOCKER_GID=%s\n' "$gid" >> "$tmp"
    echo "DOCKER_GID=$gid (group of /var/run/docker.sock)"
  else
    printf '%s\n' "$line" >> "$tmp"
  fi
done < "$ENV"
mv -f "$tmp" "$ENV"
trap - EXIT
for n in "${filled[@]+"${filled[@]}"}"; do echo "generated $n"; done

# The bundled SeaweedFS reads its identities from secrets/s3.json (a compose
# secret). Warden's identity may read, write and list objects, not create
# buckets (the s3-init service does that with the server's own access).
val() { sed -n "s/^$1=//p" "$ENV" | tail -1; }
ak="$(val WARDEN_STORAGE__ACCESS_KEY)"; sk="$(val WARDEN_STORAGE__SECRET_KEY)"
if [ -n "$ak" ] && [ "$ak" != CHANGE_ME ] && [[ "$ak$sk" =~ ^[A-Za-z0-9_-]+$ ]]; then
  mkdir -p "$DIR/secrets" && chmod 700 "$DIR/secrets"
  printf '{"identities":[{"name":"warden","credentials":[{"accessKey":"%s","secretKey":"%s"}],"actions":["Read","Write","List","Tagging"]}]}\n' \
    "$ak" "$sk" > "$DIR/secrets/s3.json"
  chmod 600 "$DIR/secrets/s3.json"
  echo "wrote $DIR/secrets/s3.json"
else
  echo "skipped secrets/s3.json: storage keys aren't generated (external S3?)"
fi
left="$(grep -c '=CHANGE_ME' "$ENV" || true)"
[ "$left" = 0 ] || { echo "gen-secrets: $left placeholder(s) left in $ENV" >&2; exit 1; }
echo "$ENV is ready (mode 600); now set the values marked \"edit\""
