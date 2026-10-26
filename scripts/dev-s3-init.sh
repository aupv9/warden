#!/usr/bin/env bash
# Creates the dev upload bucket in the compose SeaweedFS (idempotent). Warden's
# S3 identity can read and write objects but not create buckets, as in production.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
BUCKET="$(sed -n 's/^WARDEN_STORAGE__BUCKET=//p' .env 2>/dev/null || true)"
BUCKET="${BUCKET:-warden-uploads}"
[[ "$BUCKET" =~ ^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$ ]] || { echo "invalid bucket name: $BUCKET"; exit 1; }
for _ in $(seq 1 30); do
  if out="$(echo "s3.bucket.list" | docker compose exec -T s3 weed shell 2>/dev/null)"; then
    if grep -qw "$BUCKET" <<<"$out"; then echo "bucket $BUCKET ready"; exit 0; fi
    echo "s3.bucket.create -name $BUCKET" | docker compose exec -T s3 weed shell >/dev/null 2>&1 || true
  fi
  sleep 1
done
echo "could not create bucket $BUCKET"; exit 1
