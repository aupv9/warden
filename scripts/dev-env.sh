#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
if [ -f .env ]; then echo ".env exists; delete it to regenerate"; exit 0; fi
rnd() { openssl rand -base64 24 | tr '+/' '-_' | tr -d '='; }
PG_OWNER=$(rnd); PG_APP=$(rnd); REDIS=$(rnd); KC=$(rnd); S3_KEY=$(rnd); S3_SECRET=$(rnd); HMAC=$(openssl rand -hex 32)
umask 077
sed -e "s|__PG_OWNER__|$PG_OWNER|g" -e "s|__PG_APP__|$PG_APP|g" -e "s|__REDIS__|$REDIS|g" \
    -e "s|__KC__|$KC|g" -e "s|__S3_KEY__|$S3_KEY|g" -e "s|__S3_SECRET__|$S3_SECRET|g" \
    -e "s|__HMAC__|$HMAC|g" .env.example > .env
mkdir -p .cache/dev
cat > .cache/dev/s3.json <<JSON
{"identities":[{"name":"warden","credentials":[{"accessKey":"$S3_KEY","secretKey":"$S3_SECRET"}],"actions":["Read","Write","List","Tagging"]}]}
JSON
chmod 644 .cache/dev/s3.json
echo "wrote .env and .cache/dev/s3.json"
