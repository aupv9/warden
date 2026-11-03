#!/bin/bash
# The mirror CronJob's main container: Warden's own scripts/sync-mirror.sh,
# unchanged, so the Kubernetes mirror holds exactly what `make mirror` and the
# Compose mirror job write (Opengrep rules, Gitleaks config, KEV/EPSS/OSV).
#
# Its one Docker step, `docker run <pinned trivy> image --download-db-only`,
# has already been done by this Pod's trivy-db init container, which runs the
# same pinned Trivy image without Docker. The `docker` on PATH here
# (docker-shim) only acknowledges that step after checking the DB is there,
# and fails anything else.
set -euo pipefail
: "${MIRROR:?MIRROR is not set}"
SYNC=/opt/warden/scripts/sync-mirror.sh
if [ ! -x "$SYNC" ]; then
  echo "mirror: $SYNC not found: the mirror image must hold Warden's scripts/, scanners/ and rules/ under /opt/warden (deploy/helm/mirror/Dockerfile)" >&2
  exit 1
fi
if [ ! -s "$MIRROR/trivy/db/trivy.db" ] || [ ! -s "$MIRROR/trivy/db/metadata.json" ]; then
  echo "mirror: no Trivy DB under $MIRROR/trivy: the trivy-db init container should have fetched it" >&2
  exit 1
fi
export PATH="/opt/warden-helm/bin:$PATH"
exec "$SYNC"
