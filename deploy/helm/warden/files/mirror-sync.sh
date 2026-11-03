#!/bin/bash
# The mirror CronJob's main container: Warden's own scripts/sync-mirror.sh,
# unchanged, so the Kubernetes mirror holds exactly what `make mirror` and the
# Compose mirror job write (Opengrep rules, Gitleaks config, KEV/EPSS/OSV).
#
# Its one Docker step, the Trivy DB download, has already been done by this
# Pod's trivy-db init container (the same pinned Trivy image, without Docker),
# so sync-mirror.sh skips it (WARDEN_MIRROR_SKIP_TRIVY=1) once the DB is there.
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
echo "    Trivy DB: fetched by the trivy-db init container"
export WARDEN_MIRROR_SKIP_TRIVY=1
exec "$SYNC"
