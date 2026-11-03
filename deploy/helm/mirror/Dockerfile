# The image of the Helm chart's mirror CronJob (mirror.cronjob.image): bash,
# curl, jq and gzip, plus the parts of this repository scripts/sync-mirror.sh
# reads. No Docker CLI: in Kubernetes the Trivy DB is fetched by the pinned
# Trivy image itself (the CronJob's trivy-db init container).
#
# Build from the repository root, push to your registry, and set the digest:
#   docker build -f deploy/helm/mirror/Dockerfile -t registry.example.com/warden/mirror:<version> .
#
# alpine:3.24.2, pushed 2026-09-18. The packages come from Alpine's signed
# repository for that release.
FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk add --no-cache bash curl jq gzip
COPY --chmod=0555 scripts/sync-mirror.sh /opt/warden/scripts/sync-mirror.sh
COPY --chmod=0444 scanners/images.lock.json /opt/warden/scanners/images.lock.json
COPY --chmod=0444 scanners/gitleaks/gitleaks.toml /opt/warden/scanners/gitleaks/gitleaks.toml
COPY --chmod=0444 rules/opengrep/ /opt/warden/rules/opengrep/
USER 65532:65532
ENTRYPOINT ["/opt/warden/scripts/sync-mirror.sh"]
