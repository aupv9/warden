# Runs scripts/sync-mirror.sh for the `mirror` profile of
# deploy/compose/docker-compose.prod.yml: the docker CLI (the Trivy DB is
# fetched by running the pinned Trivy image) plus bash, curl and jq.
# docker:29.9.1-cli (Alpine 3.24), pushed 2026-10-16. The packages come from
# Alpine's signed repository for that release.
FROM docker:29.9.1-cli@sha256:6fae2214c3121a28d5aa639d09032f61310b7c9c75ffbad1025f261a1b621800
RUN apk add --no-cache bash curl jq
# Compose also sets user 65532 (plus the socket's group); the image doesn't
# rely on it.
USER 65532:65532
ENTRYPOINT ["/opt/warden/scripts/sync-mirror.sh"]
