# Build from the repository root: docker build -f backend/Dockerfile .
# (backend/Dockerfile.dockerignore keeps the context to what the build reads.)
#
# Every build stage runs on the builder's platform and cross-compiles or
# downloads for the target, so a multi-arch release needs no emulation (the
# final stage has no RUN). Base images are pinned by digest, the docker CLI by
# version and SHA-256, all to releases at least 2 weeks old when pinned.

# The web UI. Its output is plain JS/CSS, the same for every target.
# node:22.23.3-alpine3.24, pushed 2026-09-23.
FROM --platform=$BUILDPLATFORM node:22.23.3-alpine3.24@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402 AS web
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json frontend/.npmrc ./
# Lockfile only, and no install scripts (also set in .npmrc).
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM --platform=$BUILDPLATFORM golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5 AS build
# No defaults for TARGETOS/TARGETARCH: a default wins over the value BuildKit
# sets for each --platform, and an arm64 image would get amd64 binaries.
ARG TARGETOS TARGETARCH
ARG VERSION=dev COMMIT=none BUILD_TIME=unknown
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly
WORKDIR /src
COPY backend/go.mod backend/go.sum ./
COPY backend/cmd ./cmd
COPY backend/internal ./internal
COPY --from=web /web/dist ./internal/webui/dist
# The bundle must run under the UI's CSP (no inline script or style); this
# checks the very files that get embedded. Runs natively, before cross-compiling.
RUN go test -tags webui -count=1 ./internal/webui/
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -tags webui -o /out/ \
      -ldflags="-s -w -X github.com/aupv9/common-go/health.Version=${VERSION} -X github.com/aupv9/common-go/health.Commit=${COMMIT} -X github.com/aupv9/common-go/health.BuildTime=${BUILD_TIME}" \
      ./cmd/warden-api ./cmd/warden-worker ./cmd/warden-migrate ./cmd/warden-admin ./cmd/warden-sandbox-io

# The docker CLI (client only, statically linked) for warden-worker, which runs
# each scanner with `docker run --runtime=runsc` against the host's daemon.
# Docker 29.9.1, published 2026-10-14; SHA-256 of the upstream tarballs.
FROM --platform=$BUILDPLATFORM golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5 AS dockercli
ARG TARGETARCH
ARG DOCKER_VERSION=29.9.1
ARG DOCKER_SHA256_AMD64=c158ecc55adb3afb01bbd3539ed3b997d20c26dbdc418080506cc1bf5243ff57
ARG DOCKER_SHA256_ARM64=3e93cc6d1a686456a3b18eefdde26467a837a7a2b257af22e27cba1dbc1b2018
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) arch=x86_64 sum="$DOCKER_SHA256_AMD64" ;; \
      arm64) arch=aarch64 sum="$DOCKER_SHA256_ARM64" ;; \
      *) echo "no docker CLI pinned for $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL --proto '=https' --tlsv1.2 -o /tmp/docker.tgz \
      "https://download.docker.com/linux/static/stable/${arch}/docker-${DOCKER_VERSION}.tgz"; \
    echo "${sum}  /tmp/docker.tgz" | sha256sum -c -; \
    tar -xzf /tmp/docker.tgz -C /tmp docker/docker; \
    mkdir -p /out && install -m 0555 /tmp/docker/docker /out/docker

# No shell, no package manager: four static binaries, the docker CLI and the CA bundle.
# warden-sandbox-io is not run here: with scan.sandbox_backend=kubernetes this
# image is also scan.kube.io_image, whose containers in each scanner Pod move
# the input in and the reports out over the exec API.
FROM scratch
ARG VERSION=dev COMMIT=none
LABEL org.opencontainers.image.title="warden" \
      org.opencontainers.image.source="https://github.com/aupv9/warden" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}"
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/ /usr/local/bin/
COPY --from=dockercli /out/docker /usr/local/bin/docker
USER 65532:65532
# The worker finds docker on PATH. The CLI only reads its config directory
# (none exists in the image, so it uses defaults): no HOME is needed and the
# root filesystem can stay read-only.
ENV PATH=/usr/local/bin \
    DOCKER_CONFIG=/nonexistent \
    WARDEN_SERVER__HOST=0.0.0.0 WARDEN_SERVER__PORT=8000 WARDEN_APP__ENV=prod
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD ["/usr/local/bin/warden-api", "-healthcheck"]
ENTRYPOINT ["/usr/local/bin/warden-api"]
