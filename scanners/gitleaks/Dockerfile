# warden-redact is a static Go binary: the image is upstream Gitleaks (Alpine) plus
# one file, with no interpreter.
FROM golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5 AS build
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly
WORKDIR /src
COPY backend/go.mod backend/go.sum ./
COPY backend/cmd/warden-redact ./cmd/warden-redact
COPY backend/internal ./internal
RUN go build -trimpath -ldflags='-s -w' -o /out/warden-redact ./cmd/warden-redact

FROM ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f
COPY --from=build --chmod=0555 /out/warden-redact /usr/local/bin/warden-redact
COPY --chmod=0555 scanners/gitleaks/warden-gitleaks /usr/local/bin/warden-gitleaks
RUN mkdir -p /opt/warden/noignore
USER 65532:65532
WORKDIR /tmp
ENTRYPOINT []
