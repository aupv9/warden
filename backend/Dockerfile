# The build stage runs on the builder's platform and cross-compiles, so a
# multi-arch release needs no emulation (the final stage has no RUN).
FROM --platform=$BUILDPLATFORM golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5 AS build
ARG TARGETOS=linux TARGETARCH=amd64 VERSION=dev COMMIT=none BUILD_TIME=unknown
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly
WORKDIR /src
COPY backend/go.mod backend/go.sum ./
COPY backend/cmd ./cmd
COPY backend/internal ./internal
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -o /out/ \
      -ldflags="-s -w -X github.com/aupv9/common-go/health.Version=${VERSION} -X github.com/aupv9/common-go/health.Commit=${COMMIT} -X github.com/aupv9/common-go/health.BuildTime=${BUILD_TIME}" \
      ./cmd/warden-api ./cmd/warden-worker ./cmd/warden-migrate

# No shell, no package manager: three static binaries and the CA bundle.
FROM scratch
ARG VERSION=dev COMMIT=none
LABEL org.opencontainers.image.title="warden" \
      org.opencontainers.image.source="https://github.com/aupv9/warden" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}"
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/ /usr/local/bin/
USER 65532:65532
ENV WARDEN_SERVER__HOST=0.0.0.0 WARDEN_SERVER__PORT=8000 WARDEN_APP__ENV=prod
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD ["/usr/local/bin/warden-api", "-healthcheck"]
ENTRYPOINT ["/usr/local/bin/warden-api"]
