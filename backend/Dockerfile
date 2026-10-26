FROM golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5 AS build
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly
WORKDIR /src
COPY backend/go.mod backend/go.sum ./
COPY backend/cmd ./cmd
COPY backend/internal ./internal
RUN go build -trimpath -ldflags='-s -w' -o /out/ ./cmd/warden-api ./cmd/warden-worker ./cmd/warden-migrate

# No shell, no package manager: three static binaries and the CA bundle.
FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/ /usr/local/bin/
USER 65532:65532
ENV WARDEN_SERVER__HOST=0.0.0.0 WARDEN_SERVER__PORT=8000 WARDEN_APP__ENV=prod
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD ["/usr/local/bin/warden-api", "-healthcheck"]
ENTRYPOINT ["/usr/local/bin/warden-api"]
