SHELL   := /bin/bash
GO      := go -C backend
FAIL_ON ?= critical
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
HEALTH  := github.com/aupv9/common-go/health
LDFLAGS := -s -w -X $(HEALTH).Version=$(VERSION) -X $(HEALTH).Commit=$(shell git rev-parse --short HEAD) \
           -X $(HEALTH).BuildTime=$(shell date -u +%FT%TZ)
# Colima: testcontainers needs the VM-side socket path for its reaper container.
export TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE ?= /var/run/docker.sock

.PHONY: help setup env up idp down migrate api worker web test test-int lint vulncheck build mirror selfscan selfscan-release clean

help:  ## Show targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-17s %s\n", $$1, $$2}'

setup:  ## Download Go modules + install frontend deps (lockfile, no scripts)
	$(GO) mod download
	cd frontend && npm ci

env:  ## Generate .env with random dev secrets
	./scripts/dev-env.sh

up: env  ## Start Postgres, Redis, S3, Keycloak, Mailpit
	docker compose up -d --wait
	./scripts/dev-s3-init.sh

idp:  ## Add GitHub/Google sign-in to the dev Keycloak (GITHUB_*/GOOGLE_* in .env)
	./scripts/dev-idp.sh

down:  ## Stop the dev stack
	docker compose down

migrate:  ## Apply DB migrations (as schema owner)
	set -a; source .env; set +a; $(GO) run ./cmd/warden-migrate

api:  ## Run the API on :8010
	set -a; source .env; set +a; $(GO) run ./cmd/warden-api

worker:  ## Run a worker (scan + default queues)
	set -a; source .env; set +a; $(GO) run ./cmd/warden-worker

web:  ## Run the web UI on :5173
	cd frontend && npm run dev

test:  ## Unit tests (race detector) + coverage
	$(GO) test -race -cover ./...

test-int:  ## Integration tests (Docker: real Postgres, RLS, River)
	DOCKER_HOST=$${DOCKER_HOST:-$$(docker context inspect -f '{{.Endpoints.docker.Host}}')} $(GO) test -tags integration -count=1 ./...

lint:  ## gofmt + go vet + staticcheck + tsc
	@test -z "$$(gofmt -l backend)" || { gofmt -l backend; echo "run gofmt -w backend"; exit 1; }
	$(GO) vet ./...
	$(GO) vet -tags integration ./...
	$(GO) tool staticcheck ./...
	cd frontend && npm run lint

vulncheck:  ## Known vulnerabilities in deps and the Go toolchain
	$(GO) tool govulncheck ./...

build:  ## Build all binaries into backend/bin (version from git describe)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o bin/ ./cmd/...

mirror:  ## Sync Trivy DB + Opengrep rules + Gitleaks config into .cache/mirror
	./scripts/sync-mirror.sh

selfscan:  ## Scan Warden with Warden (FAIL_ON=critical|high)
	$(GO) run ./cmd/selfscan -root "$(CURDIR)" -fail-on $(FAIL_ON)

selfscan-release:  ## Release gate: 0 Critical and 0 un-baselined High 
	$(MAKE) selfscan FAIL_ON=high

clean:  ## Remove caches, binaries and reports (keeps .env)
	chmod -R u+w .cache/selfscan .cache/scratch 2>/dev/null || true
	rm -rf .cache/selfscan .cache/scratch reports frontend/dist backend/bin
