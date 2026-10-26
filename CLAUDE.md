# Warden — notes for Claude

Self-hosted security scanning service, open source (MIT). README.md is the user-facing
documentation; keep it accurate when behaviour or configuration changes. There is no
separate design doc: record the reason for a non-obvious choice in a code comment.

## Commands
- `make test` (unit, race detector), `make test-int` (Postgres + River via testcontainers-go,
  build tag `integration`; on Colima the Makefile sets DOCKER_HOST from the docker context
  and `TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock`)
- `make lint` (gofmt, go vet incl. integration tag, staticcheck, tsc), `make vulncheck` (govulncheck)
- `make selfscan` / `make selfscan-release` (needs `make mirror` once; needs `jq`)
- Backend is a Go module in `backend/` (module `github.com/aupv9/warden/backend`, Go 1.27.3 set by the
  `go` line: setup-go in CI reads that line, not `toolchain`). staticcheck/govulncheck are pinned as `tool` deps: `go -C backend tool ...`.
- Built on github.com/aupv9/common-go (config, logger, observability, health, httpserver, response,
  errors). Don't use its `auth` JWKS verifier, `database.Module` or `foundation.Core`: Warden's
  own replacements are stricter (see comments in `internal/auth`, `internal/db`, `internal/app`).
- Release: push a tag `vX.Y.Z[-pre]` on main; `.github/workflows/release.yml` reruns ci.yml (High gate),
  then publishes binaries, SBOMs, checksums and `ghcr.io/aupv9/warden`, all with provenance attestations.
  Version is stamped via `-X github.com/aupv9/common-go/health.Version` (Makefile, Dockerfile, release.yml).
- Config: env prefix `WARDEN_`, `__` for nesting (e.g. `WARDEN_SCAN__TIMEOUT`).

## Rules
- This is a security product, and its own security beats features. Keep the invariants in
  README "Security invariants".
- Hostile-input code (`zipcheck`, `sarif`, `redact`) must have tests for the attack, not
  just the happy path.
- New scanner flags or images: verify against real scanner output with
  `go -C backend run ./cmd/selfscan -root .. -zip <sample.zip>`, and check that no raw secret
  appears in any SARIF. Pin new images by digest to a release ≥ 2 weeks old.
- Never commit real-looking secrets as fixtures; build them at test time (see `backend/internal/scan/scantest`).
- Migrations run as `warden_owner`; runtime uses `warden_app`. Don't grant BYPASSRLS to the app.
  New tables get app grants from `internal/migrations/grants.sql`, which runs after every migrate.
- Exception to the 2-week rule: Go 1.27.3 (released 2026-10-19) was adopted on 2026-10-26 at the
  owner's request, to fix GO-2026-6809 (crypto/x509).
- New Go deps: pick a release ≥ 2 weeks old and check `make vulncheck` and the self-scan's Trivy output.
- Local ports 8000 and 8080 are taken on the dev machine. API is on 8010, Keycloak on 8180.
