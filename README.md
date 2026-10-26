# Warden

**Self-hosted security scanning for source code uploads.** Developers upload a `.zip`;
Warden runs [Gitleaks](https://github.com/gitleaks/gitleaks), [Opengrep](https://github.com/opengrep/opengrep),
[Trivy](https://github.com/aquasecurity/trivy) and [Checkov](https://github.com/bridgecrewio/checkov)
in throw-away sandboxes and turns every finding into a tracked issue with an owner, an SLA and an audit trail.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Go 1.27](https://img.shields.io/badge/go-1.27-00ADD8.svg)
![Status: alpha](https://img.shields.io/badge/status-alpha-orange.svg)

> [!WARNING]
> Warden is in early development. The scan engine, sandboxing, authentication and data
> model are implemented and tested; the upload API, issue workflow endpoints and web UI
> are not finished yet. Don't run it in production.

## Why Warden

A security scanner runs untrusted code against untrusted input. Warden is built around
that threat model instead of bolting it on:

- **Hostile archives are expected.** Uploads are validated before anything touches them:
  zip-slip, zip bombs (ratio and total size, counted on real bytes, not headers), symlinks,
  encrypted entries, duplicate entries and absurd paths are all rejected or neutralized.
- **Scanners can't escape or phone home.** Each scanner runs in its own container under
  gVisor (`runsc`) with no network, a read-only root filesystem, a non-root user, no Linux
  capabilities, `no-new-privileges` and pids/CPU/memory limits. Images are pinned by digest.
- **Uploads can't silence their own scan.** Scanner configs are explicit; in-repo
  `.gitleaks.toml`, `.gitleaksignore` and `nosemgrep` comments are ignored.
- **Secrets never leave the sandbox.** Gitleaks is the only secret scanner. Its output is
  redacted inside the sandbox: every detected secret is masked everywhere in the report and
  replaced by an HMAC with a per-organization key, so findings stay deduplicated without
  storing the secret.
- **Tenants are isolated in the database.** Every business table has an `org_id` under
  forced row-level security that fails closed. The application role can't bypass RLS,
  change the schema, or rewrite the audit log.
- **Uploaded source is short-lived.** The extracted source and the uploaded object are
  deleted on every exit path of a scan.

## How it works

```
 upload.zip ─▶ object storage ─▶ worker (River job, queue "scan")
                                    │
                                    ├─ verify SHA-256, validate + extract (zipcheck)
                                    ├─ run scanners in parallel, one sandbox each
                                    │    gitleaks ─▶ warden-redact (inside the sandbox)
                                    │    opengrep · trivy · checkov
                                    ├─ parse SARIF (treated as hostile input)
                                    ├─ fingerprint findings ─▶ issues (dedupe, auto-fix, reopen)
                                    └─ delete source + uploaded object
```

Findings keep their identity when code moves: fingerprints hash the tool, rule, file and
the whitespace-normalized flagged lines, plus the finding's order within the file.

## Quick start

Requirements: Go 1.27, Docker (Colima works on macOS), Node.js 22, `jq`, `openssl`.

```bash
make setup      # Go modules + frontend deps (npm ci, scripts disabled)
make up         # writes .env with random secrets; starts Postgres, Redis, S3 (SeaweedFS), Keycloak, Mailpit
make migrate    # schema as the owner role; the app connects as warden_app (RLS enforced)
make api        # http://127.0.0.1:8010   (Keycloak http://localhost:8180, Mailpit http://localhost:8025)
make worker
make web        # http://localhost:5173
```

On macOS there is no gVisor, so local scans fall back to `runc` with a warning.
CI and production must use `runsc`.

## Configuration

Settings come from defaults, then an optional `config.yaml` (path in `WARDEN_CONFIG_FILE`),
then environment variables. Variables use the `WARDEN_` prefix and `__` for nesting. Any
secret can be given as `file:/path`, for Docker and Kubernetes secrets.

| Variable | Default | |
|---|---|---|
| `WARDEN_SERVER__HOST` / `WARDEN_SERVER__PORT` | `127.0.0.1` / `8010` | API listen address |
| `WARDEN_DATABASE__DSN` | | Runtime connection, as `warden_app` |
| `WARDEN_MIGRATE__DSN` | | Schema owner; used only by `warden-migrate` |
| `WARDEN_OIDC__ISSUER` / `WARDEN_OIDC__AUDIENCE` | Keycloak realm / `warden-api` | Access tokens: RS256 only, JWKS from the issuer |
| `WARDEN_SCAN__SANDBOX_RUNTIME` | `runsc` | `runsc` (gVisor) or `runc` for local development |
| `WARDEN_SCAN__IMAGES` | | Scanner images; must be pinned by `@sha256` digest |
| `WARDEN_SCAN__HMAC_KEY` | | Key for secret fingerprints |
| `WARDEN_SCAN__TIMEOUT` / `WARDEN_SCAN__SLOTS_PER_NODE` | `30m` / `7` | Per-scan timeout, concurrent scans per worker |
| `WARDEN_STORAGE__*` | | S3-compatible object storage |
| `WARDEN_LOG__LEVEL` / `WARDEN_LOG__FORMAT` | `info` / `json` | |
| `WARDEN_OTEL__ENABLED` | `false` | OpenTelemetry traces and metrics |

See [`.env.example`](.env.example) for a complete local setup and
[`backend/internal/config`](backend/internal/config/config.go) for every option.

## API

REST under `/api/v1`, authenticated with OIDC bearer tokens. Every response is an envelope:

```json
{ "data": { "sub": "…", "email": "dev@example.com", "name": null, "mfa": true },
  "error": null,
  "meta": { "request_id": "…" } }
```

Errors carry a stable `error.code` (`UNAUTHORIZED`, `NOT_FOUND`, …). The OpenAPI document is
served at `/api/v1/openapi.json`. Health endpoints: `/healthz`, `/readyz`, `/info`.

## Development

| Command | |
|---|---|
| `make test` | Unit tests with the race detector |
| `make test-int` | Integration tests against a real Postgres (testcontainers): RLS, grants, River |
| `make lint` | gofmt, go vet, staticcheck, tsc |
| `make vulncheck` | govulncheck over dependencies and the Go toolchain |
| `make build` | Static binaries in `backend/bin` |

Code that handles hostile input (`zipcheck`, `sarif`, `redact`) has tests for the attacks,
not just the happy path. Test fixtures never contain real-looking secrets; they are built
at test time.

### Self-scan

Warden scans itself with its own pipeline before every release:

```bash
make mirror             # Trivy DB + pinned Opengrep rules (the only step that needs the Internet)
make selfscan           # fails on any Critical finding
make selfscan-release   # fails on any Critical or un-baselined High
```

Accepted findings live in [`.warden/baseline.json`](.warden/baseline.json); each entry needs a
reason of at least 20 characters and expires within 180 days. To push any archive through
the pipeline locally: `go -C backend run ./cmd/selfscan -root .. -zip some.zip`.

## Project layout

```
backend/                 Go module
  cmd/                   warden-api, warden-worker, warden-migrate, warden-redact,
                         warden-sarif-gate, selfscan
  internal/api/          REST API (gin)
  internal/auth/         OIDC access-token and JWKS verification
  internal/domain/       fingerprints, severity mapping, issue state machine, permission matrix
  internal/scan/         zipcheck, sandbox, SARIF parser, redactor, orchestrator, release gate
  internal/worker/       background jobs (River)
  internal/migrations/   SQL migrations (goose), River tables, role grants
frontend/                React + TypeScript + Vite, OIDC (PKCE)
scanners/                sandbox images and pinned digests
rules/opengrep/          Warden's own guardrail rules, run on every self-scan
deploy/                  Keycloak realm, Postgres role bootstrap
scripts/                 mirror sync, local env generator
```

Warden is built on [common-go](https://github.com/aupv9/common-go) (configuration,
logging, OpenTelemetry, health checks, the HTTP server and the response envelope), with
[pgx](https://github.com/jackc/pgx), [goose](https://github.com/pressly/goose) and
[River](https://github.com/riverqueue/river) for Postgres, migrations and jobs.

## Releases

Tags `vMAJOR.MINOR.PATCH` on `main` publish a [GitHub release](https://github.com/aupv9/warden/releases)
after the full CI suite and the release self-scan gate pass: static Linux binaries
(`warden-api`, `warden-worker`, `warden-migrate`; amd64 and arm64) with SPDX SBOMs and
checksums, and the image `ghcr.io/aupv9/warden` (amd64 and arm64). The version is stamped
into the binaries and served at `/info`.

### Verifying a release

Every artifact and the image carry a Sigstore build-provenance attestation that ties them
to this repository's release workflow. Verify before running:

```bash
sha256sum -c --ignore-missing warden_v0.1.0_checksums.txt
gh attestation verify warden_v0.1.0_linux_amd64.tar.gz -R aupv9/warden
gh attestation verify oci://ghcr.io/aupv9/warden@sha256:<digest> -R aupv9/warden
```

Pull the image by the digest from the release notes, not by tag.

## Security invariants

Changes that weaken one of these need an explicit discussion in the pull request:

- Archives are only ever extracted by `zipcheck.Extract`.
- Scanner containers run with `runsc`, `--network=none`, a read-only rootfs, a non-root
  user and `--cap-drop=ALL`, with no Docker socket. Images are pinned by digest.
- Gitleaks is the only secret scanner, and raw secrets never leave its sandbox.
- Uploaded code can't configure its own scan.
- Every business table has `org_id` under forced RLS. The app role has no `BYPASSRLS` and
  can't update or delete the audit log. Only `warden-migrate` connects as the schema owner.
- Permissions are checked in the service layer (`internal/domain/rbac`); RLS is the second
  line of defence.
- Authentication errors are generic; the reason is logged, never returned.

## Contributing

Issues and pull requests are welcome. Please run `make lint test` before opening a pull
request, and `make test-int` when touching the database. For changes to scanners, flags or
images, run a sample archive through the real pipeline and check that no raw secret appears
in any SARIF report.

## Reporting a vulnerability

Please don't open a public issue. Use GitHub's
[private vulnerability reporting](https://github.com/aupv9/warden/security/advisories/new).

## License

[MIT](LICENSE)
