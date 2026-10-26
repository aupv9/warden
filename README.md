# Warden

**Self-hosted security scanning for source code uploads.** Developers upload a `.zip`;
Warden runs [Gitleaks](https://github.com/gitleaks/gitleaks), [Opengrep](https://github.com/opengrep/opengrep),
[Trivy](https://github.com/aquasecurity/trivy) and [Checkov](https://github.com/bridgecrewio/checkov)
in throw-away sandboxes and turns every finding into a tracked issue with an owner, an SLA and an audit trail.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Go 1.27](https://img.shields.io/badge/go-1.27-00ADD8.svg)
![Status: alpha](https://img.shields.io/badge/status-alpha-orange.svg)

> [!WARNING]
> Warden is alpha software. Uploads, scans, the issue workflow, exceptions, members and the
> audit log are implemented, but the API and data model may still change between releases.
> Don't run it in production yet.

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
make up         # writes .env with random secrets; starts Postgres, Redis, S3 (SeaweedFS), Keycloak, Mailpit;
                # creates the upload bucket (browser uploads allowed from http://localhost:5173 only)
make migrate    # schema as the owner role; the app connects as warden_app (RLS enforced)
make api        # http://127.0.0.1:8010   (Keycloak http://localhost:8180, Mailpit http://localhost:8025)
make worker
make web        # http://localhost:5173
```

Sign in to the web UI once (that creates your Warden user), then create an organization
with yourself as its first admin. Organizations are created by an operator; there is no
API for it:

```bash
set -a; source .env; set +a
go -C backend run ./cmd/warden-admin org create --name "Acme" --admin you@example.com
```

`warden-admin` connects with the runtime role (`WARDEN_DATABASE__DSN`), like the API.
`warden-admin audit verify --org <org id>` checks an organization's audit-log hash chain.

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
| `WARDEN_SCAN__HMAC_KEY` | | Master key for secret fingerprints, at least 32 bytes (`openssl rand -hex 32`). Each organization gets its own key derived from it, so changing it changes every secret's fingerprint |
| `WARDEN_SCAN__TIMEOUT` / `WARDEN_SCAN__SLOTS_PER_NODE` | `30m` / `7` | Per-scan timeout, concurrent scans per worker |
| `WARDEN_SCAN__UPLOAD_MAX_MB` | `200` | Largest upload; the presigned URL pins the exact size and the worker refuses larger objects |
| `WARDEN_SCAN__SCRATCH_DIR` / `WARDEN_SCAN__MIRROR_DIR` | `/scratch` / `/mirror` | Worker's per-scan working directory; offline scanner data (`make mirror`) |
| `WARDEN_SCAN__SOURCE_RETENTION` | `1h` | Uploaded objects still present after this are deleted by a sweep (normally a scan deletes its own upload when it ends). Uploads never started within 1 hour are cancelled (`UPLOAD_ABANDONED`) |
| `WARDEN_SCAN__AUTOCLOSE_GUARD_RATIO` | `0.5` | A scan may auto-fix at most this fraction of a project's active issues; above it nothing is closed and the scan is flagged `needs_confirmation` |
| `WARDEN_STORAGE__ENDPOINT` / `WARDEN_STORAGE__BUCKET` | `http://localhost:8333` / `warden-uploads` | S3-compatible store. Any non-AWS endpoint uses path-style URLs; for AWS use `https://s3.<region>.amazonaws.com` (the region is read from it). The bucket must exist and allow CORS `PUT` from the web UI's origin |
| `WARDEN_STORAGE__ACCESS_KEY` / `WARDEN_STORAGE__SECRET_KEY` | | Needs object read, write and delete on the bucket only |
| `WARDEN_SMTP__HOST` / `WARDEN_SMTP__PORT` | `localhost` / `1025` | Mail relay for notification email (Mailpit in development). STARTTLS is required unless the host is `localhost` or a loopback address |
| `WARDEN_SMTP__FROM` | `warden@localhost` | Sender address |
| `WARDEN_SMTP__USERNAME` / `WARDEN_SMTP__PASSWORD` | | Optional `AUTH PLAIN`; credentials are only ever sent over TLS (or to a loopback host) |
| `WARDEN_SMTP__IMPLICIT_TLS` | `false` | TLS from the first byte (port 465) instead of STARTTLS |
| `WARDEN_SMTP__PUBLIC_BASE_URL` | `http://localhost:5173` | Web UI address; links in emails are built from it |
| `WARDEN_SMTP__DIGEST_HOUR` | `8` | UTC hour of the daily SLA digest |
| `WARDEN_LOG__LEVEL` / `WARDEN_LOG__FORMAT` | `info` / `json` | |
| `WARDEN_OTEL__ENABLED` | `false` | OpenTelemetry traces and metrics |

See [`.env.example`](.env.example) for a complete local setup and
[`backend/internal/config`](backend/internal/config/config.go) for every option.

## API

REST under `/api/v1`, authenticated with OIDC bearer tokens (Keycloak access tokens, RS256).
The OpenAPI 3.1 document is served unauthenticated at `/api/v1/openapi.json`; health
endpoints are `/healthz`, `/readyz` and `/info`. Every response is an envelope:

```json
{ "data": { "id": "…", "sub": "…", "email": "dev@example.com", "name": null, "mfa": true, "orgs": [], "limits": { … } },
  "error": null,
  "meta": { "request_id": "…" } }
```

| | |
|---|---|
| `GET /me` | Your profile, orgs and server limits. The first call creates your Warden user. |
| `/me/notifications`, `/me/notification-prefs` | Your notifications (all orgs) and email preferences |
| `/orgs/{org_id}`, `/summary`, `/metrics` | Organization and SLA policy, dashboard counts, trend metrics |
| `/orgs/{org_id}/members` | Org members and roles (`org_admin`, `security_lead`, `member`) |
| `/orgs/{org_id}/projects` | Projects, their members (`owner`, `developer`, `viewer`), scans, auto-assign rules, archiving |
| `/orgs/{org_id}/scans/{id}` | Scan status, `start`, `cancel` |
| `/orgs/{org_id}/issues` | Issues: filters, counts, transitions, bulk assignment, comments, history |
| `/orgs/{org_id}/exceptions` | False-positive and risk-acceptance requests and decisions |
| `/orgs/{org_id}/audit-log` | Hash-chained audit log |

How it behaves:

- **Uploads bypass the API.** `POST …/projects/{id}/scans` returns a presigned `PUT` URL
  (15 minutes, pinned size and SHA-256); the browser uploads the `.zip` to object storage and
  then calls `POST …/scans/{id}/start`, which checks the object and queues the scan. Scan
  creation is limited per user per hour (`WARDEN_SCAN__RATE_LIMIT_PER_HOUR`, default 10;
  `429` with `Retry-After`).
- **Tenancy.** Anything under `/orgs/{org_id}` requires membership; non-members get `404`, as
  do projects, scans and issues the caller can't see. Each request's database work runs with
  `app.org_id` set, so row-level security backs up the permission checks.
- **Permissions** follow the matrix in [`internal/domain/rbac`](backend/internal/domain/rbac/rbac.go)
  (`403 FORBIDDEN` when a member lacks one). Developers may change only issues assigned to them.
- **Issue workflow.** Status changes follow [`internal/domain/issuestate`](backend/internal/domain/issuestate/issuestate.go)
  and carry the issue's `version` (`409 VERSION_CONFLICT` if stale). `false_positive` and
  `risk_accepted` are reached only through an approved exception; a requester can't decide
  their own request, and risk acceptances expire within 180 days.
- **Audit.** Every write appends an audit entry in the same transaction. Entries are
  hash-chained per organization and the application role can't update or delete them.
- **Errors** carry a stable `error.code`: `UNAUTHORIZED`, `FORBIDDEN`, `NOT_FOUND`,
  `VALIDATION_FAILED` (with `metadata.fields`), `CONFLICT`, `VERSION_CONFLICT`,
  `INVALID_TRANSITION`, `USER_NOT_FOUND`, `UPLOAD_MISMATCH`, `RATE_LIMITED`, `PROJECT_ARCHIVED`. Unknown JSON
  fields are rejected; internal errors are logged and returned as a generic `500`.
- Lists take `?limit=` (default 50, max 200) and an opaque `?cursor=`, and return
  `{ "items": [...], "next_cursor": … }`.
- **Policy and automation.** Security leads set the SLA days per severity
  (`PATCH /orgs/{org_id}`, optionally re-dating open issues). Project owners define ordered
  auto-assign rules (path glob, tool, minimum severity → a project member); the first
  matching rule assigns each *new* issue when a scan is processed. An archived project
  keeps its issues readable but accepts no scans (`409 PROJECT_ARCHIVED`).

## Notifications

Changes that someone should hear about write an event to an outbox table in the same
transaction as the change itself: an issue assigned to you, an issue reopened (its
assignee, else the project owners), an exception requested (security leads) or decided
(the requester), a scan finished (whoever started it), and a daily SLA digest of your
issues that are overdue or due within three days. The worker's `dispatch_notifications`
job (every minute, and right after each event) turns events into in-app notifications,
re-checking that every recipient is still an active member who can see the object, and
sends email to those whose preference allows it (on by default, except `scan.finished`).
Delivery is idempotent per event and recipient; a failing address is retried with backoff
without holding up anyone else's mail.

Emails contain only the organization, project key, issue key, title, severity, status,
the actor's name and a link to the web UI. They never include snippets, descriptions,
file contents, comments or secrets; titles are HTML-escaped, and header values with line
breaks are refused.

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
  cmd/                   warden-api, warden-worker, warden-migrate, warden-admin,
                         warden-redact, warden-sarif-gate, selfscan
  internal/api/          REST API (gin), OpenAPI document
  internal/service/      business rules: permissions, issue workflow, exceptions, scans
  internal/store/        Postgres repositories, hash-chained audit log
  internal/auth/         OIDC access-token and JWKS verification
  internal/domain/       fingerprints, severity mapping, issue state machine, permission matrix
  internal/scan/         zipcheck, sandbox, SARIF parser, redactor, orchestrator, result
                         processor (findings → issues), release gate
  internal/storage/      S3-compatible client (presigned uploads, download, delete)
  internal/notify/       notification dispatch (outbox → notifications), email rendering, SMTP
  internal/worker/       background jobs (River): scans, source purge, risk-acceptance expiry,
                         notifications, SLA digest
  internal/migrations/   SQL migrations (goose), River tables, role grants
frontend/                React + TypeScript + Vite, OIDC (PKCE); design spec in DESIGN.md
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
