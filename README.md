# Warden

**Self-hosted security scanning for source code uploads.** Developers upload a `.zip` (or a
container image saved with `docker save`); Warden runs [Gitleaks](https://github.com/gitleaks/gitleaks),
[Opengrep](https://github.com/opengrep/opengrep), [Trivy](https://github.com/aquasecurity/trivy) and
[Checkov](https://github.com/bridgecrewio/checkov) in throw-away sandboxes and turns every finding into a
tracked issue with an owner, an SLA and an audit trail. Each scan also yields a CycloneDX SBOM, an
org can turn licenses it doesn't accept into issues, and dependency issues are ranked by CISA KEV and
FIRST EPSS.

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
  deleted on every exit path of a scan. Image tarballs are validated without being unpacked,
  and Warden never pulls from a registry or holds registry credentials.

## How it works

```
 upload.zip ─▶ object storage ─▶ worker (River job, queue "scan")
 (image.tar)                        │
                                    ├─ verify SHA-256, validate + extract (zipcheck)
                                    │    image scans: validate the tarball (imagecheck), no extraction
                                    ├─ run scanners in parallel, one sandbox each
                                    │    gitleaks ─▶ warden-redact (inside the sandbox)
                                    │    opengrep · checkov
                                    │    trivy ─▶ one JSON report ─▶ SARIF + CycloneDX SBOM
                                    ├─ parse SARIF and Trivy JSON (treated as hostile input)
                                    ├─ license policy ─▶ license findings
                                    ├─ fingerprint findings ─▶ issues (dedupe, auto-fix, reopen)
                                    ├─ store the SBOM (object storage, scan.sbom_retention)
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
`warden-admin org set-role --org <org id> --email them@example.com --role org_admin` is the
break-glass path when nobody who manages members can sign in (for example, an admin lost
their second factor); it keeps at least one `org_admin` and is audited as `member.role_changed`
with `via: warden-admin`. `warden-admin org add-member --org <org id> --email … --role …` adds
someone who has signed in once (it honours the org's allowed email domains). Moving people to
another identity provider is `warden-admin user relink` (see "Sign-in and identity providers").

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
| `WARDEN_OIDC__ISSUER` / `WARDEN_OIDC__AUDIENCE` | Keycloak realm / `warden-api` | Any OIDC provider; the access token's `iss` and `aud` must match exactly. Keys come from the issuer's `/.well-known/openid-configuration` (see "Sign-in and identity providers") |
| `WARDEN_OIDC__JWKS_URL` | | Pin the signing-key URL instead of discovering it |
| `WARDEN_OIDC__ALGORITHMS` | `RS256` | Accepted token signatures: `RS256` and/or `ES256` (anything else is refused at startup) |
| `WARDEN_OIDC__MFA_AMR` / `WARDEN_OIDC__MFA_ACR` | `otp,mfa,hwk,webauthn` / | A token proves a second factor when its `amr` claim holds one of these, or its `acr` equals one of these (for providers that use `acr`) |
| `WARDEN_OIDC__REQUIRE_MFA_ROLES` | `org_admin,security_lead` | Org roles that must sign in with a second factor (the token's `amr` claim: `otp`, `mfa`, `hwk` or `webauthn`); otherwise every request under the org is `403 MFA_REQUIRED`. Comma-separated (a YAML list in `config.yaml`); empty disables the rule, as `.env.example` does for the dev realm. Orgs can add roles, not remove these. API tokens are exempt |
| `WARDEN_OIDC__CONSOLE_URL` | | Optional link to the identity provider's admin console, shown to org admins on the Sign-in settings page (http or https; never fetched) |
| `WARDEN_SCAN__SANDBOX_RUNTIME` | `runsc` | `runsc` (gVisor) or `runc` for local development |
| `WARDEN_SCAN__IMAGES` | | Scanner images; must be pinned by `@sha256` digest |
| `WARDEN_SCAN__HMAC_KEY` | | Master key for secret fingerprints, at least 32 bytes (`openssl rand -hex 32`). Each organization gets its own key derived from it, so changing it changes every secret's fingerprint |
| `WARDEN_SCAN__TIMEOUT` / `WARDEN_SCAN__SLOTS_PER_NODE` | `30m` / `7` | Per-scan timeout, concurrent scans per worker |
| `WARDEN_SCAN__UPLOAD_MAX_MB` | `200` | Largest source upload; the presigned URL pins the exact size and the worker refuses larger objects |
| `WARDEN_SCAN__UNZIP_MAX_MB` / `WARDEN_SCAN__UNZIP_MAX_FILES` | `1024` / `100000` | Unpacked size and file count a source archive may have |
| `WARDEN_SCAN__IMAGE_UPLOAD_MAX_MB` | `2048` | Largest `docker save` tarball for image scans |
| `WARDEN_SCAN__SBOM_RETENTION` | `8760h` | How long a scan's SBOM is kept before the purge job deletes it (at least `1h`) |
| `WARDEN_SCAN__SCRATCH_DIR` / `WARDEN_SCAN__MIRROR_DIR` | `/scratch` / `/mirror` | Worker's per-scan working directory; offline scanner data (`make mirror`) |
| `WARDEN_SCAN__SOURCE_RETENTION` | `1h` | Uploaded objects still present after this are deleted by a sweep (normally a scan deletes its own upload when it ends). Uploads never started within 1 hour are cancelled (`UPLOAD_ABANDONED`) |
| `WARDEN_SCAN__AUTOCLOSE_GUARD_RATIO` | `0.5` | A scan that would auto-fix 5 or more issues may fix at most this fraction of the project's active issues; above it nothing is closed and the scan is flagged `needs_confirmation`. Fewer than 5 are always fixed |
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

## Sign-in and identity providers

Warden never handles passwords: the web UI signs people in with OIDC (authorization code +
PKCE) at an identity provider, and the API accepts that provider's access tokens.

**More sign-in methods (Keycloak).** Everything on the sign-in page is Keycloak
configuration, not Warden code: social logins and corporate SSO under *Identity providers*
(OIDC or SAML: Google, GitHub, Microsoft Entra ID, Okta, ADFS…), LDAP / Active Directory under
*User federation*, passkeys and OTP under *Authentication*. For the dev realm,
`make idp` adds "Sign in with GitHub / Google" from `GITHUB_CLIENT_ID`/`GITHUB_CLIENT_SECRET`
and `GOOGLE_CLIENT_ID`/`GOOGLE_CLIENT_SECRET` (optionally `GOOGLE_HOSTED_DOMAIN` to allow one
Workspace domain) in `.env`; register `http://localhost:8180/realms/warden/broker/<github|google>/endpoint`
as the callback at the provider. Only providers that verify email addresses should be marked
"trust email": Warden rejects tokens with `email_verified: false` and never merges two
accounts that share an address.

**Another identity provider instead of Keycloak.** Any provider that issues JWT access tokens
for an API works:

| Provider | API side (`WARDEN_OIDC__…`) | Web side (build-time `VITE_OIDC_…`) |
|---|---|---|
| Okta | `ISSUER=https://<org>.okta.com/oauth2/default`, `AUDIENCE=` the authorization server's audience | `ISSUER` same, `CLIENT_ID` of a SPA app |
| Microsoft Entra ID | `ISSUER=https://login.microsoftonline.com/<tenant>/v2.0`, `AUDIENCE=` the API's application ID; "Expose an API" with a scope | `SCOPE="openid profile email api://<api-app>/access"` |
| Auth0 | `ISSUER=https://<tenant>.auth0.com/` (trailing slash), `AUDIENCE=` the API identifier | `AUDIENCE=` the same identifier |
| Authentik, Zitadel, Keycloak elsewhere | issuer of the application/realm | client ID of a public SPA client |

Google and GitHub can't be used directly: they don't issue JWT access tokens for your own
API, so put them behind a broker (Keycloak, Auth0, Dex). The token must carry `sub`, `email`,
`iss`, `aud`, `exp`, `iat` and a `kid`. If the provider signs with ES256, set
`WARDEN_OIDC__ALGORITHMS=RS256,ES256`. If it reports a second factor in `acr` rather than
`amr` (for example Okta's `urn:okta:loa:2fa:any`), set `WARDEN_OIDC__MFA_ACR`, or the
two-factor rule will block org admins and security leads.

**What org admins see and control.** *Settings → Sign-in* in the web UI shows org admins
and security leads how Warden trusts the identity provider: issuer, audience, algorithms,
where the keys come from and whether the last fetch worked, which `amr`/`acr` values count as
a second factor, and a link to the provider's console (`WARDEN_OIDC__CONSOLE_URL`). None of
that can be changed from the UI: the issuer is the root of trust for every org on the
server, so switching providers stays an operator setting. What an org admin can change is the
org's sign-in policy, which only tightens the server's rules:

- **Two-factor roles**: require a second factor for more roles (for example every member)
  on top of `WARDEN_OIDC__REQUIRE_MFA_ROLES`. An admin who signed in without one can't
  require it for their own role (`409 MFA_NOT_ENABLED`), so the rule can't lock them out.
- **Allowed email domains**: up to 20 domains; adding a member at any other address is
  refused. Existing members stay. Subdomains must be listed themselves.

**Moving to another identity provider.** Warden links an account to the provider's `sub`
claim, and a new provider gives everyone a new one. A sign-in whose email belongs to an
existing account with a different subject is refused (Warden never merges accounts by
email; the warning in the API log names the new `sub`). To move accounts over:

```bash
# the account's subject at the new provider, if you know it
warden-admin user relink --email them@example.com --sub 00u1abcd2EFGH3ijk4x7
# or: the next sign-in with this email, verified by the new provider, takes over the account
warden-admin user relink --email them@example.com --next-sign-in --within 24h
```

The window (`--within`, at most 7 days) closes after the first sign-in that uses it, and it
needs `email_verified: true` in the token. Both are audited (`user.relink_allowed`,
`user.relinked`) in every org the person belongs to. People who have never signed in need
nothing: they are created on first sign-in.

**Authentik** (tested with 2026.8): create an OAuth2/OpenID provider of client type *public*
with grant types `authorization_code` and `refresh_token` (they start empty), a redirect URI
of the web UI's origin with a trailing `/`, and a signing key (otherwise tokens are HS256,
which Warden refuses). Its default `email` scope mapping sends `email_verified: false`, which
Warden rejects; add a mapping that returns `true` only if your enrollment really verifies
addresses. The issuer is `https://<host>/application/o/<slug>/` with the trailing slash, the
audience is the client ID, and the web UI needs `VITE_OIDC_SCOPE="openid profile email
offline_access"` for refresh tokens. Upstream logins (Google, Okta, …) are *Sources* in
Authentik, shown on its sign-in page once added to the identification stage.

## API

REST under `/api/v1`, authenticated with OIDC bearer tokens (Keycloak access tokens, RS256)
or, for CI, with project API tokens (see below).
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
| `/orgs/{org_id}/projects/{id}/tokens` | API tokens for CI: list, create (the secret is shown once), revoke |
| `/orgs/{org_id}/scans/{id}` | Scan status, `start`, `cancel`, the CI `gate`, and the `sbom` download link |
| `/orgs/{org_id}/license-policy` | The org's license policy (any member reads it, security leads change it) |
| `/orgs/{org_id}/vuln-data` | How fresh the Trivy DB, CISA KEV and FIRST EPSS data are |
| `/orgs/{org_id}/issues` | Issues: filters, counts, transitions, bulk assignment, comments, history |
| `/orgs/{org_id}/exceptions` | False-positive and risk-acceptance requests and decisions |
| `/orgs/{org_id}/audit-log` | Hash-chained audit log |

How it behaves:

- **Uploads bypass the API.** `POST …/projects/{id}/scans` returns a presigned `PUT` URL
  (15 minutes, pinned size and SHA-256); the browser uploads the `.zip` (or, with
  `kind: image` and a `target`, the `.tar`) to object storage and
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
- **Two-factor sign-in.** Roles listed in `WARDEN_OIDC__REQUIRE_MFA_ROLES` (by default
  `org_admin` and `security_lead`), plus roles an org adds in its sign-in policy, get
  `403 MFA_REQUIRED` under `/orgs/{org_id}` unless their access token shows a second factor.
  `GET /me` lists those orgs in `mfa_required_orgs`, so the UI can explain before calling.
- **Sign-in settings.** `GET /orgs/{org_id}/sign-in` (org admins, security leads) returns the
  server's provider settings, the signing-key cache (`ok` / `error` with a category only /
  `not_loaded`; it never triggers a fetch) and the org's policy. `PUT /orgs/{org_id}/sign-in-policy`
  (org admins) sets `mfa_roles` and `allowed_email_domains`; audited as
  `org.sign_in_policy_changed`. API tokens can call neither.
- **API tokens** (`wdn_<prefix>_<secret>`) are machine credentials for CI. A project owner or a
  security lead creates one for one project, with scopes `scan:write` and/or `issues:read` and
  an expiry of 1 to 365 days; the creator also needs `run_scan` there, because a token acts as
  its creator. The secret is returned once; Warden stores only its SHA-256. A token can only
  create, start, cancel and read scans and read the gate (`scan:write`), and list and read
  issues (`issues:read`), in its own project: any other route is `403 TOKEN_SCOPE`, another
  project or org is `404`. Every request re-checks that the creator is still an active member
  who may run scans in the project. A bad, expired or revoked token gets the same `401` as a
  bad access token. Each token is limited to 60 requests per minute (`429` with `Retry-After`,
  counted per API instance). Tokens are exempt from the two-factor rule (creating one as an
  admin or security lead needs it). Creation and revocation are audited (`token.created`,
  `token.revoked`), scans record the token in `via_token`, and every write made with a token
  carries `via_token` in its audit entry.
- **Scan gate.** `GET …/scans/{id}/gate?fail_on=critical|high|medium|low` (default `high`)
  returns `pass`, the severity `counts` of the active issues seen in that scan and up to 100
  `blocking` issues at or above `fail_on`. `false_positive` and `risk_accepted` issues never
  block; a scan that hasn't finished, failed or was cancelled never passes. With
  `fail_on_kev=true`, an active issue with a CVE in CISA KEV blocks whatever its severity.
- **SBOM download.** `GET …/scans/{id}/sbom` returns a presigned `GET` URL valid for 5 minutes,
  served as an attachment (`application/vnd.cyclonedx+json`), with its size and SHA-256. It
  needs view access to the project (API tokens: `scan:write` or `issues:read`); `404` when
  the scan has no SBOM or it expired.
- **Errors** carry a stable `error.code`: `UNAUTHORIZED`, `FORBIDDEN`, `MFA_REQUIRED`,
  `MFA_NOT_ENABLED`, `TOKEN_SCOPE`, `NOT_FOUND`, `VALIDATION_FAILED` (with `metadata.fields`), `CONFLICT`,
  `VERSION_CONFLICT`, `INVALID_TRANSITION`, `USER_NOT_FOUND`, `UPLOAD_MISMATCH`,
  `RATE_LIMITED`, `PROJECT_ARCHIVED`. Unknown JSON fields are rejected; internal errors are logged and returned as
  a generic `500`.
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

## Images, SBOMs, licenses and exploit data

**Container images.** An image scan takes the tarball from `docker save` (Docker and OCI
layouts), at most `WARDEN_SCAN__IMAGE_UPLOAD_MAX_MB`. Warden checks it before Trivy sees it
(`imagecheck`: one image, at most 4096 entries and 256 layers, only files and directories, every
referenced blob present, safe names; it is never unpacked by Warden) and runs only Trivy, in the
same sandbox as any scanner. Rejections are scan errors `IMAGE_INVALID`, `IMAGE_TOO_LARGE` and
`IMAGE_MULTIPLE`. Issues are tracked per `target` (the image repository): an image scan only
auto-fixes issues of the same target, never source-code issues or another image's. Secrets in
image layers are not scanned, because Gitleaks is the only secret scanner (its output is the only
output Warden redacts).

**SBOM.** Trivy writes one JSON report per scan; Warden converts it to SARIF for findings and to a
CycloneDX SBOM (spec 1.7) named after the project key, with a `warden:scan_id` property. It is
kept in object storage for `WARDEN_SCAN__SBOM_RETENTION`. Development dependencies are left out,
as Trivy does by default. A missing or invalid SBOM never fails the scan.

**License policy.** Off until a security lead sets it (Org settings, or
`PUT /orgs/{org_id}/license-policy`). Each Trivy license category (forbidden, restricted,
reciprocal, notice, permissive, unencumbered, unknown) is *allow*, *review* (a Medium issue) or
*block* (a High issue, which fails the default gate); a Deny list of SPDX ids always blocks and an
Allow list never reports (Allow wins, ids compare without case). Expressions follow SPDX: with `OR`
one acceptable alternative is enough, with `AND` any blocked id blocks, `WITH` exceptions count as
the base license; anything else is `LicenseRef-unknown` in Trivy's category. License data comes
from the lockfile: npm `package-lock.json`, Cargo and images carry it, `go.mod` and
`requirements.txt` don't. Changes apply from the next scan (license issues that no longer match
are auto-fixed) and are audited as `org.license_policy_changed`.

**Exploit data.** `make mirror` also downloads the [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
catalog and the [FIRST EPSS](https://www.first.org/epss/) scores into the mirror
(`scripts/sync-mirror.sh intel` refreshes only these; `WARDEN_KEV_URL` and `WARDEN_EPSS_URL`
override the sources). The worker's `load_vuln_intel` job loads them hourly when they change,
after strict checks (sizes, gzip bomb, every row), and keeps the previous data if a file is bad.
Issues then show whether a CVE is known exploited and its EPSS score; the issue list filters
(`kev`, `epss_min`) and sorts (`-epss`) on them, and the gate can fail on KEV. They only rank
issues: they never change severity, status or the SLA, and never hide an issue. KEV matches the
CVE ids Trivy reports, so an alias Trivy doesn't use (for example CVE-2023-44487, which Trivy
reports for `golang.org/x/net` as CVE-2023-39325) isn't flagged. Run the sync daily (cron, or a
Kubernetes CronJob writing to the mirror volume); Org settings warns when a feed is more than 7
days old. Loading uses a temporary table, so the database must keep the default `TEMPORARY`
privilege for `warden_app`.

## CI integration

The `warden` CLI scans a git checkout from a pipeline and fails the build on blocking issues.
It zips the tracked and untracked-but-not-ignored files (no symlinks), uploads the archive,
starts the scan, waits for it and applies the scan gate:

```bash
export WARDEN_TOKEN=wdn_...   # a project API token with scope scan:write
warden scan --url https://warden.example.com --org <org id> --project <project id> \
  [--dir .] [--tools gitleaks,opengrep] [--fail-on high] [--fail-on-kev] [--timeout 30m] \
  [--sbom-out bom.cdx.json]

# a container image instead of the checkout (Trivy only):
warden scan --url … --org … --project … --image ghcr.io/acme/api:1.4.2
warden scan --url … --org … --project … --image-tar api.tar --target ghcr.io/acme/api
```

`--image` runs `docker save` and tracks issues under the repository without its tag
(`alpine` becomes `docker.io/library/alpine`). `--sbom-out` writes the scan's CycloneDX SBOM
after checking its SHA-256 (exit `2` if the scan has none).

It prints the blocking issues (key, severity, title, file:line, link) and exits `0` when the
gate passes, `1` when it fails and `2` on any error (authentication, network, a failed or
timed-out scan). The token is read only from `$WARDEN_TOKEN` and never printed; only `https://`
servers are accepted (plain `http://` only for `localhost`). Create the token under the
project's settings in the web UI (or `POST /orgs/{org_id}/projects/{id}/tokens`) and store it
as a secret CI variable. The `warden` binary ships in the release archives
(`go install github.com/aupv9/warden/backend/cmd/warden@<tag>` also works).

### GitHub Actions

```yaml
name: Warden
on:
  push:
    branches: [main]
  pull_request:          # pull requests from forks get no secrets, so no scan
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-24.04
    env:
      WARDEN_VERSION: v0.2.0
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with: { persist-credentials: false }
      - name: Install the Warden CLI (checksum and provenance verified)
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          a="warden_${WARDEN_VERSION}_linux_amd64"
          gh release download "$WARDEN_VERSION" -R aupv9/warden -D "$RUNNER_TEMP" -p "$a.tar.gz" -p "warden_${WARDEN_VERSION}_checksums.txt"
          cd "$RUNNER_TEMP"
          sha256sum -c --ignore-missing "warden_${WARDEN_VERSION}_checksums.txt"
          gh attestation verify "$a.tar.gz" -R aupv9/warden
          tar -xzf "$a.tar.gz" --strip-components=1 "$a/warden"
      - name: Scan
        env:
          WARDEN_TOKEN: ${{ secrets.WARDEN_TOKEN }}
        run: |
          "$RUNNER_TEMP/warden" scan --url https://warden.example.com \
            --org 00000000-0000-0000-0000-000000000000 --project 00000000-0000-0000-0000-000000000000 --fail-on high
```

### GitLab CI

Add `WARDEN_TOKEN` under Settings → CI/CD → Variables as a masked, protected variable.

```yaml
warden:
  stage: test
  image: alpine:3.22          # pin by digest
  variables:
    WARDEN_VERSION: v0.2.0
    WARDEN_URL: https://warden.example.com
    WARDEN_ORG: 00000000-0000-0000-0000-000000000000
    WARDEN_PROJECT: 00000000-0000-0000-0000-000000000000
  script:
    - apk add --no-cache git curl
    - git config --global --add safe.directory "$CI_PROJECT_DIR"
    - a="warden_${WARDEN_VERSION}_linux_amd64"
    - base="https://github.com/aupv9/warden/releases/download/${WARDEN_VERSION}"
    - curl -fsSLO "$base/$a.tar.gz" && curl -fsSLO "$base/warden_${WARDEN_VERSION}_checksums.txt"
    - grep " $a.tar.gz\$" "warden_${WARDEN_VERSION}_checksums.txt" | sha256sum -c -
    - tar -xzf "$a.tar.gz" --strip-components=1 "$a/warden"
    - ./warden scan --url "$WARDEN_URL" --org "$WARDEN_ORG" --project "$WARDEN_PROJECT" --fail-on high
  rules:
    - if: $CI_COMMIT_REF_PROTECTED == "true"
```

Protected variables are only exposed on protected branches and tags, hence the rule.

## Development

| Command | |
|---|---|
| `make test` | Unit tests with the race detector |
| `make test-int` | Integration tests against a real Postgres (testcontainers): RLS, grants, River |
| `make lint` | gofmt, go vet, staticcheck, tsc |
| `make vulncheck` | govulncheck over dependencies and the Go toolchain |
| `make build` | Static binaries in `backend/bin` |

Code that handles hostile input (`zipcheck`, `imagecheck`, `sarif`, `trivyjson`, `sbom`,
`redact`, `intel`) has tests for the attacks, not just the happy path. Test fixtures never contain real-looking secrets; they are built
at test time.

### Self-scan

Warden scans itself with its own pipeline before every release:

```bash
make mirror             # Trivy DB, pinned Opengrep rules, CISA KEV, FIRST EPSS (the only step that needs the Internet)
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
                         warden-redact, warden-sarif-gate, selfscan, warden (CI client)
  internal/api/          REST API (gin), OpenAPI document
  internal/service/      business rules: permissions, issue workflow, exceptions, scans
  internal/store/        Postgres repositories, hash-chained audit log
  internal/auth/         OIDC access-token and JWKS verification
  internal/domain/       fingerprints, severity mapping, issue state machine, permission matrix,
                         license policy
  internal/scan/         zipcheck, imagecheck, sandbox, SARIF and Trivy JSON parsers, SBOM,
                         redactor, orchestrator, result processor (findings → issues), release gate
  internal/intel/        CISA KEV and FIRST EPSS parsers
  internal/storage/      S3-compatible client (presigned uploads and downloads, put, delete)
  internal/notify/       notification dispatch (outbox → notifications), email rendering, SMTP
  internal/pack/         zips a git working tree like an upload (selfscan, warden CLI)
  internal/worker/       background jobs (River): scans, source and SBOM purge, risk-acceptance
                         expiry, notifications, SLA digest, exploit-data loading
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
(`warden-api`, `warden-worker`, `warden-migrate` and the `warden` CI client; amd64 and arm64) with SPDX SBOMs and
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

- Archives are only ever extracted by `zipcheck.Extract`. Image tarballs are checked by
  `imagecheck` and never extracted by Warden; Trivy reads them inside the sandbox.
- Everything a scanner writes (SARIF, Trivy JSON, the SBOM) is hostile input: size-capped and
  parsed into typed values. SBOMs are only served as attachments through 5-minute links.
- CISA KEV and EPSS only rank issues; they never change severity or status or hide an issue.
- Scanner containers run with `runsc`, `--network=none`, a read-only rootfs, a non-root
  user and `--cap-drop=ALL`, with no Docker socket. Images are pinned by digest.
- Gitleaks is the only secret scanner, and raw secrets never leave its sandbox.
- Uploaded code can't configure its own scan.
- Every business table has `org_id` under forced RLS. The app role has no `BYPASSRLS` and
  can't update or delete the audit log. Only `warden-migrate` connects as the schema owner.
- Permissions are checked in the service layer (`internal/domain/rbac`); RLS is the second
  line of defence.
- Authentication errors are generic; the reason is logged, never returned.
- The identity provider (issuer, audience, keys) is server configuration only; no API or
  org setting can change it. An org's sign-in policy can only add requirements. Accounts are
  never linked by email: only `warden-admin user relink` moves one to a new subject.
- API tokens: only a SHA-256 of the secret is stored and the secret is shown once. Tokens
  are looked up across orgs only through the `warden_lookup_token` SECURITY DEFINER function
  (exact prefix, one row); everything after that runs under the token's org. What a token may
  call is one allow-list (`internal/api/tokens.go`), default deny. Credentials never appear
  in logs.

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
