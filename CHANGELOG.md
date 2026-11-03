# Changelog

All notable changes to Warden are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- A Kubernetes sandbox backend (`WARDEN_SCAN__SANDBOX_BACKEND=kubernetes`, `WARDEN_SCAN__KUBE__*`):
  each scanner runs as a hardened gVisor Pod in a sandbox namespace, with no service-account
  token and no network (a startup canary and a per-Pod gate check it); source and reports move
  only through `warden-sandbox-io` over the exec API (checked like hostile archives, fuzzed);
  the worker needs no Docker socket and only a Role in that namespace. Readiness check
  `sandbox` replaces `docker`.
- Helm chart `deploy/helm/warden`: API, migrate hook, worker, sandbox namespace (Pod Security
  restricted, default-deny NetworkPolicy, quota), minimal RBAC, secrets from an existing Secret
  mounted per Pod, mirror claims and CronJob without Docker, optional ServiceMonitor, a strict
  values schema; CI jobs `helm` (lint, kubeconform, security properties) and `kube` (kind with
  gVisor).

### Fixed

- An Opengrep result whose rule id was only Warden's rules-directory prefix (`data.rules.`)
  became a finding with no rule id and no title (found by `FuzzParse` during the
  v0.5.0-alpha.2 release, whose run stopped there; nothing was published for that tag).
- An SPDX SBOM with a key that differs from `documentNamespace`, `name`, `creationInfo` or
  `comment` only in case (`docUmentNamespace`) kept it next to the value Warden stamped, so a
  reader that matches keys without case could take the forged one; such keys are now removed
  (found by `FuzzStampSPDX`).

## [0.6.0-alpha.1] - 2026-11-03

### Added

- An organization's own scan rules (`/orgs/{org_id}/scan-rules`, *Settings → Scan rules*):
  Opengrep and Gitleaks rules parsed into a subset that can only add findings and rendered again
  before a scanner sees them (`internal/rules`, fuzzed), per org or per project, versioned
  (append-only), audited without their bodies, closed to API tokens. Findings and issues carry
  `org.<key>`; scans record the org rules they ran (`Scan.org_rules`) and only those can fix
  their issues. `Issue.org_rule`, an Org rule tag and card. Rule check (`validate`) and *Test on a
  snippet* (job `test_rules`, the draft rule alone in the sandbox, snippet deleted afterwards).
  Error code `RULE_INVALID`; permission `manage_rules` (org admins, security leads); migration
  00014. Org rules can't carry a secret out of the sandbox: Opengrep messages can't use
  metavariables, an org Opengrep finding takes its title from the rule and keeps no source
  snippet, and secrets org Gitleaks rules find are masked whole.

## [0.5.0-alpha.2] - 2026-11-02

### Added

- `GET …/issues/export.csv`: the issue list as CSV with its filters and visibility, fixed
  columns without descriptions or snippets, at most 50,000 rows, 30 per user per hour, audited
  (`issues.exported`), spreadsheet formulas defused; an Export CSV button on the issue list.
- `POST …/audit-log/verify` and a Verify chain button on the audit log (10 per org per hour,
  audited as `audit.verified`).
- `GET /orgs/{org}/targets` (the issue list's Image filter without a project in scope) and
  `GET …/components/ecosystems` (the inventory's ecosystem filter, with counts).
- Webhook delivery log filter `?state=pending|delivered|failed`.
- Backups: `scripts/backup.sh`, `scripts/restore.sh` (empty databases only, manifest checked)
  and `make backup-drill`; README sections on backups, upgrading and rollback.
- Job `prune_notifications` (`WARDEN_NOTIFY__READ_RETENTION`, 90 days;
  `WARDEN_NOTIFY__UNREAD_RETENTION`, 365 days), through the `SECURITY DEFINER` function
  `warden_prune_notifications()` (migration 00013); the app role still can't delete them.

### Changed

- `POST …/issues/assign` returns `skipped` next to `updated`.
- `POST …/webhooks` answers `409 WEBHOOK_LIMIT` or `409 SECRETS_KEY_MISSING` instead of
  `CONFLICT`; updating or rotating a webhook without `secrets.key` is `SECRETS_KEY_MISSING`.
- A project's component list puts malicious components first; cursors from earlier versions
  are refused (`422`).
- River keeps completed and cancelled jobs 7 days and discarded ones 30 days.
- Fuzz targets for every hostile-input parser (26, each asserting a property), `make fuzz`
  and a CI job `fuzz` (30 s per target on every pull request).

### Fixed

- Gitleaks output whose secret matched a SARIF key (`runs`, `results`, `ruleId`) was masked
  into a document with no results, so the secret went unreported; such a document now fails
  the scanner visibly.
- A CycloneDX property with a repeated key (`{"name":"warden:scan_id","name":"x"}`) passed the
  check on Warden's own properties and was kept as written; properties are now re-encoded from
  what was checked, and `warden:` is matched in any case.
- Archive entries with a path component over 255 bytes, a path too long for the file system, or
  a name it can't store made extraction fail with an internal error instead of rejecting the
  upload (`ZIP_PATH_TRAVERSAL`).

## [0.5.0-alpha.1] - 2026-11-02

### Added

- Production deployment with Docker Compose (`deploy/compose/`): profiles `core` (Postgres,
  migrate, API with the web UI, Caddy with automatic TLS), `s3` (SeaweedFS), `scanner` (the
  worker on `runsc`, ideally on a dedicated scan VM) and `mirror` (daily sync, systemd timer);
  `scripts/gen-secrets.sh` and `scripts/scanner-images.sh`.
- The release image bundles the web UI in `warden-api` (`-tags webui`, served with its own
  Content Security Policy built from the identity provider's discovery document) and a pinned
  static `docker` CLI for the worker.
- `GET /api/v1/web-config`: the web UI reads its OIDC client settings at run time
  (`WARDEN_WEB__OIDC_CLIENT_ID`, `__OIDC_SCOPE`, `__OIDC_AUDIENCE`) and shows "Can't reach the
  server's sign-in settings" if it can't.
- `WARDEN_STORAGE__PUBLIC_ENDPOINT`: presigned URLs for the store's public name while the API and
  worker use the internal endpoint.
- `WARDEN_APP__ENV=prod` refuses `runc`, plain-http sign-in and public URLs, and placeholder
  secrets; the worker also refuses scanners without an image, checks Docker for the runtime,
  pulls missing pinned images and removes containers and scratch directories of scans that are
  no longer running (scanner containers are labelled `warden.scan`).
- Schema gate: the API and worker refuse a database migrated by a newer Warden; on an older one
  the API isn't ready and the worker takes no jobs until `warden-migrate` runs.
  `warden-migrate status`.
- Prometheus metrics on an internal listener (`WARDEN_ADMIN__ADDR`), with the worker's
  `/healthz` and `/readyz` and `warden-worker -healthcheck`: scans, scan duration, queue depth,
  tool runs, webhook deliveries, notifications sent and feed age, with no org or project labels.
- `make build-webui`, `make image`, `make image-smoke`; CI smoke-tests the image and the
  production compose on gVisor.

### Changed

- The web UI no longer takes `VITE_OIDC_*` at build time (and no longer falls back to a
  localhost Keycloak); set `WARDEN_WEB__OIDC_*` on the API instead. Fonts are no longer inlined
  as `data:` URLs.
- Redis is gone from the dev stack and `.env.example` (nothing used it).
- `sync-mirror.sh` falls back to CISA's `cisagov/kev-data` copy on GitHub when the KEV feed at
  cisa.gov fails (`WARDEN_KEV_FALLBACK_URL`).
- `warden_app` may read `goose_db_version` (for the schema gate).

### Fixed

- The arm64 release image contained amd64 binaries (`ARG TARGETARCH=amd64` overrode
  BuildKit's value).

## [0.4.0-alpha.2] - 2026-11-02

### Added

- Secrets in git history: `warden scan --history` uploads a `git bundle` (checked by
  `bundlecheck` without being unpacked, read by git only inside the Gitleaks sandbox) and scans
  every commit with Gitleaks. One issue per rule and secret under the target `(history)`, with
  the oldest commit that added it; author, email and commit message never leave the sandbox.
  Issue filter `source=history`, scan errors `BUNDLE_*`, `WARDEN_SCAN__HISTORY_UPLOAD_MAX_MB`
  and `__HISTORY_MAX_COMMITS`, and `selfscan -bundle`.
- Webhooks and Slack (Organization → Integrations, `/orgs/{org_id}/webhooks`, org admins and
  security leads): signed generic webhooks (Standard Webhooks) and Slack Incoming Webhooks for
  scan, issue, exception and malicious-package events, with project and severity filters, a
  test button and a 30-day delivery log. URLs and secrets are encrypted under
  `WARDEN_SECRETS__KEY` (`warden-admin secrets rotate`); delivery refuses internal addresses,
  proxies and redirects; failing webhooks are turned off after `WARDEN_WEBHOOK__FAILURE_LIMIT`
  failures (or `410`) with a "Webhook turned off" notification.
- `warden scan --comment auto|github|gitlab`: one summary comment on the pull or merge request,
  updated on every run, with hostile text escaped; the CI token goes only to the CI's API.
  `Gate.blocking_new` marks the blocking issues a scan created or reopened.
- Web UI: history issues ("Found in git history"), the Integrations page, and CI setup switches
  for PR/MR comments and nightly history scans.

## [0.4.0-alpha.1] - 2026-11-02

### Added

- Org-wide component inventory: every package of each project's current scan per target,
  searchable by name, ecosystem and version ("which projects use xz 5.6.0?") with where each
  one is used, plus a Components tab per project and `GET …/projects/{id}/targets`.
- Malicious-package detection from OSV `MAL-` advisories (mirrored per ecosystem by
  `make mirror`): a matching package is a Critical issue with a `component.malicious`
  notification, at scan time and, for packages already in the inventory, as soon as a new
  advisory is loaded. Issue filter `kind=malicious`, a "Malicious" view and an Overview banner.
- SPDX 2.3 JSON SBOM next to the CycloneDX one (`GET …/sbom?format=spdx`,
  `warden scan --sbom-format spdx`).
- `license_category` on license-policy issues (existing issues are backfilled).
- `make e2e`: an end-to-end smoke test against the running dev stack.

## [0.3.0-alpha.1] - 2026-10-28

The first published release of everything merged since 0.1.0-alpha.1, including the v0.2
work (CI integration, notifications, two-factor sign-in, SLA policy and metrics), which was
never tagged on its own.

### Added

- CI integration: project API tokens (`wdn_…`, one project, scopes `scan:write` /
  `issues:read`, 1–365 day expiry, stored as a SHA-256 hash, shown once, revocable, rate
  limited), a scan gate endpoint, and the `warden scan` CLI that uploads a git checkout,
  waits for the scan and exits non-zero on blocking issues. README has GitHub Actions and
  GitLab CI examples that install a checksum- and provenance-verified CLI release.
- Two-factor sign-in required for org admins and security leads (configurable with
  `WARDEN_OIDC__REQUIRE_MFA_ROLES`); `warden-admin org set-role` as a break-glass.
- Notifications: in-app (bell) and email for assignments, reopened issues, exception requests
  and decisions, finished scans and a daily SLA digest; per-user preferences. Emails never
  contain snippets, descriptions or secrets.
- Org SLA policy, project auto-assign rules (path glob, scanner, severity) and archiving.
- Overview page with metrics: open issues by severity over time, new vs fixed, time to fix,
  SLA compliance; counts on every saved view.
- Route-level code splitting in the web UI (entry chunk 586 kB → 70 kB).
- Sign-in settings for org admins and security leads: a read-only view of how Warden trusts
  the identity provider (issuer, audience, algorithms, signing-key status, second-factor
  claims, optional console link from `WARDEN_OIDC__CONSOLE_URL`), and an org sign-in policy
  that can only tighten the server's rules: require a second factor for more roles, and limit
  new members to allowed email domains. An admin can't require a second factor for their own
  role without having one (`409 MFA_NOT_ENABLED`).
- `warden-admin org add-member` and `warden-admin user relink` (`--sub`, or `--next-sign-in`
  within a window of up to 7 days) for moving accounts to another identity provider. Accounts
  are still never linked by email automatically.
- Container image scans: upload a `docker save` tarball (or `warden scan --image REF`); it is
  validated without being unpacked and scanned by Trivy only. Issues are tracked per image
  repository, so image and source scans never auto-fix each other's issues.
- A CycloneDX SBOM for every scan that runs Trivy, downloadable from the scan (5-minute
  link) or with `warden scan --sbom-out`; kept for `WARDEN_SCAN__SBOM_RETENTION` (1 year).
- Org license policy (off by default): per Trivy license category allow / review (Medium) /
  block (High), plus Deny and Allow lists of SPDX ids.
- CISA KEV and FIRST EPSS from the mirror (`make mirror`), loaded hourly by the worker:
  KEV and EPSS on issues, filters and a sort in the issue list, "Exploited (KEV)" and
  "Licenses" views, `fail_on_kev` on the gate (`warden scan --fail-on-kev`), and a
  "Vulnerability data" card that shows how fresh the feeds are.
- Web UI redesign: a quiet light theme (Inter, indigo accent, severity marks), issue triage
  with saved views, filter chips, issues grouped by severity and a split view (list beside
  the open issue), keyboard shortcuts (J/K, Enter, Esc, A, X, /) and a ⌘K command palette.
- Dark theme: follows the OS by default, with a System / Light / Dark switch in the sidebar.

### Changed

- CI blocks un-baselined High self-scan findings on every pull request, not only on tags.
- Trivy writes one JSON report; the SARIF and the SBOM are converted from it. Vulnerability
  fingerprints are unchanged.

### Fixed

- `WARDEN_SCAN__UNZIP_MAX_MB` and `WARDEN_SCAN__UNZIP_MAX_FILES` were ignored (the worker
  always used 1 GB and 100,000 files), and source archives were capped at 200 MB whatever
  `WARDEN_SCAN__UPLOAD_MAX_MB` said.
- The auto-close guard applies only when a scan would fix 5 or more issues, so a small
  project fixing its only finding gets it closed.

## [0.1.0-alpha.1] - 2026-10-26

Tagged, but the release workflow failed, so no binaries or image were published for it.

### Added

- REST API for the first usable release (OpenAPI 3.1 at `/api/v1/openapi.json`):
  - sign-in provisions the user; orgs are created by an operator with
    `warden-admin org create`
  - org and project members with role-based permissions; objects outside your reach
    return 404
  - scans uploaded straight to object storage through a presigned URL that pins the size
    and SHA-256; per-user hourly limit
  - issues: filters, the status workflow with optimistic locking, bulk assign, comments,
    history
  - exceptions (false positive, accepted risk up to 180 days) decided by a security lead,
    never by the requester
  - append-only audit log, hash-chained per org; `warden-admin audit verify` checks it
- Scan worker runs the full pipeline: download, verify, extract, sandboxed scanners,
  findings turned into issues (dedupe by fingerprint, automatic fixed and reopened, a guard
  against mass auto-close), source deleted on every path. Periodic jobs purge old sources
  and abandoned uploads, and reopen expired accepted risks.
- Web UI for all core screens: projects, upload and scans (in-browser SHA-256 with
  progress), issue list and detail, exceptions, members and roles, audit log; loading,
  empty and error states; phone layout.
- The frontend's API types are checked against the backend's OpenAPI document in CI.
- UI/UX design for the first usable release ([`frontend/DESIGN.md`](frontend/DESIGN.md)):
  - core flows (scan, triage, fix, exception, access)
  - wireframes for six screens, with images in `frontend/design/`: projects, upload and
    scans, issue list, issue detail, exceptions, members and roles
  - security rules for the UI
  - a visual system of its own
  - audit log, states, upload flow, dialogs and phone layout (images 07–14)

[Unreleased]: https://github.com/aupv9/warden/compare/v0.6.0-alpha.1...HEAD
[0.6.0-alpha.1]: https://github.com/aupv9/warden/compare/v0.5.0-alpha.2...v0.6.0-alpha.1
[0.5.0-alpha.2]: https://github.com/aupv9/warden/compare/v0.5.0-alpha.1...v0.5.0-alpha.2
[0.5.0-alpha.1]: https://github.com/aupv9/warden/compare/v0.4.0-alpha.2...v0.5.0-alpha.1
[0.4.0-alpha.2]: https://github.com/aupv9/warden/compare/v0.4.0-alpha.1...v0.4.0-alpha.2
[0.4.0-alpha.1]: https://github.com/aupv9/warden/compare/v0.3.0-alpha.1...v0.4.0-alpha.1
[0.3.0-alpha.1]: https://github.com/aupv9/warden/compare/v0.1.0-alpha.1...v0.3.0-alpha.1
[0.1.0-alpha.1]: https://github.com/aupv9/warden/releases/tag/v0.1.0-alpha.1
