# Changelog

All notable changes to Warden are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
- Web UI redesign: a quiet light theme (Inter, indigo accent, severity marks), issue triage
  with saved views, filter chips, issues grouped by severity and a split view (list beside
  the open issue), keyboard shortcuts (J/K, Enter, Esc, A, X, /) and a ⌘K command palette.
- Dark theme: follows the OS by default, with a System / Light / Dark switch in the sidebar.
- The frontend's API types are checked against the backend's OpenAPI document in CI.
- UI/UX design for the first usable release ([`frontend/DESIGN.md`](frontend/DESIGN.md)):
  - core flows (scan, triage, fix, exception, access)
  - wireframes for six screens, with images in `frontend/design/`: projects, upload and
    scans, issue list, issue detail, exceptions, members and roles
  - security rules for the UI
  - a visual system of its own
  - audit log, states, upload flow, dialogs and phone layout (images 07–14)
