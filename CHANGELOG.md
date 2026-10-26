# Changelog

All notable changes to Warden are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
- Web UI redesign: a quiet light theme (Inter, indigo accent, severity marks), issue triage
  with saved views, filter chips, issues grouped by severity and a split view (list beside
  the open issue), keyboard shortcuts (J/K, Enter, Esc, A, X, /) and a ⌘K command palette.
- The frontend's API types are checked against the backend's OpenAPI document in CI.
- UI/UX design for the first usable release ([`frontend/DESIGN.md`](frontend/DESIGN.md)):
  - core flows (scan, triage, fix, exception, access)
  - wireframes for six screens, with images in `frontend/design/`: projects, upload and
    scans, issue list, issue detail, exceptions, members and roles
  - security rules for the UI
  - a visual system of its own
  - audit log, states, upload flow, dialogs and phone layout (images 07–14)
