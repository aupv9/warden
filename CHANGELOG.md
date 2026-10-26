# Changelog

All notable changes to Warden are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- UI/UX design for the first usable release ([`frontend/DESIGN.md`](frontend/DESIGN.md)):
  - core flows (scan, triage, fix, exception, access)
  - wireframes for six screens, with images in `frontend/design/`: projects, upload and
    scans, issue list, issue detail, exceptions, members and roles
  - security rules for the UI
  - a visual system of its own: dark sidebar, teal accent, severity colors that differ in
    lightness, IBM Plex type

The web UI itself is still a skeleton (sign-in and `/api/v1/me`). The screens above are not
implemented yet.
