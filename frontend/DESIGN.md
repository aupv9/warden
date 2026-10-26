# Warden web UI: design spec (v0.1)

This is the target for the first usable release of the web UI: a team uploads code, sees
issues, and works them to closed. The images below are screenshots of the app running on its
mock data (`npm run dev:mock`), so names and numbers are examples. Earlier wireframes and the
design concepts live on a canvas that only maintainers can open; this file is the source of
truth for contributors.

## Flows

1. **Scan:** a project owner or developer uploads a `.zip`, watches each scanner run, and
   lands on the scan's results.
2. **Triage:** a security lead or project owner filters the issue list (severity, status,
   assignee, past SLA) and assigns issues.
3. **Fix:** the assignee starts work and fixes the code. The next scan moves the issue to
   *Fixed*, and the security lead or a later scan moves it to *Verified*. If the finding
   comes back, the issue is *Reopened*.
4. **Exception:** anyone who can update an issue may request *False positive* or *Risk
   accepted*. Only a security lead decides. An accepted risk lasts at most 180 days and then
   reopens by itself.
5. **Access:** an org admin gives people an org role; project owners and security leads give
   them project roles.

Status changes follow `backend/internal/domain/issuestate`, and permissions follow
`backend/internal/domain/rbac`. The UI hides actions the user may not take, and the API
enforces them anyway.

## Screens

| # | Screen | Who | Main content |
|---|---|---|---|
| 1 | Projects | everyone | Org summary (open issues, Critical + High, past SLA, exceptions to review); a card per project with open issues by severity, your role, the last scan and the number past SLA; an empty state for a project with no scan |
| 2 | Upload & scans (project) | owner, developer, security lead | Drop zone with the real limits (200 MB zipped, 1 GB unpacked, 100,000 files); scanner checkboxes (project defaults); live progress per scanner (queued, running, succeeded, failed, timeout); scan history with new / fixed / reopened counts, *partial* (a scanner failed) and *rejected* (archive refused, with the reason) |
| 3 | Issue list | everyone with access | Saved views (Active, Assigned to me, Past SLA, Secrets); search (title, rule, file, `WEB-41`); filter chips for severity, status, project, assignee, scanner, past SLA; grouped by severity; bulk assign; sorted by due date. See "Issue triage" |
| 4 | Issue detail | everyone with access | Opens beside the list on wide screens, as a page otherwise. Severity, status, SLA due date; status stepper; location with the masked snippet; what was found; how to fix; comments; details (assignee, rule, CWE/CVE, package and fixed version, first and last scan seen, number of scans it appeared in); activity from `issue_event`. Actions: start progress, reassign, request exception |
| 5 | Exceptions | security lead decides; others see their own | Tabs: pending, approved, rejected, expiring soon. A queue on the left and a review panel on the right: reason, "accepted until" (≤ 180 days), decision note (required to reject), approve or reject |
| 6 | Members & roles | org admin, security lead, project owner | Org members with org role, projects, MFA, status; project roles per project; the permission matrix, read-only, generated from `rbac.Matrix` |
| 7 | Audit log | org admin, security lead | Filters for action, actor and date range; one row per entry (time, actor, action, target, IP) that expands to show the entry's `data`; a note that the log is append-only and hash-chained |

Members without `view_audit_log` don't see "Audit log" in the navigation.
States, the upload flow, dialogs and the phone layout are specified below the screenshots.

## Screens in the app

Desktop width (1440 px) unless marked as phone (390 px).

### 1. Projects
![Projects: stat strip and compact project cards](design/01-projects.png)

### 2. Upload & scans
![Project Scans tab: drop zone, scanner choice, scan progress, scan history](design/02-upload-and-scans.png)

### 3. Issue list
![Issue list: saved views, filter chips, issues grouped by severity, shortcut footer](design/03-issue-list.png)

### 4. Issue triage (split view)
![An issue open beside the list: stepper, masked snippet, how to fix, comments](design/04-issue-triage.png)

### 5. Exceptions
![Exceptions: pending queue and review panel](design/05-exceptions.png)

### 6. Members & roles
![Members and roles: org members, project roles, permission matrix](design/06-members-and-roles.png)

### 7. Audit log
![Audit log: append-only note, filters, entries](design/07-audit-log.png)

### 8. Command palette (⌘K)
![Command palette: jump to an issue, a project or a page](design/08-command-palette.png)

### 9. Assign dialog
![Assign dialog: searchable list of project members](design/09-assign-dialog.png)

### 10. Empty state
![No issues match the filters](design/10-empty-state.png)

### 11. Dark theme
![Issue triage in the dark theme](design/14-dark-issue-triage.png)

### 12. Phone (390 px)
<img src="design/11-phone-issue-list.png" alt="Phone: issue list as stacked rows" width="260"> <img src="design/12-phone-issue.png" alt="Phone: issue page with vertical stepper" width="260"> <img src="design/13-phone-menu.png" alt="Phone: navigation drawer open" width="260">

## Issue triage

- **Saved views** in the header are presets of the URL filters: Active (default), Assigned to me
  (`assignee=me`), Past SLA (`past_sla=true`), Secrets (`tool=gitleaks`). Search, sort and project
  are kept when switching.
- **Filter chips** read as sentences ("Severity is Critical, High"), each with its own remove
  button; "+ Filter" adds severity, status, project, assignee, scanner or past SLA. "Group by"
  (severity or none, remembered per browser) and "Sort" sit on the right.
- **Groups** are collapsible with counts. Medium, Low and Info start collapsed when they hold 10
  or more issues, unless the open issue is in them.
- **Split view** from 1200 px: `/orgs/:org/issues/:id?<filters>` keeps the list on the left
  (compact rows, the open issue marked with an indigo bar) and the issue on the right, with
  previous/next/close controls and "n of m". Below 1200 px the issue is a page with a
  "‹ Issues / KEY" link back to the filtered list. Only known filters are carried in links.
- **Keyboard** (never while typing in a field or while a dialog is open):

  | Key | Action |
  |---|---|
  | `J` / `K` | Next / previous issue (the open pane follows) |
  | `Enter` | Open the selected issue |
  | `Esc` | Close the pane, focus back on its row |
  | `A` | Assign (bulk selection, else the open or selected issue, if allowed) |
  | `X` | Add or remove the selected issue from the bulk selection |
  | `/` | Focus the search box |
  | `⌘K` / `Ctrl+K` | Command palette: jump to an issue by key or title, a project, or a page |

  A footer bar shows these hints on the issue list.

## Audit log

- Data: `GET /orgs/{org_id}/audit-log`, newest first, paginated with "Load older entries"
  (cursor), not page numbers. Only org admins and security leads (`view_audit_log`).
- Filters: action (the action names, shown as they are, in mono), actor (org members) and a
  from/to date range (see Open decisions). "Clear" resets all three.
- Row: time (relative for today and yesterday, then `Oct 24 14:05`, in the viewer's time zone,
  stated above the table), actor (`null` = "System"), action, target, IP. The target column is
  a one-line summary built from `target_type`, `target_id` and `data` (an issue key and the
  status change, a project key and file name, a member and the role change). If the UI can't
  summarise an action, it shows `target_type` and `target_id`.
- The expand button (`aria-expanded`, `aria-controls`) shows the entry number, the actor's
  email, the full target ID, the UTC timestamp and `data` as pretty-printed JSON. `data` is
  shown as text, never as HTML.
- The note above the filters says what the log guarantees: entries can't be changed or deleted,
  and each hash covers the previous entry. It doesn't claim the chain was verified; the UI
  can't check it (see Open decisions).

## States

### Loading
- Show a skeleton only if data takes more than 300 ms. The page title, tabs and filters render
  at once; only data areas get skeletons. Skeletons are static grey bars (`#E2E7EC`), no
  shimmer.
- The loading region has `aria-busy="true"` and a visually hidden `role="status"` text
  ("Loading issues…").
- Lists: 5 skeleton rows in the real column layout. Detail pages: header bars, then the real
  card layout with bars inside.

### Empty
| Where | Title | Text and action |
|---|---|---|
| `/me` returns no orgs | You're not in an organization yet | Shows the signed-in email and the operator command `warden-admin org create --name "…" --admin <your email>`; "or ask an org admin to add you". Buttons: Sign out, Reload. No navigation besides the logo. |
| Project with no scans | No scans yet | "Upload a .zip of the source to run the first scan. Issues appear here when it finishes." Button "Upload a .zip" only for roles with `run_scan`. Same block on the project's Issues tab. |
| Issue list, filters give nothing | No issues match these filters | Repeats the active filters in words; button "Clear filters". With the default filter: "No active issues. New findings appear here after a scan." |
| Exceptions, pending tab | Nothing to review | "New requests for a false positive or an accepted risk show up here." Non-security-leads: "You have no pending requests." |

### Errors
- **Load failed** (network or 5xx): in place of the data, "Couldn't load issues", a "Try again"
  button, and the `meta.request_id` (when there is one) in small mono text so people can quote
  it to the operator.
- **403 page:** "You don't have access to this", "Your role in <org> doesn't include this page.
  Ask an org admin if you need it." Button back to Projects.
- **404 page:** "Not found", "This page doesn't exist, or you don't have access to it." The API
  answers 404 for objects in orgs or projects the caller can't see, so the UI must not suggest
  which case it is.
- **Sign-in failed / session ended:** one message for every cause (see Security rules).

### Messages
- **Toasts** confirm a finished action or report an action that failed with no better place
  to show it. Bottom right on desktop, full width above the bottom edge on phones, newest at
  the bottom, at most 3. Success: dark (`#0B1220`) with a teal check, `role="status"`, closes
  after 6 s, paused while hovered or focused. Error (`#FFF1F2` / `#881337`) and warning
  (`#FFFBEB` / `#78350F`): `role="alert"`, stay until dismissed. The dismiss button is 44 px.
- **Inline banners** sit where the problem is: at the top of the issue page for
  `VERSION_CONFLICT` and `INVALID_TRANSITION` (actions disabled until "Reload issue"; a comment
  being typed is kept), at the top of a dialog for `CONFLICT`.
- **Field errors** go under the field: text plus an icon, `aria-invalid` and
  `aria-describedby`, a 2 px Critical-colored border, and focus moves to the first invalid
  field. Map `error.metadata.fields` to fields by name; anything left over goes in a banner.

## Error messages

Show the plain words; for scan errors also show the code in small mono text under them, so
people can search for it or quote it. Unknown codes fall back to the last row of each table.

### Scan `error_code`

A scan with status `failed` and a `ZIP_*` or `CHECKSUM_MISMATCH` code is shown as
**Rejected** (the archive was refused before any scanner ran); any other failed scan is
**Failed**. There is no `rejected` status in the API. History rows use the short text; the scan
card uses the full text.

| Code | Short (history) | Full message |
|---|---|---|
| `ZIP_PATH_TRAVERSAL` | path outside the root | The archive has a path outside its root. An entry such as `../config.yml` or `/etc/hosts` would land outside the folder. Re-create the .zip from inside the project folder. |
| `ZIP_BOMB` | suspected zip bomb | The archive unpacks to more than 1 GB, or a file in it is compressed more than 100 to 1. Remove large generated or binary files and try again. |
| `ZIP_TOO_LARGE` | archive over 200 MB | The archive is larger than 200 MB. Leave out dependencies and build output (`node_modules`, `vendor`, `dist`). |
| `ZIP_TOO_MANY_FILES` | over 100,000 files | The archive has more than 100,000 files. Leave out dependencies and build output. |
| `ZIP_ENCRYPTED` | password-protected | The archive is password-protected. Upload a .zip without a password. |
| `ZIP_INVALID` | not a readable .zip | This isn't a readable .zip file. Create the archive again with a standard zip tool. |
| `ZIP_EMPTY` | no source files | No files were left to scan. Warden skips `node_modules`, `vendor`, `dist`, `build`, `.git` and `.venv`. |
| `CHECKSUM_MISMATCH` | file changed in upload | The stored file doesn't match the one you picked, so it was not scanned. Upload it again. |
| `ALL_SCANNERS_FAILED` | every scanner failed | Every scanner failed, so there are no results. Each scanner's error is listed below. If it happens again, tell your operator. |
| `TIMEOUT` | took over 30 min | The scan took longer than the 30-minute limit and was stopped. |
| anything else | failed | The scan failed (`<code>`). Tell your operator; the worker log has the details. |

The numbers are the server defaults (`WARDEN_SCAN__UPLOAD_MAX_MB`, `__UNZIP_MAX_MB`,
`__UNZIP_MAX_FILES`, `__TIMEOUT`); see Open decisions. A *partial* scan says which scanner
failed or timed out: "Partial · Trivy timed out".

Status labels: `pending_upload` Uploading, `queued` Queued, `running` Running · *n* of *m* done,
`completed` Completed, `partial` Partial, `failed` Rejected or Failed, `cancelled` Cancelled.

### API `error.code`

| Code | Where it shows | Message |
|---|---|---|
| `UNAUTHORIZED` (401) | Whole app | Try one silent token refresh and repeat the request. If that fails, go to sign-in with the generic "We couldn't sign you in. Try again." |
| `FORBIDDEN` (403) | Page: 403 page. Action: error toast | "You don't have permission to do that." Then refetch, so the page shows only what the role allows. |
| `NOT_FOUND` (404) | Page: 404 page. Action: error toast | "This no longer exists, or you no longer have access to it." |
| `VALIDATION_FAILED` (422) | Under each field in `metadata.fields` | The server's per-field message; the UI checks the same rules first (key pattern, reason ≥ 20 characters, date ≤ 180 days). |
| `CONFLICT` (409) | Banner in the dialog or toast | Depends on the action: "A project with key WEB already exists." / "Thu Ha is already a member." / "<name> is the last org admin. Make someone else an org admin first." / "This scan already finished." / "This issue already has a pending exception request." |
| `VERSION_CONFLICT` (409) | Banner on the issue page | "Someone changed this issue while you had it open. Your change wasn't saved. Reload to see the latest version, then try again." Never retried automatically. |
| `INVALID_TRANSITION` (422) | Banner on the issue page | "This issue can't move to <status> any more. Reload to see what changed." |
| `USER_NOT_FOUND` (404) | Under the email field, add-member dialog | "No one with this email has signed in to Warden yet. Ask them to sign in once, then add them here." |
| `UPLOAD_MISMATCH` (422) | Upload card, same layout as "upload failed" | "The upload didn't arrive complete. Upload the file again." |
| `RATE_LIMITED` (429) | Upload card (scan create); toast elsewhere | Scans: "You've reached the scan limit for this hour. Nothing was uploaded. Try again later." Elsewhere: "Too many requests in a short time. Wait a minute, then try again." If the response has `Retry-After`, say when. |
| network error, 5xx | Load: in place of the data. Action: error toast | "Warden didn't answer. Check your connection and try again." plus the request ID if there is one. |

## Upload flow

What the New scan card shows at each step:

1. **Choose a file.** The browser checks the extension (`.zip`), the name (≤ 255 characters, no
   `/` or `\`) and the size (≤ 200 MB) before anything is sent.
2. **Checking the file:** the SHA-256 is computed in the browser, with a progress bar. Use
   an incremental hash in a Web Worker (`crypto.subtle.digest` has no progress and needs the
   whole file in memory). "Cancel" stops it; nothing has been sent yet.
3. `POST …/scans` with name, size, hash and the chosen scanners. A 429 shows the hourly-limit
   banner here and nothing is uploaded.
4. **Uploading:** PUT the file to `upload.url` with exactly `upload.headers`, using
   `XMLHttpRequest` so `upload.onprogress` can drive "18 of 48 MB · 38%" (`fetch` has no
   upload progress). "Cancel upload" aborts the request and calls `…/cancel` on the scan.
5. **Upload failed** (network error or a non-2xx answer from storage): "Upload failed at 64%",
   with "Retry upload" and "Choose another file". Retry PUTs again while the link is valid
   (`expires_at`, 15 minutes); after that it cancels the old scan and starts again from step 3,
   without hashing again. The user doesn't see the difference.
6. `POST …/start`. `UPLOAD_MISMATCH` shows the upload-failed card with its own message. On
   success the right-hand card becomes "Scan progress" (screenshot 2).
7. **Finished:** Completed, Partial, Failed or Rejected. A rejected archive shows the full
   message from the table above, the code, "Nothing was scanned and no issues changed" and
   "Upload a new .zip". A cancelled scan shows who cancelled it, when, each scanner's state, and
   "A cancelled scan doesn't change any issue."

Keep the tab open during steps 2–5; if the user tries to leave, the browser's
"leave page?" prompt asks first (`beforeunload`). Poll `GET …/scans/{id}` every 3 s while a
scan is queued or running, and stop when it finishes.

## Dialogs

All dialogs (screenshot 9 shows one): modal, `role="dialog"`, `aria-modal="true"`, `aria-labelledby` on the
title; focus starts on the first field, stays in the dialog, Esc and the 44 px close button
cancel, and focus returns to the button that opened it. The primary button is on the right
and says what it does ("Create project", not "OK"). While the request runs, the primary button
is disabled and shows a spinner; errors appear in the dialog, which stays open.

- **New project** (Projects page; org admin, security lead): key (mono, uppercased while
  typing, `^[A-Z][A-Z0-9]{1,9}$`, "can't be changed later"), name, optional description, default
  scanners (all four checked, at least one). 409: "A project with key WEB already exists."
- **Assign** (issue list bulk action; issue detail "Reassign"; security lead, project owner):
  the selected issues as chips, a search box, and a radio list of the project's members
  (`GET …/projects/{id}/members`) with their project role. The button names the person
  ("Assign to Minh Pham"). `POST …/issues/assign` returns `updated`; if it is less than the
  number selected, the toast says how many were skipped and why ("1 was skipped because it is
  already fixed").
- **Request exception** (issue detail; when `can_request_exception`): the issue key, title and
  severity; type as two radio cards (False positive / Risk accepted, each with one line on what
  it means); reason (live character count, at least 20); "Accepted until" only for Risk accepted:
  a date input with `min` tomorrow and `max` today + 180 days, and the help text names the last
  allowed date. The issue keeps its status until a security lead decides; afterwards the issue
  page shows "Exception requested" and hides the button (`pending_exception_id`).
- **Add org member** (Members page; org admin): email, and the org role as radio cards with one
  line each on what the role can do (Member, Security lead, Org admin). `USER_NOT_FOUND` shows
  under the email field. Warden sends no invitations.

## Phone layout

Below 800 px (screenshots in section 12):

- The sidebar becomes a 56 px light top bar: a 44 px menu button (`aria-expanded`,
  `aria-controls`), the logo, the org name (truncated) and the user's initials. The menu opens
  as a 304 px drawer from the left over a dimmed page, with the org switcher, the navigation,
  the user and "Sign out". Esc, the close button or a tap outside closes it.
- Tables become stacked rows. An issue row is one link (the whole row): key, severity and status;
  title; file and scanner; assignee and due date. Other tables (scans, exceptions, members, audit
  log) follow the same pattern with their first column as the title.
- Issue list: search, then "Filters · *n*" (opens the other filters in a full-screen sheet) and
  the sort select side by side, then the severity chips in one row that scrolls sideways. No
  checkboxes and no bulk assign on phones.
- Issue detail: a 44 px "‹ Issues" back link; the actions under the title, primary full width
  and the others side by side; then the sections in one column in the desktop order (status
  stepper, shown vertically; where; what was found; how to fix; comments; details; activity). The code snippet scrolls sideways inside
  its block (`tabindex="0"` so keyboard users can scroll it).
- Page padding is 16 px; every control stays at least 44 px tall.

## Security rules for the UI

- Never show a raw secret. Secret findings show the masked value only (`AKIA****`, from
  `redact.Mask`) and say that Warden does not keep the secret.
- The comment box warns people not to paste secrets.
- Show authentication errors as one generic message; the reason goes to the server logs.
- Severity is never shown by color alone: every badge carries its label.
- Uploads go straight to object storage. The UI never reads the archive's contents (it
  only hashes the bytes).
- Text that came from scanned code or other users (titles, snippets, comments, audit `data`,
  server error messages) is rendered as text, never as HTML.
- A 404 never says whether the object exists in an org or project the user can't see.

## Visual system

Quiet and light: neutral greys, one indigo accent, severity as small coloured marks next to
their label. Tokens live in `frontend/src/styles/tokens.css`.

| Token | Value | Use |
|---|---|---|
| Ground | `#FBFBFC` | Page background |
| Surface | `#FFFFFF` | Panels, tables, header bars |
| Sidebar | `#F6F6F8` | Sidebar; active item `#E9E9EE` |
| Hover | `#F3F4F6` / `#EEEFF2`; rows `#F8F8FA` | Hover backgrounds |
| Lines | `#ECEDF0` dividers, `#F1F2F4` rows, `#E3E5E8` controls, `#D3D6DB` chips | Borders |
| Ink | `#111318` | Text; primary button (white text, hover `#2A2D35`); code blocks |
| Text 2 / muted / faint | `#3F4450` / `#5E6470` / `#6B7079` | Secondary text; faint is the lightest text colour and is never used on `#EEEFF2` or `#E9E9EE` |
| Accent | `#4F46E5` (hover `#4338CA`) | Links, focus rings, selection, active tabs; tints `#F5F5FF` / `#E8E7FC` |
| Danger | `#D1343A` | Overdue and past-SLA text |

Severity is a 8 px square (radius 2) beside its label, never colour alone:

| Severity | Mark |
|---|---|
| Critical | `#E5484D` |
| High | `#F76B15` |
| Medium | `#FFB224` |
| Low | `#8B8D98` |
| Info | `#C1C4CB` |

Status is a small icon beside its label: open (grey ring), assigned (indigo half ring), in
progress (indigo ring with a filled quarter), reopened (amber `#D97706` dashed ring), fixed
(indigo check), verified (green `#2B9A66` check), false positive and risk accepted (grey
slashed ring).

### Dark theme

The app follows the operating system (`prefers-color-scheme`) unless the viewer picks
System, Light or Dark with the switch at the bottom of the sidebar (also in the phone menu).
The choice is stored per browser (`warden.theme` in localStorage, ignored if invalid) and
applied before the first render as `data-theme` on `<html>`; no inline script, so a strict
CSP still works. Dark tokens use the same names, with the same 4.5:1 rule:

| Token | Dark value |
|---|---|
| Ground / surface / sidebar | `#0E0F12` / `#15171B` / `#111216` |
| Hover / active nav | `#1C1E23`, `#23262C` / `#24272E` |
| Lines | `#24272D` dividers, `#2E3138` controls |
| Ink / text 2 / muted / faint | `#EDEEF0` / `#C5C8CE` / `#A1A5AD` / `#8E929B` |
| Accent | `#8F8BFF` (hover `#AAA7FF`), tints `#1D1C33` / `#2A2850` |
| Primary button | inverted: `#EDEEF0` with `#111318` text |
| Danger | `#FF6B6F` |
| Severity | Critical `#F2555A`, High `#FF802B`, Medium `#FFC53D`, Low `#9497A2`, Info `#6B6F78` |
| Messages | errors `#2A1416` / `#FFA3A6`, warnings `#2A1F0E` / `#FFC97A` |
| Code blocks | `#0A0B0D`, flagged line `#3A1619` |

- **Type:** Inter 400/500/600 for text, JetBrains Mono 400/500 for issue keys, paths, rules
  and code; both self-hosted (`@fontsource`), no requests to font CDNs. Base size 13 px;
  numbers are tabular.
- **Shapes and sizes:** radius 6 for controls, 8 for panels, 2 for marks; 1 px borders and
  almost no shadow. Controls 32 px, table rows 46 px, header bars 52 px, sidebar 224 px; on
  phones every target is at least 44 px.
- **Code blocks:** `#111318` background, `#E6E8EB` text, `#8B8D98` line numbers; the flagged
  line `#4A1D22` with a `#E5484D` bar.
- **Messages:** errors `#FEF2F2` with text `#9B1C1F`; warnings `#FFF8EB` with text `#7A2E0B`;
  skeleton bars `#EDEEF1`.
- **Accessibility:** real `<button>`, `<a>`, `<label>` and `<input>` elements; `aria-label`
  on icon-only controls; visible indigo focus rings; every text/background pair at least
  4.5:1; reduced motion respected.

## Open decisions

In the v0.1 API contract and being built (the UI can rely on them once they land):

- Block a security lead from deciding an exception they requested themselves (403, also
  enforced in the database).
- An "Expiring soon" tab for accepted risks (`?status=expiring`, 14 days).
- Cancel a scan, including a running one.

In the design but not in the API contract:

- Export the issue list as CSV.
- Show users who are deactivated in the identity provider. The API has only Warden's own
  `is_active` flag.
- Audit log date range: the endpoint filters by `action` and `actor_id` only. It needs
  `from`/`to` parameters, or the date filter is dropped.
- Audit log chain check: no endpoint verifies the chain or returns the hashes, so the screen
  only states the guarantee. A "verify" action (or `warden-admin audit verify` for operators)
  would back it up.
- Limits: upload size, unpacked size, file count, scan timeout and the hourly scan limit are
  server settings that no endpoint returns, so the UI shows the defaults (200 MB, 1 GB,
  100,000 files, 30 minutes). An operator who changes them gets wrong text. Proposal: return
  them from `GET /me` or a small `GET /config`.
- `Retry-After` on 429: not specified, so the UI can only say "try again later".
- Abandoned uploads: a scan whose upload never finished (tab closed) stays `pending_upload`
  until something cleans it up. The server should expire them after the 15-minute link.
- Cancelled scans: the design says a cancelled scan changes no issue, and that scanners which
  didn't finish show as *Skipped*. The worker must behave that way.
- Bulk assign across projects: the dialog lists people who are members of every selected
  issue's project. The API doesn't say what happens when the assignee isn't a member of one of
  them; it should skip that issue and count it as skipped.

## Not in v0.1

API tokens and a CI gate, email or Slack notifications, trend dashboards, automatic assignment
rules, per-org SLA and severity overrides, and archiving projects.
