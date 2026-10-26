# Warden web UI: design spec (v0.2)

v0.1 was the first usable release: a team uploads code, sees issues, and works them to closed.
v0.2 adds CI (API tokens and a gate), notifications, an SLA policy, auto-assign rules, archived
projects, an Overview page and the MFA rule; see "v0.2 screens" below. The images below are screenshots of the app running on its
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
| 8 | Overview (v0.2) | everyone (`view_dashboard`) | First item in the navigation. Range 30 / 90 / 180 days and a project filter; open now, new, fixed, open past SLA; open issues per severity over time; new vs fixed; time to fix per severity; SLA compliance. Every chart has its data as a table |
| 9 | Project settings (v0.2) | everyone reads; project owner, security lead edit | General details; API tokens (create with a show-once token, revoke); CI setup snippets; auto-assign rules; archive / unarchive |
| 10 | Org settings (v0.2) | everyone reads; security lead edits (`configure_policy`) | SLA days per severity, with an option to recalculate open issues' due dates |
| 11 | Notifications (v0.2) | everyone, own data | A bell with the unread count in the sidebar header (phone: top bar), a popover with the latest notifications, and a preferences page under the user menu |

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

Screenshots 02 and 04–14 were taken before v0.2 and don't show the Overview and Settings
navigation items or the bell; 01 and 03 are current.

### 13. Overview (v0.2)
![Overview: filters, stat strip, open issues per severity, new vs fixed, time to fix, SLA compliance](design/15-overview.png)

### 14. Project settings: API tokens and CI setup (v0.2)
![Project settings: general, API tokens table, CI setup snippet](design/16-project-settings.png)

### 15. A new API token, shown once (v0.2)
![Create token dialog after creation: warning, the token, Copy](design/17-token-created.png)

### 16. Auto-assign rules (v0.2)
![Rules editor with a moved rule and an invalid new rule](design/18-assign-rules.png)

### 17. Org settings: SLA policy (v0.2)
![SLA policy form](design/19-org-settings.png)

### 18. Notifications (v0.2)
![Bell popover with unread and read notifications](design/20-notifications.png)
![Notification preferences: an email switch per type](design/21-notification-preferences.png)

### 19. Two-factor sign-in required (v0.2)
![MFA_REQUIRED full-page state](design/22-mfa-required.png)

### 20. Archived project (v0.2)
![Archived banner and the disabled upload on the Scans tab](design/23-archived-project.png)

### 21. Dark theme (v0.2 screens)
![Overview in the dark theme](design/24-dark-overview.png)
![A new API token in the dark theme](design/25-dark-project-settings.png)

### 22. Phone (v0.2)
<img src="design/26-phone-overview.png" alt="Phone: Overview with the severity panels stacked" width="260"> <img src="design/27-phone-notifications.png" alt="Phone: notifications popover from the top bar" width="260">

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

- **Counts (v0.2):** every saved view shows its count from `GET /issues/counts` (for the
  project in scope). While a search narrows the current view, that view shows the live match
  count instead.

## v0.2 screens

### Overview

- First item in the navigation (`/orgs/:org/overview`); the org still opens on Projects.
- One row of filters above everything they scope: range as a segmented control (30, 90, 180
  days; `?days=`) and a project select (`?project=`). Changing them keeps the previous charts
  on screen at reduced opacity until the new data arrives (no skeleton flash).
- Stat strip: open now (last day of `open_by_day`), new and fixed in the range, open past SLA
  (`sla.open_overdue`, in the danger colour when above 0).
- **Open issues by severity:** small multiples, one panel per severity, rather than a stacked
  area: Critical and High are too close in colour to share a chart, so each panel is named
  by its label and colour is only a second cue. 2 px line with a 10 % area wash, the current
  value and the change over the range in the panel header, each panel on its own scale (said
  in the subtitle, the maximum on the axis). One crosshair runs through all four panels and
  every header shows the value for that day; the group is focusable and the arrow keys
  (Shift for a week, Home/End, Esc) move the crosshair.
- **New vs fixed:** columns around one zero line, new above (accent) and fixed below (the
  verified green), on one scale. Per day for 30 days, per week (7-day buckets ending today)
  for 90 and 180. Columns are at most 24 px with a 4 px rounded end; hovering a column shows
  both values. A legend with the totals sits in the card header.
- **Time to fix:** a horizontal bar per severity (mean hours from found to first fixed or
  verified, for issues fixed in the range) with the value at the tip ("2.2 days");
  `null` reads "No fixes".
- **SLA compliance:** the share of SLA outcomes that met the SLA, `fixed_in_time ÷
  (fixed_in_time + fixed_late + open_overdue)`, as a large figure, a 100 % bar with 2 px gaps
  (in time green, late amber, open past SLA red) and a legend with the counts.
- Every chart card ends with "Show the data as a table" (a `<details>` with a real table, the
  text alternative for every chart); charts that aren't interactive carry a summary in
  `aria-label`. Colours are theme tokens, so both themes work; text never takes a series colour.

### Project settings

Cards in this order; a project owner or security lead (`manage_project_members`) edits, everyone
else reads.

- **General:** the v0.1 details plus Status (Active / Archived on a date).
- **API tokens:** table of name with the prefix only (`wdn_k7m2q4xa_…`), scopes, created
  (date and by), last used, status (Active with the end date, "Expires in n days" in amber
  within 7 days, Expired, Revoked with the date). Revoked rows are dimmed; "n active of m"
  under the table. "Create token" needs `run_scan` as well (a token scans as its creator): an
  org admin who isn't a project member sees it disabled, with the reason, and can still list
  and revoke. Archived projects can't get new tokens.
- **Create token dialog:** name (1–80, "say where it's used"), scopes as cards (Run scans
  `scan:write`, default on; Read issues `issues:read`; at least one), expiry (7, 30, 90
  (default), 180 days, 1 year, with the date). After "Create token" the same dialog shows the
  token once: a warning banner ("Copy the token now. This is the only time Warden shows it…"),
  the token in a read-only mono box that is focused and selected, a Copy button whose result
  is announced in a polite live region (or, when the Clipboard API fails, the text stays
  selected and the message says to press ⌘C / Ctrl+C), the hint to store it as `WARDEN_TOKEN`,
  and "Done".
- **Revoke:** confirm dialog naming the token and its prefix ("CI jobs that use it start failing
  at once. This can't be undone."), danger button "Revoke token".
- **CI setup:** three steps (create a token with `scan:write`, store it as the CI secret
  `WARDEN_TOKEN`, add the job), then tabs (ARIA tabs, arrow keys) for GitHub Actions and
  GitLab CI with a Copy button. The snippets run `warden scan --url <this server> --org <org id>
  --project <project id> --fail-on high` and read the token from the CI secret; no token is
  ever written into a snippet, not even right after one was created. A note explains the exit
  codes (1 gate failed, 2 error).
- **Auto-assign rules:** an ordered list; the first matching rule wins and only new issues are
  assigned. Each rule is a fieldset ("Rule n") with path glob (mono, ≤ 200 characters), scanner
  (Any or one), severity at least (Any or one) and the assignee (project members with their
  role). Move up / down and remove are icon buttons with names ("Move rule 2 up"); after a move
  focus stays on the moved rule and a live region says "Rule moved to position 1 of 3".
  Errors under the fields: no condition, glob too long or not printable, no assignee, an
  assignee who left the project ("Former member (skipped)" in the select); at most 50 rules.
  Server field errors (`items[i].…`) map to the rule. "n of 50", "Discard changes", "Save
  rules" (enabled when something changed). Without the permission the rules read as sentences
  ("Path matches deploy/** and severity is High or above → Linh Tran").
- **Archive / Unarchive** (org admin, security lead): a card with a red border, explaining what
  stops and what stays, and a confirm dialog.
- **Archived projects:** a warning-coloured strip under the project header ("Archived Oct 6,
  2026. This project takes no new scans…", with "Unarchive…" for those who may), an Archived
  tag in the title, no "Upload .zip" button, and the New scan card replaced by a disabled drop
  zone. The Projects page hides archived projects unless "Show archived" is ticked
  (`?archived=1`), where they carry an Archived tag. The scan history names the token for scans
  run from CI ("via token GitHub Actions (main)").

### Org settings

`/orgs/:org/settings`, "Settings" under Organization in the navigation. SLA policy: one field
per severity (whole days, 1–365, text inputs with a "days" suffix so scrolling can't change
them), and "Also recalculate the due dates of open issues" (`recompute_open`) with what it
does. "Save policy" is enabled once something changed; the toast says whether open issues
were recalculated. Without `configure_policy` the values are shown as text with "Only security
leads can change the SLA policy."

### Notifications

- **Bell:** next to the org switcher in the sidebar header (in the phone top bar, next to the
  avatar). The accessible name carries the count ("Notifications, 3 unread"); the badge shows
  up to 99+. The count is polled every 60 s while the tab is visible and not at all while it's
  hidden; coming back to the tab refreshes it at once.
- **Popover:** "Notifications" with "Mark all as read"; the latest 20 (then "Load older"), each
  with an unread dot, the server's title (as text), who and when, and the org when the user is in
  several; a check button marks one read. Opening one marks it read and goes to its link. Links
  are followed only when they are same-origin app paths (`/…`, not `//…` or a URL); otherwise
  the item has no link. Footer link to the preferences.
- **Preferences** (user menu → Notification preferences; `/orgs/:org/preferences`): one row per
  type with what it means and an Email switch (a checkbox with `role="switch"`). Defaults: all
  on except "Scan finished". These are the user's own and apply in every org.
- **User menu:** the person at the bottom of the sidebar is now a menu button (email,
  Notification preferences, Sign out).

### Two-factor sign-in required

When `me.mfa_required_orgs` lists the org, or any request in the org answers `MFA_REQUIRED`, the
org's pages are replaced by one full-page state: "Two-factor sign-in required", why (the role
in that org needs it; this session didn't use it), what to do, a primary "Sign out and sign in
again" button, and links to the user's other orgs. The org's navigation, search and data stay
unloaded behind it; the org switcher, theme and bell still work. It is never shown as a 403 or
a toast.

### Code splitting

Every page is its own chunk, loaded on first visit (`React.lazy`, a Suspense skeleton in the
org and project layouts after the usual 300 ms). React, the router, TanStack Query and
oidc-client-ts are vendor chunks preloaded next to the entry, cached across Warden upgrades.

### Mock mode (v0.2)

`npm run dev:mock` also has: tokens (active, expiring, expired, revoked; a created token is a
plainly fake `wdn_<prefix>_mocksecret…`), auto-assign rules on WEB, notifications, preferences,
deterministic metrics per project, an archived project (LEG), a read-only org (Acme Labs, where
the user is a member) and an org that requires MFA (Acme Security). `?mock_bulk=1` adds 240
tokens and 300 notifications to check long lists.

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
| `MFA_REQUIRED` (403, v0.2) | Whole org: the "Two-factor sign-in required" page | Never a 403 page or a toast. |
| `PROJECT_ARCHIVED` (409, v0.2) | Upload card | "This project is archived, so it doesn't take new scans. Unarchive it first." (The UI hides uploads for archived projects, so this only shows after a race.) |
| `TOKEN_SCOPE` (403, v0.2) | CLI only | "This API token isn't allowed to do that." The UI never uses tokens. |

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
- **API tokens (v0.2):** the full token is in the create response only. It is kept in the
  dialog's component state and dropped when the dialog closes; the create mutation resolves
  with the token's metadata only, so it never reaches TanStack Query's caches, and it is never
  put in the URL, browser storage or a log (`src/api/tokens.test.ts`). Lists show the prefix
  only. CI snippets read the token from a CI secret and never contain one.
- **Notification links (v0.2)** are followed only when they are same-origin app paths.

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

## Not in v0.2

Slack notifications, severity overrides, editing project details (name, default scanners),
and a custom date range on the Overview. (API tokens and the CI gate, email notifications,
trend charts, auto-assign rules, the per-org SLA policy and archiving shipped in v0.2.)
