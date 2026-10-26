# Warden web UI: design spec (v0.1)

This is the target for the first usable release of the web UI: a team uploads code, sees
issues, and works them to closed. The screens below are wireframes. Copy, names and numbers in
them are examples. The wireframes live on a design canvas that only maintainers can open;
this file is the source of truth for contributors.

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
| 3 | Issue list | everyone with access | Search (title, rule, file, `WEB-41`); filters for project, status (default: active), assignee, scanner, severity chips with counts, "past SLA only"; bulk assign; sorted by due date |
| 4 | Issue detail | everyone with access | Severity, status, SLA due date; location with the masked snippet; how to fix; comments; details (assignee, rule, CWE/CVE, package and fixed version, first and last scan seen, number of scans it appeared in); workflow steps; history from `issue_event`. Actions: start progress, reassign, request exception |
| 5 | Exceptions | security lead decides; others see their own | Tabs: pending, approved, rejected, expiring soon. A queue on the left and a review panel on the right: reason, "accepted until" (≤ 180 days), decision note (required to reject), approve or reject |
| 6 | Members & roles | org admin, security lead, project owner | Org members with org role, projects, MFA, status; project roles per project; the permission matrix, read-only, generated from `rbac.Matrix` |

Audit log is in the navigation but has no screen yet.

## Wireframes

Desktop width (1440 px). Names, numbers and files are examples.

### 1. Projects
![Projects: org summary and project cards](design/01-projects.png)

### 2. Upload & scans
![Upload and scans: drop zone, live scanner progress, scan history](design/02-upload-and-scans.png)

### 3. Issue list
![Issue list: search, filters, severity chips, results table](design/03-issue-list.png)

### 4. Issue detail
![Issue detail: masked secret, how to fix, comments, details, workflow, history](design/04-issue-detail.png)

### 5. Exceptions
![Exceptions: pending queue and review panel](design/05-exceptions.png)

### 6. Members & roles
![Members and roles: org members, project roles, permission matrix](design/06-members-and-roles.png)

## Security rules for the UI

- Never show a raw secret. Secret findings show the masked value only (`AKIA****`, from
  `redact.Mask`) and say that Warden does not keep the secret.
- The comment box warns people not to paste secrets.
- Show authentication errors as one generic message; the reason goes to the server logs.
- Severity is never shown by color alone: every badge carries its label.
- Uploads go straight to object storage. The UI never reads the archive's contents.

## Visual system

Warden has its own look, not tied to any company brand.

| Token | Value | Use |
|---|---|---|
| Ink | `#0B1220` | Text; sidebar background; code block background |
| Muted | `#556070` | Secondary text (≥ 4.5:1 on white) |
| Ground | `#F4F6F8` | Page background |
| Surface | `#FFFFFF` | Cards, tables |
| Line | `#DDE2E8` / `#EDF0F3` | Borders / row dividers |
| Accent | `#0F766E` (hover `#115E59`) | Primary buttons, links, progress, selected state |
| Accent tint | `#F0FDFA` / `#99F6E4` | Selected chips, drop zone, success pills |
| Sidebar active | `#134E4A` on `#5EEAD4` text | Current navigation item |

Severity, by the usual security-tool convention, also differing in lightness:

| Severity | Badge |
|---|---|
| Critical | `#9F1239`, white text |
| High | `#C2410C`, white text |
| Medium | `#FEF3C7`, text `#92400E` |
| Low | `#E2E8F0`, text `#334155` |

"Past SLA" text and the highlighted secret line in a code snippet use the Critical color.

- **Type:** IBM Plex Sans for text; IBM Plex Mono for code, rule IDs, file paths and issue keys
  (`WEB-41`).
- **Shapes:** cards have a 12 px radius and a 1 px border with no shadow; buttons and status
  pills are fully rounded (pills).
- **Sizes:** controls are at least 44 px tall, and dense table controls at least 36 px. Page
  padding is 32 × 40 px and the gap between cards is 16–20 px.
- **Layout:** a 232 px dark sidebar beside fluid content. Below about 800 px the sidebar
  stacks on top and wide tables scroll inside their card.
- **Accessibility:** use real `<button>`, `<a>`, `<label>` and `<input>` elements;
  `aria-label` on icon-only controls; text contrast of at least 4.5:1.

## Open decisions

These are in the wireframes but not yet in the backend:

- Block a security lead from deciding an exception they requested themselves.
- An "Expiring soon" tab for accepted risks.
- Export the issue list as CSV.
- Cancel a running scan.
- Show users who are deactivated in the identity provider.

## Not in v0.1

API tokens and a CI gate, email or Slack notifications, trend dashboards, automatic assignment
rules, per-org SLA and severity overrides, and archiving projects.
