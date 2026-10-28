import type { NotificationType } from "../api/types";

export const NOTIFICATION_LABELS: Record<NotificationType, { label: string; detail: string }> = {
  "issue.assigned": { label: "Issue assigned to you", detail: "Someone (or an auto-assign rule) assigns an issue to you." },
  "issue.reopened": {
    label: "Issue reopened",
    detail: "A scan finds an issue you own again. Project owners hear about unassigned ones.",
  },
  "exception.requested": {
    label: "Exception requested",
    detail: "Someone asks for a false positive or an accepted risk. Sent to security leads.",
  },
  "exception.decided": { label: "Exception decided", detail: "A security lead approves or rejects your request." },
  "scan.finished": { label: "Scan finished", detail: "A scan you started, from the UI or with your API token, ends." },
  "sla.due_soon": { label: "Due soon (daily digest)", detail: "One email a day listing your issues close to their SLA." },
  "sla.overdue": { label: "Overdue (daily digest)", detail: "One email a day listing your issues past their SLA." },
  "component.malicious": {
    label: "Malicious package found",
    detail: "An OSV advisory lists a package version in your projects as malicious, at scan time or later. Sent to security leads and project owners.",
  },
};

/** The contract's defaults: email on for every type except scan.finished. */
export function defaultEmail(type: NotificationType): boolean {
  return type !== "scan.finished";
}

/** A notification's `link` is an app path from the server. Only a same-origin absolute path is
 *  followed; anything else (a full URL, `//host`, `/\host`, `javascript:`) is shown without a
 *  link, so a bad or hostile value can't send the user elsewhere. */
export function safeAppPath(link: unknown): string | null {
  if (typeof link !== "string" || !link.startsWith("/")) return null;
  if (link.startsWith("//") || link.startsWith("/\\")) return null;
  // Control characters (tabs, newlines) are stripped by URL parsers and could hide a "//".
  if (/[\u0000-\u001f\u007f]/.test(link)) return null;
  return link;
}

export function unreadLabel(n: number): string {
  return n > 0 ? `Notifications, ${n} unread` : "Notifications";
}

export function badgeText(n: number): string {
  return n > 99 ? "99+" : String(n);
}
