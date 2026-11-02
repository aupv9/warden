import { SEVERITIES, WEBHOOK_EVENT_TYPES } from "../api/types";
import type {
  CreateWebhookBody,
  Severity,
  UpdateWebhookBody,
  Webhook,
  WebhookDelivery,
  WebhookDeliveryState,
  WebhookDeliveryType,
  WebhookEventType,
  WebhookKind,
} from "../api/types";
import { relativeTime } from "./format";

// v0.4 wave 2: webhooks and Slack channels (the Integrations page, DESIGN.md "Wave 2:
// integrations"). A webhook's URL is sent once (create, or a replacement on edit) and never read
// back: the list only has `url_hint` (scheme and host), shown as text, never as a link. The
// signing secret follows the API token rules (see hooks/webhooks.ts and webhooks.test.ts).

export const WEBHOOK_MAX = 20;
export const WEBHOOK_NAME_MAX = 80;
export const WEBHOOK_URL_MAX = 2048;
export const WEBHOOK_PROJECTS_MAX = 100;
export const SLACK_URL_PREFIX = "https://hooks.slack.com/services/";
/** Test deliveries per webhook per hour (the server's rate limit). */
export const TESTS_PER_HOUR = 10;
export const TEST_RATE_LIMITED = `You've sent ${TESTS_PER_HOUR} tests in the last hour. Try again later.`;
/** After "Send test", the delivery log polls this often, for this long. */
export const DELIVERY_POLL_MS = 5_000;
export const DELIVERY_POLL_FOR_MS = 60_000;

export const WEBHOOK_KIND_LABELS: Record<WebhookKind, string> = { slack: "Slack", generic: "Webhook" };

export const WEBHOOK_EVENT_LABELS: Record<WebhookEventType, string> = {
  "scan.finished": "Scan finished",
  "issue.assigned": "Issue assigned",
  "issue.reopened": "Issue reopened",
  "exception.requested": "Exception requested",
  "exception.decided": "Exception decided",
  "component.malicious": "Malicious package found",
};

export const DELIVERY_TYPE_LABELS: Record<WebhookDeliveryType, string> = { ...WEBHOOK_EVENT_LABELS, "webhook.test": "Test" };

/** Events that carry an issue severity (min_severity applies to them). */
export const ISSUE_EVENTS: WebhookEventType[] = ["issue.assigned", "issue.reopened", "component.malicious"];

/** v0.5 wave 2: the delivery log's state filter (`?state=` on GET …/deliveries). */
export const DELIVERY_STATE_FILTERS: { value: "" | WebhookDeliveryState; label: string }[] = [
  { value: "", label: "All" },
  { value: "pending", label: "Pending" },
  { value: "delivered", label: "Delivered" },
  { value: "failed", label: "Failed" },
];

export function emptyDeliveriesText(state: "" | WebhookDeliveryState): string {
  if (state === "") return "No deliveries in the last 30 days. Send a test to see one here.";
  return `No ${state} deliveries in the last 30 days.`;
}

export function deliveryTypeLabel(t: string): string {
  return (DELIVERY_TYPE_LABELS as Record<string, string>)[t] ?? t;
}

/** The delivery error in words (DESIGN.md). The contract's enum may grow: anything else falls
 *  back to a generic sentence, and the raw value is never shown as markup. */
export function deliveryErrorText(d: Pick<WebhookDelivery, "error" | "status_code">): string | null {
  switch (d.error) {
    case null:
      return null;
    case "timeout":
      return "No answer within 10 seconds";
    case "dns":
      return "The host name didn't resolve";
    case "connect":
      return "Couldn't connect";
    case "tls":
      return "TLS failed";
    case "blocked_address":
      return "The host resolved to a private or internal address";
    case "redirect":
      return "The endpoint answered with a redirect; Warden doesn't follow redirects";
    case "http_status":
      return d.status_code ? `The endpoint answered HTTP ${d.status_code}` : "The endpoint answered with an error";
    case "disabled":
      return "Not sent: the webhook was off";
    case "key_unavailable":
      return "The server can't read this webhook's URL or secret; edit the URL or ask your operator";
    default:
      return "The delivery failed";
  }
}

export type WebhookState = { tone: "success" | "neutral" | "danger"; text: string };

/** Active, Off (turned off by someone), or turned off by Warden after failed deliveries. */
export function webhookState(w: Pick<Webhook, "enabled" | "disabled_reason">): WebhookState {
  if (w.enabled) return { tone: "success", text: "Active" };
  if (w.disabled_reason === "failures") return { tone: "danger", text: "Turned off after failed deliveries" };
  return { tone: "neutral", text: "Off" };
}

/** "Delivered 5 min ago", "Failed 2 h ago · HTTP 500", "Pending since …", "No deliveries yet". */
export function lastDeliveryText(w: Pick<Webhook, "last_delivery">, now: Date = new Date()): string {
  const d = w.last_delivery;
  if (!d) return "No deliveries yet";
  const when = relativeTime(d.at, now);
  if (d.state === "delivered") return `Delivered ${when}`;
  if (d.state === "pending") return `Pending since ${when}`;
  return `Failed ${when}${d.status_code ? ` · HTTP ${d.status_code}` : ""}`;
}

export function eventsText(events: WebhookEventType[]): string {
  const known = WEBHOOK_EVENT_TYPES.filter((e) => events.includes(e));
  return known.length === WEBHOOK_EVENT_TYPES.length ? "All events" : known.map((e) => WEBHOOK_EVENT_LABELS[e]).join(", ");
}

export function projectsText(ids: string[]): string {
  if (ids.length === 0) return "All projects";
  return `${ids.length} project${ids.length === 1 ? "" : "s"}`;
}

const SEVERITY_WORDS: Record<Severity, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };

export function minSeverityText(s: Severity | null): string {
  if (!s) return "Any severity";
  if (s === "info") return "Any severity";
  return s === "critical" ? "Critical only" : `${SEVERITY_WORDS[s]} and above`;
}

// ---- The add / edit form ----

export interface WebhookForm {
  kind: WebhookKind;
  name: string;
  /** Empty on edit: keep the stored URL. Never prefilled (the server never returns it). */
  url: string;
  events: WebhookEventType[];
  allProjects: boolean;
  projectIds: string[];
  minSeverity: Severity | "";
}

export const NEW_WEBHOOK_FORM: WebhookForm = {
  kind: "slack",
  name: "",
  url: "",
  events: ["scan.finished", "issue.reopened", "component.malicious"],
  allProjects: true,
  projectIds: [],
  minSeverity: "high",
};

export function formFromWebhook(w: Webhook): WebhookForm {
  return {
    kind: w.kind,
    name: w.name,
    url: "",
    events: WEBHOOK_EVENT_TYPES.filter((e) => w.events.includes(e)),
    allProjects: w.project_ids.length === 0,
    projectIds: [...w.project_ids],
    minSeverity: w.min_severity ?? "",
  };
}

/** What the browser checks before sending. The server checks the URL again (https, the host
 *  doesn't resolve to a private address, Slack's prefix) and its words go under the field. */
export function validateWebhookForm(f: WebhookForm, editing: boolean): Record<string, string> {
  const e: Record<string, string> = {};
  const name = f.name.trim();
  if (!name) e.name = "Give it a name, such as the channel or the system it feeds.";
  else if (name.length > WEBHOOK_NAME_MAX) e.name = `Use at most ${WEBHOOK_NAME_MAX} characters.`;

  const url = f.url.trim();
  if (!url) {
    if (!editing) e.url = f.kind === "slack" ? "Paste the Slack incoming webhook URL." : "Enter the URL Warden sends events to.";
  } else if (url.length > WEBHOOK_URL_MAX) {
    e.url = `Use at most ${WEBHOOK_URL_MAX.toLocaleString("en-US")} characters.`;
  } else {
    let parsed: URL | null = null;
    try {
      parsed = new URL(url);
    } catch {
      parsed = null;
    }
    if (!parsed || (parsed.protocol !== "https:" && parsed.protocol !== "http:") || !parsed.hostname) e.url = "Enter a full URL starting with https://.";
    else if (parsed.username || parsed.password) e.url = "Leave the user name and password out of the URL.";
    else if (f.kind === "slack" && !url.startsWith(SLACK_URL_PREFIX)) e.url = `Slack URLs start with ${SLACK_URL_PREFIX}`;
  }

  if (f.events.length === 0) e.events = "Choose at least one event.";
  if (!f.allProjects) {
    if (f.projectIds.length === 0) e.project_ids = "Choose at least one project, or All projects.";
    else if (f.projectIds.length > WEBHOOK_PROJECTS_MAX) e.project_ids = `Choose at most ${WEBHOOK_PROJECTS_MAX} projects.`;
  }
  return e;
}

export function createBody(f: WebhookForm): CreateWebhookBody {
  return {
    kind: f.kind,
    name: f.name.trim(),
    url: f.url.trim(),
    events: WEBHOOK_EVENT_TYPES.filter((e) => f.events.includes(e)),
    project_ids: f.allProjects ? [] : [...new Set(f.projectIds)],
    min_severity: f.minSeverity || null,
  };
}

/** Only the fields that changed (the contract wants at least one). The URL goes only when a new
 *  one was typed; null when nothing changed. */
export function updateBody(f: WebhookForm, w: Webhook): UpdateWebhookBody | null {
  const b: UpdateWebhookBody = {};
  const next = createBody(f);
  if (next.name !== w.name) b.name = next.name;
  if (next.url) b.url = next.url;
  if (next.events.join() !== WEBHOOK_EVENT_TYPES.filter((e) => w.events.includes(e)).join()) b.events = next.events;
  const ids = next.project_ids ?? [];
  if ([...ids].sort().join() !== [...w.project_ids].sort().join()) b.project_ids = ids;
  if ((next.min_severity ?? null) !== (w.min_severity ?? null)) b.min_severity = next.min_severity ?? null;
  return Object.keys(b).length ? b : null;
}

/** Server field names → the form's fields (`project_ids[3]` belongs to the project picker). */
export function webhookFieldErrors(fields: Record<string, string>): { byField: Record<string, string>; leftover: string[] } {
  const known = ["name", "url", "events", "project_ids", "min_severity", "kind"];
  const byField: Record<string, string> = {};
  const leftover: string[] = [];
  for (const [k, v] of Object.entries(fields)) {
    const base = k.replace(/\[\d+\]$/, "");
    if (known.includes(base)) byField[base] ??= v;
    else leftover.push(`${k}: ${v}`);
  }
  return { byField, leftover };
}

export const SEVERITY_OPTIONS: { value: Severity | ""; label: string }[] = [
  { value: "", label: "Any severity" },
  ...SEVERITIES.filter((s) => s !== "info").map((s) => ({ value: s, label: minSeverityText(s) })),
];

// ---- The signing secret, shown once ----

/** The secret dialog's state: the secret lives here (component state) and nowhere else. */
export interface SecretDialogState {
  secret: string | null;
  webhook: Pick<Webhook, "id" | "name"> | null;
}
export type SecretDialogAction = { type: "secret"; secret: string; webhook: Pick<Webhook, "id" | "name"> } | { type: "close" };
export const INITIAL_SECRET_DIALOG: SecretDialogState = { secret: null, webhook: null };

export function secretDialogReducer(_state: SecretDialogState, action: SecretDialogAction): SecretDialogState {
  switch (action.type) {
    case "secret":
      return { secret: action.secret, webhook: { id: action.webhook.id, name: action.webhook.name } };
    case "close":
      return INITIAL_SECRET_DIALOG;
  }
}
