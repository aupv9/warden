import { afterEach, describe, expect, it } from "vitest";
import { ApiError } from "../api/client";
import { deliveriesQuery } from "../api/hooks/webhooks";
import { qk } from "../api/keys";
import type { Webhook } from "../api/types";
import { createQueryClient } from "../App";
import { auditTargetSummary } from "./auditSummary";
import { clearToasts, currentToasts } from "./toast";
import {
  createBody,
  DELIVERY_STATE_FILTERS,
  deliveryErrorText,
  deliveryTypeLabel,
  emptyDeliveriesText,
  eventsText,
  formFromWebhook,
  lastDeliveryText,
  minSeverityText,
  NEW_WEBHOOK_FORM,
  projectsText,
  TEST_RATE_LIMITED,
  updateBody,
  validateWebhookForm,
  webhookFieldErrors,
  webhookState,
} from "./webhooks";

const P1 = "3f6c1a2b-0000-4000-8000-00000000a9d2";
const P2 = "3f6c1a2b-0000-4000-8000-00000000a9d3";
const NOW = new Date("2026-10-29T12:00:00Z");

const base: Webhook = {
  id: "00000000-0000-4000-8000-0000000000aa",
  kind: "generic",
  name: "Ticket relay",
  url_hint: "https://relay.acme.example",
  events: ["scan.finished", "issue.reopened"],
  project_ids: [P1],
  min_severity: "high",
  enabled: true,
  disabled_reason: null,
  consecutive_failures: 0,
  last_delivery: null,
  created_by: { id: "u1", email: "linh@acme.example", display_name: "Linh Tran" },
  created_at: "2026-10-01T10:00:00Z",
  updated_at: "2026-10-01T10:00:00Z",
};

describe("webhook form", () => {
  const ok = { ...NEW_WEBHOOK_FORM, name: "#security-alerts", url: "https://hooks.slack.com/services/T0/B0/x" };

  it("checks name, URL, events and projects before sending", () => {
    expect(validateWebhookForm(ok, false)).toEqual({});
    expect(validateWebhookForm({ ...ok, name: "  " }, false).name).toBeDefined();
    expect(validateWebhookForm({ ...ok, name: "x".repeat(81) }, false).name).toMatch(/80/);
    expect(validateWebhookForm({ ...ok, url: "" }, false).url).toMatch(/Slack/);
    expect(validateWebhookForm({ ...ok, events: [] }, false).events).toBeDefined();
    expect(validateWebhookForm({ ...ok, allProjects: false, projectIds: [] }, false).project_ids).toBeDefined();
    expect(validateWebhookForm({ ...ok, allProjects: false, projectIds: Array.from({ length: 101 }, (_, i) => String(i)) }, false).project_ids).toMatch(/100/);
  });

  it("refuses URLs that aren't absolute http(s), carry user info, or aren't Slack's for a Slack channel", () => {
    const url = (u: string, kind: Webhook["kind"] = "generic") => validateWebhookForm({ ...ok, kind, url: u }, false).url;
    expect(url("javascript:alert(1)")).toBeDefined();
    expect(url("ftp://relay.acme.example/x")).toBeDefined();
    expect(url("relay.acme.example/hook")).toBeDefined();
    expect(url("https://user:pass@relay.acme.example/hook")).toMatch(/user name and password/);
    expect(url("https://relay.acme.example/hook")).toBeUndefined();
    expect(url("https://hooks.slack.com.evil.example/services/x", "slack")).toMatch(/Slack URLs start with https:\/\/hooks\.slack\.com\/services\//);
    expect(url("https://example.com/" + "a".repeat(2048))).toMatch(/2,048/);
    // On edit an empty URL means "keep the stored one".
    expect(validateWebhookForm({ ...ok, url: "" }, true)).toEqual({});
  });

  it("builds the create body: trimmed, events in the contract order, empty projects for all", () => {
    expect(createBody({ ...ok, name: " #sec ", url: " https://hooks.slack.com/services/T0/B0/x ", events: ["component.malicious", "scan.finished"], minSeverity: "" })).toEqual({
      kind: "slack",
      name: "#sec",
      url: "https://hooks.slack.com/services/T0/B0/x",
      events: ["scan.finished", "component.malicious"],
      project_ids: [],
      min_severity: null,
    });
  });

  it("edit sends only what changed, the URL only when a new one was typed, and nothing when nothing changed", () => {
    const f = formFromWebhook(base);
    expect(f.url).toBe("");
    expect(updateBody(f, base)).toBeNull();
    expect(updateBody({ ...f, name: "Relay" }, base)).toEqual({ name: "Relay" });
    expect(updateBody({ ...f, url: "https://relay2.acme.example/h" }, base)).toEqual({ url: "https://relay2.acme.example/h" });
    expect(updateBody({ ...f, allProjects: true }, base)).toEqual({ project_ids: [] });
    expect(updateBody({ ...f, projectIds: [P1, P2] }, base)).toEqual({ project_ids: [P1, P2] });
    expect(updateBody({ ...f, minSeverity: "" }, base)).toEqual({ min_severity: null });
    expect(updateBody({ ...f, events: ["issue.reopened", "scan.finished"] }, base)).toBeNull();
  });

  it("maps server field errors to the form's fields; the rest goes to a banner", () => {
    expect(webhookFieldErrors({ url: "resolves to a private address", "project_ids[3]": "not a project in this org", other: "x" })).toEqual({
      byField: { url: "resolves to a private address", project_ids: "not a project in this org" },
      leftover: ["other: x"],
    });
  });
});

describe("webhook list and delivery log words", () => {
  it("states: Active, Off, turned off after failures", () => {
    expect(webhookState(base)).toEqual({ tone: "success", text: "Active" });
    expect(webhookState({ enabled: false, disabled_reason: null })).toEqual({ tone: "neutral", text: "Off" });
    expect(webhookState({ enabled: false, disabled_reason: "failures" })).toEqual({ tone: "danger", text: "Turned off after failed deliveries" });
  });

  it("last delivery, events, projects and severity", () => {
    expect(lastDeliveryText(base, NOW)).toBe("No deliveries yet");
    expect(lastDeliveryText({ last_delivery: { at: "2026-10-29T11:55:00Z", state: "delivered", status_code: 200 } }, NOW)).toBe("Delivered 5 min ago");
    expect(lastDeliveryText({ last_delivery: { at: "2026-10-29T10:00:00Z", state: "failed", status_code: 500 } }, NOW)).toBe("Failed 2 h ago · HTTP 500");
    expect(eventsText(["issue.reopened", "scan.finished"])).toBe("Scan finished, Issue reopened");
    expect(eventsText(["scan.finished", "issue.assigned", "issue.reopened", "exception.requested", "exception.decided", "component.malicious"])).toBe("All events");
    expect(projectsText([])).toBe("All projects");
    expect(projectsText([P1, P2])).toBe("2 projects");
    expect(minSeverityText(null)).toBe("Any severity");
    expect(minSeverityText("critical")).toBe("Critical only");
    expect(minSeverityText("high")).toBe("High and above");
  });

  it("every delivery error has words; an unknown one falls back, and no body is ever shown", () => {
    const words = (error: string | null, status_code: number | null = null) => deliveryErrorText({ error: error as never, status_code });
    expect(words(null)).toBeNull();
    expect(words("timeout")).toBe("No answer within 10 seconds");
    expect(words("dns")).toBe("The host name didn't resolve");
    expect(words("connect")).toBe("Couldn't connect");
    expect(words("tls")).toBe("TLS failed");
    expect(words("blocked_address")).toBe("The host resolved to a private or internal address");
    expect(words("redirect")).toBe("The endpoint answered with a redirect; Warden doesn't follow redirects");
    expect(words("http_status", 500)).toBe("The endpoint answered HTTP 500");
    expect(words("disabled")).toBe("Not sent: the webhook was off");
    expect(words("key_unavailable")).toMatch(/can't read this webhook's URL or secret/);
    expect(words("<img src=x onerror=alert(1)>")).toBe("The delivery failed");
    expect(deliveryTypeLabel("webhook.test")).toBe("Test");
    expect(deliveryTypeLabel("something.new")).toBe("something.new");
  });

  it("audit entries name the webhook, never its URL or secret", () => {
    const e = (action: string, data: unknown) => auditTargetSummary({ action, target_type: "webhook", target_id: base.id, data });
    expect(e("webhook.created", { name: "#security-alerts", kind: "slack", url_hint: "https://hooks.slack.com", events: ["scan.finished"] })).toBe(
      "Slack channel “#security-alerts” · https://hooks.slack.com",
    );
    expect(e("webhook.updated", { name: "Ticket relay", fields: ["url", "events"] })).toBe("Webhook “Ticket relay” · changed url, events");
    expect(e("webhook.secret_rotated", {})).toBe("webhook 0000…00aa");
  });
});

describe("the test's 429 has its own words", () => {
  afterEach(() => clearToasts());

  it("a mutation's meta.errorMessages words the global error toast", async () => {
    const qc = createQueryClient();
    const limited = new ApiError(429, { code: "RATE_LIMITED", message: "rate limited" });
    await qc
      .getMutationCache()
      .build(qc, { mutationFn: () => Promise.reject(limited), meta: { errorMessages: { RATE_LIMITED: TEST_RATE_LIMITED } } })
      .execute(undefined)
      .catch(() => undefined);
    expect(currentToasts().map((t) => t.message)).toEqual(["You've sent 10 tests in the last hour. Try again later."]);
  });
});

describe("v0.5 wave 2: the delivery log's state filter", () => {
  it("offers All, Pending, Delivered and Failed, sent as ?state= (nothing for All)", () => {
    expect(DELIVERY_STATE_FILTERS.map((f) => f.label)).toEqual(["All", "Pending", "Delivered", "Failed"]);
    expect(deliveriesQuery("", undefined)).toEqual({ state: undefined, limit: 50, cursor: undefined });
    expect(deliveriesQuery("failed", "50")).toEqual({ state: "failed", limit: 50, cursor: "50" });
  });

  it("keeps one cache entry per state, under the prefix that Send test and delete refresh", () => {
    const prefix = qk.webhookDeliveries("o", "w");
    for (const s of ["", "pending", "delivered", "failed"]) {
      expect(qk.webhookDeliveryLog("o", "w", s).slice(0, prefix.length)).toEqual([...prefix]);
    }
    expect(qk.webhookDeliveryLog("o", "w", "")).not.toEqual(qk.webhookDeliveryLog("o", "w", "failed"));
  });

  it("says what is missing when a state has nothing", () => {
    expect(emptyDeliveriesText("")).toBe("No deliveries in the last 30 days. Send a test to see one here.");
    expect(emptyDeliveriesText("failed")).toBe("No failed deliveries in the last 30 days.");
  });
});
