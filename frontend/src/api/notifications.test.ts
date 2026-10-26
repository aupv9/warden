import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { badgeText, safeAppPath, unreadLabel } from "../lib/notifications";

describe("unread count polling", () => {
  let calls = 0;
  beforeEach(() => {
    calls = 0;
    vi.useFakeTimers();
    // TanStack Query turns intervals off when `window` is undefined (server rendering), and
    // decides that when it loads: give it a window, then load it fresh.
    vi.stubGlobal("window", { addEventListener: () => undefined, removeEventListener: () => undefined, location: { origin: "http://localhost" } });
    vi.resetModules();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        expect(url).toBe("/api/v1/me/notifications/unread-count");
        calls += 1;
        return new Response(JSON.stringify({ data: { count: calls }, error: null }), { status: 200, headers: { "Content-Type": "application/json" } });
      }),
    );
  });
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("polls every 60 s while the tab is visible, pauses while hidden, and refreshes on return", async () => {
    const { focusManager, QueryClient, QueryObserver } = await import("@tanstack/react-query");
    const { UNREAD_POLL_MS, unreadCountOptions } = await import("./hooks/notifications");
    expect(UNREAD_POLL_MS).toBe(60_000);
    focusManager.setFocused(true);
    const qc = new QueryClient();
    qc.mount();
    const observer = new QueryObserver(qc, unreadCountOptions());
    const unsubscribe = observer.subscribe(() => undefined);

    await vi.advanceTimersByTimeAsync(0);
    expect(calls).toBe(1);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(calls).toBe(2);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(calls).toBe(3);

    // Tab hidden (visibilitychange): no requests, however long it stays hidden.
    focusManager.setFocused(false);
    await vi.advanceTimersByTimeAsync(10 * 60_000);
    expect(calls).toBe(3);

    // Back to the tab: the count is stale, so it is fetched at once, then polling resumes.
    focusManager.setFocused(true);
    await vi.advanceTimersByTimeAsync(0);
    expect(calls).toBe(4);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(calls).toBe(5);
    expect(observer.getCurrentResult().data).toBe(5);

    unsubscribe();
    qc.unmount();
    focusManager.setFocused(undefined);
  });
});

describe("notification links and labels", () => {
  it("follows same-origin app paths only", () => {
    expect(safeAppPath("/orgs/o/issues/i")).toBe("/orgs/o/issues/i");
    expect(safeAppPath("/orgs/o/issues?assignee=me&past_sla=true")).toBe("/orgs/o/issues?assignee=me&past_sla=true");
    // Hostile or broken values never become links.
    for (const bad of ["https://evil.example/", "//evil.example/x", "/\\evil.example", "javascript:alert(1)", "/\t/evil.example", "orgs/o", "", null, 42, {}]) {
      expect(safeAppPath(bad)).toBeNull();
    }
  });
  it("says how many are unread", () => {
    expect(unreadLabel(0)).toBe("Notifications");
    expect(unreadLabel(3)).toBe("Notifications, 3 unread");
    expect(badgeText(7)).toBe("7");
    expect(badgeText(250)).toBe("99+");
  });
});
