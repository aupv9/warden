import { isMockMode } from "../api/transport";
import { completeSignIn, getUserManager, isAuthCallback } from "./oidc";

// Startup, before anything signs in or calls the API: fetch the OIDC settings (GET /web-config)
// and build the UserManager, then finish the code flow if this page load is the IdP's redirect.
// A small store (not component state) so it starts before the first render, runs once under
// StrictMode, and can be tested without a DOM.

export type BootState = { status: "loading" } | { status: "error" } | { status: "ready"; authFailed: boolean };

export interface Boot {
  getState(): BootState;
  subscribe(listener: () => void): () => void;
  /** Starts the first attempt; later calls do nothing. */
  start(): void;
  /** After a failure only: tries again from the start. */
  retry(): void;
}

export function createBoot(run: () => Promise<{ authFailed: boolean }>): Boot {
  let state: BootState = { status: "loading" };
  let started = false;
  const listeners = new Set<() => void>();
  const set = (next: BootState) => {
    state = next;
    for (const l of listeners) l();
  };
  const attempt = () => {
    started = true;
    run().then(
      (r) => set({ status: "ready", authFailed: r.authFailed }),
      // No detail is kept or logged: the page shows one message for every cause.
      () => set({ status: "error" }),
    );
  };
  return {
    getState: () => state,
    subscribe(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    start() {
      if (!started) attempt();
    },
    retry() {
      if (state.status !== "error") return;
      set({ status: "loading" });
      attempt();
    },
  };
}

/** What the app runs: the settings (WebConfigError on any failure), then the sign-in callback. */
export async function runBoot(): Promise<{ authFailed: boolean }> {
  await getUserManager();
  let authFailed = false;
  if (!isMockMode && isAuthCallback(window.location.search)) {
    let next = "/";
    try {
      next = await completeSignIn();
    } catch {
      // Any failure (state mismatch, IdP error, expired code) shows one generic message.
      authFailed = true;
    }
    // Drop ?code=&state= from the address bar and history.
    window.history.replaceState({}, "", next);
  }
  return { authFailed };
}

export const appBoot: Boot = createBoot(runBoot);
