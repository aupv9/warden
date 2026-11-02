import { InMemoryWebStorage, UserManager, WebStorageStateStore } from "oidc-client-ts";
import type { WebConfig } from "../api/types";
import { loadWebConfig } from "./webConfig";

// Tokens live in memory only (not localStorage), so an XSS can't read a stored token and a
// reload means signing in again (usually silent at the IdP). Nothing here logs a token.
//
// Any OIDC provider works (Keycloak by default). The settings come from the server at startup
// (GET /web-config, auth/webConfig.ts); there are no build-time or built-in defaults. `scope`
// may add the API scope some providers need for an access token meant for Warden (Entra ID:
// "api://<app>/access"), and `audience` is sent as `audience` (Auth0 needs it to issue a JWT
// access token).
export function createUserManager(cfg: WebConfig): UserManager {
  return new UserManager({
    authority: cfg.issuer,
    client_id: cfg.client_id,
    redirect_uri: `${window.location.origin}/`,
    response_type: "code",
    scope: cfg.scope,
    ...(cfg.audience !== null ? { extraQueryParams: { audience: cfg.audience } } : {}),
    userStore: new WebStorageStateStore({ store: new InMemoryWebStorage() }),
    automaticSilentRenew: true,
  });
}

/** Runs `load` once and shares the result. A failure isn't kept: the next call loads again
 *  (the error page's "Try again"). */
export function shared<T>(load: () => Promise<T>): () => Promise<T> {
  let current: Promise<T> | null = null;
  return () => {
    if (!current) {
      const p = load();
      current = p;
      p.catch(() => {
        if (current === p) current = null;
      });
    }
    return current;
  };
}

/** The UserManager, built from GET /web-config the first time it is asked for. Everything that
 *  needs it awaits this, so nothing can use a half-configured client. Rejects with
 *  WebConfigError. */
export const getUserManager: () => Promise<UserManager> = shared(async () => createUserManager(await loadWebConfig()));

export async function accessToken(): Promise<string | null> {
  const um = await getUserManager().catch(() => null);
  const user = await um?.getUser();
  return user && !user.expired ? user.access_token : null;
}

// One refresh at a time, shared by every request that got a 401 at once.
let refreshing: Promise<string | null> | null = null;

/** One silent token refresh (refresh token, or the IdP's silent flow). Null if it failed. */
export function refreshAccessToken(): Promise<string | null> {
  refreshing ??= getUserManager()
    .then((um) => um.signinSilent())
    .then((u) => (u && !u.expired ? u.access_token : null))
    .catch(() => null)
    .finally(() => {
      refreshing = null;
    });
  return refreshing;
}

/** Only a same-origin path may be a post-login destination (no open redirect via `state`). */
export function safeReturnTo(value: unknown): string {
  if (typeof value !== "string") return "/";
  if (!value.startsWith("/") || value.startsWith("//") || value.startsWith("/\\")) return "/";
  return value;
}

export async function signIn(): Promise<void> {
  const um = await getUserManager();
  const here = `${window.location.pathname}${window.location.search}`;
  return um.signinRedirect({ state: { returnTo: safeReturnTo(here) } });
}

/** Finishes the code flow. Returns where to go next. Errors are thrown without detail to the
 *  UI: the caller shows one generic message (README "Security invariants"). */
export async function completeSignIn(): Promise<string> {
  const um = await getUserManager();
  const user = await um.signinRedirectCallback();
  const state = user.state as { returnTo?: unknown } | undefined;
  return safeReturnTo(state?.returnTo);
}

export async function signOut(): Promise<void> {
  let um: UserManager;
  try {
    um = await getUserManager();
  } catch {
    window.location.assign("/");
    return;
  }
  await um.removeUser();
  try {
    await um.signoutRedirect({ post_logout_redirect_uri: `${window.location.origin}/` });
  } catch {
    // The IdP may not support RP-initiated logout; the local session is gone either way.
    window.location.assign("/");
  }
}

export function isAuthCallback(search: string): boolean {
  const sp = new URLSearchParams(search);
  return sp.has("state") && (sp.has("code") || sp.has("error"));
}
