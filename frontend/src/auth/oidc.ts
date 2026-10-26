import { InMemoryWebStorage, UserManager, WebStorageStateStore } from "oidc-client-ts";

// Tokens live in memory only (not localStorage), so an XSS can't read a stored token and a
// reload means signing in again (usually silent at the IdP). Nothing here logs a token.
export const userManager = new UserManager({
  authority: import.meta.env.VITE_OIDC_ISSUER ?? "http://localhost:8180/realms/warden",
  client_id: import.meta.env.VITE_OIDC_CLIENT_ID ?? "warden-web",
  redirect_uri: `${window.location.origin}/`,
  response_type: "code",
  scope: "openid profile email",
  userStore: new WebStorageStateStore({ store: new InMemoryWebStorage() }),
  automaticSilentRenew: true,
});

export async function accessToken(): Promise<string | null> {
  const user = await userManager.getUser();
  return user && !user.expired ? user.access_token : null;
}

// One refresh at a time, shared by every request that got a 401 at once.
let refreshing: Promise<string | null> | null = null;

/** One silent token refresh (refresh token, or the IdP's silent flow). Null if it failed. */
export function refreshAccessToken(): Promise<string | null> {
  refreshing ??= userManager
    .signinSilent()
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

export function signIn(): Promise<void> {
  const here = `${window.location.pathname}${window.location.search}`;
  return userManager.signinRedirect({ state: { returnTo: safeReturnTo(here) } });
}

/** Finishes the code flow. Returns where to go next. Errors are thrown without detail to the
 *  UI: the caller shows one generic message (README "Security invariants"). */
export async function completeSignIn(): Promise<string> {
  const user = await userManager.signinRedirectCallback();
  const state = user.state as { returnTo?: unknown } | undefined;
  return safeReturnTo(state?.returnTo);
}

export async function signOut(): Promise<void> {
  await userManager.removeUser();
  try {
    await userManager.signoutRedirect({ post_logout_redirect_uri: `${window.location.origin}/` });
  } catch {
    // The IdP may not support RP-initiated logout; the local session is gone either way.
    window.location.assign("/");
  }
}

export function isAuthCallback(search: string): boolean {
  const sp = new URLSearchParams(search);
  return sp.has("state") && (sp.has("code") || sp.has("error"));
}
