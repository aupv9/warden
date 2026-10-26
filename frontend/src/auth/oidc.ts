import { InMemoryWebStorage, UserManager, WebStorageStateStore } from "oidc-client-ts";

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
