import { useQueryClient } from "@tanstack/react-query";
import { createContext, useContext, useEffect, useState, useSyncExternalStore } from "react";
import type { ReactNode } from "react";
import { isMockMode } from "../api/client";
import { isForbidden, isUnauthorized } from "../api/errors";
import { useMe } from "../api/hooks/me";
import type { Me } from "../api/types";
import { AlertIcon, ShieldIcon } from "../components/Icons";
import { ErrorState, SkeletonBlock } from "../components/States";
import type { Boot } from "./boot";
import { getUserManager, signIn } from "./oidc";

type Status = "loading" | "signedOut" | "signedIn";

const MeContext = createContext<Me | null>(null);

export function useCurrentUser(): Me {
  const me = useContext(MeContext);
  if (!me) throw new Error("useCurrentUser outside AuthGate");
  return me;
}

/** Signals from anywhere (e.g. a 401 on any query) that the session is gone. */
export const sessionEnded = new EventTarget();

/** Startup (auth/boot.ts): a splash while the server's sign-in settings load, a full-page
 *  error if they can't be loaded or aren't valid, then the app. */
export function AuthBoot({ boot, children }: { boot: Boot; children: (authFailed: boolean) => ReactNode }) {
  const state = useSyncExternalStore(boot.subscribe, boot.getState, boot.getState);
  useEffect(() => boot.start(), [boot]);
  if (state.status === "loading") return <Splash />;
  if (state.status === "error") return <SettingsUnavailable onRetry={() => boot.retry()} />;
  return children(state.authFailed);
}

/** DESIGN.md "Sign-in settings unavailable": one message for every cause (network, an error
 *  status, a malformed answer). No detail is shown or logged. */
function SettingsUnavailable({ onRetry }: { onRetry: () => void }) {
  return (
    <CenterCard>
      <div className="empty" role="alert">
        <span className="state-icon danger" aria-hidden="true">
          <AlertIcon size={20} />
        </span>
        <h1 className="state-title">Can't reach the server's sign-in settings</h1>
        <p className="muted">
          Warden loads them from its server before you can sign in, and that didn't work. Check your connection and try again. If it
          keeps happening, contact your Warden operator.
        </p>
        <button type="button" className="btn btn-primary" onClick={onRetry}>
          Try again
        </button>
      </div>
    </CenterCard>
  );
}

export function AuthGate({ authFailed, children }: { authFailed: boolean; children: ReactNode }) {
  const [status, setStatus] = useState<Status>(isMockMode ? "signedIn" : "loading");
  const [failed, setFailed] = useState(authFailed);
  const qc = useQueryClient();

  useEffect(() => {
    if (isMockMode) return;
    let alive = true;
    let unsubscribe = () => {};
    // AuthBoot renders this only once the UserManager exists, so this resolves at once; awaiting
    // it anyway means the gate can never use a client that isn't configured yet.
    void getUserManager().then(
      (um) => {
        if (!alive) return;
        const onLoaded = () => setStatus("signedIn");
        const onGone = () => {
          setStatus("signedOut");
          qc.clear();
        };
        const onEnded = () => {
          setFailed(true);
          void um.removeUser();
        };
        um.events.addUserLoaded(onLoaded);
        um.events.addUserUnloaded(onGone);
        um.events.addAccessTokenExpired(onGone);
        sessionEnded.addEventListener("ended", onEnded);
        unsubscribe = () => {
          um.events.removeUserLoaded(onLoaded);
          um.events.removeUserUnloaded(onGone);
          um.events.removeAccessTokenExpired(onGone);
          sessionEnded.removeEventListener("ended", onEnded);
        };
        void um.getUser().then((u) => {
          if (alive) setStatus(u && !u.expired ? "signedIn" : "signedOut");
        });
      },
      () => {
        if (alive) setStatus("signedOut");
      },
    );
    return () => {
      alive = false;
      unsubscribe();
    };
  }, [qc]);

  const me = useMe(status === "signedIn");

  if (status === "loading") return <Splash />;
  if (status === "signedOut") return <SignIn failed={failed} />;
  if (me.isPending) return <Splash />;
  if (me.isError) {
    if (isUnauthorized(me.error)) return <SignIn failed />;
    // An inactive account gets 403 from /me: still the one generic sign-in message.
    if (isForbidden(me.error)) return <SignIn failed />;
    return (
      <CenterCard>
        <ErrorState error={me.error} onRetry={() => void me.refetch()} what="your account" />
      </CenterCard>
    );
  }
  return <MeContext value={me.data}>{children}</MeContext>;
}

function CenterCard({ children }: { children: ReactNode }) {
  return (
    <main className="center-page">
      <div className="card">
        <div className="row" style={{ gap: 8 }}>
          <ShieldIcon size={22} />
          <strong style={{ fontSize: 15 }}>Warden</strong>
        </div>
        {children}
      </div>
    </main>
  );
}

function Splash() {
  return (
    <CenterCard>
      <SkeletonBlock label="Warden" lines={3} />
    </CenterCard>
  );
}

function SignIn({ failed: failedBefore }: { failed: boolean }) {
  // The redirect can fail before leaving the page (the identity provider's discovery document
  // unreachable or blocked): the same generic message, no detail.
  const [startFailed, setStartFailed] = useState(false);
  const failed = failedBefore || startFailed;
  return (
    <CenterCard>
      <h1 className="state-title">Sign in to Warden</h1>
      {failed ? (
        // One message for every cause (expired, revoked, wrong audience, inactive account...);
        // the reason is logged on the server only.
        <div className="banner banner-error" role="alert">
          We couldn't sign you in. Try again. If it keeps failing, contact your Warden operator.
        </div>
      ) : (
        <p className="muted">Warden uses your organization's identity provider.</p>
      )}
      <div>
        <button type="button" className="btn btn-primary" onClick={() => void signIn().catch(() => setStartFailed(true))}>
          {failed ? "Sign in again" : "Sign in"}
        </button>
      </div>
    </CenterCard>
  );
}

