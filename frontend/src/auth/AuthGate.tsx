import { useQueryClient } from "@tanstack/react-query";
import { createContext, useContext, useEffect, useState } from "react";
import type { ReactNode } from "react";
import { isMockMode } from "../api/client";
import { isForbidden, isUnauthorized } from "../api/errors";
import { useMe } from "../api/hooks/me";
import type { Me } from "../api/types";
import { ShieldIcon } from "../components/Icons";
import { ErrorState, SkeletonBlock } from "../components/States";
import { signIn, userManager } from "./oidc";

type Status = "loading" | "signedOut" | "signedIn";

const MeContext = createContext<Me | null>(null);

export function useCurrentUser(): Me {
  const me = useContext(MeContext);
  if (!me) throw new Error("useCurrentUser outside AuthGate");
  return me;
}

/** Signals from anywhere (e.g. a 401 on any query) that the session is gone. */
export const sessionEnded = new EventTarget();

export function AuthGate({ authFailed, children }: { authFailed: boolean; children: ReactNode }) {
  const [status, setStatus] = useState<Status>(isMockMode ? "signedIn" : "loading");
  const [failed, setFailed] = useState(authFailed);
  const qc = useQueryClient();

  useEffect(() => {
    if (isMockMode) return;
    let alive = true;
    void userManager.getUser().then((u) => {
      if (alive) setStatus(u && !u.expired ? "signedIn" : "signedOut");
    });
    const onLoaded = () => setStatus("signedIn");
    const onGone = () => {
      setStatus("signedOut");
      qc.clear();
    };
    userManager.events.addUserLoaded(onLoaded);
    userManager.events.addUserUnloaded(onGone);
    userManager.events.addAccessTokenExpired(onGone);
    const onEnded = () => {
      setFailed(true);
      void userManager.removeUser();
    };
    sessionEnded.addEventListener("ended", onEnded);
    return () => {
      alive = false;
      userManager.events.removeUserLoaded(onLoaded);
      userManager.events.removeUserUnloaded(onGone);
      userManager.events.removeAccessTokenExpired(onGone);
      sessionEnded.removeEventListener("ended", onEnded);
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

function SignIn({ failed }: { failed: boolean }) {
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
        <button type="button" className="btn btn-primary" onClick={() => void signIn()}>
          {failed ? "Sign in again" : "Sign in"}
        </button>
      </div>
    </CenterCard>
  );
}

