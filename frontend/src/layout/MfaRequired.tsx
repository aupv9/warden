import { Link } from "react-router";
import { isMockMode } from "../api/client";
import type { Me, MeOrg } from "../api/types";
import { signOut } from "../auth/oidc";
import { KeyIcon } from "../components/Icons";
import { ORG_ROLE_LABELS } from "../lib/permissions";
import { showToast } from "../lib/toast";
import { usePageTitle } from "../lib/usePageTitle";

/** Full-page state for the org's MFA rule (contract C): the caller's role needs two-factor
 *  sign-in and this session was signed in without it. Shown from `me.mfa_required_orgs`
 *  before any call, or after any org request answered MFA_REQUIRED. Nothing of the org is
 *  loaded behind it. */
export function MfaRequired({ me, org }: { me: Me; org: MeOrg }) {
  usePageTitle("Two-factor sign-in required");
  const others = me.orgs.filter((o) => o.id !== org.id && !(me.mfa_required_orgs ?? []).includes(o.id));
  const signOutAgain = () => {
    if (isMockMode) {
      showToast({ tone: "warning", message: "Mock mode has no sign-in. Run Warden with an identity provider to try this." });
      return;
    }
    void signOut();
  };
  return (
    <div className="page-body">
      <section className="card mfa-card" aria-labelledby="mfa-h">
        <div className="empty">
          <span className="state-icon" aria-hidden="true">
            <KeyIcon size={18} />
          </span>
          <span className="mono muted">MFA_REQUIRED</span>
          <h1 id="mfa-h" className="state-title">
            Two-factor sign-in required
          </h1>
          <p className="muted">
            Your role in <strong className="ink">{org.name}</strong> ({ORG_ROLE_LABELS[org.role]}) requires two-factor sign-in, and
            this session was signed in without it. Warden shows nothing from this organization until you sign in again with your
            second factor, such as an authenticator app or a security key.
          </p>
          <p className="muted small">
            If your identity provider doesn't ask for a second factor, set one up there first, or ask your Warden operator.
          </p>
          <div className="row" style={{ justifyContent: "center", marginTop: 8 }}>
            <button type="button" className="btn btn-primary" onClick={signOutAgain}>
              Sign out and sign in again
            </button>
          </div>
          {others.length > 0 && (
            <p className="muted small" style={{ marginTop: 12 }}>
              Or go to{" "}
              {others.map((o, i) => (
                <span key={o.id}>
                  {i > 0 && (i === others.length - 1 ? " or " : ", ")}
                  <Link to={`/orgs/${o.id}/projects`}>{o.name}</Link>
                </span>
              ))}
              .
            </p>
          )}
        </div>
      </section>
    </div>
  );
}
