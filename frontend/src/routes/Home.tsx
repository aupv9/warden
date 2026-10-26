import { Navigate } from "react-router";
import { isMockMode } from "../api/client";
import { useCurrentUser } from "../auth/AuthGate";
import { signOut } from "../auth/oidc";
import { BuildingIcon } from "../components/Icons";
import { Shell } from "../layout/OrgLayout";
import { lastOrg } from "../layout/lastOrg";
import { usePageTitle } from "../lib/usePageTitle";

/** "/" → the last org used (if still a member) or the first; or the no-org explanation. */
export function Home() {
  const me = useCurrentUser();
  const remembered = lastOrg();
  const target = me.orgs.find((o) => o.id === remembered) ?? me.orgs[0];
  if (target) return <Navigate to={`/orgs/${target.id}/projects`} replace />;
  return <NoOrg />;
}

function NoOrg() {
  usePageTitle("No organization");
  const me = useCurrentUser();
  return (
    <Shell me={me} minimal>
      <div className="page-body">
      <section className="card" aria-labelledby="no-org-h" style={{ maxWidth: 640, margin: "40px auto 0", width: "100%" }}>
        <div className="empty">
          <span className="state-icon" aria-hidden="true">
            <BuildingIcon />
          </span>
          <h1 id="no-org-h" className="state-title">
            You're not in an organization yet
          </h1>
          <p className="muted">
            You're signed in as <strong style={{ color: "var(--ink)" }}>{me.email}</strong>. Ask your Warden operator to
            create an org for you:
          </p>
          <pre className="code" style={{ textAlign: "left", width: "100%" }} tabIndex={0}>
            <span className="line">
              <span className="txt">{`warden-admin org create --name "Your team" \\`}</span>
            </span>
            <span className="line">
              <span className="txt">{`  --admin ${me.email}`}</span>
            </span>
          </pre>
          <p className="muted">Or ask an org admin to add you. Then reload.</p>
          <div className="row" style={{ justifyContent: "center" }}>
            {!isMockMode && (
              <button type="button" className="btn btn-ghost" onClick={() => void signOut()}>
                Sign out
              </button>
            )}
            <button type="button" className="btn btn-primary" onClick={() => window.location.reload()}>
              Reload
            </button>
          </div>
        </div>
      </section>
      </div>
    </Shell>
  );
}
