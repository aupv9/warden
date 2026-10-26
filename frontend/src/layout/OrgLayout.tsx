import { createContext, useContext, useEffect, useId, useRef, useState } from "react";
import type { ReactNode } from "react";
import { NavLink, Outlet, useLocation, useNavigate, useParams } from "react-router";
import { isMockMode } from "../api/client";
import { useOrgSummary } from "../api/hooks/orgs";
import type { Me, MeOrg } from "../api/types";
import { useCurrentUser } from "../auth/AuthGate";
import { signOut } from "../auth/oidc";
import { CloseIcon, MenuIcon, ShieldIcon } from "../components/Icons";
import { NotFoundState } from "../components/States";
import { initials } from "../lib/format";
import { can, ORG_ROLE_LABELS } from "../lib/permissions";
import { usePageTitle } from "../lib/usePageTitle";
import { rememberOrg } from "./lastOrg";

export interface OrgCtx {
  orgId: string;
  org: MeOrg;
  me: Me;
}

const OrgContext = createContext<OrgCtx | null>(null);

export function useOrgCtx(): OrgCtx {
  const ctx = useContext(OrgContext);
  if (!ctx) throw new Error("useOrgCtx outside OrgLayout");
  return ctx;
}

/** Everything under /orgs/:orgId. An org the user isn't a member of looks exactly like any
 *  other missing page (the API answers 404 too, so org IDs can't be probed). */
export function OrgLayout() {
  const { orgId = "" } = useParams();
  const me = useCurrentUser();
  const org = me.orgs.find((o) => o.id === orgId);

  useEffect(() => {
    if (org) rememberOrg(org.id);
  }, [org]);

  if (!org) return <NotFoundPage />;
  return (
    <OrgContext value={{ orgId, org, me }}>
      <Shell me={me} org={org}>
        <Outlet />
      </Shell>
    </OrgContext>
  );
}

export function NotFoundPage() {
  usePageTitle("Not found");
  const me = useCurrentUser();
  return (
    <Shell me={me}>
      <NotFoundState />
    </Shell>
  );
}

export function Shell({ me, org, minimal, children }: { me: Me; org?: MeOrg; minimal?: boolean; children: ReactNode }) {
  const mainRef = useRef<HTMLElement>(null);
  const { pathname } = useLocation();
  const first = useRef(true);
  const [menuOpen, setMenuOpen] = useState(false);
  const drawerId = useId();

  // On navigation (not filter changes) move focus to the content, so keyboard and screen-reader
  // users start at the new page; and close the phone menu.
  useEffect(() => {
    setMenuOpen(false);
    if (first.current) {
      first.current = false;
      return;
    }
    mainRef.current?.focus();
  }, [pathname]);

  const displayName = me.name?.trim() || me.email;
  return (
    <div className="shell">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <header className="topbar">
        {!minimal && (
          <button
            type="button"
            className="menu-btn"
            aria-label="Menu"
            aria-expanded={menuOpen}
            aria-controls={drawerId}
            onClick={() => setMenuOpen(true)}
          >
            <MenuIcon />
          </button>
        )}
        <NavLink to={org ? `/orgs/${org.id}/projects` : "/"} className="brand">
          <ShieldIcon size={24} />
          Warden
        </NavLink>
        <span className="org">{org ? `· ${org.name}` : ""}</span>
        <span className="avatar" title={displayName} aria-hidden="true">
          {initials(displayName)}
        </span>
      </header>
      <Sidebar me={me} org={org} minimal={minimal} />
      {!minimal && (
        <Drawer id={drawerId} open={menuOpen} onClose={() => setMenuOpen(false)}>
          <Sidebar me={me} org={org} onClose={() => setMenuOpen(false)} />
        </Drawer>
      )}
      <main id="main" className="main" ref={mainRef} tabIndex={-1}>
        {children}
      </main>
    </div>
  );
}

/** The phone menu: a native modal <dialog> (focus trap, Esc), closed by a tap outside too. */
function Drawer({ id, open, onClose, children }: { id: string; open: boolean; onClose: () => void; children: ReactNode }) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) d.showModal();
    if (!open && d.open) d.close();
  }, [open]);
  return (
    <dialog
      id={id}
      ref={ref}
      className="drawer"
      aria-label="Menu"
      onCancel={(e) => {
        e.preventDefault();
        onClose();
      }}
      onClick={(e) => {
        if (e.target === ref.current) onClose();
      }}
      onClose={onClose}
    >
      {open && children}
    </dialog>
  );
}

function Sidebar({ me, org, minimal, onClose }: { me: Me; org?: MeOrg; minimal?: boolean; onClose?: () => void }) {
  const navigate = useNavigate();
  const displayName = me.name?.trim() || me.email;
  return (
    <aside className="sidebar">
      <div className="row" style={{ gap: 4, flexWrap: "nowrap" }}>
        {onClose && (
          <button type="button" className="icon-btn" aria-label="Close menu" onClick={onClose} style={{ color: "#fff" }}>
            <CloseIcon size={22} />
          </button>
        )}
        <NavLink to={org ? `/orgs/${org.id}/projects` : "/"} className="brand">
          <ShieldIcon />
          Warden
        </NavLink>
      </div>
      {minimal ? (
        <span className="org-switch">No organization</span>
      ) : (
        me.orgs.length > 0 && (
          <label className="org-switch">
            Organization
            {me.orgs.length > 1 ? (
              <select value={org?.id ?? ""} onChange={(e) => navigate(`/orgs/${e.target.value}/projects`)}>
                {!org && <option value="">Choose…</option>}
                {me.orgs.map((o) => (
                  <option key={o.id} value={o.id}>
                    {o.name}
                  </option>
                ))}
              </select>
            ) : (
              <span className="org-name">{me.orgs[0]?.name}</span>
            )}
          </label>
        )
      )}
      {org && <OrgNav org={org} />}
      {!minimal && (
        <div className="user-box">
          <span className="avatar" aria-hidden="true">
            {initials(displayName)}
          </span>
          <div className="who">
            <strong title={displayName}>{displayName}</strong>
            <span>
              {org ? ORG_ROLE_LABELS[org.role] : "No organization"}
              {me.mfa ? " · MFA" : ""}
            </span>
          </div>
          {!isMockMode && (
            <button type="button" onClick={() => void signOut()}>
              Sign out
            </button>
          )}
        </div>
      )}
    </aside>
  );
}

function OrgNav({ org }: { org: MeOrg }) {
  const summary = useOrgSummary(org.id);
  const pending = summary.data?.exceptions_pending ?? 0;
  const base = `/orgs/${org.id}`;
  return (
    <nav className="nav" aria-label="Main">
      <NavLink to={`${base}/projects`}>Projects</NavLink>
      <NavLink to={`${base}/issues`}>Issues</NavLink>
      <NavLink to={`${base}/exceptions`}>
        Exceptions
        {pending > 0 && (
          <span className="count">
            {pending}
            <span className="visually-hidden"> to review</span>
          </span>
        )}
      </NavLink>
      <NavLink to={`${base}/members`}>Members</NavLink>
      {can("view_audit_log", org.role) && <NavLink to={`${base}/audit-log`}>Audit log</NavLink>}
    </nav>
  );
}
