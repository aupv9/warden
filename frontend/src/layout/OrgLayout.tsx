import { createContext, Suspense, useContext, useEffect, useId, useRef, useState } from "react";
import type { ReactNode } from "react";
import { NavLink, Outlet, useLocation, useParams } from "react-router";
import { isMockMode } from "../api/client";
import { useOrgSummary } from "../api/hooks/orgs";
import { useProjects } from "../api/hooks/projects";
import type { Me, MeOrg } from "../api/types";
import { useCurrentUser } from "../auth/AuthGate";
import { signOut } from "../auth/oidc";
import { Avatar, ProjectDot } from "../components/Avatar";
import { Count } from "../components/Badges";
import { CommandPalette } from "../components/CommandPalette";
import { NotificationsBell } from "../components/NotificationsBell";
import {
  AuditIcon,
  BellIcon,
  CheckIcon,
  CloseIcon,
  ExceptionsIcon,
  IssuesIcon,
  MembersIcon,
  MenuIcon,
  OverviewIcon,
  PackageIcon,
  ProjectsIcon,
  SearchIcon,
  SettingsIcon,
  ShieldIcon,
  SignOutIcon,
  UpDownIcon,
} from "../components/Icons";
import { Kbd } from "../components/PageHeader";
import { Popover } from "../components/Popover";
import { ThemeSwitch } from "../components/ThemeSwitch";
import { NotFoundState, RouteFallback } from "../components/States";
import { useMfaBlocked } from "../lib/mfa";
import { MfaRequired } from "./MfaRequired";
import { can, ORG_ROLE_LABELS } from "../lib/permissions";
import { useShortcuts } from "../lib/shortcuts";
import { SPLIT_QUERY } from "../lib/useMediaQuery";
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
  const mfaBlocked = useMfaBlocked(me, orgId);

  useEffect(() => {
    if (org) rememberOrg(org.id);
  }, [org]);

  if (!org) return <NotFoundPage />;
  if (mfaBlocked) {
    // No org data at all behind this state: the nav, the palette and the page stay unmounted.
    return (
      <Shell me={me} org={org} blocked>
        <MfaRequired me={me} org={org} />
      </Shell>
    );
  }
  return (
    <OrgContext value={{ orgId, org, me }}>
      <Shell me={me} org={org}>
        <Suspense fallback={<RouteFallback />}>
          <Outlet />
        </Suspense>
      </Shell>
    </OrgContext>
  );
}

export function NotFoundPage() {
  usePageTitle("Not found");
  const me = useCurrentUser();
  return (
    <Shell me={me}>
      <div className="page-body">
        <NotFoundState />
      </div>
    </Shell>
  );
}

/** An unknown page inside an org: the org's shell stays, the content says "Not found". */
export function OrgNotFound() {
  usePageTitle("Not found");
  const { orgId } = useOrgCtx();
  return (
    <div className="page-body">
      <NotFoundState backTo={`/orgs/${orgId}/projects`} />
    </div>
  );
}

// Moving between the issue list and an issue in the split view is not a page change: the list
// keeps its scroll position and focus is handled by the list itself.
const ISSUES_PATH = /^\/orgs\/[^/]+\/issues(\/[^/]+)?$/;
function isSplitMove(from: string, to: string): boolean {
  return ISSUES_PATH.test(from) && ISSUES_PATH.test(to) && window.matchMedia(SPLIT_QUERY).matches;
}

export function Shell({
  me,
  org,
  minimal,
  blocked,
  children,
}: {
  me: Me;
  org?: MeOrg;
  minimal?: boolean;
  /** The org's MFA rule blocks this session: no org navigation or search. */
  blocked?: boolean;
  children: ReactNode;
}) {
  const mainRef = useRef<HTMLElement>(null);
  const { pathname } = useLocation();
  const prevPath = useRef(pathname);
  const [menuOpen, setMenuOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const drawerId = useId();

  // On navigation (not filter changes) move focus to the content, so keyboard and screen-reader
  // users start at the new page; and close the phone menu.
  useEffect(() => {
    setMenuOpen(false);
    const from = prevPath.current;
    prevPath.current = pathname;
    if (from === pathname || isSplitMove(from, pathname)) return;
    // preventScroll: focusing <main> would scroll it under the sticky phone top bar.
    window.scrollTo(0, 0);
    mainRef.current?.focus({ preventScroll: true });
  }, [pathname]);

  useShortcuts({
    palette: () => {
      if (!org || blocked) return false;
      setPaletteOpen(true);
    },
  });

  const openPalette = () => {
    setMenuOpen(false);
    setPaletteOpen(true);
  };
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
          <ShieldIcon size={20} />
          Warden
        </NavLink>
        <span className="org">{org ? `· ${org.name}` : ""}</span>
        {!minimal && <NotificationsBell me={me} orgId={org?.id} />}
        <span className="topbar-avatar" title={displayName}>
          <Avatar name={displayName} size={28} />
        </span>
      </header>
      <Sidebar me={me} org={org} minimal={minimal} blocked={blocked} onOpenPalette={openPalette} />
      {!minimal && (
        <Drawer id={drawerId} open={menuOpen} onClose={() => setMenuOpen(false)}>
          <Sidebar me={me} org={org} blocked={blocked} onClose={() => setMenuOpen(false)} onOpenPalette={openPalette} />
        </Drawer>
      )}
      <main id="main" className="main" ref={mainRef} tabIndex={-1}>
        {children}
      </main>
      {org && !blocked && <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />}
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

function Sidebar({
  me,
  org,
  minimal,
  blocked,
  onClose,
  onOpenPalette,
}: {
  me: Me;
  org?: MeOrg;
  minimal?: boolean;
  blocked?: boolean;
  onClose?: () => void;
  onOpenPalette: () => void;
}) {
  const showOrg = org && !blocked;
  return (
    <aside className="sidebar">
      <div className="sidebar-top">
        <OrgSwitcher me={me} org={org} minimal={minimal} />
        {!minimal && !onClose && <NotificationsBell me={me} orgId={org?.id} />}
        {onClose && (
          <button type="button" className="icon-btn" aria-label="Close menu" onClick={onClose}>
            <CloseIcon size={18} />
          </button>
        )}
      </div>
      {showOrg && (
        <button type="button" className="jump-btn" onClick={onOpenPalette}>
          <SearchIcon />
          <span>Search or jump to…</span>
          <Kbd>⌘K</Kbd>
        </button>
      )}
      {showOrg && <OrgNav org={org} />}
      <div className="theme-row">
        <span>Theme</span>
        <ThemeSwitch />
      </div>
      {!minimal && <UserMenu me={me} org={org} blocked={blocked} onNavigate={onClose} />}
    </aside>
  );
}

/** The user at the bottom of the sidebar; opens a menu with the preferences and sign-out. */
function UserMenu({ me, org, blocked, onNavigate }: { me: Me; org?: MeOrg; blocked?: boolean; onNavigate?: () => void }) {
  const displayName = me.name?.trim() || me.email;
  const roleText = org ? ORG_ROLE_LABELS[org.role] : "No organization";
  return (
    <div className="user-box">
      <Popover
        up
        buttonClassName="user-btn"
        buttonLabel={`${displayName}, ${roleText}. Account menu`}
        panelLabel="Account"
        button={
          <>
            <Avatar name={displayName} size={24} />
            <span className="who">
              <strong>{displayName}</strong>
              <span>
                {roleText}
                {me.mfa ? " · MFA" : ""}
              </span>
            </span>
            <UpDownIcon />
          </>
        }
      >
        {(close) => (
          <ul className="menu-list" aria-label="Account">
            <li className="menu-title">{me.email}</li>
            {org && !blocked && (
              <li>
                <NavLink
                  to={`/orgs/${org.id}/preferences`}
                  className="menu-item"
                  onClick={() => {
                    close(false);
                    onNavigate?.();
                  }}
                >
                  <BellIcon size={14} />
                  <span className="grow">Notification preferences</span>
                </NavLink>
              </li>
            )}
            {!isMockMode && (
              <li>
                <button type="button" className="menu-item" onClick={() => void signOut()}>
                  <SignOutIcon size={14} />
                  <span className="grow">Sign out</span>
                </button>
              </li>
            )}
          </ul>
        )}
      </Popover>
    </div>
  );
}

function OrgSwitcher({ me, org, minimal }: { me: Me; org?: MeOrg; minimal?: boolean }) {
  const label = minimal ? "Warden" : (org?.name ?? "Choose an organization");
  if (minimal || me.orgs.length <= 1) {
    return (
      <div className="org-switch static">
        <ShieldIcon />
        <span className="org-name">{minimal ? "Warden" : (org?.name ?? me.orgs[0]?.name ?? "Warden")}</span>
      </div>
    );
  }
  return (
    <Popover
      buttonClassName="org-switch"
      buttonLabel={`Organization: ${label}. Switch organization`}
      panelLabel="Organizations"
      button={
        <>
          <ShieldIcon />
          <span className="org-name">{label}</span>
          <UpDownIcon />
        </>
      }
    >
      {(close) => (
        <ul className="menu-list" aria-label="Organizations">
          {me.orgs.map((o) => (
            <li key={o.id}>
              <NavLink to={`/orgs/${o.id}/projects`} className="menu-item" aria-current={o.id === org?.id ? "true" : undefined} onClick={() => close(false)}>
                <span className="grow">{o.name}</span>
                <span className="faint">{ORG_ROLE_LABELS[o.role]}</span>
                {o.id === org?.id && <CheckIcon size={14} />}
              </NavLink>
            </li>
          ))}
        </ul>
      )}
    </Popover>
  );
}

const SIDEBAR_PROJECTS = 8;

function OrgNav({ org }: { org: MeOrg }) {
  const summary = useOrgSummary(org.id);
  const projects = useProjects(org.id);
  const pending = summary.data?.exceptions_pending ?? 0;
  const open = summary.data?.open_issues;
  const base = `/orgs/${org.id}`;
  const list = projects.data ?? [];
  return (
    <nav className="nav" aria-label="Main">
      {/* view_dashboard is granted to every role; the metrics cover the projects the caller can see. */}
      <NavLink to={`${base}/overview`}>
        <OverviewIcon />
        <span className="grow">Overview</span>
      </NavLink>
      <NavLink to={`${base}/projects`} end>
        <ProjectsIcon />
        <span className="grow">All projects</span>
      </NavLink>
      <NavLink to={`${base}/issues`}>
        <IssuesIcon />
        <span className="grow">Issues</span>
        {open !== undefined && open > 0 && <Count label="open">{open}</Count>}
      </NavLink>
      {/* v0.4: the component inventory, next to the issues it explains. */}
      <NavLink to={`${base}/components`}>
        <PackageIcon />
        <span className="grow">Components</span>
      </NavLink>
      <NavLink to={`${base}/exceptions`}>
        <ExceptionsIcon />
        <span className="grow">Exceptions</span>
        {pending > 0 && <Count label="to review">{pending}</Count>}
      </NavLink>

      {list.length > 0 && (
        <>
          <h2 className="nav-head">Projects</h2>
          {list.slice(0, SIDEBAR_PROJECTS).map((p) => (
            <NavLink key={p.id} to={`${base}/projects/${p.id}`}>
              <ProjectDot projectKey={p.key} />
              <span className="grow ellipsis">{p.name}</span>
              <span className="nav-key">{p.key}</span>
            </NavLink>
          ))}
          {list.length > SIDEBAR_PROJECTS && (
            <NavLink to={`${base}/projects`} end className="nav-more">
              <span className="grow">All {list.length} projects</span>
            </NavLink>
          )}
        </>
      )}

      <h2 className="nav-head">Organization</h2>
      <NavLink to={`${base}/members`}>
        <MembersIcon />
        <span className="grow">Members</span>
      </NavLink>
      {can("view_audit_log", org.role) && (
        <NavLink to={`${base}/audit-log`}>
          <AuditIcon />
          <span className="grow">Audit log</span>
        </NavLink>
      )}
      <NavLink to={`${base}/settings`}>
        <SettingsIcon />
        <span className="grow">Settings</span>
      </NavLink>
    </nav>
  );
}
