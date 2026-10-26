import { useEffect, useState } from "react";
import type { CSSProperties, ReactNode } from "react";
import { Link } from "react-router";
import { errorMessage, isForbidden, isNotFound, isToastedActionError, supportReference } from "../api/errors";
import type { ErrorOverrides } from "../api/errors";
import { AlertIcon, LockIcon, SearchIcon } from "./Icons";

export function EmptyState({
  title,
  children,
  action,
  icon,
}: {
  title: ReactNode;
  children?: ReactNode;
  action?: ReactNode;
  icon?: ReactNode;
}) {
  return (
    <div className="empty">
      {icon && (
        <span className="state-icon" aria-hidden="true">
          {icon}
        </span>
      )}
      <h3>{title}</h3>
      {children && <div className="muted">{children}</div>}
      {action}
    </div>
  );
}

/** A failed load, in place of the data. 403 and 404 get their own wording (and never hint
 *  whether a 404'd object exists). Network/5xx show the request ID to quote to the operator. */
export function ErrorState({
  error,
  onRetry,
  what = "this page",
}: {
  error: unknown;
  onRetry?: () => void;
  what?: string;
}) {
  if (isNotFound(error)) return <NotFoundState />;
  if (isForbidden(error)) return <ForbiddenState />;
  const ref = supportReference(error);
  return (
    <div className="empty" role="alert">
      <span className="state-icon danger" aria-hidden="true">
        <AlertIcon size={20} />
      </span>
      <h3>Couldn't load {what}</h3>
      <p className="muted">
        {errorMessage(error)}
        {ref ? " If it keeps happening, give your operator the request ID." : ""}
      </p>
      {onRetry && (
        <button type="button" className="btn btn-primary" onClick={onRetry}>
          Try again
        </button>
      )}
      {ref && <p className="mono muted ref">Request ID {ref}</p>}
    </div>
  );
}

export function NotFoundState({ backTo, backLabel }: { backTo?: string; backLabel?: string }) {
  return (
    <div className="empty">
      <span className="state-icon" aria-hidden="true">
        <SearchIcon size={20} />
      </span>
      <span className="mono muted">404</span>
      <h3>Not found</h3>
      <p className="muted">This page doesn't exist, or you don't have access to it. Check the link, or ask the person who sent it.</p>
      <Link className="btn btn-ghost" to={backTo ?? "/"}>
        {backLabel ?? "Back to projects"}
      </Link>
    </div>
  );
}

export function ForbiddenState({ orgName, backTo }: { orgName?: string; backTo?: string }) {
  return (
    <div className="empty">
      <span className="state-icon" aria-hidden="true">
        <LockIcon size={20} />
      </span>
      <span className="mono muted">403</span>
      <h3>You don't have access to this</h3>
      <p className="muted">
        Your role{orgName ? ` in ${orgName}` : ""} doesn't include this page. Ask an org admin if you need it.
      </p>
      <Link className="btn btn-ghost" to={backTo ?? "/"}>
        Back to projects
      </Link>
    </div>
  );
}

/** An inline banner for a failed action. Codes reported by toast (403, 404, 429, network/5xx)
 *  render nothing here, so the same error isn't shown twice. */
export function ActionError({ error, overrides, always }: { error: unknown; overrides?: ErrorOverrides; always?: boolean }) {
  if (!error || (!always && isToastedActionError(error))) return null;
  return (
    <div className="banner banner-error" role="alert">
      <AlertIcon />
      <span>{errorMessage(error, overrides)}</span>
    </div>
  );
}

export function Banner({ tone = "error", title, children, action }: { tone?: "error" | "warning" | "info"; title?: ReactNode; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className={`banner banner-${tone}`} role={tone === "info" ? "status" : "alert"}>
      {tone === "info" ? <LockIcon /> : <AlertIcon />}
      <div className="stack" style={{ gap: 10 }}>
        <span>
          {title && <strong>{title} </strong>}
          {children}
        </span>
        {action}
      </div>
    </div>
  );
}

/** True once `ms` have passed: skeletons wait 300 ms so fast loads don't flash. */
export function useDelayed(ms = 300): boolean {
  const [ready, setReady] = useState(false);
  useEffect(() => {
    const t = setTimeout(() => setReady(true), ms);
    return () => clearTimeout(t);
  }, [ms]);
  return ready;
}

export function Skeleton({ width = "100%", height = 14, style }: { width?: number | string; height?: number; style?: CSSProperties }) {
  return <span className="skeleton" style={{ width, height, ...style }} aria-hidden="true" />;
}

/** A loading region: aria-busy, a hidden status text, and static bars after 300 ms. */
export function Loading({ label, children }: { label: string; children: ReactNode }) {
  const show = useDelayed();
  return (
    <div aria-busy="true">
      <span role="status" className="visually-hidden">
        Loading {label}…
      </span>
      {show && children}
    </div>
  );
}

export function SkeletonBlock({ label, lines = 4, height = 14 }: { label: string; lines?: number; height?: number }) {
  return (
    <Loading label={label}>
      <div className="stack" style={{ gap: 12 }}>
        {Array.from({ length: lines }, (_, i) => (
          <Skeleton key={i} height={height} width={i === lines - 1 ? "60%" : "100%"} />
        ))}
      </div>
    </Loading>
  );
}

/** Five rows in a table-like layout. */
export function SkeletonRows({ label, rows = 5 }: { label: string; rows?: number }) {
  return (
    <Loading label={label}>
      <div className="skeleton-rows">
        {Array.from({ length: rows }, (_, i) => (
          <div key={i} className="skeleton-row">
            <div className="stack" style={{ gap: 6, flex: 3 }}>
              <Skeleton width={`${60 + ((i * 13) % 30)}%`} />
              <Skeleton width="35%" height={10} />
            </div>
            <Skeleton width={64} height={22} style={{ borderRadius: 999 }} />
            <Skeleton width={80} />
            <Skeleton width={56} />
          </div>
        ))}
      </div>
    </Loading>
  );
}

export function SkeletonCards({ label, count = 3, height = 150 }: { label: string; count?: number; height?: number }) {
  return (
    <Loading label={label}>
      <div className="grid grid-cards">
        {Array.from({ length: count }, (_, i) => (
          <div key={i} className="card stack" style={{ gap: 12, minHeight: height }}>
            <Skeleton width="30%" height={10} />
            <Skeleton width="70%" height={18} />
            <Skeleton width="55%" />
          </div>
        ))}
      </div>
    </Loading>
  );
}
