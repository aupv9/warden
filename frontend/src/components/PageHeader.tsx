import type { ReactNode } from "react";

/** The 52 px bar at the top of every page: title, optional segmented views, actions on the right.
 *  On phones it wraps into a normal heading block. */
export function PageHeader({
  title,
  titleAs: Title = "h1",
  children,
  actions,
}: {
  title: ReactNode;
  /** "div" when the page's h1 is further down (the issue page puts its title there). */
  titleAs?: "h1" | "div";
  children?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <header className="page-head">
      <Title className="page-title">{title}</Title>
      {children && <div className="page-head-mid">{children}</div>}
      {actions && <div className="page-head-actions">{actions}</div>}
    </header>
  );
}

/** A segmented control around links (`nav`) or tab buttons (`tablist`). The active item gets
 *  the white "lifted" look; links mark it with aria-current, tabs with aria-selected. */
export function Segmented({ label, as = "nav", children }: { label: string; as?: "nav" | "tablist" | "group"; children: ReactNode }) {
  if (as === "nav") {
    return (
      <nav className="segmented" aria-label={label}>
        {children}
      </nav>
    );
  }
  return (
    <div className="segmented" role={as} aria-label={label}>
      {children}
    </div>
  );
}

/** A keyboard key hint. */
export function Kbd({ children }: { children: ReactNode }) {
  return <kbd className="kbd">{children}</kbd>;
}
