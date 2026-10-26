import type { ReactNode } from "react";
import { Button } from "./Button";

/** A table that scrolls sideways inside its card on narrow screens, or (with `stack`) turns into
 *  stacked rows below 800 px. Cells give their column name in `data-label` for that layout. */
export function Table({
  caption,
  head,
  children,
  stack = true,
}: {
  caption: string;
  head: ReactNode;
  children: ReactNode;
  stack?: boolean;
}) {
  return (
    <div className={stack ? "table-wrap stackable" : "table-wrap"} tabIndex={0} role="region" aria-label={caption}>
      <table className="table">
        <caption className="visually-hidden">{caption}</caption>
        <thead>{head}</thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}

export function LoadMore({
  hasNext,
  loading,
  onLoad,
  shown,
  noun = "entries",
  label = "Load more",
}: {
  hasNext: boolean;
  loading: boolean;
  onLoad: () => void;
  shown: number;
  noun?: string;
  label?: string;
}) {
  return (
    <div className="table-foot">
      <span>
        Showing {shown} {noun}
      </span>
      {hasNext && (
        <Button size="sm" onClick={onLoad} busy={loading}>
          {loading ? "Loading…" : label}
        </Button>
      )}
    </div>
  );
}
