import type { HTMLAttributes, ReactNode } from "react";

export function Card({
  title,
  titleId,
  actions,
  flush,
  dashed,
  className,
  children,
  as: Tag = "section",
  ...rest
}: {
  title?: ReactNode;
  titleId?: string;
  actions?: ReactNode;
  flush?: boolean;
  dashed?: boolean;
  as?: "section" | "div" | "article" | "aside";
} & HTMLAttributes<HTMLElement>) {
  const classes = ["card", flush ? "card-flush" : "", dashed ? "card-dashed" : "", className ?? ""]
    .filter(Boolean)
    .join(" ");
  return (
    <Tag className={classes} aria-labelledby={title && titleId ? titleId : undefined} {...rest}>
      {(title || actions) && (
        <div className="card-head">
          {title && <h2 id={titleId}>{title}</h2>}
          {actions && <div className="row">{actions}</div>}
        </div>
      )}
      {children}
    </Tag>
  );
}
