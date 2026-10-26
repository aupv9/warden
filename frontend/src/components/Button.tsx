import type { ButtonHTMLAttributes, ReactNode } from "react";
import { Link } from "react-router";
import type { LinkProps } from "react-router";

type Variant = "primary" | "ghost" | "danger";

function cls(variant: Variant, size: "md" | "sm", extra?: string) {
  return ["btn", `btn-${variant}`, size === "sm" ? "btn-sm" : "", extra ?? ""].filter(Boolean).join(" ");
}

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: "md" | "sm";
  busy?: boolean;
}

export function Button({ variant = "ghost", size = "md", busy, className, children, disabled, ...rest }: ButtonProps) {
  return (
    <button
      type="button"
      className={cls(variant, size, className)}
      disabled={disabled || busy}
      aria-busy={busy || undefined}
      {...rest}
    >
      {children}
    </button>
  );
}

export function ButtonLink({
  variant = "ghost",
  size = "md",
  className,
  ...rest
}: LinkProps & { variant?: Variant; size?: "md" | "sm"; children: ReactNode }) {
  return <Link className={cls(variant, size, className)} {...rest} />;
}
