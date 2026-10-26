import { useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import type { CSSProperties, ReactNode } from "react";

/** A small non-modal popover under a button (filter menus, org switcher). The button carries
 *  aria-expanded / aria-controls; the panel holds ordinary buttons and form controls. Focus goes
 *  to the first control on open; Esc closes it and returns focus to the button; a click or focus
 *  outside closes it. Esc is stopped here so the page's own Esc shortcut doesn't also fire.
 *
 *  `fixed` positions the panel against the viewport instead of the button's box, for buttons
 *  inside a scroll container that would clip it (the notifications bell in the sidebar).
 *  `up` opens it above the button (the user menu at the bottom of the sidebar). */
export function Popover({
  button,
  buttonClassName,
  buttonLabel,
  align = "start",
  panelLabel,
  panelClassName,
  open: openProp,
  onOpenChange,
  fixed,
  up,
  children,
}: {
  button: ReactNode;
  buttonClassName?: string;
  buttonLabel?: string;
  align?: "start" | "end";
  panelLabel: string;
  panelClassName?: string;
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
  fixed?: boolean;
  up?: boolean;
  children: (close: (refocus?: boolean) => void) => ReactNode;
}) {
  const [openState, setOpenState] = useState(false);
  const open = openProp ?? openState;
  const wrap = useRef<HTMLSpanElement>(null);
  const btn = useRef<HTMLButtonElement>(null);
  const panel = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState<CSSProperties | undefined>(undefined);
  const id = useId();
  const latest = useRef(onOpenChange);
  latest.current = onOpenChange;
  const controlled = openProp !== undefined;

  const setOpen = (v: boolean) => {
    latest.current?.(v);
    if (!controlled) setOpenState(v);
  };
  const setOpenRef = useRef(setOpen);
  setOpenRef.current = setOpen;

  const close = (refocus = true) => {
    setOpen(false);
    if (refocus) btn.current?.focus();
  };

  useLayoutEffect(() => {
    if (!open || !fixed) return;
    const place = () => {
      const b = btn.current?.getBoundingClientRect();
      const w = panel.current?.offsetWidth ?? 320;
      if (!b) return;
      const left = Math.max(8, Math.min(b.left, window.innerWidth - w - 8));
      setPos({ position: "fixed", top: b.bottom + 4, left, right: "auto" });
    };
    place();
    window.addEventListener("resize", place);
    return () => window.removeEventListener("resize", place);
  }, [open, fixed]);

  useEffect(() => {
    if (!open) return;
    const first = panel.current?.querySelector<HTMLElement>(
      "[data-autofocus], input:not([disabled]), button:not([disabled]), a[href], select",
    );
    (first ?? panel.current)?.focus();
    const onDown = (e: PointerEvent) => {
      if (wrap.current && !wrap.current.contains(e.target as Node)) setOpenRef.current(false);
    };
    document.addEventListener("pointerdown", onDown);
    return () => document.removeEventListener("pointerdown", onDown);
  }, [open]);

  return (
    <span
      className="pop-wrap"
      ref={wrap}
      onBlur={(e) => {
        if (open && e.relatedTarget && !wrap.current?.contains(e.relatedTarget as Node)) setOpen(false);
      }}
    >
      <button
        ref={btn}
        type="button"
        className={buttonClassName}
        aria-label={buttonLabel}
        aria-expanded={open}
        aria-controls={open ? id : undefined}
        onClick={() => setOpen(!open)}
      >
        {button}
      </button>
      {open && (
        <div
          id={id}
          ref={panel}
          role="group"
          aria-label={panelLabel}
          tabIndex={-1}
          style={fixed ? (pos ?? { position: "fixed", opacity: 0 }) : undefined}
          className={["popover", `popover-${align}`, up ? "popover-up" : "", panelClassName ?? ""].filter(Boolean).join(" ")}
          onKeyDown={(e) => {
            if (e.key === "Escape") {
              e.preventDefault();
              e.stopPropagation();
              close();
            }
          }}
        >
          {children(close)}
        </div>
      )}
    </span>
  );
}
