import { useEffect, useId, useRef, useState } from "react";
import type { ReactNode } from "react";

/** A small non-modal popover under a button (filter menus, org switcher). The button carries
 *  aria-expanded / aria-controls; the panel holds ordinary buttons and form controls. Focus goes
 *  to the first control on open; Esc closes it and returns focus to the button; a click or focus
 *  outside closes it. Esc is stopped here so the page's own Esc shortcut doesn't also fire. */
export function Popover({
  button,
  buttonClassName,
  buttonLabel,
  align = "start",
  panelLabel,
  panelClassName,
  open: openProp,
  onOpenChange,
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
  children: (close: (refocus?: boolean) => void) => ReactNode;
}) {
  const [openState, setOpenState] = useState(false);
  const open = openProp ?? openState;
  const wrap = useRef<HTMLSpanElement>(null);
  const btn = useRef<HTMLButtonElement>(null);
  const panel = useRef<HTMLDivElement>(null);
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
          className={["popover", `popover-${align}`, panelClassName ?? ""].filter(Boolean).join(" ")}
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
