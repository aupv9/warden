import { useEffect, useId, useRef } from "react";
import type { ReactNode } from "react";
import { CloseIcon } from "./Icons";

/** A modal on the native <dialog>: showModal() gives the focus trap, Esc and an inert page.
 *  Focus goes to the first field (or the dialog) on open and back to the opener on close.
 *  Children mount only while open, so forms start fresh each time. */
export function Dialog({
  open,
  onClose,
  title,
  description,
  children,
  className = "dialog",
}: {
  className?: string;
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  description?: ReactNode;
  children: ReactNode;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const opener = useRef<HTMLElement | null>(null);
  const titleId = useId();
  const descId = useId();

  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) {
      opener.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
      dialog.showModal();
      const first = dialog.querySelector<HTMLElement>(
        "[data-autofocus], .dialog-body input:not([type=hidden]), .dialog-body textarea, .dialog-body select",
      );
      (first ?? dialog).focus();
    } else if (!open && dialog.open) {
      dialog.close();
    }
  }, [open]);

  useEffect(() => {
    // Restore focus when the dialog unmounts or closes.
    if (!open && opener.current) {
      opener.current.focus();
      opener.current = null;
    }
  }, [open]);

  return (
    <dialog
      ref={ref}
      className={className}
      aria-modal="true"
      aria-labelledby={titleId}
      aria-describedby={description ? descId : undefined}
      tabIndex={-1}
      onCancel={(e) => {
        e.preventDefault();
        onClose();
      }}
    >
      {open && (
        <div className="dialog-body">
          <div className="dialog-head">
            <div className="stack" style={{ gap: 4 }}>
              <h2 id={titleId}>{title}</h2>
              {description && (
                <p id={descId} className="muted">
                  {description}
                </p>
              )}
            </div>
            <button type="button" className="icon-btn" aria-label="Close" onClick={onClose}>
              <CloseIcon />
            </button>
          </div>
          {children}
        </div>
      )}
    </dialog>
  );
}
