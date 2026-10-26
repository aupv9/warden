import { useEffect, useRef, useState } from "react";
import { dismissToast, useToasts } from "../lib/toast";
import type { Toast } from "../lib/toast";
import { CheckIcon, CloseIcon, ClockIcon, AlertIcon } from "./Icons";

const SUCCESS_MS = 6000;

export function Toaster() {
  const toasts = useToasts();
  return (
    <div className="toaster" aria-label="Notifications">
      {toasts.map((t) => (
        <ToastItem key={t.id} toast={t} />
      ))}
    </div>
  );
}

function ToastItem({ toast }: { toast: Toast }) {
  const [paused, setPaused] = useState(false);
  const remaining = useRef(SUCCESS_MS);
  const startedAt = useRef(Date.now());

  useEffect(() => {
    if (toast.tone !== "success" || paused) return;
    startedAt.current = Date.now();
    const t = setTimeout(() => dismissToast(toast.id), remaining.current);
    return () => {
      clearTimeout(t);
      remaining.current -= Date.now() - startedAt.current;
    };
  }, [paused, toast.id, toast.tone]);

  const Icon = toast.tone === "success" ? CheckIcon : toast.tone === "warning" ? ClockIcon : AlertIcon;
  return (
    <div
      className={`toast toast-${toast.tone}`}
      role={toast.tone === "success" ? "status" : "alert"}
      onMouseEnter={() => setPaused(true)}
      onMouseLeave={() => setPaused(false)}
      onFocus={() => setPaused(true)}
      onBlur={() => setPaused(false)}
    >
      <Icon />
      <div className="toast-text">
        {toast.title && <strong>{toast.title} </strong>}
        {toast.message}
        {toast.reference && <div className="mono ref">Request ID {toast.reference}</div>}
      </div>
      <button type="button" className="toast-close" aria-label="Dismiss" onClick={() => dismissToast(toast.id)}>
        <CloseIcon />
      </button>
    </div>
  );
}
