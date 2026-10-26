import { useSyncExternalStore } from "react";

// A tiny toast store outside React, so the query client's global error handler can post toasts.
// DESIGN.md "Messages": at most 3, newest at the bottom; success closes after 6 s (paused on
// hover/focus, handled by the Toaster); error and warning stay until dismissed.

export type ToastTone = "success" | "error" | "warning";

export interface Toast {
  id: number;
  tone: ToastTone;
  /** Bold lead-in, optional. */
  title?: string;
  message: string;
  /** For server errors: the request ID to quote to an operator. */
  reference?: string;
}

const MAX = 3;
let toasts: Toast[] = [];
let nextId = 1;
const listeners = new Set<() => void>();

function emit() {
  for (const l of listeners) l();
}

export function showToast(t: Omit<Toast, "id">): number {
  const id = nextId++;
  // Same message twice in a row (e.g. several queries failing at once): keep one.
  if (toasts.some((x) => x.message === t.message && x.tone === t.tone)) return id;
  toasts = [...toasts, { ...t, id }].slice(-MAX);
  emit();
  return id;
}

export function dismissToast(id: number): void {
  toasts = toasts.filter((t) => t.id !== id);
  emit();
}

export function clearToasts(): void {
  toasts = [];
  emit();
}

export function useToasts(): Toast[] {
  return useSyncExternalStore(
    (cb) => {
      listeners.add(cb);
      return () => listeners.delete(cb);
    },
    () => toasts,
    () => toasts,
  );
}
