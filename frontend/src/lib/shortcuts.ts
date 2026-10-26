import { useEffect, useRef } from "react";

// Keyboard shortcuts. Only the documented ones exist (the footer bar on the Issues page lists
// them); each page that uses some registers just those, and the listener is removed when the
// page unmounts. None of them fire while the user is typing in a field, while a dialog (modal,
// drawer, command palette) is open, or when another handler already took the key.

export type Shortcut = "palette" | "next" | "prev" | "open" | "close" | "assign" | "select" | "search";

/** The parts of a KeyboardEvent the matcher looks at (so it can be tested without a DOM). */
export interface KeyLike {
  key: string;
  metaKey: boolean;
  ctrlKey: boolean;
  altKey: boolean;
  shiftKey?: boolean;
  isComposing?: boolean;
  defaultPrevented?: boolean;
  target: unknown;
}

interface TargetLike {
  tagName?: string;
  isContentEditable?: boolean;
  type?: string;
  getAttribute?: (name: string) => string | null;
  closest?: (selector: string) => unknown;
}

const TEXT_INPUT_TYPES = new Set(["", "text", "search", "email", "url", "tel", "password", "number", "date", "datetime-local", "month", "time", "week"]);

/** True when keys typed here are text: inputs (text-like), textareas, selects, contenteditable. */
export function isTypingTarget(target: unknown): boolean {
  if (!target || typeof target !== "object") return false;
  const t = target as TargetLike;
  if (t.isContentEditable) return true;
  const tag = (t.tagName ?? "").toUpperCase();
  if (tag === "TEXTAREA" || tag === "SELECT") return true;
  if (tag === "INPUT") return TEXT_INPUT_TYPES.has((t.type ?? "").toLowerCase());
  const role = t.getAttribute?.("role");
  return role === "textbox" || role === "combobox" || role === "searchbox";
}

/** True for elements where Enter already does something (links, buttons, form controls). */
export function isInteractiveTarget(target: unknown): boolean {
  if (!target || typeof target !== "object") return false;
  const t = target as TargetLike;
  const tag = (t.tagName ?? "").toUpperCase();
  if (["A", "BUTTON", "INPUT", "SELECT", "TEXTAREA", "SUMMARY", "LABEL"].includes(tag)) return true;
  const role = t.getAttribute?.("role");
  return role === "button" || role === "link" || role === "tab" || role === "option" || role === "checkbox";
}

/** Which shortcut a key press means, or null. `dialogOpen`: any modal dialog is open. */
export function matchShortcut(e: KeyLike, env: { dialogOpen: boolean }): Shortcut | null {
  if (e.defaultPrevented || e.isComposing || env.dialogOpen) return null;
  if (isTypingTarget(e.target)) return null;
  const mod = e.metaKey || e.ctrlKey;
  if (mod && !e.altKey && (e.key === "k" || e.key === "K")) return "palette";
  if (mod || e.altKey) return null;
  switch (e.key) {
    case "j":
    case "J":
      return "next";
    case "k":
    case "K":
      return "prev";
    case "Enter":
      return isInteractiveTarget(e.target) ? null : "open";
    case "Escape":
      return "close";
    case "a":
    case "A":
      return "assign";
    case "x":
    case "X":
      return "select";
    case "/":
      return "search";
    default:
      return null;
  }
}

/** Any open modal <dialog> (dialogs, the phone drawer, the command palette). */
export function anyDialogOpen(doc: Document = document): boolean {
  return doc.querySelector("dialog[open]") !== null;
}

/** Register handlers for some shortcuts while the calling component is mounted. A handler
 *  returns false to say it didn't use the key (so the browser's default stays). */
export function useShortcuts(handlers: Partial<Record<Shortcut, () => boolean | void>>): void {
  const latest = useRef(handlers);
  latest.current = handlers;
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const s = matchShortcut(e, { dialogOpen: anyDialogOpen() });
      if (!s) return;
      const h = latest.current[s];
      if (!h) return;
      if (h() !== false) e.preventDefault();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
}
