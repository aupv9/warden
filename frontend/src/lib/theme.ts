import { useSyncExternalStore } from "react";

// Colour theme. "system" follows prefers-color-scheme through CSS alone (tokens.css); an
// explicit choice sets data-theme on <html>. The choice is a per-browser convenience: storage
// may be unavailable (private mode, blocked site data), and then it lasts for the page only.
export type Theme = "system" | "light" | "dark";

export const THEMES: readonly Theme[] = ["system", "light", "dark"];
const KEY = "warden.theme";
const listeners = new Set<() => void>();
let current: Theme = "system";

function isTheme(v: unknown): v is Theme {
  return typeof v === "string" && (THEMES as readonly string[]).includes(v);
}

function apply(t: Theme): void {
  const root = document.documentElement;
  if (t === "system") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", t);
}

/** Reads the stored choice and applies it; call once before the first render. */
export function initTheme(): Theme {
  let stored: string | null = null;
  try {
    stored = localStorage.getItem(KEY);
  } catch {
    // ignore
  }
  current = isTheme(stored) ? stored : "system";
  apply(current);
  return current;
}

export function getTheme(): Theme {
  return current;
}

export function setTheme(t: Theme): void {
  if (!isTheme(t)) return;
  current = t;
  apply(t);
  try {
    if (t === "system") localStorage.removeItem(KEY);
    else localStorage.setItem(KEY, t);
  } catch {
    // ignore
  }
  listeners.forEach((l) => l());
}

function subscribe(l: () => void): () => void {
  listeners.add(l);
  return () => listeners.delete(l);
}

export function useTheme(): Theme {
  return useSyncExternalStore(subscribe, getTheme, getTheme);
}
