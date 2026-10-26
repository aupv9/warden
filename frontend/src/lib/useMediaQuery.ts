import { useSyncExternalStore } from "react";

export function useMediaQuery(query: string): boolean {
  return useSyncExternalStore(
    (cb) => {
      const mql = window.matchMedia(query);
      mql.addEventListener("change", cb);
      return () => mql.removeEventListener("change", cb);
    },
    () => window.matchMedia(query).matches,
    () => false,
  );
}

/** DESIGN.md "Phone layout" breakpoint. */
export function useIsPhone(): boolean {
  return useMediaQuery("(max-width: 800px)");
}

/** From 1200 px the issue list and an opened issue sit side by side (split view). */
export const SPLIT_QUERY = "(min-width: 1200px)";
export function useIsWide(): boolean {
  return useMediaQuery(SPLIT_QUERY);
}
