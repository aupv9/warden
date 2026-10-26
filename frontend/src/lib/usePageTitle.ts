import { useEffect } from "react";

/** Sets document.title. `null` leaves it to another component (e.g. the issue in the split view). */
export function usePageTitle(title: string | undefined | null): void {
  useEffect(() => {
    if (title === null) return;
    document.title = title ? `${title} · Warden` : "Warden";
  }, [title]);
}
