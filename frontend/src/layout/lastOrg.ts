// The last org the user opened, so "/" lands there. A convenience only: storage may be
// unavailable (private mode, blocked site data), and the value is checked against /me.
const KEY = "warden.lastOrg";

export function rememberOrg(id: string): void {
  try {
    localStorage.setItem(KEY, id);
  } catch {
    // ignore
  }
}

export function lastOrg(): string | null {
  try {
    return localStorage.getItem(KEY);
  } catch {
    return null;
  }
}
