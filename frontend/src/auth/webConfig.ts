import { transport } from "../api/transport";
import type { WebConfig } from "../api/types";

// The web UI's OIDC settings come from the server it is served by (GET /api/v1/web-config,
// public), so one prebuilt UI works with any Warden instance; nothing about the identity
// provider is baked in at build time. The answer decides where the browser sends people to
// sign in, so every field is checked before use and anything unexpected is an error: the UI then
// shows "Can't reach the server's sign-in settings" rather than guessing or falling back.

/** Any failure to get usable settings (network, non-200, not JSON, a bad field). Deliberately
 *  carries no detail: nothing of the response reaches the UI or a log. */
export class WebConfigError extends Error {
  constructor() {
    super("web config unavailable");
    this.name = "WebConfigError";
  }
}

export interface WebConfigRules {
  /** Accept an `http://` issuer on a loopback host (the dev Keycloak on localhost:8180). */
  allowLoopbackHttp: boolean;
}

const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** `npm run dev`, or the UI itself served from a loopback address: only then can a plain-http
 *  issuer on this machine be what the operator meant. A UI on a real host never accepts one. */
export function defaultRules(): WebConfigRules {
  return { allowLoopbackHttp: import.meta.env.DEV || LOOPBACK.has(window.location.hostname) };
}

const MAX_URL = 2048;
const MAX_TEXT = 1024;
// Control characters and whitespace (U+0000–U+0020, U+007F–U+009F).
const CONTROL = /[\u0000- \u007f-\u009f]/;
// RFC 6749 client_id: VSCHAR (printable ASCII); no leading or trailing space.
const CLIENT_ID = /^[\x21-\x7e](?:[\x20-\x7e]{0,253}[\x21-\x7e])?$/;
// RFC 6749 scope: scope-tokens (NQCHAR) separated by single spaces.
const SCOPE = /^[\x21\x23-\x5b\x5d-\x7e]+(?: [\x21\x23-\x5b\x5d-\x7e]+)*$/;

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function validIssuer(v: unknown, rules: WebConfigRules): v is string {
  if (typeof v !== "string" || v.length === 0 || v.length > MAX_URL || CONTROL.test(v)) return false;
  // An OIDC issuer has no query or fragment (OIDC Discovery 1.0, section 4).
  if (v.includes("?") || v.includes("#")) return false;
  let u: URL;
  try {
    u = new URL(v);
  } catch {
    return false;
  }
  if (u.username || u.password || !u.hostname) return false;
  if (u.protocol === "https:") return true;
  return u.protocol === "http:" && rules.allowLoopbackHttp && LOOPBACK.has(u.hostname);
}

function validAudience(v: unknown): v is string | null {
  if (v === null) return true;
  return typeof v === "string" && v.length > 0 && v.length <= MAX_TEXT && v.trim() === v && !/[\u0000-\u001f\u007f-\u009f]/.test(v);
}

/** The `data` of a GET /web-config envelope, checked field by field. Unknown extra fields are
 *  ignored (a newer server may add some); a missing, mistyped or malformed field throws. */
export function parseWebConfig(body: unknown, rules: WebConfigRules): WebConfig {
  if (!isObject(body) || (body.error !== null && body.error !== undefined)) throw new WebConfigError();
  const d = body.data;
  if (!isObject(d)) throw new WebConfigError();
  const { issuer, client_id, scope, audience } = d;
  if (!validIssuer(issuer, rules)) throw new WebConfigError();
  if (typeof client_id !== "string" || !CLIENT_ID.test(client_id)) throw new WebConfigError();
  if (typeof scope !== "string" || scope.length > MAX_TEXT || !SCOPE.test(scope) || !scope.split(" ").includes("openid")) {
    throw new WebConfigError();
  }
  if (!("audience" in d) || !validAudience(audience)) throw new WebConfigError();
  return { issuer, client_id, scope, audience };
}

export type Fetcher = (url: string, init: RequestInit) => Promise<Response>;

const TIMEOUT_MS = 15_000;

/** GET /api/v1/web-config: same origin, no token, no cookies; a redirect (e.g. a proxy's login
 *  page) is an error. Throws WebConfigError for every failure. */
export async function loadWebConfig(fetchFn: Fetcher = transport, rules: WebConfigRules = defaultRules()): Promise<WebConfig> {
  let res: Response;
  try {
    res = await fetchFn("/api/v1/web-config", {
      method: "GET",
      headers: { Accept: "application/json" },
      credentials: "omit",
      redirect: "error",
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch {
    throw new WebConfigError();
  }
  if (res.status !== 200 || !/^application\/json\b/i.test(res.headers.get("Content-Type") ?? "")) throw new WebConfigError();
  let body: unknown;
  try {
    body = await res.json();
  } catch {
    throw new WebConfigError();
  }
  return parseWebConfig(body, rules);
}
