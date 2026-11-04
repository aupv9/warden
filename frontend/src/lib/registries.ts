import type {
  CreateRegistryCredentialBody,
  RegistryCredential,
  RegistryTestResult,
  UpdateRegistryCredentialBody,
} from "../api/types";
import { relativeTime } from "./format";

// v0.7 wave 2: registry credentials (Org settings → Registries, manage_registries) and scans of
// images Warden pulls itself (New scan → Image from a registry). DESIGN.md "v0.7 screens".
//
// A password or token is typed once and never read back: the API doesn't return it, the form
// clears it as soon as it is submitted (credentialFormReducer), and the request body reaches
// the mutation through a closure, never as mutation variables (hooks/registries.ts;
// registries.test.ts checks the caches, storage and the console).

/** The server's limits (openapi: RegistryCredential, CreateRegistryCredentialRequest). */
export const REGISTRY_MAX = 20;
export const REGISTRY_HOST_MAX = 253;
export const REGISTRY_USERNAME_MAX = 256;
export const REGISTRY_PASSWORD_MAX = 4096;
/** Tests per credential per hour (the server's rate limit). */
export const REGISTRY_TESTS_PER_HOUR = 10;

/** The contract's host pattern: lower case DNS name with at least one dot, an optional port. */
export const REGISTRY_HOST_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+(:[0-9]{1,5})?$/;
const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}(:\d+)?$/;

export const REGISTRY_TEST_RATE_LIMITED = `These credentials were tested ${REGISTRY_TESTS_PER_HOUR} times in the last hour, the most Warden allows. Try again later.`;

/** 409 SECRETS_KEY_MISSING on POST and PATCH …/registries. The list loads without the key, so
 *  this only shows once someone saves. */
export const REGISTRY_SECRETS_KEY_MISSING =
  "Registry credentials are turned off on this server: it has no key to encrypt them. Ask your operator to set WARDEN_SECRETS__KEY.";

export const REGISTRY_EXISTS = "This org already has credentials for this host. Change those instead of adding new ones.";
export const REGISTRY_LIMIT = `This org already has credentials for ${REGISTRY_MAX} hosts, the most Warden allows. Delete one you no longer use, then add this one.`;

/** The words for the create dialog's 409 CONFLICT (a host that has credentials, or the 20th). */
export function registryConflictText(items: Pick<RegistryCredential, "host">[] | undefined, host: string): string {
  if (items?.some((c) => c.host === host)) return REGISTRY_EXISTS;
  if (items && items.length >= REGISTRY_MAX) return REGISTRY_LIMIT;
  return "This org already has credentials for this host, or for 20 hosts. Reload the list, then try again.";
}

/** Host as the server stores it: trimmed and lower case. */
export function tidyHost(raw: string): string {
  return raw.trim().toLowerCase();
}

export function validateHost(raw: string): string | null {
  const s = tidyHost(raw);
  if (!s) return "Enter the registry's host, such as ghcr.io.";
  if (s.length > REGISTRY_HOST_MAX) return `At most ${REGISTRY_HOST_MAX} characters.`;
  if (/^[a-z][a-z0-9+.-]*:\/\//.test(s)) return "Leave out https:// : only the host, such as ghcr.io.";
  if (s.includes("/")) return "Only the host (and port), without a path: such as registry.example.com:5000.";
  if (IPV4_RE.test(s) || s.startsWith("[")) return "Use the registry's host name, not an IP address.";
  if (s.includes("@")) return "Only the host: the username goes in its own field.";
  if (!REGISTRY_HOST_RE.test(s)) return "Use a host name with a dot, such as ghcr.io or registry.example.com:5000.";
  const port = s.match(/:(\d+)$/)?.[1];
  if (port && (Number(port) < 1 || Number(port) > 65535)) return "The port is a number from 1 to 65535.";
  return null;
}

export function validateUsername(raw: string): string | null {
  const s = raw.trim();
  if (!s) return "Enter the username.";
  if (s.length > REGISTRY_USERNAME_MAX) return `At most ${REGISTRY_USERNAME_MAX} characters.`;
  return null;
}

/** `required` on create; on edit an empty field keeps the stored password. */
export function validatePassword(raw: string, required: boolean): string | null {
  if (!raw) return required ? "Enter the password or access token." : null;
  if (raw.length > REGISTRY_PASSWORD_MAX) return `At most ${REGISTRY_PASSWORD_MAX} characters.`;
  return null;
}

// ---- The add / change form ----

export interface CredentialForm {
  host: string;
  username: string;
  /** Typed once, sent once, then cleared ("submitted"). Never prefilled. */
  password: string;
}

export const NEW_CREDENTIAL_FORM: CredentialForm = { host: "", username: "", password: "" };

export type CredentialFormAction =
  | { type: "set"; patch: Partial<CredentialForm> }
  /** The request was built: the password leaves the form state at once, before any answer. */
  | { type: "submitted" }
  | { type: "reset"; form: CredentialForm };

export function credentialFormReducer(state: CredentialForm, action: CredentialFormAction): CredentialForm {
  switch (action.type) {
    case "set":
      return { ...state, ...action.patch };
    case "submitted":
      return { ...state, password: "" };
    case "reset":
      return { ...action.form, password: "" };
  }
}

export function formFromCredential(c: RegistryCredential): CredentialForm {
  return { host: c.host, username: c.username, password: "" };
}

export function validateCredentialForm(f: CredentialForm, editing: boolean): Partial<Record<keyof CredentialForm, string>> {
  const out: Partial<Record<keyof CredentialForm, string>> = {};
  const host = editing ? null : validateHost(f.host);
  const user = validateUsername(f.username);
  const pass = validatePassword(f.password, !editing);
  if (host) out.host = host;
  if (user) out.username = user;
  if (pass) out.password = pass;
  return out;
}

export function createCredentialBody(f: CredentialForm): CreateRegistryCredentialBody {
  // The password is sent exactly as typed (no trimming: a token's characters all count).
  return { host: tidyHost(f.host), username: f.username.trim(), password: f.password };
}

/** Only what changed; null when nothing did. An empty password field keeps the stored one. */
export function updateCredentialBody(f: CredentialForm, c: RegistryCredential): UpdateRegistryCredentialBody | null {
  const body: UpdateRegistryCredentialBody = {};
  const username = f.username.trim();
  if (username !== c.username) body.username = username;
  if (f.password) body.password = f.password;
  return Object.keys(body).length ? body : null;
}

// ---- The list ----

/** The last failure in words (RegistryCredential.last_error, the test's error). The enum may
 *  grow: anything else falls back to a generic sentence; the raw value is never shown as markup. */
export function registryErrorText(error: string | null): string | null {
  switch (error) {
    case null:
      return null;
    case "unauthorized":
      return "The registry refused these credentials. Check the username and the password or token (a token needs read access to packages), then change them here.";
    case "unreachable":
      return "Warden couldn't reach the registry. Check the host name and port, and that the registry answers on https.";
    case "blocked":
      return "The host resolves to a private or internal address, so Warden doesn't connect to it.";
    default:
      return "The last attempt with these credentials failed.";
  }
}

/** A short label for the list's status column. */
export function registryErrorLabel(error: string | null): string | null {
  switch (error) {
    case null:
      return null;
    case "unauthorized":
      return "Refused";
    case "unreachable":
      return "Unreachable";
    case "blocked":
      return "Blocked address";
    default:
      return "Failed";
  }
}

export function lastUsedText(c: Pick<RegistryCredential, "last_used_at">, now: Date = new Date()): string {
  return c.last_used_at ? `Used ${relativeTime(c.last_used_at, now)}` : "Not used yet";
}

/** The result of "Test", in words. */
export function testResultText(r: RegistryTestResult, host: string): string {
  if (r.ok) return `Warden signed in to ${host} with these credentials.`;
  return registryErrorText(r.error ?? "") ?? "The test failed.";
}

// ---- Pulled images (New scan → Image from a registry) ----

export const PULL_REF_MAX = 512;
/** The contract's pattern (PullScanRequest.image_ref): host[:port]/repository@sha256:<64 hex>. */
export const PULL_REF_RE =
  /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?(\/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)+@sha256:[0-9a-f]{64}$/;
export const PULL_REF_EXAMPLE = "ghcr.io/acme/api@sha256:…";

/** Why a reference can't be pulled, checked before anything is sent; null when it can. The last
 *  check is the contract's own pattern, so nothing the server refuses gets through; the ones
 *  before it only explain the common mistakes. */
export function validatePullRef(raw: string): string | null {
  const s = raw.trim();
  if (!s) return `Enter the image, pinned by digest: registry/repository@sha256:…`;
  if (s.length > PULL_REF_MAX) return `At most ${PULL_REF_MAX} characters.`;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) return "Leave out the scheme (https://): start with the registry host, such as ghcr.io.";
  if (s !== s.toLowerCase()) return "Use lower case: registry hosts and repository names are lower case.";
  const at = s.indexOf("@");
  if (at < 0) {
    return "Pin the image by digest: registry/repository@sha256:…. Warden never pulls by tag, because a tag can point to another image tomorrow.";
  }
  const name = s.slice(0, at);
  const digest = s.slice(at + 1);
  if (!/^sha256:[0-9a-f]{64}$/.test(digest)) return "The digest is sha256: followed by 64 hex characters.";
  const slash = name.indexOf("/");
  const host = slash < 0 ? name : name.slice(0, slash);
  if (slash < 0 || !(host.includes(".") || host.includes(":") || host === "localhost")) {
    return "Start with the registry host, such as docker.io/library/alpine@sha256:… or ghcr.io/acme/api@sha256:….";
  }
  if (/:[^/]*$/.test(name.slice(slash))) return "Leave out the tag: the digest alone says which image, as in ghcr.io/acme/api@sha256:….";
  if (!PULL_REF_RE.test(s)) return "Use registry/repository@sha256:<digest>, such as ghcr.io/acme/api@sha256:….";
  return null;
}

/** The registry host of a well-formed reference ("ghcr.io" for ghcr.io/acme/api@sha256:…). */
export function pullRefHost(ref: string): string | null {
  if (!PULL_REF_RE.test(ref)) return null;
  return ref.slice(0, ref.indexOf("/"));
}

/** "Pulled from ghcr.io" for a pulled scan; the host comes from its reference, else its target. */
export function pulledFromText(s: { image_ref: string | null; target: string }): string {
  const host = (s.image_ref && pullRefHost(s.image_ref)) || (s.target.includes("/") ? s.target.slice(0, s.target.indexOf("/")) : "");
  return host ? `Pulled from ${host}` : "Pulled from its registry";
}
