import type { Ecosystem } from "../api/types";
import { isImageTarget } from "./intel";

// v0.4: the component inventory (Components page, a project's Components tab). Filters live in
// the URL like the issue list's; the URL is untrusted input, so every value is checked against
// the contract's patterns before it reaches the API. Component names, versions, paths and purls
// come from scanned lockfiles and images: they are shown as text only, never as links or HTML.

/** The contract's Ecosystem pattern. */
export const ECOSYSTEM_RE = /^[A-Za-z0-9.+_-]{1,32}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** `q` (name prefix) and `version` limits in the contract. */
export const COMPONENT_Q_MAX = 128;
export const COMPONENT_VERSION_MAX = 128;
/** What the search box keeps in the URL: a name, a space and a version at most. */
const SEARCH_MAX = COMPONENT_Q_MAX + 1 + COMPONENT_VERSION_MAX;

/** Offered in the ecosystem filter. The inventory may hold others (any purl type); a URL may
 *  name one, and it is then shown as it is. */
export const ECOSYSTEMS: Ecosystem[] = ["npm", "PyPI", "Go", "Maven", "crates.io", "RubyGems", "NuGet", "Packagist", "deb", "apk", "rpm"];
const ECOSYSTEM_LABELS: Record<string, string> = {
  deb: "Debian packages (deb)",
  apk: "Alpine packages (apk)",
  rpm: "RPM packages",
};

export function ecosystemLabel(eco: string): string {
  return ECOSYSTEM_LABELS[eco] ?? eco;
}

/** The ecosystem filter's options; a value from the URL that isn't in the list stays shown. */
export function ecosystemOptions(current: string): { value: string; label: string }[] {
  const known = ECOSYSTEMS.map((e) => ({ value: e, label: ecosystemLabel(e) }));
  return [{ value: "", label: "All ecosystems" }, ...known, ...(current && !ECOSYSTEMS.includes(current) ? [{ value: current, label: current }] : [])];
}

export interface ComponentFilters {
  /** What was typed: a name prefix, optionally followed by a version ("xz 5.6.0"). */
  search: string;
  /** "" = any. */
  ecosystem: string;
  /** "" = every project the caller can see. */
  project: string;
  /** Only components listed by an OSV malicious-package advisory. */
  malicious: boolean;
}

export const DEFAULT_COMPONENT_FILTERS: ComponentFilters = { search: "", ecosystem: "", project: "", malicious: false };

/**
 * Splits the search box into the name prefix and an exact version: "xz 5.6.0" and
 * "log4j-core@2.14.1" both give a version; "@acme/ui" (an npm scope) doesn't. Only the last
 * space or the last "@" after the first character separates them.
 */
export function splitSearch(raw: string): { q: string; version: string } {
  const s = raw.trim();
  const space = s.lastIndexOf(" ");
  if (space > 0) return { q: s.slice(0, space).trim().slice(0, COMPONENT_Q_MAX), version: s.slice(space + 1).slice(0, COMPONENT_VERSION_MAX) };
  const at = s.lastIndexOf("@");
  if (at > 0 && at < s.length - 1) return { q: s.slice(0, at).slice(0, COMPONENT_Q_MAX), version: s.slice(at + 1).slice(0, COMPONENT_VERSION_MAX) };
  return { q: s.slice(0, COMPONENT_Q_MAX), version: "" };
}

export function parseComponentFilters(sp: URLSearchParams): ComponentFilters {
  const ecosystem = sp.get("ecosystem") ?? "";
  const project = sp.get("project") ?? "";
  return {
    search: (sp.get("q") ?? "").trim().slice(0, SEARCH_MAX),
    ecosystem: ECOSYSTEM_RE.test(ecosystem) ? ecosystem : "",
    project: UUID_RE.test(project) ? project : "",
    malicious: sp.get("malicious") === "true",
  };
}

export function componentFiltersToSearch(f: ComponentFilters): URLSearchParams {
  const sp = new URLSearchParams();
  if (f.search) sp.set("q", f.search);
  if (f.ecosystem) sp.set("ecosystem", f.ecosystem);
  if (f.project) sp.set("project", f.project);
  if (f.malicious) sp.set("malicious", "true");
  return sp;
}

export function hasComponentFilters(f: ComponentFilters): boolean {
  return componentFiltersToSearch(f).toString() !== "";
}

/** Query for GET /orgs/{org}/components; every key is a contract parameter (contract.check.ts). */
export interface ComponentApiQuery {
  q?: string;
  version?: string;
  ecosystem?: string;
  project_id?: string;
  malicious?: "true";
  limit: number;
}

export function componentFiltersToApiQuery(f: ComponentFilters): ComponentApiQuery {
  const { q, version } = splitSearch(f.search);
  return {
    q: q || undefined,
    version: version || undefined,
    ecosystem: f.ecosystem || undefined,
    project_id: f.project || undefined,
    malicious: f.malicious ? "true" : undefined,
    limit: 50,
  };
}

// ---- A project's Components tab ----

/** The URL value for "source code" in the target filter: parentheses can't occur in an image
 *  repository, so it never collides with one. */
export const SOURCE_TARGET = "(source)";

export interface ProjectComponentFilters {
  search: string;
  ecosystem: string;
  /** "" = every target; SOURCE_TARGET = source code; else an image repository. */
  target: string;
  malicious: boolean;
}

export function parseProjectComponentFilters(sp: URLSearchParams): ProjectComponentFilters {
  const ecosystem = sp.get("ecosystem") ?? "";
  const target = sp.get("target") ?? "";
  return {
    search: (sp.get("q") ?? "").trim().slice(0, COMPONENT_Q_MAX),
    ecosystem: ECOSYSTEM_RE.test(ecosystem) ? ecosystem : "",
    target: target === SOURCE_TARGET || isImageTarget(target) ? target : "",
    malicious: sp.get("malicious") === "true",
  };
}

export function projectComponentFiltersToSearch(f: ProjectComponentFilters): URLSearchParams {
  const sp = new URLSearchParams();
  if (f.search) sp.set("q", f.search);
  if (f.ecosystem) sp.set("ecosystem", f.ecosystem);
  if (f.target) sp.set("target", f.target);
  if (f.malicious) sp.set("malicious", "true");
  return sp;
}

/** Query for GET /orgs/{org}/projects/{p}/components. */
export interface ProjectComponentApiQuery {
  q?: string;
  ecosystem?: string;
  /** The contract's source target is the empty string; buildQuery drops empty values, but sends
   *  every item of an array, so source code goes as `[""]` (→ `target=`). */
  target?: string | readonly string[];
  malicious?: "true";
  limit: number;
}

export function projectComponentFiltersToApiQuery(f: ProjectComponentFilters): ProjectComponentApiQuery {
  return {
    q: f.search || undefined,
    ecosystem: f.ecosystem || undefined,
    target: f.target === SOURCE_TARGET ? [""] : f.target || undefined,
    malicious: f.malicious ? "true" : undefined,
    limit: 50,
  };
}

/** "Source code" or the image repository. */
export function targetLabel(target: string): string {
  return target === "" ? "Source code" : target;
}

/** A link to a project's Components tab, narrowed to one target and a name. The name only goes
 *  into the query string (encoded), as data for the search box. */
export function projectComponentsHref(orgId: string, projectId: string, f: Partial<ProjectComponentFilters>): string {
  const sp = projectComponentFiltersToSearch({
    ecosystem: f.ecosystem ?? "",
    target: f.target ?? "",
    malicious: f.malicious ?? false,
    search: (f.search ?? "").slice(0, COMPONENT_Q_MAX),
  });
  const s = sp.toString();
  return `/orgs/${orgId}/projects/${encodeURIComponent(projectId)}/components${s ? `?${s}` : ""}`;
}

/** Licenses as one line: "MIT, Apache-2.0", or "–". */
export function licensesText(licenses: string[]): string {
  return licenses.length ? licenses.join(", ") : "–";
}
