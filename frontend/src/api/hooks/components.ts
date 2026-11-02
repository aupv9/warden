import { useQuery } from "@tanstack/react-query";
import { api } from "../client";
import type { QueryParams } from "../client";
import { qk } from "../keys";
import { useCursorList } from "../paging";
import type { ComponentSummary, ComponentUsage, ItemList, Page, ProjectComponent, ProjectTarget } from "../types";
import type { ComponentApiQuery, ProjectComponentApiQuery } from "../../lib/components";

// v0.4: the component inventory. Every list is cursor-paginated like the issue list.

const orgBase = (orgId: string) => `/orgs/${encodeURIComponent(orgId)}`;
const projectBase = (orgId: string, projectId: string) => `${orgBase(orgId)}/projects/${encodeURIComponent(projectId)}`;

/** GET /orgs/{org}/components: one row per (ecosystem, name, version) in the visible projects. */
export function useComponents(orgId: string, query: ComponentApiQuery) {
  const q = query as unknown as QueryParams;
  return useCursorList<Page<ComponentSummary>>(qk.components(orgId, q), `${orgBase(orgId)}/components`, q);
}

export interface ComponentRef {
  ecosystem: string;
  name: string;
  version: string;
}

/** GET /orgs/{org}/components/usage: where one component is used (the "Used in" panel). */
export function useComponentUsage(orgId: string, c: ComponentRef | null) {
  const q: QueryParams = c ? { ecosystem: c.ecosystem, name: c.name, version: c.version, limit: 50 } : {};
  return useCursorList<Page<ComponentUsage>>(qk.componentUsage(orgId, q), `${orgBase(orgId)}/components/usage`, q, { enabled: !!c });
}

/** GET /orgs/{org}/projects/{p}/components. */
export function useProjectComponents(orgId: string, projectId: string, query: ProjectComponentApiQuery) {
  const q = query as unknown as QueryParams;
  return useCursorList<Page<ProjectComponent>>(qk.projectComponents(orgId, projectId, q), `${projectBase(orgId, projectId)}/components`, q);
}

/** GET /orgs/{org}/projects/{p}/targets: source code ("") and each scanned image repository.
 *  `enabled` is false when no project is in scope (the list is per project). */
export function useProjectTargets(orgId: string, projectId: string | undefined) {
  return useQuery({
    queryKey: qk.projectTargets(orgId, projectId ?? ""),
    queryFn: ({ signal }) => api<ItemList<ProjectTarget>>(`${projectBase(orgId, projectId ?? "")}/targets`, { signal }),
    select: (d) => d.items,
    enabled: !!projectId,
  });
}
