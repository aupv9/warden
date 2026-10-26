import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { api } from "../client";
import { qk } from "../keys";
import type { IssueCounts, Metrics, MetricsDays } from "../types";

const base = (orgId: string) => `/orgs/${encodeURIComponent(orgId)}`;

/** GET /metrics (perm view_dashboard). The server caches it for 5 minutes, so the client does
 *  too; switching range or project keeps the previous charts on screen while the next load. */
export function useMetrics(orgId: string, days: MetricsDays, projectId: string | undefined) {
  const query = { days, project_id: projectId || undefined };
  return useQuery({
    queryKey: qk.metrics(orgId, query),
    queryFn: ({ signal }) => api<Metrics>(`${base(orgId)}/metrics`, { signal, query }),
    staleTime: 5 * 60_000,
    placeholderData: keepPreviousData,
  });
}

/** Counts for the saved views (Active, Assigned to me, Past SLA, Secrets). */
export function useIssueCounts(orgId: string, projectId: string | undefined) {
  return useQuery({
    queryKey: qk.issueCounts(orgId, projectId),
    queryFn: ({ signal }) =>
      api<IssueCounts>(`${base(orgId)}/issues/counts`, { signal, query: { project_id: projectId || undefined } }),
  });
}
