import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../client";
import type { QueryParams } from "../client";
import { qk } from "../keys";
import type { BulkAssignBody, Comment, Issue, IssueEvent, IssuePage, ItemList, TransitionBody } from "../types";

const orgBase = (orgId: string) => `/orgs/${encodeURIComponent(orgId)}`;
const issuePath = (orgId: string, issueId: string) => `${orgBase(orgId)}/issues/${encodeURIComponent(issueId)}`;

export function useIssues(orgId: string, query: QueryParams, enabled = true) {
  return useInfiniteQuery({
    queryKey: qk.issues(orgId, query),
    queryFn: ({ pageParam, signal }) =>
      api<IssuePage>(`${orgBase(orgId)}/issues`, { query: { ...query, cursor: pageParam }, signal }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.next_cursor ?? undefined,
    enabled,
  });
}

export function useIssue(orgId: string, issueId: string) {
  return useQuery({
    queryKey: qk.issue(orgId, issueId),
    queryFn: ({ signal }) => api<Issue>(issuePath(orgId, issueId), { signal }),
  });
}

export function useIssueEvents(orgId: string, issueId: string) {
  return useQuery({
    queryKey: qk.issueEvents(orgId, issueId),
    queryFn: ({ signal }) => api<ItemList<IssueEvent>>(`${issuePath(orgId, issueId)}/events`, { signal }),
    select: (d) => d.items,
  });
}

export function useIssueComments(orgId: string, issueId: string) {
  return useQuery({
    queryKey: qk.issueComments(orgId, issueId),
    queryFn: ({ signal }) => api<ItemList<Comment>>(`${issuePath(orgId, issueId)}/comments`, { signal }),
    select: (d) => d.items,
  });
}

/** Refresh everything an issue change can affect: lists, counts, the project cards. */
export function useInvalidateIssueWork(orgId: string) {
  const qc = useQueryClient();
  return (issueId?: string) =>
    Promise.all([
      qc.invalidateQueries({ queryKey: qk.issueLists(orgId) }),
      qc.invalidateQueries({ queryKey: qk.summary(orgId) }),
      qc.invalidateQueries({ queryKey: qk.projects(orgId) }),
      issueId
        ? qc.invalidateQueries({ queryKey: qk.issue(orgId, issueId) })
        : qc.invalidateQueries({ queryKey: qk.issueAll(orgId) }),
    ]);
}

/** Status change with the optimistic-lock `version`. On VERSION_CONFLICT / INVALID_TRANSITION
 *  nothing is refetched or retried automatically: the issue page shows a banner and the user
 *  reloads explicitly (DESIGN.md), so a typed comment is never lost. */
export function useTransitionIssue(orgId: string, issueId: string) {
  const qc = useQueryClient();
  const invalidate = useInvalidateIssueWork(orgId);
  return useMutation({
    mutationFn: (body: TransitionBody) =>
      api<Issue>(`${issuePath(orgId, issueId)}/transitions`, { method: "POST", body }),
    onSuccess: async (issue) => {
      qc.setQueryData(qk.issue(orgId, issueId), issue);
      await invalidate(issueId);
    },
  });
}

export function useBulkAssign(orgId: string) {
  const invalidate = useInvalidateIssueWork(orgId);
  return useMutation({
    mutationFn: (body: BulkAssignBody) =>
      api<{ updated: number }>(`${orgBase(orgId)}/issues/assign`, { method: "POST", body }),
    onSuccess: () => invalidate(),
  });
}

export function useAddComment(orgId: string, issueId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: string) =>
      api<Comment>(`${issuePath(orgId, issueId)}/comments`, { method: "POST", body: { body } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.issue(orgId, issueId) }),
  });
}
