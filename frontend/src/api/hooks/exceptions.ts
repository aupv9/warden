import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../client";
import { qk } from "../keys";
import { useCursorList } from "../paging";
import type { CreateExceptionBody, DecisionBody, ExceptionRequest, ExceptionTab, Page } from "../types";
import { useInvalidateIssueWork } from "./issues";

const orgBase = (orgId: string) => `/orgs/${encodeURIComponent(orgId)}`;

export function useExceptions(orgId: string, tab: ExceptionTab) {
  return useCursorList<Page<ExceptionRequest>>(qk.exceptions(orgId, tab), `${orgBase(orgId)}/exceptions`, {
    status: tab,
    limit: 50,
  });
}

export function useRequestException(orgId: string, issueId: string) {
  const qc = useQueryClient();
  const invalidate = useInvalidateIssueWork(orgId);
  return useMutation({
    mutationFn: (body: CreateExceptionBody) =>
      api<ExceptionRequest>(`${orgBase(orgId)}/issues/${encodeURIComponent(issueId)}/exceptions`, {
        method: "POST",
        body,
      }),
    onSuccess: () =>
      Promise.all([invalidate(issueId), qc.invalidateQueries({ queryKey: qk.exceptionLists(orgId) })]),
  });
}

export function useDecideException(orgId: string) {
  const qc = useQueryClient();
  const invalidate = useInvalidateIssueWork(orgId);
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: DecisionBody }) =>
      api<ExceptionRequest>(`${orgBase(orgId)}/exceptions/${encodeURIComponent(id)}/decision`, {
        method: "POST",
        body,
      }),
    onSuccess: (exc) =>
      Promise.all([invalidate(exc.issue.id), qc.invalidateQueries({ queryKey: qk.exceptionLists(orgId) })]),
  });
}
