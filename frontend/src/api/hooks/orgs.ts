import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../client";
import { qk } from "../keys";
import type { AddOrgMemberBody, ItemList, Org, OrgMember, OrgRole, OrgSummary } from "../types";

const base = (orgId: string) => `/orgs/${encodeURIComponent(orgId)}`;

export function useOrg(orgId: string) {
  return useQuery({ queryKey: qk.orgDetail(orgId), queryFn: ({ signal }) => api<Org>(base(orgId), { signal }) });
}

export function useOrgSummary(orgId: string) {
  return useQuery({
    queryKey: qk.summary(orgId),
    queryFn: ({ signal }) => api<OrgSummary>(`${base(orgId)}/summary`, { signal }),
  });
}

export function useOrgMembers(orgId: string, enabled = true) {
  return useQuery({
    queryKey: qk.members(orgId),
    queryFn: ({ signal }) => api<ItemList<OrgMember>>(`${base(orgId)}/members`, { signal }),
    select: (d) => d.items,
    enabled,
  });
}

function useInvalidateMembers(orgId: string) {
  const qc = useQueryClient();
  return () =>
    Promise.all([
      qc.invalidateQueries({ queryKey: qk.members(orgId) }),
      // Removing an org member also removes their project memberships.
      qc.invalidateQueries({ queryKey: qk.projects(orgId) }),
      qc.invalidateQueries({ queryKey: qk.me }),
    ]);
}

export function useAddOrgMember(orgId: string) {
  const invalidate = useInvalidateMembers(orgId);
  return useMutation({
    mutationFn: (body: AddOrgMemberBody) => api<OrgMember>(`${base(orgId)}/members`, { method: "POST", body }),
    onSuccess: invalidate,
  });
}

export function useChangeOrgRole(orgId: string) {
  const invalidate = useInvalidateMembers(orgId);
  return useMutation({
    mutationFn: ({ userId, role }: { userId: string; role: OrgRole }) =>
      api<OrgMember>(`${base(orgId)}/members/${encodeURIComponent(userId)}`, { method: "PATCH", body: { role } }),
    onSuccess: invalidate,
  });
}

export function useRemoveOrgMember(orgId: string) {
  const invalidate = useInvalidateMembers(orgId);
  return useMutation({
    mutationFn: (userId: string) =>
      api<void>(`${base(orgId)}/members/${encodeURIComponent(userId)}`, { method: "DELETE" }),
    onSuccess: invalidate,
  });
}
