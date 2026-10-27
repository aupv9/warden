import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../client";
import { qk } from "../keys";
import type {
  AddOrgMemberBody,
  ItemList,
  Org,
  OrgMember,
  OrgRole,
  OrgSummary,
  SignInPolicyInput,
  SignInSettings,
  UpdatePolicyBody,
} from "../types";

const base = (orgId: string) => `/orgs/${encodeURIComponent(orgId)}`;

export function useOrg(orgId: string) {
  return useQuery({ queryKey: qk.orgDetail(orgId), queryFn: ({ signal }) => api<Org>(base(orgId), { signal }) });
}

/** v0.2: SLA policy (perm configure_policy). */
export function useUpdatePolicy(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: UpdatePolicyBody) => api<Org>(base(orgId), { method: "PATCH", body }),
    onSuccess: (org, body) => {
      qc.setQueryData(qk.orgDetail(orgId), org);
      // Recomputed due dates change past-SLA counts everywhere.
      if (body.recompute_open) {
        return Promise.all([
          qc.invalidateQueries({ queryKey: qk.issueLists(orgId) }),
          qc.invalidateQueries({ queryKey: qk.issueAll(orgId) }),
          qc.invalidateQueries({ queryKey: qk.summary(orgId) }),
          qc.invalidateQueries({ queryKey: qk.projects(orgId) }),
          qc.invalidateQueries({ queryKey: qk.metricsAll(orgId) }),
        ]);
      }
    },
  });
}

/** How Warden trusts the identity provider, and the org's sign-in policy (org admin, security
 *  lead). Reading it never makes the server fetch keys. */
export function useSignInSettings(orgId: string, enabled = true) {
  return useQuery({
    queryKey: qk.signIn(orgId),
    queryFn: ({ signal }) => api<SignInSettings>(`${base(orgId)}/sign-in`, { signal }),
    enabled,
  });
}

/** Org admins only. Answers with the same body as GET …/sign-in. */
export function useUpdateSignInPolicy(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: SignInPolicyInput) => api<SignInSettings>(`${base(orgId)}/sign-in-policy`, { method: "PUT", body }),
    onSuccess: (settings) => {
      qc.setQueryData(qk.signIn(orgId), settings);
      return Promise.all([
        qc.invalidateQueries({ queryKey: qk.signIn(orgId) }),
        // The effective two-factor roles feed /me's mfa_required_orgs.
        qc.invalidateQueries({ queryKey: qk.me }),
      ]);
    },
  });
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
