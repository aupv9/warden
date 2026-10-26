import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { QueryClient } from "@tanstack/react-query";
import { api } from "../client";
import { qk } from "../keys";
import type { ApiToken, CreatedToken, CreateTokenBody, ItemList } from "../types";

const tokensPath = (orgId: string, projectId: string) =>
  `/orgs/${encodeURIComponent(orgId)}/projects/${encodeURIComponent(projectId)}/tokens`;

export function useTokens(orgId: string, projectId: string, enabled = true) {
  return useQuery({
    queryKey: qk.tokens(orgId, projectId),
    queryFn: ({ signal }) => api<ItemList<ApiToken>>(tokensPath(orgId, projectId), { signal }),
    select: (d) => d.items,
    enabled,
  });
}

/** Options for the create-token mutation.
 *
 *  The response is the only place the full token (`secret`) ever appears. TanStack Query keeps
 *  a mutation's result (`state.data`) in its MutationCache for minutes after it settles, so the
 *  mutation function hands the secret straight to `onSecret` (the dialog's component state) and
 *  resolves with the ApiToken alone: the secret never reaches the query or mutation cache, the
 *  URL, storage or a log. tokens.test.ts checks this. */
export function createTokenMutation(qc: QueryClient, orgId: string, projectId: string, onSecret: (secret: string) => void) {
  return {
    mutationFn: async (body: CreateTokenBody): Promise<ApiToken> => {
      const { token, secret } = await api<CreatedToken>(tokensPath(orgId, projectId), { method: "POST", body });
      onSecret(secret);
      return token;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.tokens(orgId, projectId) }),
  };
}

export function useCreateToken(orgId: string, projectId: string, onSecret: (secret: string) => void) {
  const qc = useQueryClient();
  return useMutation(createTokenMutation(qc, orgId, projectId, onSecret));
}

export function useRevokeToken(orgId: string, projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (tokenId: string) =>
      api<void>(`${tokensPath(orgId, projectId)}/${encodeURIComponent(tokenId)}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.tokens(orgId, projectId) }),
  });
}
