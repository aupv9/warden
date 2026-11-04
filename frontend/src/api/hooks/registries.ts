import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { QueryClient } from "@tanstack/react-query";
import { api } from "../client";
import { qk } from "../keys";
import type {
  CreateRegistryCredentialBody,
  ItemList,
  PullScanBody,
  RegistryCredential,
  RegistryTestResult,
  Scan,
  UpdateRegistryCredentialBody,
} from "../types";
import { REGISTRY_TEST_RATE_LIMITED } from "../../lib/registries";

// v0.7 wave 2: registry credentials (manage_registries: org admins, security leads) and scans of
// images Warden pulls itself (run_scan). Others never call the registry endpoints: the page and
// its Settings card are hidden for them.

const registriesPath = (orgId: string) => `/orgs/${encodeURIComponent(orgId)}/registries`;
const registryPath = (orgId: string, id: string) => `${registriesPath(orgId)}/${encodeURIComponent(id)}`;

export function useRegistries(orgId: string, enabled = true) {
  return useQuery({
    queryKey: qk.registries(orgId),
    queryFn: ({ signal }) => api<ItemList<RegistryCredential>>(registriesPath(orgId), { signal }),
    enabled,
  });
}

/** Options for the create mutation. The body holds the password: TanStack Query keeps mutation
 *  variables in its MutationCache, so the body is read through a closure instead (mutate() takes
 *  no variables), and the mutation resolves with what the server returns, which never has the
 *  password. registries.test.ts checks it. */
export function createRegistryMutation(qc: QueryClient, orgId: string, body: () => CreateRegistryCredentialBody) {
  return {
    mutationFn: () => api<RegistryCredential>(registriesPath(orgId), { method: "POST", body: body() }),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.registries(orgId) }),
  };
}

export function useCreateRegistry(orgId: string, body: () => CreateRegistryCredentialBody) {
  const qc = useQueryClient();
  return useMutation(createRegistryMutation(qc, orgId, body));
}

/** PATCH: a new username and/or password, through a closure like create. */
export function updateRegistryMutation(qc: QueryClient, orgId: string, id: string, body: () => UpdateRegistryCredentialBody) {
  return {
    mutationFn: () => api<RegistryCredential>(registryPath(orgId, id), { method: "PATCH", body: body() }),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.registries(orgId) }),
  };
}

export function useUpdateRegistry(orgId: string, id: string, body: () => UpdateRegistryCredentialBody) {
  const qc = useQueryClient();
  return useMutation(updateRegistryMutation(qc, orgId, id, body));
}

export function useDeleteRegistry(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api<void>(registryPath(orgId, id), { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.registries(orgId) }),
  });
}

/** Sign in to the registry with the stored credentials. The result is shown on the row; the list
 *  is refreshed because a failed test sets last_error. 429 (10 per credential per hour) has its
 *  own words. */
export function useTestRegistry(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api<RegistryTestResult>(`${registryPath(orgId, id)}/test`, { method: "POST" }),
    meta: { errorMessages: { RATE_LIMITED: REGISTRY_TEST_RATE_LIMITED } },
    onSettled: () => qc.invalidateQueries({ queryKey: qk.registries(orgId) }),
  });
}

/** Queue a scan of an image the worker pulls by digest. Nothing is uploaded from the browser. */
export function usePullScan(orgId: string, projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: PullScanBody) =>
      api<Scan>(`/orgs/${encodeURIComponent(orgId)}/projects/${encodeURIComponent(projectId)}/scans/pull`, { method: "POST", body }),
    // Shown in the card (the hourly limit, field errors, PROJECT_ARCHIVED), never as a toast.
    meta: { inlineErrors: true },
    onSuccess: (scan) => {
      qc.setQueryData(qk.scan(orgId, scan.id), scan);
      return Promise.all([
        qc.invalidateQueries({ queryKey: qk.scans(orgId, projectId) }),
        qc.invalidateQueries({ queryKey: qk.projects(orgId), exact: true }),
        qc.invalidateQueries({ queryKey: qk.project(orgId, projectId), exact: true }),
      ]);
    },
  });
}
