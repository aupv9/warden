import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../client";
import { qk } from "../keys";
import type { CreateProjectBody, ItemList, Project, ProjectMember, ProjectRole } from "../types";

const base = (orgId: string) => `/orgs/${encodeURIComponent(orgId)}/projects`;
const one = (orgId: string, projectId: string) => `${base(orgId)}/${encodeURIComponent(projectId)}`;

export function useProjects(orgId: string) {
  return useQuery({
    queryKey: qk.projects(orgId),
    queryFn: ({ signal }) => api<ItemList<Project>>(base(orgId), { signal }),
    select: (d) => d.items,
  });
}

export function useProject(orgId: string, projectId: string | undefined) {
  return useQuery({
    queryKey: qk.project(orgId, projectId ?? ""),
    queryFn: ({ signal }) => api<Project>(one(orgId, projectId ?? ""), { signal }),
    enabled: !!projectId,
  });
}

export function useCreateProject(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateProjectBody) => api<Project>(base(orgId), { method: "POST", body }),
    onSuccess: () =>
      Promise.all([
        qc.invalidateQueries({ queryKey: qk.projects(orgId) }),
        qc.invalidateQueries({ queryKey: qk.summary(orgId) }),
      ]),
  });
}

export function useProjectMembers(orgId: string, projectId: string | undefined, enabled = true) {
  return useQuery({
    queryKey: qk.projectMembers(orgId, projectId ?? ""),
    queryFn: ({ signal }) => api<ItemList<ProjectMember>>(`${one(orgId, projectId ?? "")}/members`, { signal }),
    select: (d) => d.items,
    enabled: enabled && !!projectId,
  });
}

function useInvalidateProjectMembers(orgId: string) {
  const qc = useQueryClient();
  return () =>
    Promise.all([
      // The projects prefix covers project members, each project's my_role and the list.
      qc.invalidateQueries({ queryKey: qk.projects(orgId) }),
      qc.invalidateQueries({ queryKey: qk.members(orgId) }),
    ]);
}

export function useSetProjectMember(orgId: string, projectId: string) {
  const invalidate = useInvalidateProjectMembers(orgId);
  return useMutation({
    mutationFn: ({ userId, role }: { userId: string; role: ProjectRole }) =>
      api<ProjectMember>(`${one(orgId, projectId)}/members/${encodeURIComponent(userId)}`, {
        method: "PUT",
        body: { role },
      }),
    onSuccess: invalidate,
  });
}

export function useRemoveProjectMember(orgId: string, projectId: string) {
  const invalidate = useInvalidateProjectMembers(orgId);
  return useMutation({
    mutationFn: (userId: string) =>
      api<void>(`${one(orgId, projectId)}/members/${encodeURIComponent(userId)}`, { method: "DELETE" }),
    onSuccess: invalidate,
  });
}
