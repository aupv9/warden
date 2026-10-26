import { useState } from "react";
import type { FormEvent } from "react";
import { useOrgMembers } from "../api/hooks/orgs";
import { useProjectMembers, useProjects, useRemoveProjectMember, useSetProjectMember } from "../api/hooks/projects";
import { PROJECT_ROLES } from "../api/types";
import type { Project, ProjectMember, ProjectRole } from "../api/types";
import { Avatar } from "../components/Avatar";
import { Button } from "../components/Button";
import { Card } from "../components/Card";
import { Dialog } from "../components/Dialog";
import { Select } from "../components/Field";
import { ActionError, EmptyState, ErrorState, SkeletonRows } from "../components/States";
import { Table } from "../components/Table";
import { useOrgCtx } from "../layout/OrgLayout";
import { userName } from "../lib/format";
import { can, PROJECT_ROLE_LABELS } from "../lib/permissions";
import { showToast } from "../lib/toast";

const ROLE_OPTIONS = PROJECT_ROLES.map((r) => ({ value: r, label: PROJECT_ROLE_LABELS[r] }));

/** Project roles for one project. On the Members page the project is picked from a select;
 *  on a project's Members tab it is fixed. */
export function ProjectRolesCard({ fixedProject }: { fixedProject?: Project }) {
  const { orgId } = useOrgCtx();
  const projects = useProjects(orgId);
  const [picked, setPicked] = useState("");
  const project = fixedProject ?? projects.data?.find((p) => p.id === picked) ?? projects.data?.[0];

  return (
    <Card
      title="Project roles"
      titleId="proj-roles-h"
      flush
      actions={
        !fixedProject && (projects.data?.length ?? 0) > 0 ? (
          <Select
            aria-label="Project"
            dense
            value={project?.id ?? ""}
            onChange={(e) => setPicked(e.target.value)}
            options={(projects.data ?? []).map((p) => ({ value: p.id, label: `${p.key} · ${p.name}` }))}
          />
        ) : undefined
      }
    >
      {!fixedProject && projects.isPending ? (
        <SkeletonRows label="projects" rows={3} />
      ) : !fixedProject && projects.isError ? (
        <ErrorState error={projects.error} onRetry={() => void projects.refetch()} what="projects" />
      ) : !project ? (
        <EmptyState title="No projects yet">Project roles appear here once a project exists.</EmptyState>
      ) : (
        <ProjectRolesTable key={project.id} project={project} />
      )}
    </Card>
  );
}

function ProjectRolesTable({ project }: { project: Project }) {
  const { orgId, org } = useOrgCtx();
  const manage = can("manage_project_members", org.role, project.my_role);
  const members = useProjectMembers(orgId, project.id);
  const setRole = useSetProjectMember(orgId, project.id);
  const remove = useRemoveProjectMember(orgId, project.id);
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<ProjectMember | null>(null);

  if (members.isPending) return <SkeletonRows label="project members" rows={3} />;
  if (members.isError) return <ErrorState error={members.error} onRetry={() => void members.refetch()} what="project members" />;

  return (
    <>
      <div style={{ padding: "0 16px" }}>
        <ActionError error={setRole.error} overrides={{ VALIDATION_FAILED: "That person isn't a member of this organization." }} />
      </div>
      {members.data.length === 0 ? (
        <EmptyState title="No members yet">
          {manage ? "Add org members to this project to give them a role." : "No one has a role in this project yet."}
        </EmptyState>
      ) : (
        <Table
          caption={`Members of ${project.name}`}
          head={
            <tr>
              <th>Person</th>
              <th>Role</th>
              {manage && <th aria-label="Actions" />}
            </tr>
          }
        >
          {members.data.map((m) => (
            <tr key={m.user.id}>
              <td>
                <span className="person-cell">
                  <Avatar name={userName(m.user)} size={24} />
                  <span>
                    {userName(m.user)}
                    <span className="sub">{m.user.email}</span>
                  </span>
                </span>
              </td>
              <td data-label="Role">
                {manage ? (
                  <Select
                    aria-label={`Project role for ${userName(m.user)}`}
                    dense
                    value={m.role}
                    disabled={setRole.isPending}
                    onChange={(e) =>
                      setRole.mutate(
                        { userId: m.user.id, role: e.target.value as ProjectRole },
                        {
                          onSuccess: (r) =>
                            showToast({ tone: "success", message: `${userName(m.user)} is now ${PROJECT_ROLE_LABELS[r.role].toLowerCase()} of ${project.key}.` }),
                        },
                      )
                    }
                    options={ROLE_OPTIONS}
                  />
                ) : (
                  PROJECT_ROLE_LABELS[m.role]
                )}
              </td>
              {manage && (
                <td className="no-label" style={{ textAlign: "right" }}>
                  <Button size="sm" onClick={() => setRemoving(m)}>
                    Remove
                  </Button>
                </td>
              )}
            </tr>
          ))}
        </Table>
      )}
      {manage && (
        <div style={{ padding: 16 }}>
          <Button onClick={() => setAdding(true)}>Add to project</Button>
        </div>
      )}

      <Dialog open={adding} onClose={() => setAdding(false)} title={`Add someone to ${project.name}`}>
        <AddToProjectForm project={project} existing={members.data} onDone={() => setAdding(false)} />
      </Dialog>
      <Dialog open={!!removing} onClose={() => setRemoving(null)} title="Remove from project">
        {removing && (
          <div className="form-grid">
            <p>
              Remove <strong>{userName(removing.user)}</strong> from {project.name}? They lose access to its scans and issues
              unless their org role gives it.
            </p>
            <ActionError error={remove.error} />
            <div className="dialog-actions">
              <Button onClick={() => setRemoving(null)}>Cancel</Button>
              <Button
                variant="danger"
                busy={remove.isPending}
                onClick={() =>
                  remove.mutate(removing.user.id, {
                    onSuccess: () => {
                      showToast({ tone: "success", message: `${userName(removing.user)} was removed from ${project.key}.` });
                      setRemoving(null);
                    },
                  })
                }
              >
                Remove
              </Button>
            </div>
          </div>
        )}
      </Dialog>
    </>
  );
}

function AddToProjectForm({ project, existing, onDone }: { project: Project; existing: ProjectMember[]; onDone: () => void }) {
  const { orgId } = useOrgCtx();
  const orgMembers = useOrgMembers(orgId);
  const setRole = useSetProjectMember(orgId, project.id);
  const [userId, setUserId] = useState("");
  const [role, setRoleValue] = useState<ProjectRole>("developer");
  const taken = new Set(existing.map((m) => m.user.id));
  const candidates = (orgMembers.data ?? []).filter((m) => !taken.has(m.user.id) && m.user.is_active);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!userId) return;
    const person = candidates.find((c) => c.user.id === userId);
    const ok = await setRole.mutateAsync({ userId, role }).then(
      () => true,
      () => false,
    );
    if (ok) {
      showToast({ tone: "success", message: `${person ? userName(person.user) : "They"} can now work on ${project.key} as ${PROJECT_ROLE_LABELS[role].toLowerCase()}.` });
      onDone();
    }
  }

  return (
    <form className="form-grid" onSubmit={submit}>
      {orgMembers.isError ? (
        <ActionError always error={orgMembers.error} />
      ) : (
        <Select
          label="Person"
          hint="Org members only. To add someone new, an org admin adds them to the organization first."
          value={userId}
          disabled={orgMembers.isPending}
          onChange={(e) => setUserId(e.target.value)}
          options={[
            { value: "", label: orgMembers.isPending ? "Loading…" : candidates.length ? "Choose a person" : "Everyone is already in this project" },
            ...candidates.map((m) => ({ value: m.user.id, label: `${userName(m.user)} (${m.user.email})` })),
          ]}
        />
      )}
      <fieldset>
        <legend>Project role</legend>
        <div className="choices">
          {PROJECT_ROLES.map((r) => (
            <label key={r} className="choice-card">
              <input type="radio" name="proj-role" checked={role === r} onChange={() => setRoleValue(r)} />
              <span>
                <strong>{PROJECT_ROLE_LABELS[r]}</strong>
                <span className="desc">
                  {r === "owner"
                    ? "Runs scans, assigns issues, manages the project's members."
                    : r === "developer"
                      ? "Runs scans, works on issues assigned to them, requests exceptions."
                      : "Reads scans and issues."}
                </span>
              </span>
            </label>
          ))}
        </div>
      </fieldset>
      <ActionError error={setRole.error} overrides={{ VALIDATION_FAILED: "That person isn't a member of this organization." }} />
      <div className="dialog-actions">
        <Button onClick={onDone}>Cancel</Button>
        <Button type="submit" variant="primary" disabled={!userId} busy={setRole.isPending}>
          Add to project
        </Button>
      </div>
    </form>
  );
}
