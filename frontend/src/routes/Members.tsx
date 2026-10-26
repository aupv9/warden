import { useState } from "react";
import type { FormEvent } from "react";
import { isApiError } from "../api/client";
import { fieldErrors } from "../api/errors";
import { useAddOrgMember, useChangeOrgRole, useOrgMembers, useRemoveOrgMember } from "../api/hooks/orgs";
import { ORG_ROLES } from "../api/types";
import type { OrgMember, OrgRole } from "../api/types";
import { Pill } from "../components/Badges";
import { Button } from "../components/Button";
import { Card } from "../components/Card";
import { Dialog } from "../components/Dialog";
import { focusFirstInvalid, Select, TextField } from "../components/Field";
import { ActionError, ErrorState, SkeletonRows } from "../components/States";
import { Table } from "../components/Table";
import { useOrgCtx } from "../layout/OrgLayout";
import { userName } from "../lib/format";
import { can, MATRIX, MATRIX_ROLES, matrixCell, ORG_ROLE_LABELS, PERM_LABELS, PROJECT_ROLE_LABELS, ROLE_LABELS } from "../lib/permissions";
import type { Perm } from "../lib/permissions";
import { showToast } from "../lib/toast";
import { usePageTitle } from "../lib/usePageTitle";
import { ProjectRolesCard } from "./ProjectRoles";

const ROLE_HELP: Record<OrgRole, string> = {
  member: "Sees only the projects they are added to.",
  security_lead: "Sees every project, decides exceptions, reads the audit log.",
  org_admin: "Manages members and roles, creates projects.",
};

export function MembersPage() {
  usePageTitle("Members");
  const { org } = useOrgCtx();
  const [adding, setAdding] = useState(false);
  const manage = can("manage_users", org.role);

  return (
    <>
      <header className="page-head">
        <div className="titles">
          <h1>Members</h1>
          <p className="muted">People sign in with your identity provider. Add them here to give them a role.</p>
        </div>
        {manage && (
          <div className="actions">
            <Button variant="primary" onClick={() => setAdding(true)}>
              Add member
            </Button>
          </div>
        )}
      </header>
      <OrgMembersCard />
      <div className="grid grid-2">
        <ProjectRolesCard />
        <MatrixCard />
      </div>
      <Dialog open={adding} onClose={() => setAdding(false)} title={`Add a member to ${org.name}`}>
        <AddMemberForm onDone={() => setAdding(false)} />
      </Dialog>
    </>
  );
}

function projectsText(m: OrgMember): string {
  if (m.role === "org_admin" || m.role === "security_lead") return "All";
  if (m.projects.length === 0) return "None";
  return m.projects.map((p) => `${p.key} ${PROJECT_ROLE_LABELS[p.role].toLowerCase()}`).join(", ");
}

function OrgMembersCard() {
  const { orgId, org, me } = useOrgCtx();
  const members = useOrgMembers(orgId);
  const change = useChangeOrgRole(orgId);
  const remove = useRemoveOrgMember(orgId);
  const [removing, setRemoving] = useState<OrgMember | null>(null);
  const manage = can("manage_users", org.role);
  const lastAdminName = (id?: string) => {
    const m = members.data?.find((x) => x.user.id === id);
    return m ? userName(m.user) : "This person";
  };

  return (
    <Card
      title="Organization"
      titleId="org-members-h"
      flush
      actions={members.data ? <span className="muted">{members.data.length} members</span> : undefined}
    >
      <div style={{ padding: "0 20px" }}>
        <ActionError
          error={change.error}
          overrides={{
            CONFLICT: `${lastAdminName(change.variables?.userId)} is the last org admin. Make someone else an org admin first, then change their role.`,
          }}
        />
      </div>
      {members.isPending ? (
        <SkeletonRows label="members" />
      ) : members.isError ? (
        <ErrorState error={members.error} onRetry={() => void members.refetch()} what="members" />
      ) : (
        <Table
          caption="Organization members"
          head={
            <tr>
              <th>Person</th>
              <th>Org role</th>
              <th>Projects</th>
              <th>MFA</th>
              <th>Status</th>
              {manage && <th aria-label="Actions" />}
            </tr>
          }
        >
          {members.data.map((m) => (
            <tr key={m.user.id}>
              <td>
                {userName(m.user)}
                {m.user.id === me.id && <span className="muted"> (you)</span>}
                <div className="muted" style={{ fontSize: 12, fontWeight: 400 }}>
                  {m.user.email}
                </div>
              </td>
              <td data-label="Org role">
                {manage ? (
                  <Select
                    aria-label={`Org role for ${userName(m.user)}`}
                    dense
                    value={m.role}
                    disabled={change.isPending}
                    onChange={(e) =>
                      change.mutate(
                        { userId: m.user.id, role: e.target.value as OrgRole },
                        {
                          onSuccess: (r) =>
                            showToast({ tone: "success", message: `${userName(m.user)} is now ${ORG_ROLE_LABELS[r.role].toLowerCase()}.` }),
                        },
                      )
                    }
                    options={ORG_ROLES.map((r) => ({ value: r, label: ORG_ROLE_LABELS[r] }))}
                  />
                ) : (
                  ORG_ROLE_LABELS[m.role]
                )}
              </td>
              <td data-label="Projects">{projectsText(m)}</td>
              <td data-label="MFA">
                {m.mfa === null ? <span className="muted">Unknown</span> : <Pill tone={m.mfa ? "success" : "default"}>{m.mfa ? "On" : "Off"}</Pill>}
              </td>
              <td data-label="Status">{m.user.is_active ? "Active" : <span className="muted">Deactivated</span>}</td>
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
      <Dialog open={!!removing} onClose={() => setRemoving(null)} title={`Remove from ${org.name}`}>
        {removing && (
          <div className="form-grid">
            <p>
              Remove <strong>{userName(removing.user)}</strong> from {org.name}? This also removes them from every project in
              it. Their issues stay assigned to them until someone reassigns them.
            </p>
            <ActionError
              error={remove.error}
              overrides={{ CONFLICT: `${userName(removing.user)} is the last org admin. Make someone else an org admin first.` }}
            />
            <div className="dialog-actions">
              <Button onClick={() => setRemoving(null)}>Cancel</Button>
              <Button
                variant="danger"
                busy={remove.isPending}
                onClick={() =>
                  remove.mutate(removing.user.id, {
                    onSuccess: () => {
                      showToast({ tone: "success", message: `${userName(removing.user)} was removed from ${org.name}.` });
                      setRemoving(null);
                    },
                  })
                }
              >
                Remove member
              </Button>
            </div>
          </div>
        )}
      </Dialog>
    </Card>
  );
}

function AddMemberForm({ onDone }: { onDone: () => void }) {
  const { orgId } = useOrgCtx();
  const add = useAddOrgMember(orgId);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<OrgRole>("member");
  const [touched, setTouched] = useState(false);
  const validEmail = /^[^\s@]+@[^\s@]+$/.test(email.trim());
  const emailError = touched && !validEmail
    ? "Enter an email address."
    : isApiError(add.error, "USER_NOT_FOUND")
      ? "No one with this email has signed in to Warden yet. Ask them to sign in once, then add them here."
      : fieldErrors(add.error).email;

  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = e.currentTarget;
    setTouched(true);
    if (!validEmail) return focusFirstInvalid(form);
    const res = await add.mutateAsync({ email: email.trim(), role }).catch(() => undefined);
    if (res) {
      showToast({ tone: "success", message: `${userName(res.user)} was added as ${ORG_ROLE_LABELS[res.role].toLowerCase()}.` });
      onDone();
    } else focusFirstInvalid(form);
  }

  return (
    <form className="form-grid" onSubmit={submit} noValidate>
      <ActionError
        error={add.error && !isApiError(add.error, "USER_NOT_FOUND") && !fieldErrors(add.error).email ? add.error : null}
        overrides={{ CONFLICT: `${email.trim()} is already a member.` }}
      />
      <TextField label="Email" type="email" autoComplete="off" value={email} onChange={(e) => setEmail(e.target.value)} error={emailError} required />
      <fieldset>
        <legend>Org role</legend>
        <div className="choices">
          {(["member", "security_lead", "org_admin"] as OrgRole[]).map((r) => (
            <label key={r} className="choice-card">
              <input type="radio" name="org-role" checked={role === r} onChange={() => setRole(r)} />
              <span>
                <strong>{ORG_ROLE_LABELS[r]}</strong>
                <span className="desc">{ROLE_HELP[r]}</span>
              </span>
            </label>
          ))}
        </div>
      </fieldset>
      <p className="muted" style={{ fontSize: 13 }}>
        Warden doesn't send invitations. Project roles are set on each project's Members tab.
      </p>
      <div className="dialog-actions">
        <Button onClick={onDone}>Cancel</Button>
        <Button type="submit" variant="primary" busy={add.isPending}>
          Add member
        </Button>
      </div>
    </form>
  );
}

/** Read-only, generated from the rbac.Matrix copy in lib/permissions.ts. */
function MatrixCard() {
  const perms = Object.keys(MATRIX) as Perm[];
  return (
    <Card title="What each role can do" titleId="matrix-h" flush>
      <Table
        caption="Permissions by role"
        stack={false}
        head={
          <tr>
            <th>Permission</th>
            {MATRIX_ROLES.map((r) => (
              <th key={r} style={{ textAlign: "center" }}>
                {ROLE_LABELS[r]}
              </th>
            ))}
          </tr>
        }
      >
        {perms.map((p) => (
          <tr key={p}>
            <th scope="row" style={{ textTransform: "none", letterSpacing: 0, fontSize: 13, color: "var(--ink)", fontWeight: 500, whiteSpace: "normal" }}>
              {PERM_LABELS[p]}
            </th>
            {MATRIX_ROLES.map((r) => {
              const cell = matrixCell(p, r);
              return (
                <td key={r} style={{ textAlign: "center", fontSize: 13 }} className={cell === "–" ? "muted" : undefined}>
                  {cell === "Yes" ? <strong style={{ color: "var(--accent)" }}>Yes</strong> : cell === "–" ? <span aria-label="No">–</span> : cell}
                </td>
              );
            })}
          </tr>
        ))}
      </Table>
      <p className="muted" style={{ padding: "12px 20px 20px", fontSize: 12 }}>
        Org admin, security lead and member are org roles; owner, developer and viewer are per project. A person has the
        permissions of both.
      </p>
    </Card>
  );
}
