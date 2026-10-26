import { useQueries } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import type { FormEvent } from "react";
import { api, isApiError } from "../api/client";
import { useBulkAssign, useTransitionIssue } from "../api/hooks/issues";
import { qk } from "../api/keys";
import type { IssueStatus, ItemList, ProjectMember, UserRef } from "../api/types";
import { Pill } from "../components/Badges";
import { Button } from "../components/Button";
import { ActionError, SkeletonBlock } from "../components/States";
import { useOrgCtx } from "../layout/OrgLayout";
import { initials, userName } from "../lib/format";
import { PROJECT_ROLE_LABELS } from "../lib/permissions";
import { showToast } from "../lib/toast";

export function isConflict(err: unknown): boolean {
  return isApiError(err, "VERSION_CONFLICT") || isApiError(err, "INVALID_TRANSITION");
}

export interface AssignTarget {
  id: string;
  key: string;
  title: string;
  project_id: string;
  status: IssueStatus;
  assignee: UserRef | null;
}

/** People who are members of every given project (DESIGN.md "Assign": for a cross-project bulk
 *  assign, only people in every selected issue's project). */
export function intersectMembers(lists: ProjectMember[][]): ProjectMember[] {
  if (lists.length === 0) return [];
  const [first, ...rest] = lists;
  const sets = rest.map((l) => new Set(l.map((m) => m.user.id)));
  return first!.filter((m) => sets.every((s) => s.has(m.user.id)));
}

/** Skipped = selected − updated, said in words for the toast. */
export function assignResultText(updated: number, selected: number, name: string, key?: string): string {
  if (selected === 1 && updated === 1 && key) return `${key} assigned to ${name}.`;
  const skipped = selected - updated;
  const head = `${updated} of ${selected} issue${selected === 1 ? "" : "s"} assigned to ${name}.`;
  if (skipped <= 0) return head;
  return `${head} ${skipped} ${skipped === 1 ? "was" : "were"} skipped because ${skipped === 1 ? "it is" : "they are"} already fixed or closed.`;
}

/** Assign dialog body. `version` (single issue) uses the transition endpoint with the
 *  optimistic lock; otherwise POST /issues/assign. */
export function AssignForm({
  issues,
  version,
  onDone,
  onConflict,
}: {
  issues: AssignTarget[];
  version?: number;
  onDone: (assigned: boolean) => void;
  /** VERSION_CONFLICT / INVALID_TRANSITION go to the issue page banner, not the dialog. */
  onConflict?: (err: unknown) => void;
}) {
  const { orgId } = useOrgCtx();
  const projectIds = useMemo(() => [...new Set(issues.map((i) => i.project_id))], [issues]);
  const lists = useQueries({
    queries: projectIds.map((pid) => ({
      queryKey: qk.projectMembers(orgId, pid),
      queryFn: ({ signal }: { signal: AbortSignal }) =>
        api<ItemList<ProjectMember>>(`/orgs/${encodeURIComponent(orgId)}/projects/${encodeURIComponent(pid)}/members`, { signal }),
    })),
  });
  const single = issues.length === 1 ? issues[0] : undefined;
  const transition = useTransitionIssue(orgId, single?.id ?? "");
  const bulk = useBulkAssign(orgId);
  const [search, setSearch] = useState("");
  const [assignee, setAssignee] = useState("");

  const pending = lists.some((l) => l.isPending);
  const failed = lists.find((l) => l.isError);
  const members = pending || failed ? [] : intersectMembers(lists.map((l) => l.data?.items ?? []));
  const currentIds = new Set(issues.map((i) => i.assignee?.id).filter(Boolean));
  const term = search.trim().toLowerCase();
  const shown = members.filter(
    (m) => !term || m.user.email.toLowerCase().includes(term) || m.user.display_name.toLowerCase().includes(term),
  );
  const chosen = members.find((m) => m.user.id === assignee);
  const useTransition = single !== undefined && version !== undefined;
  const error = useTransition ? transition.error : bulk.error;
  const busy = transition.isPending || bulk.isPending;

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!chosen) return;
    const name = userName(chosen.user);
    if (useTransition && single) {
      const ok = await transition
        .mutateAsync({ to: "assigned", version: version!, assignee_id: chosen.user.id })
        .then(
          () => true,
          (err: unknown) => {
            if (isConflict(err)) onConflict?.(err);
            return false;
          },
        );
      if (ok) {
        showToast({ tone: "success", message: `${single.key} assigned to ${name}.` });
        onDone(true);
      }
      return;
    }
    const res = await bulk
      .mutateAsync({ issue_ids: issues.map((i) => i.id), assignee_id: chosen.user.id })
      .catch(() => undefined);
    if (res) {
      const skipped = issues.length - res.updated;
      showToast({
        tone: skipped > 0 ? "warning" : "success",
        message: assignResultText(res.updated, issues.length, name, single?.key),
      });
      onDone(true);
    }
  }

  return (
    <form className="form-grid" onSubmit={submit}>
      <div className="issue-chips" aria-label="Issues">
        {issues.slice(0, 8).map((i) => (
          <Pill key={i.id}>
            <span className="mono">{i.key}</span> {i.title}
          </Pill>
        ))}
        {issues.length > 8 && <Pill>+{issues.length - 8} more</Pill>}
      </div>
      <div className="field">
        <label htmlFor="assign-search">Find a person</label>
        <input
          id="assign-search"
          className="input"
          type="search"
          placeholder="Name or email"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          autoComplete="off"
        />
      </div>
      <fieldset>
        <legend>{projectIds.length > 1 ? "Members of every selected project" : "Project members"}</legend>
        {pending ? (
          <SkeletonBlock label="members" lines={3} height={36} />
        ) : failed ? (
          <ActionError always error={failed.error} />
        ) : shown.length === 0 ? (
          <p className="muted">
            {members.length === 0
              ? projectIds.length > 1
                ? "No one is a member of all these projects. Select issues from fewer projects."
                : "This project has no members yet."
              : "No one matches that search."}
          </p>
        ) : (
          <div className="person-list">
            {shown.map((m) => (
              <label key={m.user.id} className="choice-card" style={{ alignItems: "center" }}>
                <input type="radio" name="assignee" value={m.user.id} checked={assignee === m.user.id} onChange={() => setAssignee(m.user.id)} style={{ marginTop: 0 }} />
                <span className="avatar light" aria-hidden="true">
                  {initials(userName(m.user))}
                </span>
                <span style={{ flex: 1, minWidth: 0 }}>
                  <strong>{userName(m.user)}</strong>
                  {currentIds.has(m.user.id) && <span className="muted"> (current)</span>}
                  <span className="desc" style={{ overflowWrap: "anywhere" }}>
                    {m.user.email}
                  </span>
                </span>
                <Pill>{PROJECT_ROLE_LABELS[m.role]}</Pill>
              </label>
            ))}
          </div>
        )}
      </fieldset>
      <p className="muted" style={{ fontSize: 13 }}>
        Only project members can be assigned. Open and reopened issues move to Assigned; fixed or closed ones are skipped.
      </p>
      <ActionError error={error} />
      <div className="dialog-actions">
        <Button onClick={() => onDone(false)}>Cancel</Button>
        <Button type="submit" variant="primary" disabled={!chosen} busy={busy}>
          {chosen ? `Assign to ${userName(chosen.user)}` : "Assign"}
        </Button>
      </div>
    </form>
  );
}
