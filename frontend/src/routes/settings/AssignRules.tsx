import { useEffect, useRef, useState } from "react";
import { fieldErrors } from "../../api/errors";
import { useAssignRules, useProjectMembers, useSaveAssignRules } from "../../api/hooks/projects";
import { SEVERITIES, TOOLS } from "../../api/types";
import type { AssignRule, Project, ProjectMember, Severity, Tool } from "../../api/types";
import { Button } from "../../components/Button";
import { Card } from "../../components/Card";
import { Select, TextField } from "../../components/Field";
import { AlertIcon, ArrowDownIcon, ArrowUpIcon, PlusIcon, TrashIcon } from "../../components/Icons";
import { ActionError, EmptyState, ErrorState, SkeletonBlock } from "../../components/States";
import { useOrgCtx } from "../../layout/OrgLayout";
import {
  describeRule,
  emptyDraft,
  fromDraft,
  GLOB_MAX,
  hasErrors,
  MAX_RULES,
  moveRule,
  sameRules,
  serverRuleErrors,
  toDraft,
  validateRules,
} from "../../lib/assignRules";
import type { RuleDraft, RuleErrors } from "../../lib/assignRules";
import { PROJECT_ROLE_LABELS } from "../../lib/permissions";
import { SEVERITY_LABELS, TOOL_LABELS, userName } from "../../lib/format";
import { showToast } from "../../lib/toast";

export function AssignRulesCard({ project, canEdit }: { project: Project; canEdit: boolean }) {
  const { orgId } = useOrgCtx();
  const rules = useAssignRules(orgId, project.id);
  const members = useProjectMembers(orgId, project.id);
  return (
    <Card title="Auto-assign rules" titleId="rules-h">
      <p className="card-intro-plain muted">
        New issues from a scan go to the first rule that matches, top to bottom, and start as Assigned. Issues that already exist
        aren't changed. A rule whose person has left the project is skipped.
      </p>
      {rules.isPending || members.isPending ? (
        <SkeletonBlock label="auto-assign rules" lines={3} height={36} />
      ) : rules.isError ? (
        <ErrorState error={rules.error} onRetry={() => void rules.refetch()} what="the rules" />
      ) : members.isError ? (
        <ErrorState error={members.error} onRetry={() => void members.refetch()} what="the project members" />
      ) : canEdit ? (
        <RulesEditor project={project} saved={rules.data} members={members.data} />
      ) : (
        <RulesList rules={rules.data} members={members.data} />
      )}
    </Card>
  );
}

function RulesList({ rules, members }: { rules: AssignRule[]; members: ProjectMember[] }) {
  if (rules.length === 0) {
    return <p className="muted">No rules. New issues start as Open, without an assignee.</p>;
  }
  return (
    <>
      <ol className="rule-list">
        {rules.map((r, i) => {
          const d = describeRule(r, members);
          return (
            <li key={i}>
              <span className="rule-num num" aria-hidden="true">
                {i + 1}
              </span>
              <span>
                {d.when} <span className="faint">→</span> <strong>{d.who}</strong>
                {d.left && <span className="faint"> (skipped)</span>}
              </span>
            </li>
          );
        })}
      </ol>
      <p className="faint small" style={{ marginTop: 10 }}>
        Project owners and security leads can change these rules.
      </p>
    </>
  );
}

const anyOption = { value: "", label: "Any" };

function RulesEditor({ project, saved, members }: { project: Project; saved: AssignRule[]; members: ProjectMember[] }) {
  const { orgId } = useOrgCtx();
  const save = useSaveAssignRules(orgId, project.id);
  const [drafts, setDrafts] = useState<RuleDraft[]>(() => saved.map(toDraft));
  const [showErrors, setShowErrors] = useState(false);
  const [announce, setAnnounce] = useState("");
  const listRef = useRef<HTMLOListElement>(null);
  const pendingFocus = useRef<string | null>(null);

  // A newer saved version (another tab, a refetch) replaces the drafts only while there are no
  // unsaved edits, so typing is never lost.
  const savedKey = JSON.stringify(saved);
  const lastSaved = useRef(savedKey);
  const current = drafts.map(fromDraft);
  const dirty = !sameRules(current, JSON.parse(lastSaved.current) as AssignRule[]);
  useEffect(() => {
    if (savedKey === lastSaved.current) return;
    if (!dirty) setDrafts((JSON.parse(savedKey) as AssignRule[]).map(toDraft));
    lastSaved.current = savedKey;
  }, [savedKey]);

  useEffect(() => {
    const sel = pendingFocus.current;
    if (!sel) return;
    pendingFocus.current = null;
    listRef.current?.querySelector<HTMLElement>(sel)?.focus();
  });

  const validation = validateRules(drafts, members);
  const server = serverRuleErrors(fieldErrors(save.error), drafts.length);
  const errorsFor = (i: number): RuleErrors => {
    const local = showErrors ? (validation.rules[i] ?? {}) : {};
    return { ...(server.rules[i] ?? {}), ...local };
  };

  const update = (i: number, patch: Partial<RuleDraft>) => {
    save.reset();
    setDrafts((list) => list.map((d, idx) => (idx === i ? { ...d, ...patch } : d)));
  };

  const move = (i: number, delta: -1 | 1) => {
    const next = moveRule(drafts, i, delta);
    if (next === drafts) return;
    save.reset();
    const moved = drafts[i]!;
    const to = i + delta;
    setDrafts(next);
    setAnnounce(`Rule moved to position ${to + 1} of ${next.length}.`);
    // Keep focus on the moved rule: the same button if it can still move that way, else the other.
    const atEdge = delta === -1 ? to === 0 : to === next.length - 1;
    const dir = atEdge ? (delta === -1 ? "down" : "up") : delta === -1 ? "up" : "down";
    pendingFocus.current = `[data-rule="${moved.key}"] [data-move="${dir}"]`;
  };

  const remove = (i: number) => {
    save.reset();
    const next = drafts.filter((_, idx) => idx !== i);
    setDrafts(next);
    setAnnounce(`Rule ${i + 1} removed. ${next.length} ${next.length === 1 ? "rule" : "rules"} left.`);
    const neighbour = next[Math.min(i, next.length - 1)];
    pendingFocus.current = neighbour ? `[data-rule="${neighbour.key}"] input` : null;
    if (!neighbour) requestAnimationFrame(() => document.getElementById("add-rule")?.focus());
  };

  const add = () => {
    if (drafts.length >= MAX_RULES) return;
    save.reset();
    const d = emptyDraft();
    setDrafts([...drafts, d]);
    setAnnounce(`Rule ${drafts.length + 1} added.`);
    pendingFocus.current = `[data-rule="${d.key}"] input`;
  };

  const submit = () => {
    setShowErrors(true);
    if (!validation.valid) {
      setAnnounce("Some rules need attention.");
      requestAnimationFrame(() => listRef.current?.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus());
      return;
    }
    save.mutate(current, {
      onSuccess: (res) => {
        setShowErrors(false);
        lastSaved.current = JSON.stringify(res.items);
        setDrafts(res.items.map(toDraft));
        showToast({ tone: "success", message: `Auto-assign rules saved for ${project.key}.` });
      },
      onError: () => requestAnimationFrame(() => listRef.current?.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus()),
    });
  };

  const memberOptions = (d: RuleDraft) => {
    const opts = members.map((m) => ({ value: m.user.id, label: `${userName(m.user)} (${PROJECT_ROLE_LABELS[m.role]})` }));
    const known = members.some((m) => m.user.id === d.assignee_id);
    return [
      { value: "", label: "Choose a person…" },
      ...(d.assignee_id && !known ? [{ value: d.assignee_id, label: "Former member (skipped)" }] : []),
      ...opts,
    ];
  };

  return (
    <div className="stack" style={{ gap: 12 }}>
      <span className="visually-hidden" role="status" aria-live="polite">
        {announce}
      </span>
      {drafts.length === 0 ? (
        <EmptyState title="No rules yet">New issues start as Open, without an assignee, until you add a rule.</EmptyState>
      ) : (
        <ol className="rule-editor" ref={listRef}>
          {drafts.map((d, i) => {
            const e = errorsFor(i);
            return (
              <li key={d.key} data-rule={d.key} className={hasErrors(e) ? "rule invalid" : "rule"}>
                <fieldset>
                  <legend className="rule-legend">
                    <span className="rule-num num">{i + 1}</span>
                    <span className="visually-hidden">Rule {i + 1}</span>
                  </legend>
                  <div className="rule-grid">
                    <TextField
                      label="Path matches"
                      className="mono"
                      placeholder="Any path"
                      value={d.path_glob}
                      onChange={(ev) => update(i, { path_glob: ev.target.value })}
                      error={e.path_glob}
                      aria-invalid={e.path_glob || e.match ? true : undefined}
                      spellCheck={false}
                      autoComplete="off"
                      maxLength={GLOB_MAX + 50}
                    />
                    <Select
                      label="Scanner"
                      value={d.tool}
                      onChange={(ev) => update(i, { tool: ev.target.value as Tool | "" })}
                      options={[anyOption, ...TOOLS.map((t) => ({ value: t, label: TOOL_LABELS[t] }))]}
                    />
                    <Select
                      label="Severity at least"
                      value={d.severity_at_least}
                      onChange={(ev) => update(i, { severity_at_least: ev.target.value as Severity | "" })}
                      options={[anyOption, ...SEVERITIES.map((s) => ({ value: s, label: SEVERITY_LABELS[s] }))]}
                    />
                    <Select
                      label="Assign to"
                      value={d.assignee_id}
                      onChange={(ev) => update(i, { assignee_id: ev.target.value })}
                      options={memberOptions(d)}
                      error={e.assignee_id}
                    />
                  </div>
                  {e.match && (
                    <p className="field-error">
                      <AlertIcon size={14} /> {e.match}
                    </p>
                  )}
                </fieldset>
                <div className="rule-actions">
                  <button
                    type="button"
                    className="icon-btn sm"
                    data-move="up"
                    aria-label={`Move rule ${i + 1} up`}
                    title="Move up"
                    disabled={i === 0}
                    onClick={() => move(i, -1)}
                  >
                    <ArrowUpIcon />
                  </button>
                  <button
                    type="button"
                    className="icon-btn sm"
                    data-move="down"
                    aria-label={`Move rule ${i + 1} down`}
                    title="Move down"
                    disabled={i === drafts.length - 1}
                    onClick={() => move(i, 1)}
                  >
                    <ArrowDownIcon />
                  </button>
                  <button type="button" className="icon-btn sm" aria-label={`Remove rule ${i + 1}`} title="Remove" onClick={() => remove(i)}>
                    <TrashIcon />
                  </button>
                </div>
              </li>
            );
          })}
        </ol>
      )}
      {showErrors && validation.list && (
        <div className="banner banner-error" role="alert">
          <AlertIcon /> <span>{validation.list}</span>
        </div>
      )}
      {server.other.map((m) => (
        <div key={m} className="banner banner-error" role="alert">
          <AlertIcon /> <span>{m}</span>
        </div>
      ))}
      <ActionError error={save.error} />
      <div className="row-between">
        <Button id="add-rule" size="sm" onClick={add} disabled={drafts.length >= MAX_RULES}>
          <PlusIcon /> Add rule
        </Button>
        <div className="row">
          <span className="faint small">
            {drafts.length} of {MAX_RULES}
          </span>
          {dirty && (
            <Button
              onClick={() => {
                save.reset();
                setShowErrors(false);
                setDrafts((JSON.parse(lastSaved.current) as AssignRule[]).map(toDraft));
                setAnnounce("Changes discarded.");
              }}
              disabled={save.isPending}
            >
              Discard changes
            </Button>
          )}
          <Button variant="primary" onClick={submit} busy={save.isPending} disabled={!dirty}>
            Save rules
          </Button>
        </div>
      </div>
    </div>
  );
}
