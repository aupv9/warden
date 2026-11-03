import { useEffect, useId, useMemo, useRef, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router";
import { useQueryClient } from "@tanstack/react-query";
import { ApiError, isApiError } from "../api/client";
import { errorMessage, fieldErrors, isForbidden, isNotFound, ruleProblems, waitText } from "../api/errors";
import { useProjects } from "../api/hooks/projects";
import { useCreateScanRule, useDeleteScanRule, useRuleCheck, useRuleTest, useScanRule, useScanRuleVersions, useStartRuleTest, useUpdateScanRule } from "../api/hooks/scanRules";
import { qk } from "../api/keys";
import { flattenPages } from "../api/paging";
import type { Project, RuleProblem, RuleTestRequest, ScanRule, ScanRuleTool, ScanRuleVersion } from "../api/types";
import { Pill, SeverityMark } from "../components/Badges";
import { Button } from "../components/Button";
import { Card } from "../components/Card";
import { Dialog } from "../components/Dialog";
import { focusFirstInvalid, Select, TextField } from "../components/Field";
import { AlertIcon, BackIcon, CheckIcon, LockIcon, RefreshIcon, TrashIcon } from "../components/Icons";
import { PageHeader, Segmented } from "../components/PageHeader";
import { ActionError, Banner, ErrorState, ForbiddenState, NotFoundState, SkeletonBlock } from "../components/States";
import { useOrgCtx } from "../layout/OrgLayout";
import { formatDateTime, relativeTime, userName } from "../lib/format";
import { can } from "../lib/permissions";
import {
  deleteConfirmed,
  diffStats,
  findingLines,
  findingRange,
  findingsSummary,
  formFromRule,
  indexProblems,
  kib,
  lineCount,
  lineDiff,
  lineOffset,
  newRuleForm,
  orgRuleId,
  parseToolParam,
  problemText,
  RULE_BODY_MAX_BYTES,
  RULE_NAME_MAX,
  RULE_PROJECTS_MAX,
  SCAN_RULE_TOOL_KIND,
  SCAN_RULE_TOOL_LABELS,
  scopeText,
  SNIPPET_MAX_BYTES,
  TEST_POLL_MAX_MS,
  TEST_RATE_LIMITED,
  testErrorText,
  updateRuleBody,
  utf8Length,
  validateRuleForm,
  validateTestInput,
  versionChanges,
} from "../lib/scanRules";
import type { RuleForm } from "../lib/scanRules";
import { showToast } from "../lib/toast";
import { usePageTitle } from "../lib/usePageTitle";
import { RULES_BASE } from "./ScanRules";

// v0.6 wave 1: one org rule (DESIGN.md "v0.6 screens: Scan rules"): /settings/scan-rules/new?tool=
// adds one, /settings/scan-rules/:id edits it (manage_rules) or shows it read-only, ?tab=history
// lists its versions with a line diff between any two.
//
// Security rules: a rule body, its name, the server's problems and a test's findings are text
// from users and scanners; everything is rendered as React text, never as HTML. The editor is a
// plain <textarea> (no rich editor, no innerHTML). A test snippet lives in the test dialog's state
// only, travels to the API through a closure (hooks/scanRules.ts) and is dropped when the dialog
// closes; nothing here writes to browser storage.

export function ScanRulePage() {
  const { ruleId } = useParams();
  const [params] = useSearchParams();
  const { orgId, org } = useOrgCtx();
  const manage = can("manage_rules", org.role);
  if (ruleId === "new") {
    const tool = parseToolParam(params.get("tool"));
    if (!manage) {
      return (
        <div className="page">
          <PageHeader title="New scan rule" />
          <div className="page-body">
            <ForbiddenState orgName={org.name} backTo={RULES_BASE(orgId)} />
          </div>
        </div>
      );
    }
    return <NewRule tool={tool} />;
  }
  return <ExistingRule id={ruleId ?? ""} manage={manage} />;
}

function BackToRules({ tool }: { tool: ScanRuleTool }) {
  const { orgId } = useOrgCtx();
  return (
    <Link to={`${RULES_BASE(orgId)}?tool=${tool}`} className="back-link">
      <BackIcon size={14} /> Scan rules
    </Link>
  );
}

function NewRule({ tool }: { tool: ScanRuleTool }) {
  usePageTitle(`New ${SCAN_RULE_TOOL_LABELS[tool]} rule`);
  return (
    <div className="page">
      <PageHeader title={`New ${SCAN_RULE_TOOL_LABELS[tool]} rule`} />
      <div className="page-body rule-page">
        <BackToRules tool={tool} />
        <RuleEditor tool={tool} rule={null} />
      </div>
    </div>
  );
}

function ExistingRule({ id, manage }: { id: string; manage: boolean }) {
  const { orgId, org } = useOrgCtx();
  const rule = useScanRule(orgId, id);
  const [params] = useSearchParams();
  const tab = params.get("tab") === "history" ? "history" : "rule";
  usePageTitle(rule.data?.name ?? "Scan rule");

  if (rule.isPending) {
    return (
      <div className="page">
        <PageHeader title="Scan rule" />
        <div className="page-body">
          <SkeletonBlock label="scan rule" lines={6} />
        </div>
      </div>
    );
  }
  if (rule.isError) {
    return (
      <div className="page">
        <PageHeader title="Scan rule" />
        <div className="page-body">
          {isNotFound(rule.error) ? (
            <NotFoundState backTo={RULES_BASE(orgId)} backLabel="Back to scan rules" />
          ) : isForbidden(rule.error) ? (
            <ForbiddenState orgName={org.name} backTo={`/orgs/${orgId}/projects`} />
          ) : (
            <ErrorState error={rule.error} onRetry={() => void rule.refetch()} what="this rule" />
          )}
        </div>
      </div>
    );
  }

  const r = rule.data;
  const base = `${RULES_BASE(orgId)}/${r.id}`;
  return (
    <div className="page">
      <PageHeader title={r.name}>
        <Segmented label="Rule pages">
          <Link to={base} aria-current={tab === "rule" ? "page" : undefined} className={tab === "rule" ? "active" : undefined}>
            Rule
          </Link>
          <Link to={`${base}?tab=history`} aria-current={tab === "history" ? "page" : undefined} className={tab === "history" ? "active" : undefined}>
            History
          </Link>
        </Segmented>
      </PageHeader>
      <div className="page-body rule-page">
        <BackToRules tool={r.tool} />
        <p className="rule-meta small">
          <Pill>{SCAN_RULE_TOOL_LABELS[r.tool]}</Pill> <span className="mono">{orgRuleId(r.key)}</span> · <SeverityMark severity={r.severity} /> ·
          version {r.version} · changed <span title={formatDateTime(r.updated_at)}>{relativeTime(r.updated_at)}</span> by{" "}
          {r.updated_by ? userName(r.updated_by) : "a former member"}
        </p>
        {tab === "history" ? (
          <RuleHistory rule={r} />
        ) : manage ? (
          // A new key per version: after a save or a reload the form starts from the stored rule.
          <RuleEditor key={`${r.id}:${r.version}`} tool={r.tool} rule={r} onReload={() => rule.refetch()} />
        ) : (
          <RuleReadOnly rule={r} />
        )}
      </div>
    </div>
  );
}

// ---- Read-only ----

function RuleReadOnly({ rule: r }: { rule: ScanRule }) {
  const { orgId } = useOrgCtx();
  const projects = useProjects(orgId);
  return (
    <>
      <Card title="Rule" titleId="rule-h">
        <div className="stack" style={{ gap: 12 }}>
          <dl className="kv">
            <dt>Scanner</dt>
            <dd>
              {SCAN_RULE_TOOL_LABELS[r.tool]} ({SCAN_RULE_TOOL_KIND[r.tool]})
            </dd>
            <dt>Findings carry</dt>
            <dd className="mono">{orgRuleId(r.key)}</dd>
            <dt>Severity</dt>
            <dd>
              <SeverityMark severity={r.severity} />
            </dd>
            <dt>Runs</dt>
            <dd>{r.enabled ? "On: scans run it" : "Off: scans don't run it"}</dd>
            <dt>Projects</dt>
            <dd>{projectNames(r.project_ids, projects.data)}</dd>
            <dt>Created</dt>
            <dd>
              {formatDateTime(r.created_at)} by {r.created_by ? userName(r.created_by) : "a former member"}
            </dd>
          </dl>
          <CodeView text={r.body} label={`${r.name}, as Warden stores it`} />
          <p className="note">
            <LockIcon size={14} />
            <span>Only org admins and security leads can change scan rules.</span>
          </p>
        </div>
      </Card>
    </>
  );
}

function projectNames(ids: string[] | null, projects: Project[] | undefined): string {
  if (ids === null) return "All projects, including projects created later";
  const keys = ids.map((id) => projects?.find((p) => p.id === id)?.key).filter((k): k is string => !!k);
  const hidden = ids.length - keys.length;
  return [...keys, ...(hidden > 0 ? [`${hidden} project${hidden === 1 ? "" : "s"} you can't see`] : [])].join(", ") || scopeText(ids);
}

/** Plain text with line numbers, optionally some lines highlighted (a test's findings). */
export function CodeView({ text, label, highlight }: { text: string; label: string; highlight?: Set<number> }) {
  const lines = text.replace(/\n$/, "").split("\n");
  return (
    <pre className="code rule-code" aria-label={label} tabIndex={0}>
      {lines.map((t, i) => {
        const hl = highlight?.has(i + 1) ?? false;
        return (
          <span key={i} className={hl ? "line hl" : "line"}>
            <span className="ln">{i + 1}</span>
            <span className="txt">{t}</span>
            {hl && <span className="visually-hidden"> (found)</span>}
          </span>
        );
      })}
    </pre>
  );
}

// ---- Editor ----

type Dialogs = "test" | "delete" | null;

function RuleEditor({ tool, rule, onReload }: { tool: ScanRuleTool; rule: ScanRule | null; onReload?: () => Promise<unknown> }) {
  const { orgId } = useOrgCtx();
  const navigate = useNavigate();
  const projects = useProjects(orgId);
  const [form, setForm] = useState<RuleForm>(() => (rule ? formFromRule(rule) : newRuleForm(tool)));
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [conflict, setConflict] = useState(false);
  const [reloading, setReloading] = useState(false);
  const [dialog, setDialog] = useState<Dialogs>(null);
  const [saveProblems, setSaveProblems] = useState<{ body: string; problems: RuleProblem[] } | null>(null);
  const [checkingSave, setCheckingSave] = useState(false);
  const create = useCreateScanRule(orgId);
  const update = useUpdateScanRule(orgId);
  const mutation = rule ? update : create;
  const { check, checkNow } = useRuleCheck(orgId, tool, form.body, true);
  const formRef = useRef<HTMLFormElement>(null);
  const bodyRef = useRef<HTMLTextAreaElement>(null);
  const set = (patch: Partial<RuleForm>) => setForm((f) => ({ ...f, ...patch }));

  const server = fieldErrors(mutation.error);
  const shown = { ...server, ...errors };
  // Problems from the last save (RULE_INVALID) win while the body is unchanged; else the check's.
  const problems =
    saveProblems && saveProblems.body === form.body
      ? saveProblems.problems
      : check.status === "done" && check.body === form.body
        ? check.result.problems
        : [];
  const dirty = rule ? updateRuleBody(form, rule) !== null : true;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (conflict) return;
    const v = validateRuleForm(form);
    setErrors(v);
    if (Object.keys(v).length) {
      focusFirstInvalid(formRef.current);
      return;
    }
    // Check on save too: a body with problems isn't sent (the server would refuse it anyway).
    setCheckingSave(true);
    const checked = await checkNow(form.body);
    setCheckingSave(false);
    if (checked && !checked.ok) {
      bodyRef.current?.focus();
      return;
    }
    const onError = (err: unknown) => {
      if (isApiError(err, "VERSION_CONFLICT")) setConflict(true);
      const p = ruleProblems(err);
      if (p.length) {
        setSaveProblems({ body: form.body, problems: p });
        bodyRef.current?.focus();
      } else focusFirstInvalid(formRef.current);
    };
    if (rule) {
      const body = updateRuleBody(form, rule);
      if (!body) return;
      update.mutate(
        { id: rule.id, body },
        {
          onSuccess: (r) => showToast({ tone: "success", message: `“${r.name}” saved as version ${r.version}. It applies from the next scan.` }),
          onError,
        },
      );
    } else {
      create.mutate(
        { tool, name: form.name.trim(), body: form.body, enabled: form.enabled, project_ids: form.allProjects ? null : form.projectIds },
        {
          onSuccess: (r) => {
            showToast({ tone: "success", message: `“${r.name}” added. ${r.enabled ? "It runs from the next scan." : "It's off until you turn it on."}` });
            void navigate(`${RULES_BASE(orgId)}/${r.id}`);
          },
          onError,
        },
      );
    }
  };

  const reload = async () => {
    setReloading(true);
    await onReload?.();
    setReloading(false);
  };

  return (
    <>
      {conflict && <RuleConflictBanner onReload={() => void reload()} reloading={reloading} />}
      <form ref={formRef} className="stack rule-form" onSubmit={(e) => void submit(e)} noValidate>
        <Card title="Rule" titleId="rule-h">
          <div className="form-grid">
            <TextField
              label="Name"
              value={form.name}
              maxLength={RULE_NAME_MAX + 20}
              onChange={(e) => set({ name: e.target.value })}
              error={shown.name}
              hint="Shown in the rule list and on its issues, such as “No eval of request data”."
              autoComplete="off"
              disabled={conflict}
            />
            <RuleBodyField
              tool={tool}
              value={form.body}
              onChange={(body) => set({ body })}
              problems={problems}
              error={shown.body}
              textareaRef={bodyRef}
              disabled={conflict}
            />
            <CheckStatus check={check} body={form.body} problems={problems} />
            {check.status === "done" && check.body === form.body && check.result.ok && check.result.body !== null && (
              <details className="rule-canonical">
                <summary>Warden will store</summary>
                <p className="small muted">
                  Warden stores and runs the rule as it rendered it from what it understood, not the text as typed: comments and
                  formatting aren't kept.
                </p>
                <CodeView text={check.result.body} label="The rule as Warden will store it" />
              </details>
            )}
          </div>
        </Card>

        <Card title="Where it runs" titleId="scope-h">
          <div className="form-grid">
            <ScopePicker
              projects={projects.data ?? []}
              all={form.allProjects}
              selected={form.projectIds}
              error={shown.project_ids}
              onChange={(allProjects, projectIds) => set({ allProjects, projectIds })}
            />
            <label className="switch rule-enabled">
              <input type="checkbox" role="switch" checked={form.enabled} onChange={(e) => set({ enabled: e.target.checked })} disabled={conflict} />
              <span className="switch-track" aria-hidden="true" />
              <span className="switch-label">Run this rule in scans</span>
            </label>
            <span className="hint">Turning it off stops new findings from the next scan. It never closes the issues the rule already found.</span>
          </div>
        </Card>

        <ActionError
          error={mutation.error}
          overrides={{
            CONFLICT: `A ${SCAN_RULE_TOOL_LABELS[tool]} rule with this key already exists, or the org has the most rules Warden allows (200 per scanner, 1 MiB in all). Change the id in the rule, or delete a rule you no longer use.`,
            VERSION_CONFLICT: "Someone changed this rule while you had it open. Your change wasn't saved.",
          }}
        />

        <div className="rule-actions">
          <Button onClick={() => setDialog("test")} disabled={!form.body.trim() || conflict}>
            Test on a snippet…
          </Button>
          <span className="grow" />
          {rule && dirty && !conflict && (
            <Button onClick={() => setForm(formFromRule(rule))} disabled={mutation.isPending}>
              Discard changes
            </Button>
          )}
          <Button type="submit" variant="primary" busy={mutation.isPending || checkingSave} disabled={!dirty || conflict}>
            {rule ? "Save rule" : "Add rule"}
          </Button>
        </div>
      </form>

      {conflict && rule && form.body !== rule.body && (
        <details className="rule-kept">
          <summary>Your unsaved text</summary>
          <CodeView text={form.body} label="Your unsaved text" />
        </details>
      )}

      {rule && (
        <Card title="Delete this rule" titleId="delete-h" className="danger-zone">
          <div className="stack" style={{ gap: 10 }}>
            <p className="small text-2">
              Scans stop running it from the next scan. Its issues stay open: deleting a rule never fixes or closes what it found.
            </p>
            <div>
              <Button variant="danger" onClick={() => setDialog("delete")}>
                <TrashIcon /> Delete rule…
              </Button>
            </div>
          </div>
        </Card>
      )}

      <Dialog open={dialog === "test"} onClose={() => setDialog(null)} title="Test on a snippet" className="dialog rule-test-dialog">
        {dialog === "test" && <RuleTestDialog tool={tool} body={form.body} />}
      </Dialog>
      {rule && (
        <Dialog open={dialog === "delete"} onClose={() => setDialog(null)} title={`Delete “${rule.name}”?`}>
          {dialog === "delete" && <DeleteRuleDialog rule={rule} onDone={() => setDialog(null)} />}
        </Dialog>
      )}
    </>
  );
}

/** VERSION_CONFLICT on save: the editor locks until the rule is reloaded; never retried. */
export function RuleConflictBanner({ onReload, reloading }: { onReload: () => void; reloading: boolean }) {
  return (
    <div className="banner banner-warning" role="alert">
      <RefreshIcon />
      <div className="stack" style={{ gap: 10 }}>
        <span>
          <strong>Someone changed this rule while you had it open.</strong> Your change wasn't saved. Reload to see the latest version,
          then make your change again. Your text is kept below until you reload.
        </span>
        <div>
          <Button variant="primary" onClick={onReload} busy={reloading}>
            Reload rule
          </Button>
        </div>
      </div>
    </div>
  );
}

function CheckStatus({ check, body, problems }: { check: ReturnType<typeof useRuleCheck>["check"]; body: string; problems: RuleProblem[] }) {
  let content: ReactNode;
  if (!body.trim() || utf8Length(body) > RULE_BODY_MAX_BYTES) content = null;
  else if (check.status === "idle" || check.status === "checking" || check.body !== body) content = <span className="muted">Checking…</span>;
  else if (check.status === "error")
    content = (
      <span className="warn-text">
        Couldn't check the rule: {errorMessage(check.error)} Warden checks it again when you save.
      </span>
    );
  else if (check.result.ok)
    content = (
      <span className="ok-text">
        <CheckIcon size={14} /> Warden can use this rule.
        {check.result.key && (
          <>
            {" "}
            Findings carry <span className="mono">{orgRuleId(check.result.key)}</span>
          </>
        )}
        {check.result.severity && (
          <>
            {" "}
            · <SeverityMark severity={check.result.severity} />
          </>
        )}
      </span>
    );
  else
    content = (
      <span className="danger-text">
        <AlertIcon size={14} /> {problems.length === 1 ? "1 problem" : `${problems.length} problems`}. Warden can't use this rule until{" "}
        {problems.length === 1 ? "it's" : "they're"} fixed.
      </span>
    );
  return (
    <p className="small rule-check" role="status" aria-live="polite">
      {content}
    </p>
  );
}

/** A plain monospace textarea with a line-number gutter; lines with problems are marked in the
 *  gutter, and the problems are listed under it (each one moves the caret to its line). */
export function RuleBodyField({
  tool,
  value,
  onChange,
  problems,
  error,
  textareaRef,
  disabled,
}: {
  tool: ScanRuleTool;
  value: string;
  onChange: (v: string) => void;
  problems: RuleProblem[];
  error?: string;
  textareaRef: React.RefObject<HTMLTextAreaElement | null>;
  disabled?: boolean;
}) {
  const id = useId();
  const gutterRef = useRef<HTMLDivElement>(null);
  const lines = lineCount(value);
  const index = useMemo(() => indexProblems(problems, lines), [problems, lines]);
  const bytes = utf8Length(value);
  const invalid = !!error || problems.length > 0;
  const describedBy = [`${id}-h`, problems.length ? `${id}-p` : "", error ? `${id}-e` : ""].filter(Boolean).join(" ");

  const goTo = (line: number) => {
    const ta = textareaRef.current;
    if (!ta) return;
    const at = lineOffset(ta.value, line);
    ta.focus();
    ta.setSelectionRange(at, at);
    // 20 px per line, as in the CSS.
    ta.scrollTop = Math.max(0, (line - 3) * 20);
  };

  return (
    <div className="field">
      <label htmlFor={id}>{`Rule (${tool === "opengrep" ? "YAML" : "TOML"})`}</label>
      <div className={invalid ? "rule-editor invalid" : "rule-editor"}>
        <div className="rule-gutter" ref={gutterRef} aria-hidden="true">
          {Array.from({ length: lines }, (_, i) => (
            <span key={i} className={index.byLine.has(i + 1) ? "bad" : undefined}>
              {i + 1}
            </span>
          ))}
        </div>
        <textarea
          id={id}
          ref={textareaRef}
          className="rule-textarea"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          onScroll={(e) => {
            if (gutterRef.current) gutterRef.current.scrollTop = e.currentTarget.scrollTop;
          }}
          rows={Math.min(24, Math.max(10, lines + 1))}
          wrap="off"
          spellCheck={false}
          autoCapitalize="none"
          autoComplete="off"
          autoCorrect="off"
          aria-invalid={invalid ? true : undefined}
          aria-describedby={describedBy}
          disabled={disabled}
        />
      </div>
      <span id={`${id}-h`} className="hint">
        {tool === "opengrep"
          ? "One Opengrep rule: rules: with a single entry. Its id is the rule's key."
          : "One Gitleaks rule: a single [[rules]] table. Its id is the rule's key."}{" "}
        No allowlists, ignores or path exclusions. {kib(bytes)} of 64 KiB.
      </span>
      {problems.length > 0 && (
        <ul id={`${id}-p`} className="rule-problems" aria-label="Problems in the rule">
          {[...index.byLine.entries()]
            .sort((a, b) => a[0] - b[0])
            .flatMap(([line, ps]) =>
              ps.map((p, i) => (
                <li key={`${line}:${i}`}>
                  <button type="button" className="btn-link mono" onClick={() => goTo(line)}>
                    {`Line ${line}${p.column !== null ? `:${p.column}` : ""}`}
                  </button>{" "}
                  <span>{p.message}</span>
                </li>
              )),
            )}
          {index.general.map((p, i) => (
            <li key={`g${i}`}>{problemText(p)}</li>
          ))}
        </ul>
      )}
      {error && (
        <span id={`${id}-e`} className="error">
          <AlertIcon size={14} /> {error}
        </span>
      )}
    </div>
  );
}

function ScopePicker({
  projects,
  all,
  selected,
  error,
  onChange,
}: {
  projects: Project[];
  all: boolean;
  selected: string[];
  error?: string;
  onChange: (all: boolean, ids: string[]) => void;
}) {
  const id = useId();
  const unknown = selected.filter((p) => !projects.some((x) => x.id === p));
  return (
    <fieldset aria-describedby={error ? `${id}-e` : undefined}>
      <legend>Projects</legend>
      <div className="stack" style={{ gap: 6 }}>
        <label className="check-row">
          <input type="radio" className="check" name={`${id}-scope`} checked={all} onChange={() => onChange(true, selected)} />
          <span>
            <strong>All projects</strong>
            <span className="desc">Including projects created later.</span>
          </span>
        </label>
        <label className="check-row">
          <input type="radio" className="check" name={`${id}-scope`} checked={!all} onChange={() => onChange(false, selected)} />
          <span>
            <strong>Only these projects</strong>
            <span className="desc">Up to {RULE_PROJECTS_MAX}. Scans of other projects don't run it.</span>
          </span>
        </label>
        {!all && (
          <div className="hook-projects" role="group" aria-label="Projects that run the rule">
            {projects.map((p) => (
              <label key={p.id} className="check-row">
                <input
                  type="checkbox"
                  className="check"
                  checked={selected.includes(p.id)}
                  aria-invalid={error ? true : undefined}
                  onChange={(e) => onChange(false, e.target.checked ? [...selected, p.id] : selected.filter((x) => x !== p.id))}
                />
                <span>
                  <span className="mono faint">{p.key}</span> {p.name}
                </span>
              </label>
            ))}
            {unknown.length > 0 && (
              <p className="faint small">
                And {unknown.length} project{unknown.length === 1 ? "" : "s"} you can't see.
              </p>
            )}
          </div>
        )}
        {!all && <span className="hint">{selected.length} chosen</span>}
      </div>
      {error && (
        <span id={`${id}-e`} className="field-error">
          <AlertIcon size={14} /> {error}
        </span>
      )}
    </fieldset>
  );
}

// ---- Delete ----

function DeleteRuleDialog({ rule: r, onDone }: { rule: ScanRule; onDone: () => void }) {
  const { orgId } = useOrgCtx();
  const navigate = useNavigate();
  const del = useDeleteScanRule(orgId);
  const [typed, setTyped] = useState("");
  const ok = deleteConfirmed(typed, r.key);
  return (
    <form
      className="form-grid"
      onSubmit={(e) => {
        e.preventDefault();
        if (!ok) return;
        del.mutate(
          { id: r.id, version: r.version },
          {
            onSuccess: () => {
              showToast({ tone: "success", message: `“${r.name}” deleted. Its issues stay open.` });
              onDone();
              void navigate(`${RULES_BASE(orgId)}?tool=${r.tool}`);
            },
          },
        );
      }}
    >
      <p>
        Delete <strong>{r.name}</strong> <span className="mono faint">({orgRuleId(r.key)})</span>? Scans stop running it from the next
        scan.
      </p>
      <p className="note">
        <AlertIcon size={14} />
        <span>
          <strong>Its issues stay open.</strong> Deleting a rule never fixes or closes what it found; a security lead can close them.
          The issues keep the rule's id and say the rule was deleted.
        </span>
      </p>
      <TextField
        label={
          <>
            Type <span className="mono">{r.key}</span> to confirm
          </>
        }
        value={typed}
        onChange={(e) => setTyped(e.target.value)}
        autoComplete="off"
        autoCapitalize="none"
        spellCheck={false}
        className="mono"
        data-autofocus
      />
      <ActionError
        error={del.error}
        overrides={{ VERSION_CONFLICT: "Someone changed this rule while you had it open. Close this, reload the rule, check the change, then delete it." }}
      />
      <div className="dialog-actions">
        <Button onClick={onDone} disabled={del.isPending}>
          Cancel
        </Button>
        <Button type="submit" variant="danger" busy={del.isPending} disabled={!ok}>
          Delete rule
        </Button>
      </div>
    </form>
  );
}

// ---- Test on a snippet ----

/** The dialog keeps the snippet in its own state only; closing it drops the snippet and the
 *  cached result. */
function RuleTestDialog({ tool, body }: { tool: ScanRuleTool; body: string }) {
  const { orgId } = useOrgCtx();
  const qc = useQueryClient();
  const [filename, setFilename] = useState(tool === "gitleaks" ? "settings.env" : "app.js");
  const [snippet, setSnippet] = useState("");
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [run, setRun] = useState<{ id: string; startedAt: number; snippet: string } | null>(null);
  const [gaveUp, setGaveUp] = useState(false);
  const request = useRef<RuleTestRequest | null>(null);
  const start = useStartRuleTest(orgId, () => request.current!);
  const test = useRuleTest(orgId, run?.id ?? null, run?.startedAt ?? 0);
  const formRef = useRef<HTMLFormElement>(null);
  const bytes = utf8Length(snippet);

  // Stop waiting after 3 minutes (polling stops by itself; this shows it).
  useEffect(() => {
    if (!run) return;
    setGaveUp(false);
    const t = setTimeout(() => setGaveUp(true), Math.max(0, run.startedAt + TEST_POLL_MAX_MS - Date.now()));
    return () => clearTimeout(t);
  }, [run]);

  // The result goes with the dialog.
  const runId = run?.id;
  useEffect(() => {
    return () => {
      request.current = null;
      if (runId) qc.removeQueries({ queryKey: qk.ruleTest(orgId, runId) });
    };
  }, [qc, orgId, runId]);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const v = validateTestInput(filename, snippet);
    setErrors(v);
    if (Object.keys(v).length) {
      focusFirstInvalid(formRef.current);
      return;
    }
    request.current = { tool, body, filename: filename.trim(), snippet };
    const tested = snippet;
    start.mutate(undefined, {
      onSuccess: (t) => setRun({ id: t.id, startedAt: Date.now(), snippet: tested }),
      onSettled: () => {
        request.current = null;
      },
    });
  };

  const t = test.data;
  const finished = t && (t.state === "done" || t.state === "failed");
  const startError = start.error;
  const startProblems = ruleProblems(startError);

  if (run) {
    const snippetLines = run.snippet.replace(/\n$/, "").split("\n").length;
    const hl = t?.state === "done" ? findingLines(t.findings, snippetLines) : undefined;
    return (
      <div className="form-grid">
        <p className="small rule-test-state" role="status" aria-live="polite">
          {!t || t.state === "queued" ? (
            gaveUp ? null : (
              <span className="muted">Queued · waiting for a scanner worker…</span>
            )
          ) : t.state === "running" ? (
            gaveUp ? null : (
              <span className="muted">Running in the scanner sandbox…</span>
            )
          ) : t.state === "done" ? (
            <strong>{findingsSummary(t.findings)}</strong>
          ) : (
            <span className="danger-text">The test failed.</span>
          )}
        </p>
        {test.isError && !finished && <ErrorState error={test.error} onRetry={() => void test.refetch()} what="the test result" />}
        {gaveUp && !finished && (
          <Banner tone="warning" title="No result after 3 minutes.">
            The scanner workers may be busy. Warden stopped asking; run the test again later.
          </Banner>
        )}
        {t?.state === "failed" && <Banner title="The test failed.">{testErrorText(t.error)}</Banner>}
        {t?.state === "done" && t.findings.length > 0 && (
          <ul className="rule-findings" aria-label="Findings">
            {t.findings.map((f, i) => (
              <li key={i}>
                <span className="mono">{findingRange(f)}</span> <span>{f.message}</span>
              </li>
            ))}
          </ul>
        )}
        <CodeView text={run.snippet} label={`Snippet ${filename}`} highlight={hl} />
        {tool === "gitleaks" && <p className="faint small">Gitleaks findings are reported by line only, never with the matched text.</p>}
        <p className="note">
          <LockIcon size={14} />
          <span>The snippet was deleted when the run ended. Warden keeps only the line numbers and the rule's message, for 24 hours.</span>
        </p>
        <div className="dialog-actions">
          <Button
            variant="primary"
            onClick={() => {
              setRun(null);
              start.reset();
            }}
            disabled={!finished && !gaveUp}
          >
            Change the snippet
          </Button>
        </div>
      </div>
    );
  }

  return (
    <form ref={formRef} className="form-grid" onSubmit={submit} noValidate>
      <p className="small text-2">
        Runs the rule as it is in the editor now (saved or not) against a few lines you paste, in the same sandbox as a scan.
      </p>
      <TextField
        label="File name"
        value={filename}
        maxLength={300}
        onChange={(e) => setFilename(e.target.value)}
        error={errors.filename}
        hint={tool === "opengrep" ? "Opengrep picks the language from the extension, such as app.js or main.go." : "Only for display; Gitleaks reads any file."}
        autoComplete="off"
        spellCheck={false}
        className="mono"
      />
      <div className="field">
        <label htmlFor="rule-test-snippet">Snippet</label>
        <textarea
          id="rule-test-snippet"
          className="textarea mono rule-snippet"
          value={snippet}
          onChange={(e) => setSnippet(e.target.value)}
          rows={10}
          wrap="off"
          spellCheck={false}
          autoCapitalize="none"
          autoComplete="off"
          autoCorrect="off"
          aria-invalid={errors.snippet ? true : undefined}
          aria-describedby="rule-test-snippet-h"
          data-autofocus
        />
        <span id="rule-test-snippet-h" className="hint">
          {kib(bytes)} of {kib(SNIPPET_MAX_BYTES)}. Warden deletes the snippet when the run ends and never stores it with the results.
          Don't paste a real secret: use a made-up value in the same format.
        </span>
        {errors.snippet && (
          <span className="error">
            <AlertIcon size={14} /> {errors.snippet}
          </span>
        )}
      </div>
      {startError instanceof ApiError && startError.code === "RATE_LIMITED" ? (
        <Banner tone="warning" title={TEST_RATE_LIMITED}>
          {startError.retryAfter !== undefined ? `Try again in ${waitText(startError.retryAfter)}.` : "Try again later."}
        </Banner>
      ) : startProblems.length > 0 ? (
        <Banner title="Warden can't use this rule.">
          Fix it in the editor first:{" "}
          {startProblems.map((p, i) => (
            <span key={i} className="block">
              {problemText(p)}
            </span>
          ))}
        </Banner>
      ) : (
        <ActionError error={startError} always />
      )}
      <div className="dialog-actions">
        <Button type="submit" variant="primary" busy={start.isPending}>
          Run test
        </Button>
      </div>
    </form>
  );
}

// ---- History ----

function RuleHistory({ rule }: { rule: ScanRule }) {
  const { orgId } = useOrgCtx();
  const versions = useScanRuleVersions(orgId, rule.id);
  const items = flattenPages(versions.data?.pages);
  const [from, setFrom] = useState<number | null>(null);
  const [to, setTo] = useState<number | null>(null);

  if (versions.isPending) return <SkeletonBlock label="versions" lines={5} />;
  if (versions.isError) return <ErrorState error={versions.error} onRetry={() => void versions.refetch()} what="the rule's history" />;

  const toV = items.find((v) => v.version === to) ?? items[0];
  const fromV = items.find((v) => v.version === from) ?? items[1] ?? items[0];
  const options = items.map((v) => ({ value: String(v.version), label: `Version ${v.version} · ${formatDateTime(v.created_at)}` }));

  return (
    <div className="stack" style={{ gap: 16 }}>
      <Card title="Versions" titleId="versions-h" flush>
        <ol className="rule-versions" aria-labelledby="versions-h">
          {items.map((v, i) => {
            const prev = items[i + 1] ?? null;
            const changes = prev || !versions.hasNextPage ? versionChanges(v, prev) : ["Older versions not loaded"];
            return (
              <li key={v.version} className="rule-version">
                <div className="rule-version-head">
                  <strong>Version {v.version}</strong>
                  {v.version === rule.version && <Pill tone="success">Current</Pill>}
                  <span className="muted small">
                    {v.created_by ? userName(v.created_by) : "A former member"} ·{" "}
                    <span title={formatDateTime(v.created_at)}>{relativeTime(v.created_at)}</span>
                  </span>
                </div>
                <span className="small text-2">{changes.join(" · ")}</span>
                <span className="small muted">
                  {v.enabled ? "On" : "Off"} · {scopeText(v.project_ids)} · <span className="mono">{v.sha256.slice(0, 12)}</span>
                </span>
              </li>
            );
          })}
        </ol>
        {versions.hasNextPage && (
          <div className="list-more">
            <Button size="sm" busy={versions.isFetchingNextPage} onClick={() => void versions.fetchNextPage()}>
              {versions.isFetchingNextPage ? "Loading…" : "Load older versions"}
            </Button>
          </div>
        )}
      </Card>

      {items.length > 1 && fromV && toV && (
        <Card title="Compare versions" titleId="compare-h">
          <div className="stack" style={{ gap: 12 }}>
            <div className="row rule-compare-pick">
              <Select label="From" value={String(fromV.version)} onChange={(e) => setFrom(Number(e.target.value))} options={options} />
              <Select label="To" value={String(toV.version)} onChange={(e) => setTo(Number(e.target.value))} options={options} />
            </div>
            <VersionDiff from={fromV} to={toV} />
          </div>
        </Card>
      )}
    </div>
  );
}

function VersionDiff({ from, to }: { from: ScanRuleVersion; to: ScanRuleVersion }) {
  const diff = useMemo(() => lineDiff(from.body, to.body), [from.body, to.body]);
  const stats = diffStats(diff);
  const other = versionChanges(to, from).filter((c) => c !== "Rule changed" && c !== "No change to the rule");
  return (
    <div className="stack" style={{ gap: 8 }}>
      <p className="small" role="status">
        {from.version === to.version
          ? "The same version on both sides."
          : stats.added + stats.removed === 0
            ? "The rule text is the same in both versions."
            : `${stats.added} line${stats.added === 1 ? "" : "s"} added, ${stats.removed} removed from version ${from.version} to version ${to.version}.`}
        {other.length > 0 && from.version !== to.version && <span className="muted">{` Also: ${other.join(" · ")}.`}</span>}
      </p>
      {stats.added + stats.removed > 0 && (
        <pre className="code rule-diff" aria-label={`Changes from version ${from.version} to version ${to.version}`} tabIndex={0}>
          {diff.map((l, i) => (
            <span key={i} className={`line diff-${l.type}`}>
              <span className="ln">{l.oldLine ?? ""}</span>
              <span className="ln">{l.newLine ?? ""}</span>
              <span className="diff-sign" aria-hidden="true">
                {l.type === "add" ? "+" : l.type === "del" ? "−" : " "}
              </span>
              {l.type !== "same" && <span className="visually-hidden">{l.type === "add" ? "Added: " : "Removed: "}</span>}
              <span className="txt">{l.text}</span>
            </span>
          ))}
        </pre>
      )}
    </div>
  );
}
