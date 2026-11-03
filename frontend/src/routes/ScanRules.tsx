import type { ReactNode } from "react";
import { Link, useSearchParams } from "react-router";
import { useQueryClient } from "@tanstack/react-query";
import { isApiError } from "../api/client";
import { isForbidden } from "../api/errors";
import { useScanRules, useUpdateScanRule } from "../api/hooks/scanRules";
import { qk } from "../api/keys";
import type { ScanRule, ScanRuleTool } from "../api/types";
import { SCAN_RULE_TOOLS } from "../api/types";
import { SeverityMark } from "../components/Badges";
import { ButtonLink } from "../components/Button";
import { Card } from "../components/Card";
import { LockIcon, PlusIcon, ShieldIcon } from "../components/Icons";
import { PageHeader, Segmented } from "../components/PageHeader";
import { EmptyState, ErrorState, ForbiddenState, SkeletonRows } from "../components/States";
import { Table } from "../components/Table";
import { useOrgCtx } from "../layout/OrgLayout";
import { formatDateTime, relativeTime, userName } from "../lib/format";
import { can } from "../lib/permissions";
import { orgRuleId, parseToolParam, RULES_PER_TOOL_MAX, rulesByTool, SCAN_RULE_TOOL_KIND, SCAN_RULE_TOOL_LABELS, scopeText } from "../lib/scanRules";
import { showToast } from "../lib/toast";
import { usePageTitle } from "../lib/usePageTitle";

// v0.6 wave 1: /orgs/:org/settings/scan-rules, the org's own Opengrep and Gitleaks rules
// (DESIGN.md "v0.6 screens: Scan rules"). Everyone who can see results reads the list; org
// admins and security leads (manage_rules) add, change, turn off and delete. Names and keys are
// rendered as text.

export const RULES_BASE = (orgId: string) => `/orgs/${orgId}/settings/scan-rules`;

export function ScanRulesPage() {
  usePageTitle("Scan rules");
  const { orgId, org } = useOrgCtx();
  const [params] = useSearchParams();
  const tool = parseToolParam(params.get("tool"));
  const manage = can("manage_rules", org.role);
  const list = useScanRules(orgId);
  const qc = useQueryClient();
  const toggle = useUpdateScanRule(orgId);
  const base = RULES_BASE(orgId);

  if (list.isError && isForbidden(list.error)) {
    return (
      <div className="page">
        <PageHeader title="Scan rules" />
        <div className="page-body">
          <ForbiddenState orgName={org.name} backTo={`/orgs/${orgId}/projects`} />
        </div>
      </div>
    );
  }

  const byTool = rulesByTool(list.data?.items ?? []);
  const items = byTool[tool];
  const full = items.length >= RULES_PER_TOOL_MAX;

  const setEnabled = (r: ScanRule, enabled: boolean) =>
    toggle.mutate(
      { id: r.id, body: { version: r.version, enabled } },
      {
        onSuccess: () =>
          showToast({
            tone: "success",
            message: enabled
              ? `“${r.name}” is on. It runs from the next scan.`
              : `“${r.name}” is off. Scans stop running it; the issues it found stay open.`,
          }),
        onError: (err) => {
          if (isApiError(err, "VERSION_CONFLICT")) {
            showToast({ tone: "warning", title: "Someone changed this rule.", message: `“${r.name}” changed while you had this page open. The list now shows the latest version; try again.` });
            void qc.invalidateQueries({ queryKey: qk.scanRuleList(orgId) });
          }
        },
      },
    );

  const addLink = (label: ReactNode, variant: "primary" | "ghost" = "primary", size: "sm" | "md" = "sm") =>
    manage && !full ? (
      <ButtonLink variant={variant} size={size} to={`${base}/new?tool=${tool}`}>
        <PlusIcon /> {label}
      </ButtonLink>
    ) : undefined;

  let body: ReactNode;
  if (list.isPending) body = <SkeletonRows label="scan rules" rows={4} />;
  else if (list.isError) body = <ErrorState error={list.error} onRetry={() => void list.refetch()} what="the scan rules" />;
  else if (items.length === 0)
    body = (
      <EmptyState icon={<ShieldIcon size={18} />} title={`No ${SCAN_RULE_TOOL_LABELS[tool]} rules yet`} action={addLink(`Add ${tool === "opengrep" ? "an" : "a"} ${SCAN_RULE_TOOL_LABELS[tool]} rule`, "primary", "md")}>
        <RulesExplainer tool={tool} />
      </EmptyState>
    );
  else
    body = (
      <>
        <Table
          caption={`${SCAN_RULE_TOOL_LABELS[tool]} rules`}
          head={
            <tr>
              <th>Rule</th>
              <th>Severity</th>
              <th>Runs</th>
              <th>Projects</th>
              <th>Last changed</th>
            </tr>
          }
        >
          {items.map((r) => (
            <tr key={r.id} className={r.enabled ? undefined : "row-dim"}>
              <td data-label="Rule">
                <div className="stack" style={{ gap: 2 }}>
                  <Link to={`${base}/${r.id}`} className="rule-name">
                    {r.name}
                  </Link>
                  <span className="mono faint small">{orgRuleId(r.key)}</span>
                </div>
              </td>
              <td data-label="Severity">
                <SeverityMark severity={r.severity} />
              </td>
              <td data-label="Runs">
                {manage ? (
                  <label className="switch">
                    <input
                      type="checkbox"
                      role="switch"
                      checked={r.enabled}
                      disabled={toggle.isPending && toggle.variables?.id === r.id}
                      onChange={(e) => setEnabled(r, e.target.checked)}
                    />
                    <span className="switch-track" aria-hidden="true" />
                    <span className="switch-label">
                      {r.enabled ? "On" : "Off"}
                      <span className="visually-hidden">: run {r.name} in scans</span>
                    </span>
                  </label>
                ) : (
                  <span className={r.enabled ? undefined : "muted"}>{r.enabled ? "On" : "Off"}</span>
                )}
              </td>
              <td data-label="Projects">{scopeText(r.project_ids)}</td>
              <td data-label="Last changed" className="small">
                <span title={formatDateTime(r.updated_at)}>{relativeTime(r.updated_at)}</span>
                <span className="muted"> by {r.updated_by ? userName(r.updated_by) : "a former member"}</span>
              </td>
            </tr>
          ))}
        </Table>
        <div className="table-foot">
          <span>
            {items.length} of {RULES_PER_TOOL_MAX} {SCAN_RULE_TOOL_LABELS[tool]} rules
          </span>
          {full && <span className="muted">The org has the most rules Warden allows for this scanner. Delete one to add another.</span>}
        </div>
      </>
    );

  return (
    <div className="page">
      <PageHeader title="Scan rules" actions={items.length > 0 ? addLink("Add rule") : undefined}>
        <Segmented label="Scanner">
          {SCAN_RULE_TOOLS.map((t) => (
            <Link key={t} to={`${base}?tool=${t}`} aria-current={t === tool ? "page" : undefined} className={t === tool ? "active" : undefined}>
              {SCAN_RULE_TOOL_LABELS[t]}
              {list.data && <span className="seg-count num">{byTool[t].length}</span>}
            </Link>
          ))}
        </Segmented>
      </PageHeader>
      <div className="page-body">
        {items.length > 0 && (
          <p className="faint small comp-intro">
            Your org's own {SCAN_RULE_TOOL_LABELS[tool]} rules ({SCAN_RULE_TOOL_KIND[tool]}) run in every scan of the projects they
            apply to, next to Warden's built-in rules. They only add findings: they can't ignore, allowlist or exclude anything.
          </p>
        )}
        {!manage && (
          <p className="note rules-readonly">
            <LockIcon size={14} />
            <span>Only org admins and security leads can add or change scan rules.</span>
          </p>
        )}
        <Card flush aria-label={`${SCAN_RULE_TOOL_LABELS[tool]} rules`}>
          {body}
        </Card>
      </div>
    </div>
  );
}

/** What org rules can and can't do, for the empty state. */
export function RulesExplainer({ tool }: { tool: ScanRuleTool }) {
  return (
    <span className="stack rules-explainer" style={{ gap: 8 }}>
      <span>
        {tool === "opengrep"
          ? "Opengrep rules look for code patterns your team cares about, such as a banned function or an unsafe call in your own framework."
          : "Gitleaks rules look for your own secret formats, such as internal API tokens, that the built-in rules don't know."}{" "}
        They run in every scan of the projects they apply to, and their findings become issues like any other, with the rule's id{" "}
        <span className="mono">{"org.<key>"}</span>.
      </span>
      <span>
        <strong>They only add findings.</strong> An org rule can't ignore, allowlist or exclude anything, and Warden's built-in rules
        still run. Turning a rule off or deleting it doesn't close the issues it found.
      </span>
    </span>
  );
}
