import { queryOptions, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { QueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../client";
import { ruleProblems } from "../errors";
import { qk } from "../keys";
import { useCursorList } from "../paging";
import type {
  CreateScanRuleBody,
  ItemList,
  Page,
  RuleTest,
  RuleTestRequest,
  RuleValidation,
  ScanRule,
  ScanRuleTool,
  ScanRuleVersion,
  UpdateScanRuleBody,
  ValidateRuleBody,
} from "../types";
import { CHECK_DEBOUNCE_MS, pollDecision, RULE_BODY_MAX_BYTES, utf8Length } from "../../lib/scanRules";

// v0.6 wave 1: the org's own scan rules. Reading needs view_results; every write, the check and
// the snippet test need manage_rules (org admins, security leads). API tokens can't use these.

const rulesPath = (orgId: string) => `/orgs/${encodeURIComponent(orgId)}/scan-rules`;
const rulePath = (orgId: string, id: string) => `${rulesPath(orgId)}/${encodeURIComponent(id)}`;

export function useScanRules(orgId: string, enabled = true) {
  return useQuery({
    queryKey: qk.scanRuleList(orgId),
    queryFn: ({ signal }) => api<ItemList<ScanRule>>(rulesPath(orgId), { signal }),
    enabled,
  });
}

export function useScanRule(orgId: string, id: string | undefined) {
  return useQuery({
    queryKey: qk.scanRule(orgId, id ?? ""),
    queryFn: ({ signal }) => api<ScanRule>(rulePath(orgId, id ?? ""), { signal }),
    enabled: !!id,
  });
}

/** A rule's versions, newest first, 50 at a time. */
export function useScanRuleVersions(orgId: string, id: string, enabled = true) {
  return useCursorList<Page<ScanRuleVersion>>(qk.scanRuleVersions(orgId, id), `${rulePath(orgId, id)}/versions`, { limit: 50 }, { enabled });
}

function afterChange(qc: QueryClient, orgId: string, rule: ScanRule) {
  qc.setQueryData(qk.scanRule(orgId, rule.id), rule);
  return Promise.all([
    qc.invalidateQueries({ queryKey: qk.scanRuleList(orgId) }),
    qc.invalidateQueries({ queryKey: qk.scanRuleVersions(orgId, rule.id) }),
  ]);
}

export function useCreateScanRule(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateScanRuleBody) => api<ScanRule>(rulesPath(orgId), { method: "POST", body }),
    onSuccess: (rule) => afterChange(qc, orgId, rule),
  });
}

/** PATCH with the version that was read. VERSION_CONFLICT is shown by the page (a banner on the
 *  editor, a toast on the list's switch), never retried. */
export function useUpdateScanRule(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: UpdateScanRuleBody }) => api<ScanRule>(rulePath(orgId, id), { method: "PATCH", body }),
    onSuccess: (rule) => afterChange(qc, orgId, rule),
  });
}

export function useDeleteScanRule(orgId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, version }: { id: string; version: number }) => api<void>(rulePath(orgId, id), { method: "DELETE", query: { version } }),
    onSuccess: (_d, { id }) => {
      qc.removeQueries({ queryKey: qk.scanRule(orgId, id) });
      return qc.invalidateQueries({ queryKey: qk.scanRuleList(orgId) });
    },
  });
}

export function validateRule(orgId: string, body: ValidateRuleBody, signal?: AbortSignal): Promise<RuleValidation> {
  return api<RuleValidation>(`${rulesPath(orgId)}/validate`, { method: "POST", body, signal });
}

export type RuleCheck =
  | { status: "idle" }
  | { status: "checking"; body: string; result?: RuleValidation }
  | { status: "done"; body: string; result: RuleValidation }
  | { status: "error"; body: string; error: unknown };

/** The live "Check": POST …/validate a moment after typing stops, and on demand (before a save).
 *  An older answer never replaces a newer one (each request aborts the one before). The check
 *  isn't cached anywhere: it lives in the editor's state. */
export function useRuleCheck(orgId: string, tool: ScanRuleTool, body: string, enabled: boolean) {
  const [check, setCheck] = useState<RuleCheck>({ status: "idle" });
  const ctrl = useRef<AbortController | null>(null);
  const last = useRef<RuleCheck>(check);
  last.current = check;

  const run = useCallback(
    async (text: string): Promise<RuleValidation | null> => {
      ctrl.current?.abort();
      const c = new AbortController();
      ctrl.current = c;
      setCheck((prev) => ({ status: "checking", body: text, result: prev.status === "done" ? prev.result : undefined }));
      try {
        const result = await validateRule(orgId, { tool, body: text }, c.signal);
        if (c.signal.aborted) return null;
        setCheck({ status: "done", body: text, result });
        return result;
      } catch (error) {
        if (c.signal.aborted) return null;
        // The check answers 200 with ok:false, but a 422 RULE_INVALID carries the same problems.
        const problems = ruleProblems(error);
        if (problems.length) {
          const result: RuleValidation = { ok: false, key: null, severity: null, body: null, problems };
          setCheck({ status: "done", body: text, result });
          return result;
        }
        setCheck({ status: "error", body: text, error });
        return null;
      }
    },
    [orgId, tool],
  );

  useEffect(() => {
    if (!enabled) return;
    if (!body.trim() || utf8Length(body) > RULE_BODY_MAX_BYTES) {
      ctrl.current?.abort();
      setCheck({ status: "idle" });
      return;
    }
    const cur = last.current;
    if (cur.status !== "idle" && cur.body === body) return;
    const t = setTimeout(() => void run(body), CHECK_DEBOUNCE_MS);
    return () => clearTimeout(t);
  }, [body, enabled, run]);

  useEffect(() => () => ctrl.current?.abort(), []);

  return { check, checkNow: run };
}

/** Options for starting a snippet test.
 *
 *  The snippet is code someone pasted to try a rule: it may hold real code or secrets. It is
 *  sent once and kept only in the test dialog's state, dropped when the dialog closes. Like a
 *  webhook URL (hooks/webhooks.ts), the request reaches the mutation through a closure, not as
 *  mutation variables (TanStack Query keeps those in its MutationCache), and the result (lines
 *  and messages, never matched text) is the only thing cached. scanRules.test.ts checks it. */
export function ruleTestMutation(qc: QueryClient, orgId: string, request: () => RuleTestRequest) {
  return {
    mutationFn: async (): Promise<RuleTest> => {
      const t = await api<RuleTest>(`${rulesPath(orgId)}/tests`, { method: "POST", body: request() });
      qc.setQueryData(qk.ruleTest(orgId, t.id), t);
      return t;
    },
    // The dialog shows the 429 and every other failure in place (App.tsx skips the toast).
    meta: { inlineErrors: true },
  };
}

export function useStartRuleTest(orgId: string, request: () => RuleTestRequest) {
  const qc = useQueryClient();
  return useMutation(ruleTestMutation(qc, orgId, request));
}

/** A test's state, polled with backoff (1, 2, 3, then 5 s) until it is done or failed, or for
 *  at most 3 minutes (lib/scanRules.ts pollDecision). */
export function useRuleTest(orgId: string, testId: string | null, startedAt: number) {
  return useQuery(ruleTestQuery(orgId, testId, startedAt));
}

/** The query behind useRuleTest (exported for scanRules.test.ts). */
export function ruleTestQuery(orgId: string, testId: string | null, startedAt: number) {
  return queryOptions({
    queryKey: qk.ruleTest(orgId, testId ?? ""),
    queryFn: ({ signal }) => api<RuleTest>(`${rulesPath(orgId)}/tests/${encodeURIComponent(testId ?? "")}`, { signal }),
    enabled: !!testId,
    // Results belong to the dialog: dropped soon after it closes.
    gcTime: 0,
    staleTime: 0,
    refetchInterval: (q) => {
      const d = pollDecision(q.state.data, startedAt, Date.now(), Math.max(0, q.state.dataUpdateCount - 1));
      return "poll" in d ? d.poll : false;
    },
  });
}
