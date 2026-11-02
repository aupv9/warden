import { useEffect, useId, useReducer, useRef, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { fieldErrors } from "../api/errors";
import {
  useCreateWebhook,
  useDeleteWebhook,
  useRotateSecret,
  useSetWebhookEnabled,
  useTestWebhook,
  useUpdateWebhook,
  useWebhookDeliveries,
  useWebhooks,
} from "../api/hooks/webhooks";
import { useProjects } from "../api/hooks/projects";
import { qk } from "../api/keys";
import { flattenPages } from "../api/paging";
import { WEBHOOK_EVENT_TYPES } from "../api/types";
import type { CreateWebhookBody, Project, Severity, UpdateWebhookBody, Webhook, WebhookDelivery, WebhookEventType, WebhookKind } from "../api/types";
import { DotMark, Pill } from "../components/Badges";
import { Button } from "../components/Button";
import { Card } from "../components/Card";
import { CopyButton } from "../components/CopyButton";
import { Dialog } from "../components/Dialog";
import { focusFirstInvalid, Select, TextField } from "../components/Field";
import { AlertIcon, CloseIcon, IntegrationsIcon, LockIcon, PlusIcon, SendIcon } from "../components/Icons";
import { PageHeader } from "../components/PageHeader";
import { Popover } from "../components/Popover";
import { ActionError, Banner, EmptyState, ErrorState, ForbiddenState, SkeletonBlock, SkeletonRows } from "../components/States";
import { useOrgCtx } from "../layout/OrgLayout";
import { formatDateTime, relativeTime, userName } from "../lib/format";
import { can } from "../lib/permissions";
import { showToast } from "../lib/toast";
import { useIsPhone, useIsWide } from "../lib/useMediaQuery";
import { usePageTitle } from "../lib/usePageTitle";
import {
  createBody,
  DELIVERY_POLL_FOR_MS,
  DELIVERY_POLL_MS,
  deliveryErrorText,
  deliveryTypeLabel,
  eventsText,
  formFromWebhook,
  INITIAL_SECRET_DIALOG,
  ISSUE_EVENTS,
  lastDeliveryText,
  minSeverityText,
  NEW_WEBHOOK_FORM,
  projectsText,
  secretDialogReducer,
  SEVERITY_OPTIONS,
  SLACK_URL_PREFIX,
  updateBody,
  validateWebhookForm,
  WEBHOOK_EVENT_LABELS,
  WEBHOOK_KIND_LABELS,
  WEBHOOK_MAX,
  WEBHOOK_NAME_MAX,
  WEBHOOK_PROJECTS_MAX,
  WEBHOOK_URL_MAX,
  webhookFieldErrors,
  webhookState,
} from "../lib/webhooks";
import type { WebhookForm } from "../lib/webhooks";

// v0.4 wave 2: /orgs/:org/integrations, webhooks and Slack channels (DESIGN.md "Wave 2:
// integrations"). Org admins and security leads only (manage_integrations): members don't see
// the navigation entry, and this page never calls the API for them.
//
// Security rules: a webhook URL is typed once (create, or a replacement on edit) and never read
// back, so the list shows `url_hint` as text, never as a link. A signing secret is shown once,
// held in the dialog's component state only and dropped when the dialog closes (hooks/webhooks.ts
// keeps it out of TanStack Query's caches; webhooks.test.ts checks it). Names, hints and error
// words are rendered as text.

const README_NOTIFICATIONS = "https://github.com/aupv9/warden#notifications";

export function IntegrationsPage() {
  usePageTitle("Integrations");
  const { orgId, org } = useOrgCtx();
  const allowed = can("manage_integrations", org.role);
  if (!allowed) {
    return (
      <div className="page">
        <PageHeader title="Integrations" />
        <div className="page-body">
          <ForbiddenState orgName={org.name} backTo={`/orgs/${orgId}/projects`} />
        </div>
      </div>
    );
  }
  return <Integrations />;
}

type DialogState =
  | { type: "add" }
  | { type: "edit"; webhook: Webhook }
  | { type: "rotate"; webhook: Webhook }
  | { type: "delete"; webhook: Webhook }
  | null;

function Integrations() {
  const { orgId, org } = useOrgCtx();
  const qc = useQueryClient();
  const list = useWebhooks(orgId);
  const projects = useProjects(orgId);
  const wide = useIsWide();
  const phone = useIsPhone();
  const [dialog, setDialog] = useState<DialogState>(null);
  const [logFor, setLogFor] = useState<string | null>(null);
  const [pollUntil, setPollUntil] = useState<number | null>(null);
  const test = useTestWebhook(orgId);
  const toggle = useSetWebhookEnabled(orgId);
  const listRef = useRef<HTMLUListElement>(null);
  const panelId = useId();

  // The delivery log polls for a minute after "Send test", then stops.
  useEffect(() => {
    if (pollUntil === null) return;
    const t = setTimeout(() => setPollUntil(null), Math.max(0, pollUntil - Date.now()));
    return () => clearTimeout(t);
  }, [pollUntil]);

  const items = list.data?.items ?? [];
  const available = list.data?.available ?? true;
  const logHook = items.find((w) => w.id === logFor) ?? null;
  // A deleted webhook closes its log.
  useEffect(() => {
    if (logFor && list.data && !logHook) setLogFor(null);
  }, [logFor, list.data, logHook]);

  const closeLog = () => {
    const id = logFor;
    setLogFor(null);
    setPollUntil(null);
    if (id) listRef.current?.querySelector<HTMLElement>(`[data-log="${CSS.escape(id)}"]`)?.focus();
  };
  const openLog = (id: string) => {
    if (id !== logFor) setPollUntil(null);
    setLogFor(id);
  };

  const sendTest = (w: Webhook) =>
    test.mutate(w.id, {
      onSuccess: () => {
        showToast({ tone: "success", message: `Test sent to the queue for “${w.name}”. The delivery log shows the result.` });
        setLogFor(w.id);
        setPollUntil(Date.now() + DELIVERY_POLL_FOR_MS);
      },
    });

  const setEnabled = (w: Webhook, enabled: boolean) =>
    toggle.mutate(
      { id: w.id, enabled },
      {
        onSuccess: () =>
          showToast({
            tone: "success",
            message: enabled ? `“${w.name}” is on again.${w.disabled_reason === "failures" ? " Its failure count was reset." : ""}` : `“${w.name}” is turned off. Nothing is sent until you turn it on.`,
          }),
      },
    );

  const full = items.length >= WEBHOOK_MAX;
  const addButton =
    list.data && available ? (
      <Button variant="primary" size="sm" onClick={() => setDialog({ type: "add" })} disabled={full} aria-describedby={full ? "hooks-full" : undefined}>
        <PlusIcon /> Add
      </Button>
    ) : undefined;

  let body: ReactNode;
  if (list.isPending) body = <SkeletonRows label="webhooks" rows={3} />;
  else if (list.isError) body = <ErrorState error={list.error} onRetry={() => void list.refetch()} what="integrations" />;
  else if (!available) body = null;
  else if (items.length === 0)
    body = (
      <EmptyState
        icon={<IntegrationsIcon size={18} />}
        title="No webhooks or Slack channels yet"
        action={
          <Button variant="primary" onClick={() => setDialog({ type: "add" })}>
            <PlusIcon /> Add a webhook or Slack channel
          </Button>
        }
      >
        Send scan results, assignments, exception requests and malicious-package alerts to a Slack channel or to your own endpoint.
      </EmptyState>
    );
  else
    body = (
      <>
        <ul className="hook-list" ref={listRef} aria-label="Webhooks and Slack channels">
          {items.map((w) => (
            <HookRow
              key={w.id}
              w={w}
              projects={projects.data}
              logOpen={logFor === w.id}
              panelId={wide ? panelId : undefined}
              testing={test.isPending && test.variables === w.id}
              toggling={toggle.isPending && toggle.variables?.id === w.id}
              onLog={() => (logFor === w.id ? closeLog() : openLog(w.id))}
              onTest={() => sendTest(w)}
              onEdit={() => setDialog({ type: "edit", webhook: w })}
              onRotate={() => setDialog({ type: "rotate", webhook: w })}
              onDelete={() => setDialog({ type: "delete", webhook: w })}
              onEnable={(on) => setEnabled(w, on)}
            />
          ))}
        </ul>
        <div className="table-foot">
          <span>
            {items.length} of {WEBHOOK_MAX}
          </span>
          {full && (
            <span id="hooks-full" className="muted">
              The org has the most webhooks Warden allows. Delete one to add another.
            </span>
          )}
        </div>
      </>
    );

  const pollMs = pollUntil !== null ? DELIVERY_POLL_MS : false;

  return (
    <div className="page">
      <PageHeader title="Integrations" actions={addButton} />
      <div className="page-body">
        <p className="faint small comp-intro">
          Webhooks and Slack channels hear about events in {org.name}: finished scans, assignments, reopened issues, exception requests
          and decisions, and malicious packages. They get keys, titles, severities, statuses and links; never code, descriptions,
          comments, email addresses or secrets.
        </p>
        {list.data && !available ? (
          <Banner tone="warning" title="Webhooks are turned off on this server.">
            Warden stores webhook URLs and signing secrets encrypted, and this server has no key for that. Your operator must set{" "}
            <code>WARDEN_SECRETS__KEY</code> (README{" "}
            <a href={README_NOTIFICATIONS} target="_blank" rel="noopener noreferrer">
              “Notifications”
              <span className="visually-hidden"> (opens in a new tab)</span>
            </a>
            ). Existing webhooks aren't sent until then.
          </Banner>
        ) : (
          <div className={logHook && wide ? "comp-split with-panel" : "comp-split"}>
            <Card flush className="comp-list" aria-label="Webhooks and Slack channels">
              {body}
            </Card>
            {logHook && wide && (
              <aside id={panelId} className="card comp-panel hook-panel" aria-label={`Delivery log of ${logHook.name}`}>
                <DeliveryLog webhook={logHook} pollMs={pollMs} onClose={closeLog} autoFocus onPolled={() => void qc.invalidateQueries({ queryKey: qk.webhooks(orgId) })} />
              </aside>
            )}
          </div>
        )}
      </div>

      <Dialog open={!!logHook && !wide} onClose={closeLog} title="Delivery log" className={phone ? "dialog sheet" : "dialog used-in-dialog"}>
        {logHook && <DeliveryLog webhook={logHook} pollMs={pollMs} onPolled={() => void qc.invalidateQueries({ queryKey: qk.webhooks(orgId) })} />}
      </Dialog>

      <Dialog
        open={dialog?.type === "add" || dialog?.type === "edit"}
        onClose={() => setDialog(null)}
        title={dialog?.type === "edit" ? `Edit “${dialog.webhook.name}”` : "Add a webhook or Slack channel"}
      >
        {(dialog?.type === "add" || dialog?.type === "edit") && (
          <WebhookFormDialog webhook={dialog.type === "edit" ? dialog.webhook : null} projects={projects.data ?? []} onDone={() => setDialog(null)} />
        )}
      </Dialog>
      <Dialog open={dialog?.type === "rotate"} onClose={() => setDialog(null)} title="Rotate the signing secret?">
        {dialog?.type === "rotate" && <RotateDialog webhook={dialog.webhook} onDone={() => setDialog(null)} />}
      </Dialog>
      <Dialog open={dialog?.type === "delete"} onClose={() => setDialog(null)} title={dialog?.type === "delete" ? `Delete “${dialog.webhook.name}”?` : "Delete?"}>
        {dialog?.type === "delete" && <DeleteDialog webhook={dialog.webhook} onDone={() => setDialog(null)} />}
      </Dialog>
    </div>
  );
}

function HookRow({
  w,
  projects,
  logOpen,
  panelId,
  testing,
  toggling,
  onLog,
  onTest,
  onEdit,
  onRotate,
  onDelete,
  onEnable,
}: {
  w: Webhook;
  projects: Project[] | undefined;
  logOpen: boolean;
  panelId?: string;
  testing: boolean;
  toggling: boolean;
  onLog: () => void;
  onTest: () => void;
  onEdit: () => void;
  onRotate: () => void;
  onDelete: () => void;
  onEnable: (on: boolean) => void;
}) {
  const state = webhookState(w);
  const projectNames = w.project_ids.map((id) => projects?.find((p) => p.id === id)?.key ?? "a project you can't see");
  const last = w.last_delivery;
  return (
    <li className={logOpen ? "hook-row selected" : "hook-row"}>
      <div className="hook-main">
        <div className="hook-title">
          <strong className="hook-name">{w.name}</strong>
          <Pill>{WEBHOOK_KIND_LABELS[w.kind]}</Pill>
          <DotMark tone={state.tone}>{state.tone === "danger" ? <span className="danger-text">{state.text}</span> : state.text}</DotMark>
        </div>
        {/* The URL's scheme and host only, as text: never a link (for Slack the URL is the credential). */}
        <span className="mono faint small hook-hint">{w.url_hint}</span>
        <span className="small text-2 hook-meta">
          {eventsText(w.events)}
          {" · "}
          <span title={projectNames.length ? projectNames.join(", ") : undefined}>{projectsText(w.project_ids)}</span>
          {w.events.some((e) => ISSUE_EVENTS.includes(e)) && <> · {minSeverityText(w.min_severity)}</>}
        </span>
        <span className={last?.state === "failed" ? "small danger-text" : "small muted"} title={last ? formatDateTime(last.at) : undefined}>
          {lastDeliveryText(w)}
          {w.consecutive_failures > 1 && w.enabled && <> · {w.consecutive_failures} failures in a row</>}
        </span>
        {w.disabled_reason === "failures" && !w.enabled && (
          <span className="small text-2">
            Warden stopped sending after {w.consecutive_failures > 0 ? `${w.consecutive_failures} failed deliveries in a row` : "repeated failed deliveries"}.
            Check the delivery log, fix the endpoint, then turn it on again.
          </span>
        )}
      </div>
      <div className="hook-actions">
        {w.disabled_reason === "failures" && !w.enabled && (
          <Button size="sm" variant="primary" busy={toggling} onClick={() => onEnable(true)}>
            Turn on again
          </Button>
        )}
        <Button size="sm" data-log={w.id} aria-expanded={logOpen} aria-controls={logOpen ? panelId : undefined} onClick={onLog}>
          Delivery log
          <span className="visually-hidden"> of {w.name}</span>
        </Button>
        <Button size="sm" busy={testing} onClick={onTest}>
          <SendIcon /> Send test
          <span className="visually-hidden"> to {w.name}</span>
        </Button>
        <Button size="sm" onClick={onEdit}>
          Edit
          <span className="visually-hidden"> {w.name}</span>
        </Button>
        <Popover
          align="end"
          buttonClassName="btn btn-ghost btn-sm hook-more"
          buttonLabel={`More actions for ${w.name}`}
          panelLabel={`More actions for ${w.name}`}
          button={<span aria-hidden="true">…</span>}
        >
          {(close) => (
            <ul className="menu-list" aria-label={`More actions for ${w.name}`}>
              {w.enabled ? (
                <li>
                  <button
                    type="button"
                    className="menu-item"
                    onClick={() => {
                      close();
                      onEnable(false);
                    }}
                  >
                    <span className="grow">Turn off</span>
                  </button>
                </li>
              ) : (
                w.disabled_reason !== "failures" && (
                  <li>
                    <button
                      type="button"
                      className="menu-item"
                      onClick={() => {
                        close();
                        onEnable(true);
                      }}
                    >
                      <span className="grow">Turn on</span>
                    </button>
                  </li>
                )
              )}
              {w.kind === "generic" && (
                <li>
                  <button
                    type="button"
                    className="menu-item"
                    onClick={() => {
                      close(false);
                      onRotate();
                    }}
                  >
                    <span className="grow">Rotate secret…</span>
                  </button>
                </li>
              )}
              <li>
                <button
                  type="button"
                  className="menu-item danger-text"
                  onClick={() => {
                    close(false);
                    onDelete();
                  }}
                >
                  <span className="grow">Delete…</span>
                </button>
              </li>
            </ul>
          )}
        </Popover>
      </div>
    </li>
  );
}

// ---- Delivery log ----

function deliveryState(d: WebhookDelivery): { tone: "success" | "danger" | "accent"; text: string } {
  if (d.state === "delivered") return { tone: "success", text: "Delivered" };
  if (d.state === "failed") return { tone: "danger", text: "Failed" };
  return { tone: "accent", text: d.next_attempt_at ? `Pending · next attempt ${relativeFuture(d.next_attempt_at)}` : "Pending" };
}

function relativeFuture(ts: string, now: Date = new Date()): string {
  const diff = Date.parse(ts) - now.getTime();
  if (!Number.isFinite(diff) || diff <= 30_000) return "now";
  if (diff < 3_600_000) return `in ${Math.ceil(diff / 60_000)} min`;
  if (diff < 86_400_000) return `in ${Math.round(diff / 3_600_000)} h`;
  return formatDateTime(ts);
}

export function DeliveryLog({
  webhook: w,
  pollMs,
  onClose,
  autoFocus,
  onPolled,
}: {
  webhook: Webhook;
  pollMs: number | false;
  onClose?: () => void;
  autoFocus?: boolean;
  onPolled?: () => void;
}) {
  const { orgId } = useOrgCtx();
  const log = useWebhookDeliveries(orgId, w.id, pollMs);
  const items = flattenPages(log.data?.pages);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const headingId = useId();
  useEffect(() => {
    if (autoFocus) headingRef.current?.focus({ preventScroll: true });
  }, [autoFocus, w.id]);
  // While polling, the list's "last delivery" follows the log.
  const polled = useRef(onPolled);
  polled.current = onPolled;
  useEffect(() => {
    if (pollMs && log.dataUpdatedAt) polled.current?.();
  }, [pollMs, log.dataUpdatedAt]);

  return (
    <div className="used-in hook-log">
      <div className="used-in-head">
        <div className="stack" style={{ gap: 4, minWidth: 0 }}>
          {onClose && <p className="faint small">Delivery log</p>}
          <h2 id={headingId} className="used-in-title" ref={headingRef} tabIndex={-1}>
            {w.name}
          </h2>
          <p className="muted small">Newest first, the last 30 days. Warden doesn't keep response bodies.</p>
        </div>
        {onClose && (
          <button type="button" className="icon-btn sm" aria-label="Close the delivery log" onClick={onClose}>
            <CloseIcon />
          </button>
        )}
      </div>
      <p className="small muted" role="status" aria-live="polite">
        {pollMs ? "Checking for new deliveries every 5 seconds…" : ""}
      </p>
      {log.isPending ? (
        <SkeletonBlock label="deliveries" lines={4} height={36} />
      ) : log.isError ? (
        <ErrorState error={log.error} onRetry={() => void log.refetch()} what="the delivery log" />
      ) : items.length === 0 ? (
        <p className="muted">No deliveries in the last 30 days. Send a test to see one here.</p>
      ) : (
        <>
          <ul className="usage-list delivery-list" aria-labelledby={headingId}>
            {items.map((d) => (
              <DeliveryItem key={d.id} d={d} />
            ))}
          </ul>
          {log.hasNextPage && (
            <div className="list-more">
              <Button size="sm" busy={log.isFetchingNextPage} onClick={() => void log.fetchNextPage()}>
                {log.isFetchingNextPage ? "Loading…" : "Load older"}
              </Button>
            </div>
          )}
        </>
      )}
    </div>
  );
}

function DeliveryItem({ d }: { d: WebhookDelivery }) {
  const state = deliveryState(d);
  const error = deliveryErrorText(d);
  return (
    <li className="usage-item delivery-item">
      <span className="usage-project">
        <span className="grow">{deliveryTypeLabel(d.type)}</span>
        <DotMark tone={state.tone}>{state.text}</DotMark>
      </span>
      <span className="small muted">
        <span title={formatDateTime(d.created_at)}>{relativeTime(d.created_at)}</span>
        {" · "}
        {d.attempts} attempt{d.attempts === 1 ? "" : "s"}
        {d.status_code !== null && <> · HTTP {d.status_code}</>}
      </span>
      {error && <span className={d.state === "failed" ? "small danger-text" : "small text-2"}>{error}</span>}
    </li>
  );
}

// ---- Add / edit ----

function WebhookFormDialog({ webhook, projects, onDone }: { webhook: Webhook | null; projects: Project[]; onDone: () => void }) {
  const { orgId } = useOrgCtx();
  const editing = !!webhook;
  const [form, setForm] = useState<WebhookForm>(() => (webhook ? formFromWebhook(webhook) : NEW_WEBHOOK_FORM));
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [secret, dispatch] = useReducer(secretDialogReducer, INITIAL_SECRET_DIALOG);
  const formRef = useRef<HTMLFormElement>(null);
  // The request body (with the URL) is handed to the mutation through these refs, never as
  // mutation variables: TanStack Query keeps variables in its MutationCache.
  const createRef = useRef<CreateWebhookBody | null>(null);
  const updateRef = useRef<UpdateWebhookBody | null>(null);
  const create = useCreateWebhook(
    orgId,
    () => createRef.current!,
    (s, w) => dispatch({ type: "secret", secret: s, webhook: w }),
  );
  const update = useUpdateWebhook(orgId, webhook?.id ?? "", () => updateRef.current!);
  const mutation = editing ? update : create;
  const id = useId();

  const close = () => {
    dispatch({ type: "close" });
    createRef.current = null;
    updateRef.current = null;
    onDone();
  };

  if (secret.secret && secret.webhook) {
    return <ShowSecretOnce secret={secret.secret} name={secret.webhook.name} created onDone={close} />;
  }

  const server = webhookFieldErrors(fieldErrors(mutation.error));
  const shown = { ...server.byField, ...errors };
  const set = (patch: Partial<WebhookForm>) => setForm((f) => ({ ...f, ...patch }));

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const v = validateWebhookForm(form, editing);
    setErrors(v);
    if (Object.keys(v).length) {
      focusFirstInvalid(formRef.current);
      return;
    }
    if (webhook) {
      const b = updateBody(form, webhook);
      if (!b) {
        close();
        return;
      }
      updateRef.current = b;
      update.mutate(undefined, {
        onSuccess: (w) => {
          showToast({ tone: "success", message: `“${w.name}” saved.${b.url ? " The new URL is used from the next delivery." : ""}` });
          close();
        },
        onError: () => focusFirstInvalid(formRef.current),
      });
    } else {
      createRef.current = createBody(form);
      create.mutate(undefined, {
        onSuccess: (w) => {
          createRef.current = null;
          // A generic webhook's secret was handed to the dialog's state (shown next); Slack has none.
          if (w.kind === "slack") {
            showToast({ tone: "success", message: `Slack channel “${w.name}” added. Send a test to check it.` });
            close();
          } else {
            showToast({ tone: "success", message: `Webhook “${w.name}” added.` });
          }
        },
        onError: () => focusFirstInvalid(formRef.current),
      });
    }
  };

  const kind = form.kind;
  const issueEvents = form.events.some((e) => ISSUE_EVENTS.includes(e));

  return (
    <form ref={formRef} className="form-grid" onSubmit={submit} noValidate>
      {editing ? (
        <p className="small text-2">
          Type: <strong>{WEBHOOK_KIND_LABELS[kind]}</strong> <span className="muted">(can't be changed)</span>
        </p>
      ) : (
        <fieldset>
          <legend>Type</legend>
          <div className="choices">
            {(["slack", "generic"] as WebhookKind[]).map((k) => (
              <label key={k} className="choice-card">
                <input type="radio" name={`${id}-kind`} checked={kind === k} onChange={() => set({ kind: k })} />
                <span>
                  <strong>{k === "slack" ? "Slack channel" : "Webhook"}</strong>
                  <span className="desc">
                    {k === "slack"
                      ? "A Slack incoming webhook. Warden posts a short message per event."
                      : "A signed JSON POST to your endpoint (Standard Webhooks), for a chat relay, a ticket system or your own service."}
                  </span>
                </span>
              </label>
            ))}
          </div>
        </fieldset>
      )}
      <TextField
        label="Name"
        value={form.name}
        maxLength={WEBHOOK_NAME_MAX + 20}
        onChange={(e) => set({ name: e.target.value })}
        error={shown.name}
        hint={kind === "slack" ? "Say which channel, such as “#security-alerts”." : "Say what it feeds, such as “Ticket relay”."}
        autoComplete="off"
      />
      <TextField
        label={editing ? "New URL (optional)" : kind === "slack" ? "Slack webhook URL" : "Endpoint URL"}
        type="url"
        inputMode="url"
        value={form.url}
        maxLength={WEBHOOK_URL_MAX + 1}
        onChange={(e) => set({ url: e.target.value })}
        error={shown.url}
        placeholder={kind === "slack" ? `${SLACK_URL_PREFIX}…` : "https://"}
        autoComplete="off"
        autoCapitalize="none"
        spellCheck={false}
        className="mono"
        hint={
          editing
            ? `Enter a new URL to replace it. Warden never shows the stored URL (it now goes to ${webhook!.url_hint}).`
            : kind === "slack"
              ? "From Slack: Apps › Incoming Webhooks. The URL is the credential: anyone with it can post to the channel, so Warden stores it encrypted and never shows it again."
              : "https only. Warden signs every request, doesn't follow redirects, and refuses hosts that resolve to private addresses."
        }
      />
      <fieldset aria-describedby={shown.events ? `${id}-events-e` : undefined}>
        <legend>Events</legend>
        <div className="checks-grid">
          {WEBHOOK_EVENT_TYPES.map((ev) => (
            <label key={ev} className="checkbox-card">
              <input
                type="checkbox"
                checked={form.events.includes(ev)}
                aria-invalid={shown.events ? true : undefined}
                onChange={(e) => set({ events: e.target.checked ? WEBHOOK_EVENT_TYPES.filter((x) => x === ev || form.events.includes(x)) : form.events.filter((x) => x !== ev) })}
              />
              <span>{WEBHOOK_EVENT_LABELS[ev as WebhookEventType]}</span>
            </label>
          ))}
        </div>
        {shown.events && (
          <span id={`${id}-events-e`} className="field-error">
            <AlertIcon size={14} /> {shown.events}
          </span>
        )}
      </fieldset>
      <ProjectPicker
        projects={projects}
        all={form.allProjects}
        selected={form.projectIds}
        error={shown.project_ids}
        onChange={(allProjects, projectIds) => set({ allProjects, projectIds })}
      />
      <Select
        label="Minimum severity"
        value={form.minSeverity}
        onChange={(e) => set({ minSeverity: e.target.value as Severity | "" })}
        options={SEVERITY_OPTIONS}
        error={shown.min_severity}
        hint={
          issueEvents
            ? "For Issue assigned, Issue reopened and Malicious package found. Other events are always sent."
            : "Only applies to issue events (none chosen)."
        }
      />
      <p className="note">
        <LockIcon size={14} />
        <span>
          What is sent: keys, titles, severities, statuses and links back to Warden. Never code, descriptions, comments, email
          addresses or secrets.
        </span>
      </p>
      <ActionError
        error={mutation.error}
        // WEBHOOK_LIMIT and SECRETS_KEY_MISSING (409) have their own words in api/errors.ts.
        overrides={{ VALIDATION_FAILED: "Some fields need attention." }}
      />
      {server.leftover.map((m) => (
        <div key={m} className="banner banner-error" role="alert">
          {m}
        </div>
      ))}
      <div className="dialog-actions">
        <Button onClick={close} disabled={mutation.isPending}>
          Cancel
        </Button>
        <Button type="submit" variant="primary" busy={mutation.isPending}>
          {editing ? "Save changes" : kind === "slack" ? "Add Slack channel" : "Add webhook"}
        </Button>
      </div>
    </form>
  );
}

function ProjectPicker({
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
  // A project the caller can no longer see stays selected (and counted) but unnamed.
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
            <span className="desc">Up to {WEBHOOK_PROJECTS_MAX}. Events from other projects aren't sent.</span>
          </span>
        </label>
        {!all && (
          <div className="hook-projects" role="group" aria-label="Projects to send">
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
        {!all && (
          <span className="hint">
            {selected.length} of {WEBHOOK_PROJECTS_MAX} chosen
          </span>
        )}
      </div>
      {error && (
        <span id={`${id}-e`} className="field-error">
          <AlertIcon size={14} /> {error}
        </span>
      )}
    </fieldset>
  );
}

// ---- The signing secret, shown once ----

function ShowSecretOnce({ secret, name, created, onDone }: { secret: string; name: string; created?: boolean; onDone: () => void }) {
  const ref = useRef<HTMLTextAreaElement>(null);
  // The form (or the confirm text) that had focus is gone: focus the secret so it can be copied.
  useEffect(() => ref.current?.focus(), []);
  return (
    <div className="form-grid">
      <Banner tone="warning" title="Copy the signing secret now.">
        This is the only time Warden shows it. Warden keeps it encrypted and can't show it again: if it is lost, rotate the secret.
      </Banner>
      <div className="field">
        <label htmlFor="webhook-secret">{created ? `Signing secret for “${name}”` : `New signing secret for “${name}”`}</label>
        <div className="secret-row">
          <textarea
            id="webhook-secret"
            ref={ref}
            className="textarea mono secret-input"
            value={secret}
            readOnly
            rows={2}
            autoComplete="off"
            spellCheck={false}
            data-autofocus
            onFocus={(e) => e.currentTarget.select()}
          />
          <CopyButton text={secret} label="Copy" size="md" copiedText="Signing secret copied to the clipboard." onFailed={() => ref.current?.select()} />
        </div>
        <span className="hint">
          Store it where your endpoint reads its configuration. Each request carries the <code>webhook-id</code>,{" "}
          <code>webhook-timestamp</code> and <code>webhook-signature</code> headers (Standard Webhooks): check the HMAC-SHA256 of{" "}
          <code>id.timestamp.body</code> with this secret, and reject timestamps more than 5 minutes off. See README{" "}
          <a href={README_NOTIFICATIONS} target="_blank" rel="noopener noreferrer">
            “Notifications”
            <span className="visually-hidden"> (opens in a new tab)</span>
          </a>
          .
        </span>
      </div>
      <div className="dialog-actions">
        <Button variant="primary" onClick={onDone}>
          Done
        </Button>
      </div>
    </div>
  );
}

function RotateDialog({ webhook: w, onDone }: { webhook: Webhook; onDone: () => void }) {
  const { orgId } = useOrgCtx();
  const [secret, dispatch] = useReducer(secretDialogReducer, INITIAL_SECRET_DIALOG);
  const rotate = useRotateSecret(orgId, w.id, (s) => dispatch({ type: "secret", secret: s, webhook: w }));
  const close = () => {
    dispatch({ type: "close" });
    onDone();
  };
  if (secret.secret && secret.webhook) return <ShowSecretOnce secret={secret.secret} name={secret.webhook.name} onDone={close} />;
  return (
    <div className="form-grid">
      <p>
        Rotate the signing secret of <strong>{w.name}</strong>? The old secret stops working at once: every delivery after this is
        signed with the new one only, so update your endpoint right away.
      </p>
      <ActionError error={rotate.error} />
      <div className="dialog-actions">
        <Button onClick={close} disabled={rotate.isPending}>
          Cancel
        </Button>
        <Button
          variant="danger"
          busy={rotate.isPending}
          onClick={() => rotate.mutate(undefined, { onSuccess: () => showToast({ tone: "success", message: `New signing secret for “${w.name}”.` }) })}
        >
          Rotate secret
        </Button>
      </div>
    </div>
  );
}

function DeleteDialog({ webhook: w, onDone }: { webhook: Webhook; onDone: () => void }) {
  const { orgId } = useOrgCtx();
  const del = useDeleteWebhook(orgId);
  return (
    <div className="form-grid">
      <p>
        Delete <strong>{w.name}</strong> <span className="mono faint">({w.url_hint})</span>? Its delivery log is deleted too, and
        pending deliveries are dropped. This can't be undone.
      </p>
      <p className="faint small">Created {formatDateTime(w.created_at)} by {userName(w.created_by)}.</p>
      <ActionError error={del.error} />
      <div className="dialog-actions">
        <Button onClick={onDone} disabled={del.isPending}>
          Cancel
        </Button>
        <Button
          variant="danger"
          busy={del.isPending}
          onClick={() =>
            del.mutate(w.id, {
              onSuccess: () => {
                showToast({ tone: "success", message: `“${w.name}” deleted.` });
                onDone();
              },
            })
          }
        >
          {w.kind === "slack" ? "Delete Slack channel" : "Delete webhook"}
        </Button>
      </div>
    </div>
  );
}
