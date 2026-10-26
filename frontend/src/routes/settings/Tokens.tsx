import { useEffect, useReducer, useRef, useState } from "react";
import type { FormEvent, RefObject } from "react";
import { fieldErrors, leftoverFieldErrors } from "../../api/errors";
import { useCreateToken, useRevokeToken, useTokens } from "../../api/hooks/tokens";
import { TOKEN_SCOPES } from "../../api/types";
import type { ApiToken, Project, TokenScope } from "../../api/types";
import { DotMark, Pill } from "../../components/Badges";
import { Button } from "../../components/Button";
import { Card } from "../../components/Card";
import { CopyButton } from "../../components/CopyButton";
import { Dialog } from "../../components/Dialog";
import { focusFirstInvalid, Select, TextField } from "../../components/Field";
import { AlertIcon, KeyIcon, PlusIcon } from "../../components/Icons";
import { ActionError, Banner, EmptyState, ErrorState, SkeletonRows } from "../../components/States";
import { Table } from "../../components/Table";
import { useOrgCtx } from "../../layout/OrgLayout";
import { addDays, daysUntil, formatDate, relativeTime, userName } from "../../lib/format";
import { can } from "../../lib/permissions";
import { showToast } from "../../lib/toast";

export const SCOPE_TEXT: Record<TokenScope, { title: string; desc: string }> = {
  "scan:write": { title: "Run scans", desc: "Upload code, start and cancel scans, read their results and the gate." },
  "issues:read": { title: "Read issues", desc: "List and read this project's issues." },
};

export const EXPIRY_OPTIONS = [7, 30, 90, 180, 365] as const;
export const NAME_MAX = 80;

export type TokenStatus = { tone: "success" | "warn" | "neutral" | "danger"; text: string };

export function tokenStatus(t: ApiToken, now: Date = new Date()): TokenStatus {
  if (t.revoked_at) return { tone: "neutral", text: `Revoked ${formatDate(t.revoked_at)}` };
  if (Date.parse(t.expires_at) <= now.getTime()) return { tone: "danger", text: `Expired ${formatDate(t.expires_at)}` };
  const days = daysUntil(t.expires_at, now);
  if (days <= 7) return { tone: "warn", text: days <= 1 ? "Expires within a day" : `Expires in ${days} days` };
  return { tone: "success", text: "Active" };
}

/** The masked form shown in lists: the prefix only, never a secret. */
export function maskedToken(prefix: string): string {
  return `wdn_${prefix}_…`;
}

export function TokensCard({ project }: { project: Project }) {
  const { orgId, org } = useOrgCtx();
  const tokens = useTokens(orgId, project.id);
  const [creating, setCreating] = useState(false);
  const [revoking, setRevoking] = useState<ApiToken | null>(null);
  const archived = !!project.archived_at;
  // Listing and revoking need manage_project_members (the caller of this card); creating also
  // needs run_scan, because the token scans as its creator (the API answers 403 otherwise).
  const canRun = can("run_scan", org.role, project.my_role);
  const createBlocked = archived
    ? "Archived projects take no new scans, so new tokens can't be created."
    : !canRun
      ? "A token scans as the person who creates it, so creating one needs a role that can run scans here (owner, developer or security lead). You can still list and revoke tokens."
      : null;

  return (
    <Card
      title="API tokens"
      titleId="tokens-h"
      flush
      actions={
        <Button size="sm" onClick={() => setCreating(true)} disabled={!!createBlocked} aria-describedby={createBlocked ? "tokens-blocked" : undefined}>
          <PlusIcon /> Create token
        </Button>
      }
    >
      <p className="card-intro muted">
        A token lets CI run scans in <strong className="ink">{project.key}</strong> only. It acts as the person who created it, and
        that person's access is checked again on every request. Warden stores a hash of each token, never the token itself.
        {createBlocked && <span id="tokens-blocked"> {createBlocked}</span>}
      </p>
      {tokens.isPending ? (
        <SkeletonRows label="API tokens" rows={3} />
      ) : tokens.isError ? (
        <ErrorState error={tokens.error} onRetry={() => void tokens.refetch()} what="API tokens" />
      ) : tokens.data.length === 0 ? (
        <EmptyState icon={<KeyIcon size={18} />} title="No API tokens yet">
          Create one for your CI, then follow the CI setup below.
        </EmptyState>
      ) : (
        <Table
          caption={`API tokens for ${project.key}`}
          head={
            <tr>
              <th>Name</th>
              <th>Scopes</th>
              <th>Created</th>
              <th>Last used</th>
              <th>Status</th>
              <th aria-label="Actions" />
            </tr>
          }
        >
          {tokens.data.map((t) => {
            const status = tokenStatus(t);
            return (
              <tr key={t.id} className={t.revoked_at ? "row-dim" : undefined}>
                <td>
                  <span className="token-name">{t.name}</span>
                  <span className="sub">{maskedToken(t.prefix)}</span>
                </td>
                <td data-label="Scopes">
                  <span className="tag-row">
                    {t.scopes.map((s) => (
                      <Pill key={s}>
                        <span className="mono">{s}</span>
                      </Pill>
                    ))}
                  </span>
                </td>
                <td data-label="Created" className="nowrap">
                  {formatDate(t.created_at)}
                  <span className="sub-sans">by {userName(t.created_by)}</span>
                </td>
                <td data-label="Last used" className="nowrap">
                  {t.last_used_at ? relativeTime(t.last_used_at) : <span className="faint">Never</span>}
                </td>
                <td data-label="Status" className="nowrap">
                  <DotMark tone={status.tone === "warn" ? "warn" : status.tone}>{status.text}</DotMark>
                  {!t.revoked_at && status.tone !== "danger" && <span className="sub-sans">until {formatDate(t.expires_at)}</span>}
                </td>
                <td className="no-label" style={{ textAlign: "right" }}>
                  {!t.revoked_at && (
                    <Button size="sm" variant="danger" onClick={() => setRevoking(t)} aria-label={`Revoke ${t.name}`}>
                      Revoke
                    </Button>
                  )}
                </td>
              </tr>
            );
          })}
        </Table>
      )}
      {tokens.data && tokens.data.length > 0 && (
        <div className="table-foot">
          <span>
            {tokens.data.filter((t) => !t.revoked_at && Date.parse(t.expires_at) > Date.now()).length} active of {tokens.data.length}
          </span>
        </div>
      )}
      <Dialog
        open={creating}
        onClose={() => setCreating(false)}
        title="Create an API token"
        description={`For CI in ${project.key}. The token acts as you.`}
      >
        <CreateTokenForm project={project} onDone={() => setCreating(false)} />
      </Dialog>
      <Dialog open={!!revoking} onClose={() => setRevoking(null)} title="Revoke this token?">
        {revoking && <RevokeForm project={project} token={revoking} onDone={() => setRevoking(null)} />}
      </Dialog>
    </Card>
  );
}

// ---- Create: form, then the show-once secret ----

/** The dialog's state. The secret lives here (component state) and nowhere else: not in the
 *  query or mutation cache (see createTokenMutation), the URL, storage or a log. "close" drops
 *  it, and the dialog unmounts its content on close as well. */
export interface TokenDialogState {
  secret: string | null;
  token: ApiToken | null;
}

export type TokenDialogAction = { type: "secret"; secret: string } | { type: "created"; token: ApiToken } | { type: "close" };

export const INITIAL_TOKEN_DIALOG: TokenDialogState = { secret: null, token: null };

export function tokenDialogReducer(state: TokenDialogState, action: TokenDialogAction): TokenDialogState {
  switch (action.type) {
    case "secret":
      return { ...state, secret: action.secret };
    case "created":
      return { ...state, token: action.token };
    case "close":
      return INITIAL_TOKEN_DIALOG;
  }
}

export function validateTokenForm(name: string, scopes: TokenScope[]): Record<string, string> {
  const e: Record<string, string> = {};
  const n = name.trim();
  if (!n) e.name = "Give the token a name, such as the pipeline that uses it.";
  else if (n.length > NAME_MAX) e.name = `Use at most ${NAME_MAX} characters.`;
  if (scopes.length === 0) e.scopes = "Choose at least one scope.";
  return e;
}

function CreateTokenForm({ project, onDone }: { project: Project; onDone: () => void }) {
  const { orgId } = useOrgCtx();
  const [state, dispatch] = useReducer(tokenDialogReducer, INITIAL_TOKEN_DIALOG);
  const create = useCreateToken(orgId, project.id, (secret) => dispatch({ type: "secret", secret }));
  const [name, setName] = useState("");
  const [scopes, setScopes] = useState<TokenScope[]>(["scan:write"]);
  const [days, setDays] = useState<number>(90);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const formRef = useRef<HTMLFormElement>(null);
  const secretRef = useRef<HTMLTextAreaElement>(null);

  const close = () => {
    dispatch({ type: "close" });
    onDone();
  };

  if (state.secret && state.token) {
    return <ShowOnce secret={state.secret} token={state.token} secretRef={secretRef} onDone={close} />;
  }

  const server = fieldErrors(create.error);
  const shown = { ...server, ...errors };
  const submit = (e: FormEvent) => {
    e.preventDefault();
    const v = validateTokenForm(name, scopes);
    setErrors(v);
    if (Object.keys(v).length) {
      focusFirstInvalid(formRef.current);
      return;
    }
    create.mutate(
      { name: name.trim(), scopes, expires_in_days: days },
      {
        onSuccess: (token) => {
          dispatch({ type: "created", token });
          showToast({ tone: "success", message: `Token “${token.name}” created.` });
        },
        onError: () => focusFirstInvalid(formRef.current),
      },
    );
  };

  return (
    <form ref={formRef} className="form-grid" onSubmit={submit} noValidate>
      <TextField
        label="Name"
        value={name}
        maxLength={NAME_MAX + 20}
        onChange={(e) => setName(e.target.value)}
        error={shown.name}
        hint="Say where it's used, such as “GitHub Actions (main)”."
        autoComplete="off"
      />
      <fieldset aria-describedby={shown.scopes ? "scopes-err" : undefined}>
        <legend>Scopes</legend>
        <div className="choices">
          {TOKEN_SCOPES.map((s) => (
            <label key={s} className="choice-card">
              <input
                type="checkbox"
                checked={scopes.includes(s)}
                aria-invalid={shown.scopes ? true : undefined}
                onChange={(e) => setScopes(e.target.checked ? TOKEN_SCOPES.filter((x) => x === s || scopes.includes(x)) : scopes.filter((x) => x !== s))}
              />
              <span>
                <strong>{SCOPE_TEXT[s].title}</strong> <span className="mono faint small">{s}</span>
                <span className="desc">{SCOPE_TEXT[s].desc}</span>
              </span>
            </label>
          ))}
        </div>
        {shown.scopes && (
          <span id="scopes-err" className="field-error">
            <AlertIcon size={14} /> {shown.scopes}
          </span>
        )}
      </fieldset>
      <Select
        label="Expires after"
        value={String(days)}
        onChange={(e) => setDays(Number(e.target.value))}
        options={EXPIRY_OPTIONS.map((d) => ({ value: String(d), label: d === 365 ? "1 year" : `${d} days` }))}
        hint={`On ${formatDate(addDays(new Date(), days).toISOString())}. Create a new token before then.`}
        error={shown.expires_in_days}
      />
      <ActionError error={create.error} />
      {leftoverFieldErrors(create.error, ["name", "scopes", "expires_in_days"]).map((m) => (
        <div key={m} className="banner banner-error" role="alert">
          {m}
        </div>
      ))}
      <div className="dialog-actions">
        <Button onClick={close} disabled={create.isPending}>
          Cancel
        </Button>
        <Button type="submit" variant="primary" busy={create.isPending}>
          Create token
        </Button>
      </div>
    </form>
  );
}

function ShowOnce({
  secret,
  token,
  secretRef,
  onDone,
}: {
  secret: string;
  token: ApiToken;
  secretRef: RefObject<HTMLTextAreaElement | null>;
  onDone: () => void;
}) {
  // The form that had focus is gone: move focus to the token so it can be copied at once.
  useEffect(() => secretRef.current?.focus(), [secretRef]);
  return (
    <div className="form-grid">
      <Banner tone="warning" title="Copy the token now.">
        This is the only time Warden shows it. Warden keeps only a hash, so a lost token can't be shown again: revoke it and
        create a new one.
      </Banner>
      <div className="field">
        <label htmlFor="new-token">Token “{token.name}”</label>
        <div className="secret-row">
          <textarea
            id="new-token"
            ref={secretRef}
            className="textarea mono secret-input"
            value={secret}
            readOnly
            rows={2}
            autoComplete="off"
            spellCheck={false}
            data-autofocus
            onFocus={(e) => e.currentTarget.select()}
          />
          <CopyButton text={secret} label="Copy" size="md" copiedText="Token copied to the clipboard." onFailed={() => secretRef.current?.select()} />
        </div>
        <span className="hint">
          Save it in your CI as a secret variable named <code>WARDEN_TOKEN</code>. Scopes: {token.scopes.join(", ")}. Expires{" "}
          {formatDate(token.expires_at)}.
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

function RevokeForm({ project, token, onDone }: { project: Project; token: ApiToken; onDone: () => void }) {
  const { orgId } = useOrgCtx();
  const revoke = useRevokeToken(orgId, project.id);
  return (
    <div className="form-grid">
      <p>
        Revoke <strong>{token.name}</strong> <span className="mono faint">({maskedToken(token.prefix)})</span>? CI jobs that use it
        start failing at once. This can't be undone.
      </p>
      <ActionError error={revoke.error} />
      <div className="dialog-actions">
        <Button onClick={onDone}>Cancel</Button>
        <Button
          variant="danger"
          busy={revoke.isPending}
          onClick={() =>
            revoke.mutate(token.id, {
              onSuccess: () => {
                showToast({ tone: "success", message: `Token “${token.name}” revoked.` });
                onDone();
              },
            })
          }
        >
          Revoke token
        </Button>
      </div>
    </div>
  );
}
