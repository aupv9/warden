import { useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import { fieldErrors } from "../../api/errors";
import { useOrgMembers, useSignInSettings, useUpdateSignInPolicy } from "../../api/hooks/orgs";
import { ORG_ROLES } from "../../api/types";
import type { OrgRole, SignInPolicyInput, SignInSettings } from "../../api/types";
import { DotMark } from "../../components/Badges";
import { Button } from "../../components/Button";
import { Card } from "../../components/Card";
import { focusFirstInvalid } from "../../components/Field";
import { AlertIcon, CheckIcon, PlusIcon, TrashIcon } from "../../components/Icons";
import { ActionError, ErrorState, SkeletonBlock } from "../../components/States";
import { useOrgCtx } from "../../layout/OrgLayout";
import { formatDateTime, relativeTime } from "../../lib/format";
import { ORG_ROLE_LABELS } from "../../lib/permissions";
import {
  canEditSignInPolicy,
  effectiveRoles,
  keyStatusText,
  MAX_DOMAINS,
  mfaGap,
  namesText,
  rolesText,
  safeExternalUrl,
  sameRoles,
  serverPolicyErrors,
  validateDomains,
} from "../../lib/signIn";
import { showToast } from "../../lib/toast";

/** The org Settings "Sign-in" section: the identity provider (read-only) and the org's sign-in
 *  policy (org admins edit, security leads read). OrgSettings renders it only for roles that
 *  may read it. */
export function SignInSection() {
  const { orgId, org: meOrg } = useOrgCtx();
  const settings = useSignInSettings(orgId);
  if (settings.isPending) {
    return (
      <>
        <Card title="Identity provider" titleId="idp-h">
          <SkeletonBlock label="the identity provider settings" lines={5} />
        </Card>
        <Card title="Sign-in policy" titleId="signin-policy-h">
          <SkeletonBlock label="the sign-in policy" lines={4} height={28} />
        </Card>
      </>
    );
  }
  if (settings.isError) {
    return (
      <Card title="Sign-in" titleId="signin-h">
        <ErrorState error={settings.error} onRetry={() => void settings.refetch()} what="the sign-in settings" />
      </Card>
    );
  }
  return (
    <>
      <IdentityProviderCard settings={settings.data} />
      {canEditSignInPolicy(meOrg.role) ? <SignInPolicyForm settings={settings.data} /> : <SignInPolicyReadOnly settings={settings.data} />}
    </>
  );
}

// ---- Identity provider ----

export function IdentityProviderCard({ settings, now = new Date() }: { settings: SignInSettings; now?: Date }) {
  const { provider, keys, mfa } = settings;
  const fetched = keys.fetched_at ? relativeTime(keys.fetched_at, now) : null;
  const status = keyStatusText(keys, provider.algorithms, fetched);
  const consoleUrl = safeExternalUrl(provider.console_url);
  return (
    <Card title="Identity provider" titleId="idp-h">
      <p className="card-intro-plain muted">
        Warden trusts sign-ins from this OpenID Connect provider. Sign-in methods such as single sign-on, social login and passkeys
        are set up at the identity provider, not in Warden. Changing the provider is a server setting for your operator (README,
        “Sign-in and identity providers”).
      </p>
      <dl className="kv idp-kv">
        <dt>Issuer</dt>
        <dd className="mono">{provider.issuer}</dd>
        <dt>Audience</dt>
        <dd className="mono">{provider.audience}</dd>
        <dt>Algorithms</dt>
        <dd className="mono">{provider.algorithms.join(", ") || "–"}</dd>
        <dt>Signing keys</dt>
        <dd>
          {provider.keys_url ? (
            <>
              Pinned to <span className="mono small">{provider.keys_url}</span>
            </>
          ) : (
            "Discovered from the issuer"
          )}
        </dd>
        <dt>Key status</dt>
        <dd>
          <span className="stack" style={{ gap: 2 }}>
            <DotMark tone={status.tone}>{status.label}</DotMark>
            <span className={status.tone === "danger" ? "danger-text" : "muted"} title={keys.fetched_at ? `Last refreshed ${formatDateTime(keys.fetched_at, now)}` : undefined}>
              {status.detail}
            </span>
          </span>
        </dd>
        <dt>Second factor</dt>
        <dd>
          {mfa.amr.length === 0 && mfa.acr.length === 0 ? (
            <span className="muted">No sign-in counts as two-factor.</span>
          ) : (
            <span className="muted">
              Counts when the token has{" "}
              {mfa.amr.length > 0 && <span className="mono text-2">amr {mfa.amr.join(", ")}</span>}
              {mfa.amr.length > 0 && mfa.acr.length > 0 && " or "}
              {mfa.acr.length > 0 && <span className="mono text-2">acr {mfa.acr.join(", ")}</span>}
            </span>
          )}
        </dd>
      </dl>
      {consoleUrl && (
        <p style={{ marginTop: 14 }}>
          <a href={consoleUrl} target="_blank" rel="noopener noreferrer">
            Open identity provider console<span className="visually-hidden"> (opens in a new tab)</span>
          </a>
        </p>
      )}
    </Card>
  );
}

// ---- Sign-in policy ----

function PolicyIntro() {
  return (
    <p className="card-intro-plain muted">
      Rules for this organization on top of what the identity provider checks. API tokens aren't affected.
    </p>
  );
}

/** Who in the given roles hasn't signed in with a second factor (from the members list). */
function MfaOverview({ roles, preview }: { roles: OrgRole[]; preview: boolean }) {
  const { orgId } = useOrgCtx();
  const members = useOrgMembers(orgId);
  if (roles.length === 0) {
    return <p className="muted small">Two-factor sign-in isn't required for any role in this organization.</p>;
  }
  if (members.isPending) return <p className="faint small">Checking members…</p>;
  if (members.isError) {
    return <p className="faint small">Couldn't load the members, so Warden can't show who hasn't signed in with two-factor yet.</p>;
  }
  const gap = mfaGap(members.data, roles);
  if (gap.members.length === 0) {
    return (
      <p className="small ok-line">
        <span className="yes" aria-hidden="true">
          <CheckIcon size={14} />
        </span>
        <span>
          {preview ? "With these changes, all" : "All"} {rolesText(roles).toLowerCase()} have signed in with two-factor.
        </span>
      </p>
    );
  }
  const n = gap.members.length;
  return (
    <div className="banner banner-warning mfa-gap">
      <AlertIcon />
      <span>
        <strong>
          {preview ? "With these changes, " : ""}
          {n} {n === 1 ? "member" : "members"} in roles that require two-factor {n === 1 ? "hasn't" : "haven't"} signed in with it:
        </strong>{" "}
        {namesText(gap.shown, gap.more)}. They see “Two-factor sign-in required” in this organization until they sign in again with a
        second factor.
      </span>
    </div>
  );
}

function SignInPolicyReadOnly({ settings }: { settings: SignInSettings }) {
  const { org } = useOrgCtx();
  const { mfa, policy } = settings;
  return (
    <Card title="Sign-in policy" titleId="signin-policy-h">
      <PolicyIntro />
      <div className="policy-sections">
        <section className="policy-section" aria-labelledby="mfa-roles-h">
          <h3 id="mfa-roles-h" className="policy-head">
            Two-factor sign-in
          </h3>
          <ul className="role-list">
            {ORG_ROLES.map((r) => {
              const fixed = mfa.instance_roles.includes(r);
              const on = mfa.effective_roles.includes(r);
              return (
                <li key={r}>
                  <DotMark tone={on ? "success" : "neutral"}>
                    {ORG_ROLE_LABELS[r]}: {on ? "required" : "not required"}
                  </DotMark>
                  {fixed && <span className="faint small"> · Required by the server</span>}
                </li>
              );
            })}
          </ul>
          <div style={{ marginTop: 10 }}>
            <MfaOverview roles={mfa.effective_roles} preview={false} />
          </div>
        </section>
        <section className="policy-section" aria-labelledby="domains-h">
          <h3 id="domains-h" className="policy-head">
            Allowed email domains
          </h3>
          {policy.allowed_email_domains.length === 0 ? (
            <p>Any domain</p>
          ) : (
            <ul className="tag-row domain-tags" aria-label="Allowed email domains">
              {policy.allowed_email_domains.map((d) => (
                <li key={d} className="tag mono">
                  {d}
                </li>
              ))}
            </ul>
          )}
          <p className="muted small" style={{ marginTop: 8 }}>
            Only limits who can be added as a member. Existing members stay.
          </p>
        </section>
      </div>
      <p className="faint small" style={{ marginTop: 14 }}>
        Only org admins can change the sign-in policy. Your role in {org.name} is {ORG_ROLE_LABELS[org.role].toLowerCase()}.
      </p>
    </Card>
  );
}

interface DomainRow {
  key: number;
  value: string;
}

let rowSeq = 0;
const toRows = (domains: readonly string[]): DomainRow[] => domains.map((value) => ({ key: ++rowSeq, value }));

const policyKey = (p: SignInPolicyInput) =>
  JSON.stringify({ mfa_roles: ORG_ROLES.filter((r) => p.mfa_roles.includes(r)), allowed_email_domains: p.allowed_email_domains });

function SignInPolicyForm({ settings }: { settings: SignInSettings }) {
  const { orgId } = useOrgCtx();
  const update = useUpdateSignInPolicy(orgId);
  const instance = settings.mfa.instance_roles;
  const [roles, setRoles] = useState<OrgRole[]>(() => settings.policy.mfa_roles);
  const [rows, setRows] = useState<DomainRow[]>(() => toRows(settings.policy.allowed_email_domains));
  const [showErrors, setShowErrors] = useState(false);
  const [announce, setAnnounce] = useState("");
  const formRef = useRef<HTMLFormElement>(null);
  const pendingFocus = useRef<string | null>(null);

  // A newer saved policy (refetch, another tab) replaces the form only while nothing is being
  // edited, so typing is never lost. `lastSaved` is what "dirty" compares against.
  const savedKey = policyKey(settings.policy);
  const lastSaved = useRef(savedKey);
  const saved = JSON.parse(lastSaved.current) as SignInPolicyInput;
  const draft: SignInPolicyInput = { mfa_roles: ORG_ROLES.filter((r) => roles.includes(r)), allowed_email_domains: rows.map((r) => r.value) };
  const dirty = !sameRoles(draft.mfa_roles, saved.mfa_roles) || JSON.stringify(draft.allowed_email_domains) !== JSON.stringify(saved.allowed_email_domains);
  useEffect(() => {
    if (savedKey === lastSaved.current) return;
    if (!dirty) {
      const next = JSON.parse(savedKey) as SignInPolicyInput;
      setRoles(next.mfa_roles);
      setRows(toRows(next.allowed_email_domains));
    }
    lastSaved.current = savedKey;
  }, [savedKey]);

  useEffect(() => {
    const sel = pendingFocus.current;
    if (!sel) return;
    pendingFocus.current = null;
    formRef.current?.querySelector<HTMLElement>(sel)?.focus();
  });

  const validation = validateDomains(draft.allowed_email_domains);
  const server = serverPolicyErrors(fieldErrors(update.error), rows.length);
  const rowError = (i: number) => (showErrors ? validation.rows[i] : undefined) ?? server.rows[i];
  const listError = (showErrors ? validation.list : undefined) ?? server.list;
  const effective = effectiveRoles(instance, draft.mfa_roles);

  const edit = () => {
    if (update.error) update.reset();
  };

  const toggleRole = (r: OrgRole, on: boolean) => {
    edit();
    setRoles((list) => (on ? [...list.filter((x) => x !== r), r] : list.filter((x) => x !== r)));
  };

  const setRow = (key: number, value: string) => {
    edit();
    setRows((list) => list.map((r) => (r.key === key ? { ...r, value } : r)));
  };

  const addRow = () => {
    if (rows.length >= MAX_DOMAINS) return;
    edit();
    const row = { key: ++rowSeq, value: "" };
    setRows([...rows, row]);
    pendingFocus.current = `[data-domain="${row.key}"] input`;
  };

  const removeRow = (i: number) => {
    edit();
    const removed = rows[i]!;
    const next = rows.filter((_, idx) => idx !== i);
    setRows(next);
    setAnnounce(`${removed.value.trim() || `Domain ${i + 1}`} removed.${next.length === 0 ? " Any domain is allowed." : ""}`);
    const neighbour = next[Math.min(i, next.length - 1)];
    pendingFocus.current = neighbour ? `[data-domain="${neighbour.key}"] input` : "#add-domain";
  };

  const discard = () => {
    update.reset();
    setShowErrors(false);
    setRoles(saved.mfa_roles);
    setRows(toRows(saved.allowed_email_domains));
  };

  const submit = (e: FormEvent) => {
    e.preventDefault();
    setShowErrors(true);
    if (!validation.valid) {
      focusFirstInvalid(formRef.current);
      return;
    }
    update.mutate(
      { mfa_roles: draft.mfa_roles, allowed_email_domains: validation.domains },
      {
        onSuccess: (s) => {
          lastSaved.current = policyKey(s.policy);
          setRoles(s.policy.mfa_roles);
          setRows(toRows(s.policy.allowed_email_domains));
          setShowErrors(false);
          showToast({ tone: "success", message: "Sign-in policy saved." });
        },
        onError: () => focusFirstInvalid(formRef.current),
      },
    );
  };

  return (
    <Card title="Sign-in policy" titleId="signin-policy-h">
      <PolicyIntro />
      <span className="visually-hidden" role="status" aria-live="polite">
        {announce}
      </span>
      <form ref={formRef} onSubmit={submit} noValidate className="policy-sections">
        <fieldset className="policy-section" aria-describedby={server.roles ? "mfa-roles-e" : "mfa-roles-d"}>
          <legend className="policy-head">Require two-factor sign-in for</legend>
          <p id="mfa-roles-d" className="muted small policy-desc">
            People in these roles must sign in with a second factor (for example an authenticator app or a security key) to use this
            organization.
          </p>
          <div className="choices">
            {ORG_ROLES.map((r) => {
              const fixed = instance.includes(r);
              const id = `mfa-role-${r}`;
              return (
                <label key={r} className="check-row" htmlFor={id}>
                  <input
                    id={id}
                    type="checkbox"
                    className="check"
                    checked={fixed || roles.includes(r)}
                    disabled={fixed}
                    aria-describedby={fixed ? `${id}-h` : undefined}
                    onChange={(ev) => toggleRole(r, ev.target.checked)}
                  />
                  <span>
                    <strong>{ORG_ROLE_LABELS[r]}</strong>
                    {fixed && (
                      <span id={`${id}-h`} className="desc">
                        Required by the server
                      </span>
                    )}
                  </span>
                </label>
              );
            })}
          </div>
          {server.roles && (
            <p id="mfa-roles-e" className="field-error">
              <AlertIcon size={14} /> {server.roles}
            </p>
          )}
          <div className="policy-overview">
            <MfaOverview roles={effective} preview={!sameRoles(effective, settings.mfa.effective_roles)} />
          </div>
        </fieldset>

        <fieldset className="policy-section" aria-describedby={listError ? "domains-d domains-e" : "domains-d"}>
          <legend className="policy-head">Allowed email domains</legend>
          <p id="domains-d" className="muted small policy-desc">
            Only people with an email address at one of these domains can be added as members. Existing members stay, even if their
            domain isn't listed. Subdomains count only if listed. With no domains, any domain is allowed.
          </p>
          {rows.length === 0 ? (
            <p className="domain-any">Any domain</p>
          ) : (
            <ul className="domain-list">
              {rows.map((row, i) => {
                const err = rowError(i);
                const id = `domain-${row.key}`;
                return (
                  <li key={row.key} data-domain={row.key} className="domain-item">
                    <label htmlFor={id} className="visually-hidden">
                      Domain {i + 1}
                    </label>
                    <div className="domain-row">
                      <input
                        id={id}
                        className="input mono"
                        value={row.value}
                        placeholder="example.com"
                        autoComplete="off"
                        autoCapitalize="none"
                        spellCheck={false}
                        maxLength={300}
                        aria-invalid={err ? true : undefined}
                        aria-describedby={err ? `${id}-e` : undefined}
                        onChange={(ev) => setRow(row.key, ev.target.value)}
                      />
                      <button
                        type="button"
                        className="icon-btn"
                        aria-label={`Remove ${row.value.trim() || `domain ${i + 1}`}`}
                        title="Remove"
                        onClick={() => removeRow(i)}
                      >
                        <TrashIcon />
                      </button>
                    </div>
                    {err && (
                      <span id={`${id}-e`} className="field-error">
                        <AlertIcon size={14} /> {err}
                      </span>
                    )}
                  </li>
                );
              })}
            </ul>
          )}
          {listError && (
            <p id="domains-e" className="field-error">
              <AlertIcon size={14} /> {listError}
            </p>
          )}
          <div className="row" style={{ marginTop: 10 }}>
            <Button id="add-domain" size="sm" onClick={addRow} disabled={rows.length >= MAX_DOMAINS}>
              <PlusIcon /> Add domain
            </Button>
            <span className="faint small">
              {rows.length} of {MAX_DOMAINS}
            </span>
          </div>
        </fieldset>

        <div className="stack" style={{ gap: 12 }}>
          <ActionError error={update.error} />
          {server.other.map((m) => (
            <div key={m} className="banner banner-error" role="alert">
              <AlertIcon /> <span>{m}</span>
            </div>
          ))}
          <div className="row">
            <Button type="submit" variant="primary" busy={update.isPending} disabled={!dirty}>
              Save sign-in policy
            </Button>
            {dirty && <Button onClick={discard}>Discard changes</Button>}
          </div>
        </div>
      </form>
    </Card>
  );
}
