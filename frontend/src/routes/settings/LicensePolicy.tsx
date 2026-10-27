import { useEffect, useId, useRef, useState } from "react";
import type { FormEvent } from "react";
import { fieldErrors } from "../../api/errors";
import { useLicensePolicy, useUpdateLicensePolicy } from "../../api/hooks/orgs";
import { LICENSE_ACTIONS, LICENSE_CATEGORIES } from "../../api/types";
import type { LicenseAction, LicenseCategory, LicensePolicy, LicensePolicyInput } from "../../api/types";
import { DotMark } from "../../components/Badges";
import { Button } from "../../components/Button";
import { Card } from "../../components/Card";
import { focusFirstInvalid } from "../../components/Field";
import { AlertIcon, CloseIcon, PlusIcon } from "../../components/Icons";
import { ActionError, ErrorState, SkeletonBlock } from "../../components/States";
import { useOrgCtx } from "../../layout/OrgLayout";
import {
  ACTION_LABELS,
  ACTION_WORDS,
  addIds,
  CATEGORY_HELP,
  CATEGORY_LABELS,
  isLicenseAction,
  isPolicyOff,
  MAX_LICENSE_IDS,
  policyKey,
  RECOMMENDED,
  serverLicenseErrors,
  splitIds,
  toInput,
  validateLicensePolicy,
} from "../../lib/licensePolicy";
import type { ListName } from "../../lib/licensePolicy";
import { can, ORG_ROLE_LABELS } from "../../lib/permissions";
import { showToast } from "../../lib/toast";

/** Org Settings → License policy. Every member reads it; security leads (configure_policy)
 *  edit it. It is off until someone sets it. */
export function LicensePolicySection() {
  const { orgId, org } = useOrgCtx();
  const policy = useLicensePolicy(orgId);
  if (policy.isPending) {
    return (
      <Card title="License policy" titleId="license-h">
        <SkeletonBlock label="the license policy" lines={5} height={28} />
      </Card>
    );
  }
  if (policy.isError) {
    return (
      <Card title="License policy" titleId="license-h">
        <ErrorState error={policy.error} onRetry={() => void policy.refetch()} what="the license policy" />
      </Card>
    );
  }
  return can("configure_policy", org.role) ? <LicensePolicyForm policy={policy.data} /> : <LicensePolicyReadOnly policy={policy.data} />;
}

function StatusMark({ on }: { on: boolean }) {
  return <DotMark tone={on ? "success" : "neutral"}>{on ? "On" : "Off"}</DotMark>;
}

function Intro() {
  return (
    <>
      <p className="card-intro-plain muted">
        Trivy reads the license of each package it finds. The policy decides which licenses become issues: Block makes a High issue
        (it fails the default CI gate), Review a Medium one. Changes apply from the next scan.
      </p>
      <p className="note license-note">
        <AlertIcon size={14} />
        <span>
          License data depends on the lockfile. npm (package-lock.json), Cargo and container images have it; go.mod and
          requirements.txt don't, so packages from those have no license to check.
        </span>
      </p>
    </>
  );
}

function LicensePolicyReadOnly({ policy }: { policy: LicensePolicy }) {
  const { org } = useOrgCtx();
  return (
    <Card title="License policy" titleId="license-h" actions={<StatusMark on={policy.enabled} />}>
      <Intro />
      {!policy.enabled ? (
        <p className="license-off">
          <strong>Off.</strong> <span className="muted">No license issues are created. A security lead can turn it on.</span>
        </p>
      ) : (
        <dl className="kv license-kv">
          {LICENSE_CATEGORIES.map((c) => (
            <div key={c} className="kv-row">
              <dt>{CATEGORY_LABELS[c]}</dt>
              <dd className={policy.categories[c] === "allow" ? "muted" : undefined}>{ACTION_WORDS[policy.categories[c]]}</dd>
            </div>
          ))}
          <div className="kv-row">
            <dt>Deny</dt>
            <dd>
              <IdTags ids={policy.deny} label="Denied licenses" />
            </dd>
          </div>
          <div className="kv-row">
            <dt>Allow</dt>
            <dd>
              <IdTags ids={policy.allow} label="Allowed licenses" />
            </dd>
          </div>
        </dl>
      )}
      <p className="faint small" style={{ marginTop: 14 }}>
        Only security leads can change the license policy. Your role in {org.name} is {ORG_ROLE_LABELS[org.role].toLowerCase()}.
      </p>
    </Card>
  );
}

function IdTags({ ids, label }: { ids: string[]; label: string }) {
  if (ids.length === 0) return <span className="muted">None</span>;
  return (
    <ul className="tag-row domain-tags" aria-label={label}>
      {ids.map((id) => (
        <li key={id} className="tag mono">
          {id}
        </li>
      ))}
    </ul>
  );
}

function LicensePolicyForm({ policy }: { policy: LicensePolicy }) {
  const { orgId } = useOrgCtx();
  const update = useUpdateLicensePolicy(orgId);
  const [draft, setDraft] = useState<LicensePolicyInput>(() => toInput(policy));
  const [showErrors, setShowErrors] = useState(false);
  const [announce, setAnnounce] = useState("");
  const formRef = useRef<HTMLFormElement>(null);

  // A newer saved policy replaces the form only while nothing is being edited (as SignIn.tsx).
  const savedKey = policyKey(policy);
  const lastSaved = useRef(savedKey);
  const saved = JSON.parse(lastSaved.current) as LicensePolicyInput;
  const dirty = policyKey(draft) !== lastSaved.current;
  useEffect(() => {
    if (savedKey === lastSaved.current) return;
    if (!dirty) setDraft(JSON.parse(savedKey) as LicensePolicyInput);
    lastSaved.current = savedKey;
  }, [savedKey]);

  const validation = validateLicensePolicy(draft);
  const server = serverLicenseErrors(fieldErrors(update.error), draft);
  const listError = (l: ListName) => (showErrors ? validation[l] : undefined) ?? server.lists[l];
  const off = isPolicyOff(draft);
  const isPreset = LICENSE_CATEGORIES.every((c) => draft.categories[c] === RECOMMENDED[c]);

  const edit = (next: LicensePolicyInput) => {
    if (update.error) update.reset();
    setDraft(next);
  };

  const setAction = (c: LicenseCategory, a: LicenseAction) => edit({ ...draft, categories: { ...draft.categories, [c]: a } });

  const applyPreset = () => {
    edit({ ...draft, categories: { ...RECOMMENDED } });
    setAnnounce("Recommended preset applied: forbidden licenses blocked, restricted ones reviewed, the rest allowed. Save to use it.");
  };

  const discard = () => {
    update.reset();
    setShowErrors(false);
    setDraft(saved);
  };

  const submit = (e: FormEvent) => {
    e.preventDefault();
    setShowErrors(true);
    if (!validation.valid) {
      focusFirstInvalid(formRef.current);
      return;
    }
    update.mutate(toInput(draft), {
      onSuccess: (p) => {
        lastSaved.current = policyKey(p);
        setDraft(toInput(p));
        setShowErrors(false);
        showToast({
          tone: "success",
          message: p.enabled ? "License policy saved. It applies from the next scan." : "License policy saved. It's off: no license issues are created.",
        });
      },
      onError: () => focusFirstInvalid(formRef.current),
    });
  };

  return (
    <Card title="License policy" titleId="license-h" actions={<StatusMark on={!isPolicyOff(saved)} />}>
      <Intro />
      <span className="visually-hidden" role="status" aria-live="polite">
        {announce}
      </span>
      <form ref={formRef} onSubmit={submit} noValidate className="policy-sections">
        <fieldset className="policy-section">
          <legend className="policy-head">By category</legend>
          <div className="preset-row">
            <Button size="sm" onClick={applyPreset} disabled={isPreset} aria-describedby="license-preset-d">
              Apply recommended preset
            </Button>
            <span id="license-preset-d" className="faint small">
              Forbidden → Block, Restricted → Review, the rest Allow.
            </span>
          </div>
          <div className="license-cats">
            {LICENSE_CATEGORIES.map((c) => {
              const id = `license-cat-${c}`;
              const err = server.categories[c];
              return (
                <div key={c} className="license-cat">
                  <label htmlFor={id} className="license-cat-text">
                    <strong>{CATEGORY_LABELS[c]}</strong>
                    <span className="desc" id={`${id}-h`}>
                      {CATEGORY_HELP[c]}
                    </span>
                  </label>
                  <div className="license-cat-action">
                    <select
                      id={id}
                      className={draft.categories[c] === "allow" ? "select" : `select action-${draft.categories[c]}`}
                      value={draft.categories[c]}
                      aria-invalid={err ? true : undefined}
                      aria-describedby={err ? `${id}-h ${id}-e` : `${id}-h`}
                      onChange={(e) => isLicenseAction(e.target.value) && setAction(c, e.target.value)}
                    >
                      {LICENSE_ACTIONS.map((a) => (
                        <option key={a} value={a}>
                          {ACTION_LABELS[a]}
                        </option>
                      ))}
                    </select>
                    {err && (
                      <span id={`${id}-e`} className="field-error">
                        <AlertIcon size={14} /> {err}
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </fieldset>

        <IdList
          list="deny"
          title="Deny"
          help="These licenses are always blocked (High issue), whatever their category. Use SPDX ids such as GPL-3.0-only or LicenseRef-acme."
          draft={draft}
          error={listError("deny")}
          onChange={edit}
          announce={setAnnounce}
        />
        <IdList
          list="allow"
          title="Allow"
          help="These licenses never become issues, whatever their category. A license can't be in both lists."
          draft={draft}
          error={listError("allow")}
          onChange={edit}
          announce={setAnnounce}
        />

        <div className="stack" style={{ gap: 12 }}>
          {off && (
            <p className="muted small license-off-note">
              With these settings the policy is off: every category is Allow and Deny is empty, so no license issues are created.
            </p>
          )}
          <ActionError error={update.error} />
          {server.other.map((m) => (
            <div key={m} className="banner banner-error" role="alert">
              <AlertIcon /> <span>{m}</span>
            </div>
          ))}
          <div className="row">
            <Button type="submit" variant="primary" busy={update.isPending} disabled={!dirty}>
              Save license policy
            </Button>
            {dirty && <Button onClick={discard}>Discard changes</Button>}
          </div>
        </div>
      </form>
    </Card>
  );
}

/** A Deny or Allow list: the ids as removable chips, and a box that adds one or more ids
 *  (separated by spaces, commas or semicolons) on Enter or "Add". */
function IdList({
  list,
  title,
  help,
  draft,
  error,
  onChange,
  announce,
}: {
  list: ListName;
  title: string;
  help: string;
  draft: LicensePolicyInput;
  error?: string;
  onChange: (next: LicensePolicyInput) => void;
  announce: (text: string) => void;
}) {
  const [text, setText] = useState("");
  const [inputError, setInputError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const id = useId();
  const ids = draft[list];
  const full = ids.length >= MAX_LICENSE_IDS;
  const err = inputError ?? error;

  const add = () => {
    const parts = splitIds(text);
    if (parts.length === 0) return;
    const res = addIds(draft, list, parts);
    if (res.error) {
      setInputError(res.error);
      return;
    }
    if (res.next) {
      onChange(res.next);
      announce(`${parts.join(", ")} added to ${title}.`);
    }
    setText("");
    setInputError(null);
  };

  const remove = (i: number) => {
    const removed = ids[i]!;
    onChange({ ...draft, [list]: ids.filter((_, n) => n !== i) });
    announce(`${removed} removed from ${title}.`);
    inputRef.current?.focus();
  };

  return (
    <fieldset className="policy-section" aria-describedby={`${id}-d`}>
      <legend className="policy-head">{title}</legend>
      <p id={`${id}-d`} className="muted small policy-desc">
        {help}
      </p>
      {ids.length > 0 && (
        <ul className="id-chips" aria-label={`${title} list`}>
          {ids.map((x, i) => (
            <li key={`${x}-${i}`} className="id-chip">
              <span className="mono">{x}</span>
              <button type="button" className="id-chip-x" aria-label={`Remove ${x} from ${title}`} onClick={() => remove(i)}>
                <CloseIcon size={12} />
              </button>
            </li>
          ))}
        </ul>
      )}
      <div className="id-add">
        <label htmlFor={`${id}-in`} className="visually-hidden">
          Add to {title}
        </label>
        <input
          id={`${id}-in`}
          ref={inputRef}
          className="input mono"
          value={text}
          placeholder={list === "deny" ? "SSPL-1.0" : "MIT"}
          autoComplete="off"
          autoCapitalize="none"
          spellCheck={false}
          maxLength={2000}
          disabled={full}
          aria-invalid={err ? true : undefined}
          aria-describedby={err ? `${id}-e` : undefined}
          onChange={(e) => {
            setText(e.target.value);
            if (inputError) setInputError(null);
          }}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              add();
            }
          }}
        />
        <Button size="sm" onClick={add} disabled={full || !text.trim()}>
          <PlusIcon /> Add
        </Button>
        <span className="faint small">
          {ids.length} of {MAX_LICENSE_IDS}
        </span>
      </div>
      {err && (
        <p id={`${id}-e`} className="field-error">
          <AlertIcon size={14} /> {err}
        </p>
      )}
    </fieldset>
  );
}
