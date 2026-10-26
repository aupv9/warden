import { useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import { fieldErrors, leftoverFieldErrors } from "../api/errors";
import { useOrg, useUpdatePolicy } from "../api/hooks/orgs";
import type { Org, SlaDays } from "../api/types";
import { SeverityMark } from "../components/Badges";
import { Button } from "../components/Button";
import { Card } from "../components/Card";
import { focusFirstInvalid } from "../components/Field";
import { AlertIcon } from "../components/Icons";
import { PageHeader } from "../components/PageHeader";
import { ActionError, ErrorState, SkeletonBlock } from "../components/States";
import { useOrgCtx } from "../layout/OrgLayout";
import { can, ORG_ROLE_LABELS } from "../lib/permissions";
import { showToast } from "../lib/toast";
import { usePageTitle } from "../lib/usePageTitle";

export const SLA_KEYS = ["critical", "high", "medium", "low"] as const;
export const SLA_MIN = 1;
export const SLA_MAX = 365;

/** Text inputs (not type=number: no scroll-wheel changes, no "e"), checked here and on the server. */
export function validateSla(values: Record<keyof SlaDays, string>): { days?: SlaDays; errors: Partial<Record<keyof SlaDays, string>> } {
  const errors: Partial<Record<keyof SlaDays, string>> = {};
  const days = {} as SlaDays;
  for (const k of SLA_KEYS) {
    const raw = values[k].trim();
    const n = /^\d{1,3}$/.test(raw) ? Number(raw) : NaN;
    if (!Number.isInteger(n) || n < SLA_MIN || n > SLA_MAX) errors[k] = `Enter a whole number of days from ${SLA_MIN} to ${SLA_MAX}.`;
    else days[k] = n;
  }
  return Object.keys(errors).length ? { errors } : { days, errors };
}

export function OrgSettingsPage() {
  const { orgId, org: meOrg } = useOrgCtx();
  usePageTitle("Settings");
  const org = useOrg(orgId);
  const canEdit = can("configure_policy", meOrg.role);
  return (
    <div className="page">
      <PageHeader title="Settings" />
      <div className="page-body settings-body">
        {org.isPending ? (
          <Card title="SLA policy" titleId="sla-h">
            <SkeletonBlock label="the SLA policy" lines={4} height={32} />
          </Card>
        ) : org.isError ? (
          <ErrorState error={org.error} onRetry={() => void org.refetch()} what="the settings" />
        ) : canEdit ? (
          <SlaForm org={org.data} />
        ) : (
          <SlaReadOnly org={org.data} role={ORG_ROLE_LABELS[meOrg.role]} />
        )}
      </div>
    </div>
  );
}

function SlaIntro() {
  return (
    <p className="card-intro-plain muted">
      How many days an issue has, from when a scan first finds it, before it is past its SLA. Info findings have no SLA.
    </p>
  );
}

function SlaReadOnly({ org, role }: { org: Org; role: string }) {
  return (
    <Card title="SLA policy" titleId="sla-h">
      <SlaIntro />
      <dl className="sla-grid">
        {SLA_KEYS.map((k) => (
          <div key={k} className="sla-cell">
            <dt>
              <SeverityMark severity={k} />
            </dt>
            <dd>
              <span className="sla-value num">{org.sla_days[k]}</span> days
            </dd>
          </div>
        ))}
      </dl>
      <p className="faint small" style={{ marginTop: 14 }}>
        Only security leads can change the SLA policy. Your role in {org.name} is {role.toLowerCase()}.
      </p>
    </Card>
  );
}

const toStrings = (d: SlaDays): Record<keyof SlaDays, string> => ({
  critical: String(d.critical),
  high: String(d.high),
  medium: String(d.medium),
  low: String(d.low),
});

function SlaForm({ org }: { org: Org }) {
  const { orgId } = useOrgCtx();
  const update = useUpdatePolicy(orgId);
  const [values, setValues] = useState(() => toStrings(org.sla_days));
  const [recompute, setRecompute] = useState(false);
  const [errors, setErrors] = useState<Partial<Record<keyof SlaDays, string>>>({});
  const formRef = useRef<HTMLFormElement>(null);
  const savedKey = JSON.stringify(org.sla_days);
  const dirty = JSON.stringify(toStrings(org.sla_days)) !== JSON.stringify(values) || recompute;

  // Follow a newer saved policy while nothing is being edited.
  useEffect(() => {
    if (!dirty) setValues(toStrings(JSON.parse(savedKey) as SlaDays));
  }, [savedKey]);

  const server = fieldErrors(update.error);
  const errorFor = (k: keyof SlaDays) => errors[k] ?? server[`sla_days.${k}`];

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const v = validateSla(values);
    setErrors(v.errors);
    if (!v.days) {
      focusFirstInvalid(formRef.current);
      return;
    }
    update.mutate(
      { sla_days: v.days, recompute_open: recompute },
      {
        onSuccess: (o) => {
          setValues(toStrings(o.sla_days));
          setRecompute(false);
          showToast({
            tone: "success",
            message: recompute ? "SLA policy saved. Due dates of open issues were recalculated." : "SLA policy saved. It applies to new issues.",
          });
        },
        onError: () => focusFirstInvalid(formRef.current),
      },
    );
  };

  return (
    <Card title="SLA policy" titleId="sla-h">
      <SlaIntro />
      <form ref={formRef} onSubmit={submit} noValidate className="stack" style={{ gap: 16 }}>
        <div className="sla-grid">
          {SLA_KEYS.map((k) => {
            const err = errorFor(k);
            const id = `sla-${k}`;
            return (
              <div key={k} className="field sla-cell">
                <label htmlFor={id}>
                  <SeverityMark severity={k} />
                </label>
                <span className="input-suffix">
                  <input
                    id={id}
                    className="input num"
                    inputMode="numeric"
                    autoComplete="off"
                    value={values[k]}
                    aria-invalid={err ? true : undefined}
                    aria-describedby={err ? `${id}-e` : `${id}-h`}
                    onChange={(ev) => setValues({ ...values, [k]: ev.target.value })}
                  />
                  <span id={`${id}-h`} className="suffix">
                    days
                  </span>
                </span>
                {err && (
                  <span id={`${id}-e`} className="error">
                    <AlertIcon size={14} /> {err}
                  </span>
                )}
              </div>
            );
          })}
        </div>
        <label className="check-row">
          <input type="checkbox" className="check" checked={recompute} onChange={(e) => setRecompute(e.target.checked)} />
          <span>
            <strong>Also recalculate the due dates of open issues</strong>
            <span className="desc">
              Without this, the new days apply only to issues found from now on. With it, every active issue gets a new due date
              counted from when it was found, so some may become past SLA at once.
            </span>
          </span>
        </label>
        <ActionError error={update.error} />
        {leftoverFieldErrors(update.error, SLA_KEYS.map((k) => `sla_days.${k}`)).map((m) => (
          <div key={m} className="banner banner-error" role="alert">
            {m}
          </div>
        ))}
        <div className="row">
          <Button type="submit" variant="primary" busy={update.isPending} disabled={!dirty}>
            Save policy
          </Button>
          {dirty && (
            <Button
              onClick={() => {
                setValues(toStrings(org.sla_days));
                setRecompute(false);
                setErrors({});
                update.reset();
              }}
            >
              Discard changes
            </Button>
          )}
        </div>
      </form>
    </Card>
  );
}
