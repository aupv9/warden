import { useEffect, useState } from "react";
import { useNotificationPrefs, useSaveNotificationPrefs } from "../api/hooks/notifications";
import { NOTIFICATION_TYPES } from "../api/types";
import type { NotificationPref, NotificationType } from "../api/types";
import { Button } from "../components/Button";
import { Card } from "../components/Card";
import { PageHeader } from "../components/PageHeader";
import { ActionError, ErrorState, SkeletonRows } from "../components/States";
import { useOrgCtx } from "../layout/OrgLayout";
import { defaultEmail, NOTIFICATION_LABELS } from "../lib/notifications";
import { showToast } from "../lib/toast";
import { usePageTitle } from "../lib/usePageTitle";

type Prefs = Record<NotificationType, boolean>;

export function prefsFromItems(items: NotificationPref[]): Prefs {
  const out = {} as Prefs;
  for (const t of NOTIFICATION_TYPES) out[t] = items.find((i) => i.type === t)?.email ?? defaultEmail(t);
  return out;
}

export function PreferencesPage() {
  usePageTitle("Notification preferences");
  const { me } = useOrgCtx();
  const prefs = useNotificationPrefs();
  return (
    <div className="page">
      <PageHeader title="Notification preferences" />
      <div className="page-body settings-body">
        <Card title="Email" titleId="email-h" flush>
          <p className="card-intro muted">
            Everything below also appears under the bell in Warden. Choose which ones are emailed to{" "}
            <strong className="ink">{me.email}</strong>. These settings are yours and apply in every organization. Emails carry
            the issue key, title, severity and a link, never code, comments or secrets.
          </p>
          {prefs.isPending ? (
            <SkeletonRows label="notification preferences" rows={7} />
          ) : prefs.isError ? (
            <ErrorState error={prefs.error} onRetry={() => void prefs.refetch()} what="your preferences" />
          ) : (
            <PrefsForm saved={prefsFromItems(prefs.data)} />
          )}
        </Card>
      </div>
    </div>
  );
}

function PrefsForm({ saved }: { saved: Prefs }) {
  const save = useSaveNotificationPrefs();
  const [values, setValues] = useState<Prefs>(saved);
  const savedKey = JSON.stringify(saved);
  const dirty = JSON.stringify(values) !== savedKey;
  useEffect(() => {
    if (!dirty) setValues(JSON.parse(savedKey) as Prefs);
  }, [savedKey]);

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        save.mutate(
          NOTIFICATION_TYPES.map((type) => ({ type, email: values[type] })),
          { onSuccess: () => showToast({ tone: "success", message: "Notification preferences saved." }) },
        );
      }}
    >
      <ul className="pref-list">
        {NOTIFICATION_TYPES.map((t) => (
          <li key={t}>
            <label className="pref-row">
              <span className="pref-text">
                <strong>{NOTIFICATION_LABELS[t].label}</strong>
                <span className="muted">{NOTIFICATION_LABELS[t].detail}</span>
              </span>
              <span className="switch">
                <input
                  type="checkbox"
                  role="switch"
                  checked={values[t]}
                  onChange={(e) => setValues({ ...values, [t]: e.target.checked })}
                />
                <span className="switch-track" aria-hidden="true" />
                <span className="switch-label">Email</span>
              </span>
            </label>
          </li>
        ))}
      </ul>
      <div className="table-foot">
        <span>{NOTIFICATION_TYPES.filter((t) => values[t]).length} of {NOTIFICATION_TYPES.length} emailed</span>
        <div className="row">
          <ActionError error={save.error} />
          {dirty && (
            <Button onClick={() => setValues(saved)} disabled={save.isPending}>
              Discard changes
            </Button>
          )}
          <Button type="submit" variant="primary" busy={save.isPending} disabled={!dirty}>
            Save preferences
          </Button>
        </div>
      </div>
    </form>
  );
}
