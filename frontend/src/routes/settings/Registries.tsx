import { useReducer, useRef, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import { Link } from "react-router";
import { fieldErrors, leftoverFieldErrors } from "../../api/errors";
import { useCreateRegistry, useDeleteRegistry, useRegistries, useTestRegistry, useUpdateRegistry } from "../../api/hooks/registries";
import type { CreateRegistryCredentialBody, RegistryCredential, RegistryTestResult, UpdateRegistryCredentialBody } from "../../api/types";
import { DotMark } from "../../components/Badges";
import { Button } from "../../components/Button";
import { Card } from "../../components/Card";
import { Dialog } from "../../components/Dialog";
import { focusFirstInvalid, TextField } from "../../components/Field";
import { LockIcon, PlusIcon, RegistryIcon } from "../../components/Icons";
import { PageHeader } from "../../components/PageHeader";
import { ActionError, EmptyState, ErrorState, ForbiddenState, SkeletonRows } from "../../components/States";
import { useOrgCtx } from "../../layout/OrgLayout";
import { formatDateTime, userName } from "../../lib/format";
import { can } from "../../lib/permissions";
import {
  createCredentialBody,
  credentialFormReducer,
  formFromCredential,
  lastUsedText,
  NEW_CREDENTIAL_FORM,
  REGISTRY_HOST_MAX,
  REGISTRY_MAX,
  REGISTRY_PASSWORD_MAX,
  REGISTRY_SECRETS_KEY_MISSING,
  REGISTRY_USERNAME_MAX,
  registryConflictText,
  registryErrorLabel,
  registryErrorText,
  testResultText,
  tidyHost,
  updateCredentialBody,
  validateCredentialForm,
} from "../../lib/registries";
import type { CredentialForm } from "../../lib/registries";
import { showToast } from "../../lib/toast";
import { usePageTitle } from "../../lib/usePageTitle";

// v0.7 wave 2: /orgs/:org/settings/registries, the credentials Warden pulls images with
// (DESIGN.md "v0.7 screens: Registries"). Org admins and security leads only
// (manage_registries): others don't see the Settings card, and this page never calls the API
// for them.
//
// Security rules: the password or token is typed once into a password field, sent once and
// never read back (the API doesn't return it). The form clears it as soon as the request is
// built, and the request body reaches the mutation through a ref, never as mutation variables
// (hooks/registries.ts; registries.test.ts). Hosts and usernames are rendered as text.

export const REGISTRIES_PATH = (orgId: string) => `/orgs/${orgId}/settings/registries`;

export function RegistriesPage() {
  usePageTitle("Registries");
  const { orgId, org } = useOrgCtx();
  if (!can("manage_registries", org.role)) {
    return (
      <div className="page">
        <PageHeader title="Registries" />
        <div className="page-body">
          <ForbiddenState orgName={org.name} backTo={`/orgs/${orgId}/projects`} />
        </div>
      </div>
    );
  }
  return <Registries />;
}

type DialogState = { type: "add" } | { type: "edit"; cred: RegistryCredential } | { type: "delete"; cred: RegistryCredential } | null;

function Registries() {
  const { orgId, org } = useOrgCtx();
  const list = useRegistries(orgId);
  const test = useTestRegistry(orgId);
  const [dialog, setDialog] = useState<DialogState>(null);
  // The last test of each credential, shown on its row until the page is left.
  const [results, setResults] = useState<Record<string, RegistryTestResult>>({});

  const items = list.data?.items ?? [];
  const full = items.length >= REGISTRY_MAX;

  const runTest = (c: RegistryCredential) =>
    test.mutate(c.id, {
      onSuccess: (r) => setResults((prev) => ({ ...prev, [c.id]: r })),
    });

  const addButton = list.data ? (
    <Button variant="primary" size="sm" onClick={() => setDialog({ type: "add" })} disabled={full} aria-describedby={full ? "registries-full" : undefined}>
      <PlusIcon /> Add
    </Button>
  ) : undefined;

  let body: ReactNode;
  if (list.isPending) body = <SkeletonRows label="registry credentials" rows={3} />;
  else if (list.isError) body = <ErrorState error={list.error} onRetry={() => void list.refetch()} what="the registry credentials" />;
  else if (items.length === 0)
    body = (
      <EmptyState
        icon={<RegistryIcon size={18} />}
        title="No registry credentials yet"
        action={
          <Button variant="primary" onClick={() => setDialog({ type: "add" })}>
            <PlusIcon /> Add credentials
          </Button>
        }
      >
        Warden pulls images only by digest (registry/repository@sha256:…), never by tag. It signs in only to the hosts listed here;
        any other image is pulled anonymously, so a private image needs credentials for its host first.
      </EmptyState>
    );
  else
    body = (
      <>
        <ul className="hook-list" aria-label="Registry credentials">
          {items.map((c) => (
            <RegistryRow
              key={c.id}
              c={c}
              result={results[c.id]}
              testing={test.isPending && test.variables === c.id}
              onTest={() => runTest(c)}
              onEdit={() => setDialog({ type: "edit", cred: c })}
              onDelete={() => setDialog({ type: "delete", cred: c })}
            />
          ))}
        </ul>
        <div className="table-foot">
          <span>
            {items.length} of {REGISTRY_MAX}
          </span>
          {full && (
            <span id="registries-full" className="muted">
              The org has credentials for the most hosts Warden allows. Delete one to add another.
            </span>
          )}
        </div>
      </>
    );

  return (
    <div className="page">
      <PageHeader title="Registries" actions={addButton} />
      <div className="page-body">
        <p className="faint small comp-intro">
          Credentials Warden signs in with to pull images for scans of {org.name} (New scan › Image from a registry). Warden pulls only by
          digest, and only from the hosts listed here or anonymously. Passwords and tokens are stored encrypted and never shown again;
          use a token that can only read images. <Link to={`/orgs/${orgId}/settings`}>Back to Settings</Link>
        </p>
        <Card flush aria-label="Registry credentials">
          {body}
        </Card>
      </div>

      <Dialog
        open={dialog?.type === "add" || dialog?.type === "edit"}
        onClose={() => setDialog(null)}
        title={dialog?.type === "edit" ? `Change the credentials for ${dialog.cred.host}` : "Add registry credentials"}
      >
        {(dialog?.type === "add" || dialog?.type === "edit") && (
          <CredentialDialog cred={dialog.type === "edit" ? dialog.cred : null} items={items} onDone={() => setDialog(null)} />
        )}
      </Dialog>
      <Dialog open={dialog?.type === "delete"} onClose={() => setDialog(null)} title={dialog?.type === "delete" ? `Delete the credentials for ${dialog.cred.host}?` : "Delete?"}>
        {dialog?.type === "delete" && (
          <DeleteDialog
            cred={dialog.cred}
            onDone={(deletedId) => {
              if (deletedId) setResults(({ [deletedId]: _gone, ...rest }) => rest);
              setDialog(null);
            }}
          />
        )}
      </Dialog>
    </div>
  );
}

function RegistryRow({
  c,
  result,
  testing,
  onTest,
  onEdit,
  onDelete,
}: {
  c: RegistryCredential;
  result: RegistryTestResult | undefined;
  testing: boolean;
  onTest: () => void;
  onEdit: () => void;
  onDelete: () => void;
}) {
  const label = registryErrorLabel(c.last_error);
  const error = registryErrorText(c.last_error);
  return (
    <li className="hook-row registry-row">
      <div className="hook-main">
        <div className="hook-title">
          {/* Text, never a link: the host is what the org typed. */}
          <strong className="hook-name mono">{c.host}</strong>
          {label && (
            <DotMark tone="danger">
              <span className="danger-text">{label}</span>
            </DotMark>
          )}
        </div>
        <span className="small text-2 hook-meta">
          as <span className="mono">{c.username}</span>
        </span>
        <span className="small muted" title={c.last_used_at ? formatDateTime(c.last_used_at) : undefined}>
          {lastUsedText(c)} · added by {c.created_by ? userName(c.created_by) : "someone no longer in the org"}
        </span>
        {error && <span className="small danger-text">Last attempt: {error}</span>}
        <span className="small registry-test" role="status" aria-live="polite">
          {result && (
            <span className={result.ok ? "success-text" : "danger-text"}>
              <strong>Test:</strong> {testResultText(result, c.host)}
            </span>
          )}
        </span>
      </div>
      <div className="hook-actions">
        <Button size="sm" busy={testing} onClick={onTest}>
          Test
          <span className="visually-hidden"> the credentials for {c.host}</span>
        </Button>
        <Button size="sm" onClick={onEdit}>
          Change
          <span className="visually-hidden"> the credentials for {c.host}</span>
        </Button>
        <Button size="sm" variant="ghost" onClick={onDelete}>
          <span className="danger-text">Delete</span>
          <span className="visually-hidden"> the credentials for {c.host}</span>
        </Button>
      </div>
    </li>
  );
}

// ---- Add / change ----

function CredentialDialog({ cred, items, onDone }: { cred: RegistryCredential | null; items: RegistryCredential[]; onDone: () => void }) {
  const { orgId } = useOrgCtx();
  const editing = !!cred;
  const [form, dispatch] = useReducer(credentialFormReducer, cred ? formFromCredential(cred) : NEW_CREDENTIAL_FORM);
  const [errors, setErrors] = useState<Partial<Record<keyof CredentialForm, string>>>({});
  // The password was in the last request, and the field was cleared: say so if it failed.
  const [passwordSent, setPasswordSent] = useState(false);
  const formRef = useRef<HTMLFormElement>(null);
  // The request body (with the password) is handed to the mutation through these refs, never as
  // mutation variables, and dropped once the request has an answer.
  const createRef = useRef<CreateRegistryCredentialBody | null>(null);
  const updateRef = useRef<UpdateRegistryCredentialBody | null>(null);
  const create = useCreateRegistry(orgId, () => createRef.current!);
  const update = useUpdateRegistry(orgId, cred?.id ?? "", () => updateRef.current!);
  const mutation = editing ? update : create;

  const server = fieldErrors(mutation.error);
  const shown = { ...server, ...errors };
  const set = (patch: Partial<CredentialForm>) => dispatch({ type: "set", patch });
  const host = editing ? cred.host : tidyHost(form.host);

  const close = () => {
    createRef.current = null;
    updateRef.current = null;
    dispatch({ type: "reset", form: NEW_CREDENTIAL_FORM });
    onDone();
  };

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const v = validateCredentialForm(form, editing);
    setErrors(v);
    if (Object.keys(v).length) {
      focusFirstInvalid(formRef.current);
      return;
    }
    const settled = () => {
      createRef.current = null;
      updateRef.current = null;
    };
    if (cred) {
      const b = updateCredentialBody(form, cred);
      if (!b) {
        close();
        return;
      }
      updateRef.current = b;
      setPasswordSent(!!b.password);
      dispatch({ type: "submitted" });
      update.mutate(undefined, {
        onSettled: settled,
        onSuccess: (c) => {
          showToast({ tone: "success", message: `Credentials for ${c.host} saved.${b.password ? " Test them to check the new password." : ""}` });
          close();
        },
        onError: () => focusFirstInvalid(formRef.current),
      });
    } else {
      createRef.current = createCredentialBody(form);
      setPasswordSent(true);
      dispatch({ type: "submitted" });
      create.mutate(undefined, {
        onSettled: settled,
        onSuccess: (c) => {
          showToast({ tone: "success", message: `Credentials for ${c.host} added. Test them to check that the registry accepts them.` });
          close();
        },
        onError: () => focusFirstInvalid(formRef.current),
      });
    }
  };

  const passwordCleared = passwordSent && !!mutation.error && !form.password;

  return (
    <form ref={formRef} className="form-grid" onSubmit={submit} noValidate autoComplete="off">
      {editing ? (
        <p className="small text-2">
          Host: <strong className="mono">{cred.host}</strong> <span className="muted">(can't be changed; delete these and add new ones for another host)</span>
        </p>
      ) : (
        <TextField
          label="Registry host"
          value={form.host}
          maxLength={REGISTRY_HOST_MAX + 20}
          onChange={(e) => set({ host: e.target.value })}
          error={shown.host}
          placeholder="ghcr.io"
          autoComplete="off"
          autoCapitalize="none"
          spellCheck={false}
          className="mono"
          hint="The host (and port) as in the image reference, such as ghcr.io or registry.example.com:5000. No https:// or path. One set of credentials per host."
        />
      )}
      <TextField
        label="Username"
        value={form.username}
        maxLength={REGISTRY_USERNAME_MAX + 20}
        onChange={(e) => set({ username: e.target.value })}
        error={shown.username}
        autoComplete="off"
        autoCapitalize="none"
        spellCheck={false}
      />
      <TextField
        label={editing ? "New password or token (optional)" : "Password or access token"}
        type="password"
        value={form.password}
        maxLength={REGISTRY_PASSWORD_MAX + 1}
        onChange={(e) => set({ password: e.target.value })}
        error={shown.password}
        // A new secret for a third-party registry: not this site's sign-in, so the browser
        // shouldn't fill or offer to save the user's own password here.
        autoComplete="new-password"
        autoCapitalize="none"
        spellCheck={false}
        hint={
          passwordCleared
            ? "The field was cleared when you saved. Enter the password or token again."
            : editing
              ? "Leave empty to keep the stored one. Warden never shows it."
              : "Use a token that can only read (pull) images. Warden stores it encrypted and never shows it again."
        }
      />
      <p className="note">
        <LockIcon size={14} />
        <span>
          Warden uses these only to pull images by digest from {host || "this host"}, and records the host and username in the audit log, never the
          password. API tokens can't read or change them.
        </span>
      </p>
      <ActionError
        error={mutation.error}
        overrides={{
          VALIDATION_FAILED: "Some fields need attention.",
          SECRETS_KEY_MISSING: REGISTRY_SECRETS_KEY_MISSING,
          CONFLICT: registryConflictText(items, host),
        }}
      />
      {leftoverFieldErrors(mutation.error, ["host", "username", "password"]).map((m) => (
        <div key={m} className="banner banner-error" role="alert">
          {m}
        </div>
      ))}
      <div className="dialog-actions">
        <Button onClick={close} disabled={mutation.isPending}>
          Cancel
        </Button>
        <Button type="submit" variant="primary" busy={mutation.isPending}>
          {editing ? "Save changes" : "Add credentials"}
        </Button>
      </div>
    </form>
  );
}

function DeleteDialog({ cred: c, onDone }: { cred: RegistryCredential; onDone: (deletedId: string | null) => void }) {
  const { orgId } = useOrgCtx();
  const del = useDeleteRegistry(orgId);
  return (
    <div className="form-grid">
      <p>
        Delete the credentials for <strong className="mono">{c.host}</strong> (<span className="mono">{c.username}</span>)? Scans then pull images
        from {c.host} anonymously, so private images there fail with “registry refused access”. This can't be undone.
      </p>
      <p className="faint small">
        Added {formatDateTime(c.created_at)}
        {c.created_by ? ` by ${userName(c.created_by)}` : ""}. {lastUsedText(c)}.
      </p>
      <ActionError error={del.error} />
      <div className="dialog-actions">
        <Button onClick={() => onDone(null)} disabled={del.isPending}>
          Cancel
        </Button>
        <Button
          variant="danger"
          busy={del.isPending}
          onClick={() =>
            del.mutate(c.id, {
              onSuccess: () => {
                showToast({ tone: "success", message: `Credentials for ${c.host} deleted.` });
                onDone(c.id);
              },
            })
          }
        >
          Delete credentials
        </Button>
      </div>
    </div>
  );
}
