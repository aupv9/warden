import { useEffect, useState } from "react";
import { useLocation } from "react-router";
import { useSetArchived } from "../api/hooks/projects";
import type { Project } from "../api/types";
import { Button } from "../components/Button";
import { Card } from "../components/Card";
import { Dialog } from "../components/Dialog";
import { ArchiveIcon } from "../components/Icons";
import { ActionError } from "../components/States";
import { useOrgCtx } from "../layout/OrgLayout";
import { formatDate, TOOL_LABELS } from "../lib/format";
import { can, PROJECT_ROLE_LABELS } from "../lib/permissions";
import { showToast } from "../lib/toast";
import { useProjectCtx } from "./projectCtx";
import { AssignRulesCard } from "./settings/AssignRules";
import { CiSetupCard } from "./settings/CiSetup";
import { TokensCard } from "./settings/Tokens";

/** Project Settings tab: general details, API tokens and CI setup, auto-assign rules, archive. */
export function ProjectSettingsTab() {
  const p = useProjectCtx();
  const { org } = useOrgCtx();
  const { hash } = useLocation();
  const manage = can("manage_project_members", org.role, p.my_role);
  const canArchive = can("create_archive_project", org.role);

  // "#archive" from the archived banner: bring the card into view.
  useEffect(() => {
    if (hash === "#archive") document.getElementById("archive")?.scrollIntoView({ block: "start" });
  }, [hash]);

  return (
    <div className="page-body settings-body">
      <Card title="General" titleId="general-h">
        <dl className="kv">
          <dt>Key</dt>
          <dd className="mono">{p.key}</dd>
          <dt>Name</dt>
          <dd>{p.name}</dd>
          <dt>Description</dt>
          <dd className="prose">{p.description ?? <span className="muted">None</span>}</dd>
          <dt>Default scanners</dt>
          <dd>{p.default_tools.map((t) => TOOL_LABELS[t]).join(", ")}</dd>
          <dt>Your role</dt>
          <dd>{p.my_role ? PROJECT_ROLE_LABELS[p.my_role] : "Not a member (org-wide access)"}</dd>
          <dt>Created</dt>
          <dd>{formatDate(p.created_at)}</dd>
          <dt>Status</dt>
          <dd>{p.archived_at ? `Archived ${formatDate(p.archived_at)}` : "Active"}</dd>
        </dl>
      </Card>

      {manage ? (
        <TokensCard project={p} />
      ) : (
        <Card title="API tokens" titleId="tokens-h">
          <p className="muted">Project owners and security leads create API tokens for CI. Ask one of them if you need one.</p>
        </Card>
      )}
      <CiSetupCard project={p} canManage={manage && can("run_scan", org.role, p.my_role)} />
      <AssignRulesCard project={p} canEdit={manage} />
      {canArchive && <ArchiveCard project={p} />}
    </div>
  );
}

function ArchiveCard({ project }: { project: Project }) {
  const { orgId } = useOrgCtx();
  const [confirming, setConfirming] = useState(false);
  const setArchived = useSetArchived(orgId, project.id);
  const archived = !!project.archived_at;
  return (
    <Card title={archived ? "Unarchive project" : "Archive project"} titleId="archive-h" id="archive" className="danger-zone">
      <div className="row-between" style={{ alignItems: "flex-start", gap: 16 }}>
        <p className="muted" style={{ maxWidth: 620 }}>
          {archived
            ? `${project.key} was archived on ${formatDate(project.archived_at)}. Unarchiving lets people upload code and CI tokens run scans again.`
            : `Archiving stops new scans in ${project.key}, from the UI and from CI tokens. Issues, scans and the audit log stay readable, and the project leaves the project list. You can unarchive it at any time.`}
        </p>
        <Button variant={archived ? "ghost" : "danger"} onClick={() => setConfirming(true)}>
          <ArchiveIcon size={14} /> {archived ? "Unarchive…" : "Archive…"}
        </Button>
      </div>
      <Dialog
        open={confirming}
        onClose={() => setConfirming(false)}
        title={archived ? `Unarchive ${project.key}?` : `Archive ${project.key}?`}
      >
        <div className="form-grid">
          <p>
            {archived ? (
              <>
                <strong>{project.name}</strong> comes back to the project list and takes new scans again.
              </>
            ) : (
              <>
                New scans in <strong>{project.name}</strong> are refused, including CI jobs that use its API tokens. Nothing is
                deleted.
              </>
            )}
          </p>
          <ActionError error={setArchived.error} />
          <div className="dialog-actions">
            <Button onClick={() => setConfirming(false)}>Cancel</Button>
            <Button
              variant={archived ? "primary" : "danger"}
              busy={setArchived.isPending}
              onClick={() =>
                setArchived.mutate(!archived, {
                  onSuccess: (p) => {
                    showToast({ tone: "success", message: p.archived_at ? `${p.key} is archived.` : `${p.key} is active again.` });
                    setConfirming(false);
                  },
                })
              }
            >
              {archived ? "Unarchive project" : "Archive project"}
            </Button>
          </div>
        </div>
      </Dialog>
    </Card>
  );
}
