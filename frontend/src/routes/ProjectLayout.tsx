import { createContext, useContext } from "react";
import { Link, NavLink, Outlet, useLocation, useParams } from "react-router";
import { useProject } from "../api/hooks/projects";
import type { Project } from "../api/types";
import { ProjectDot } from "../components/Avatar";
import { ButtonLink } from "../components/Button";
import { Card } from "../components/Card";
import { UploadIcon } from "../components/Icons";
import { PageHeader, Segmented } from "../components/PageHeader";
import { ErrorState, Skeleton } from "../components/States";
import { useOrgCtx } from "../layout/OrgLayout";
import { TOOL_LABELS, formatDate } from "../lib/format";
import { can, PROJECT_ROLE_LABELS } from "../lib/permissions";
import { usePageTitle } from "../lib/usePageTitle";
import { IssueList } from "./IssueList";
import { ProjectRolesCard } from "./ProjectRoles";

const ProjectContext = createContext<Project | null>(null);

export function useProjectCtx(): Project {
  const p = useContext(ProjectContext);
  if (!p) throw new Error("useProjectCtx outside ProjectLayout");
  return p;
}

export function ProjectLayout() {
  const { orgId, org } = useOrgCtx();
  const { projectId = "" } = useParams();
  const { pathname } = useLocation();
  const project = useProject(orgId, projectId);
  usePageTitle(project.data?.name);
  const base = `/orgs/${orgId}/projects/${projectId}`;
  const canScan = !!project.data && can("run_scan", org.role, project.data.my_role);
  const onScans = pathname.startsWith(`${base}/scans`);

  return (
    <div className="page">
      <PageHeader
        title={
          <>
            <Link to={`/orgs/${orgId}/projects`} className="crumb-link">
              Projects
            </Link>
            <span className="crumb-sep" aria-hidden="true">
              /
            </span>
            {project.data ? (
              <>
                <ProjectDot projectKey={project.data.key} />
                <span className="ellipsis">{project.data.name}</span>
                <span className="mono faint crumb-key">{project.data.key}</span>
              </>
            ) : (
              <Skeleton width={160} height={14} />
            )}
          </>
        }
        actions={
          canScan && !onScans ? (
            <ButtonLink to={`${base}/scans`} variant="primary">
              <UploadIcon size={14} /> Upload .zip
            </ButtonLink>
          ) : undefined
        }
      >
        {!project.isError && (
          <Segmented label="Project">
            <NavLink to={`${base}/issues`}>Issues</NavLink>
            <NavLink to={`${base}/scans`}>Scans</NavLink>
            <NavLink to={`${base}/members`}>Members</NavLink>
            <NavLink to={`${base}/settings`}>Settings</NavLink>
          </Segmented>
        )}
      </PageHeader>
      {project.isError ? (
        <div className="page-body">
          <ErrorState error={project.error} onRetry={() => void project.refetch()} what="this project" />
        </div>
      ) : project.data ? (
        <ProjectContext value={project.data}>
          <Outlet />
        </ProjectContext>
      ) : (
        <div className="page-body">
          <Card>
            <Skeleton height={120} />
          </Card>
        </div>
      )}
    </div>
  );
}

export function ProjectIssuesTab() {
  const project = useProjectCtx();
  return <IssueList fixedProject={project} />;
}

export function ProjectMembersTab() {
  const project = useProjectCtx();
  return (
    <div className="page-body">
      <ProjectRolesCard fixedProject={project} />
    </div>
  );
}

export function ProjectSettingsTab() {
  const p = useProjectCtx();
  return (
    <div className="page-body">
    <Card title="Settings" titleId="settings-h">
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
      </dl>
      <p className="faint small" style={{ marginTop: 16 }}>
        Editing project settings and archiving projects aren't available in v0.1.
      </p>
    </Card>
    </div>
  );
}
