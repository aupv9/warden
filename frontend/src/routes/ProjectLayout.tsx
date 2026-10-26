import { createContext, useContext } from "react";
import { Link, NavLink, Outlet, useParams } from "react-router";
import { useProject } from "../api/hooks/projects";
import type { Project } from "../api/types";
import { Card } from "../components/Card";
import { ErrorState, Skeleton } from "../components/States";
import { useOrgCtx } from "../layout/OrgLayout";
import { TOOL_LABELS, formatDate } from "../lib/format";
import { PROJECT_ROLE_LABELS } from "../lib/permissions";
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
  const { orgId } = useOrgCtx();
  const { projectId = "" } = useParams();
  const project = useProject(orgId, projectId);
  usePageTitle(project.data?.name);
  const base = `/orgs/${orgId}/projects/${projectId}`;

  return (
    <>
      <header className="stack" style={{ gap: 8 }}>
        <nav className="breadcrumb" aria-label="Breadcrumb">
          <Link to={`/orgs/${orgId}/projects`}>Projects</Link> / <span className="mono">{project.data?.key ?? "…"}</span>
        </nav>
        <h1>{project.data ? project.data.name : <Skeleton width={260} height={30} />}</h1>
      </header>
      {project.isError ? (
        <ErrorState error={project.error} onRetry={() => void project.refetch()} what="this project" />
      ) : (
        <>
          <nav className="tabs" aria-label="Project">
            <NavLink to={`${base}/issues`}>Issues</NavLink>
            <NavLink to={`${base}/scans`}>Scans</NavLink>
            <NavLink to={`${base}/members`}>Members</NavLink>
            <NavLink to={`${base}/settings`}>Settings</NavLink>
          </nav>
          {project.data ? (
            <ProjectContext value={project.data}>
              <Outlet />
            </ProjectContext>
          ) : (
            <Card>
              <Skeleton height={120} />
            </Card>
          )}
        </>
      )}
    </>
  );
}

export function ProjectIssuesTab() {
  const project = useProjectCtx();
  return <IssueList fixedProject={project} />;
}

export function ProjectMembersTab() {
  const project = useProjectCtx();
  return <ProjectRolesCard fixedProject={project} />;
}

export function ProjectSettingsTab() {
  const p = useProjectCtx();
  return (
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
      <p className="muted" style={{ marginTop: 16, fontSize: 13 }}>
        Editing project settings and archiving projects aren't available in v0.1.
      </p>
    </Card>
  );
}
