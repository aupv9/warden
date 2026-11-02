import { Suspense } from "react";
import { Link, NavLink, Outlet, useLocation, useParams } from "react-router";
import { useProject } from "../api/hooks/projects";
import { ProjectDot } from "../components/Avatar";
import { ButtonLink } from "../components/Button";
import { Card } from "../components/Card";
import { ArchiveIcon, UploadIcon } from "../components/Icons";
import { PageHeader, Segmented } from "../components/PageHeader";
import { ErrorState, RouteFallback, Skeleton } from "../components/States";
import { useOrgCtx } from "../layout/OrgLayout";
import { formatDate } from "../lib/format";
import { can } from "../lib/permissions";
import { usePageTitle } from "../lib/usePageTitle";
import { IssueList } from "./IssueList";
import { ProjectRolesCard } from "./ProjectRoles";
import { ProjectContext, useProjectCtx } from "./projectCtx";

export { useProjectCtx } from "./projectCtx";

export function ProjectLayout() {
  const { orgId, org } = useOrgCtx();
  const { projectId = "" } = useParams();
  const { pathname } = useLocation();
  const project = useProject(orgId, projectId);
  usePageTitle(project.data?.name);
  const base = `/orgs/${orgId}/projects/${projectId}`;
  const archived = !!project.data?.archived_at;
  const canScan = !!project.data && can("run_scan", org.role, project.data.my_role) && !archived;
  const onScans = pathname.startsWith(`${base}/scans`);
  const onSettings = pathname.startsWith(`${base}/settings`);

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
                {archived && (
                  <span className="tag crumb-tag">
                    <ArchiveIcon size={12} /> Archived
                  </span>
                )}
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
            <NavLink to={`${base}/components`}>Components</NavLink>
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
          {archived && (
            <div className="archived-banner" role="status">
              <ArchiveIcon size={15} />
              <span>
                <strong>Archived {formatDate(project.data.archived_at)}.</strong> This project takes no new scans. Its issues
                and history stay readable.
              </span>
              {can("create_archive_project", org.role) && !onSettings && (
                <Link to={`${base}/settings#archive`} className="archived-banner-link">
                  Unarchive…
                </Link>
              )}
            </div>
          )}
          <Suspense fallback={<RouteFallback />}>
            <Outlet />
          </Suspense>
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
