import { useState } from "react";
import type { FormEvent } from "react";
import { Link, useNavigate } from "react-router";
import { fieldErrors, leftoverFieldErrors } from "../api/errors";
import { useOrgSummary } from "../api/hooks/orgs";
import { useCreateProject, useProjects } from "../api/hooks/projects";
import { SEVERITIES, TOOLS } from "../api/types";
import type { Project, Tool } from "../api/types";
import { ProjectDot } from "../components/Avatar";
import { Pill, SeverityMark } from "../components/Badges";
import { Button, ButtonLink } from "../components/Button";
import { Card } from "../components/Card";
import { Dialog } from "../components/Dialog";
import { focusFirstInvalid, TextArea, TextField } from "../components/Field";
import { PlusIcon, SearchIcon } from "../components/Icons";
import { PageHeader } from "../components/PageHeader";
import { ActionError, EmptyState, ErrorState, Skeleton, SkeletonCards } from "../components/States";
import { showToast } from "../lib/toast";
import { useOrgCtx } from "../layout/OrgLayout";
import { relativeTime, SCAN_STATUS_LABELS, TOOL_KIND, TOOL_LABELS } from "../lib/format";
import { can, PROJECT_ROLE_LABELS } from "../lib/permissions";
import { usePageTitle } from "../lib/usePageTitle";

export function ProjectsPage() {
  usePageTitle("Projects");
  const { orgId, org } = useOrgCtx();
  const projects = useProjects(orgId);
  const [search, setSearch] = useState("");
  const [creating, setCreating] = useState(false);
  const canCreate = can("create_archive_project", org.role);

  const term = search.trim().toLowerCase();
  const shown = (projects.data ?? []).filter(
    (p) => !term || p.name.toLowerCase().includes(term) || p.key.toLowerCase().includes(term),
  );

  return (
    <div className="page">
      <PageHeader
        title="Projects"
        actions={
          <>
            <label className="search">
              <SearchIcon />
              <span className="visually-hidden">Search projects</span>
              <input type="search" placeholder="Search projects" value={search} onChange={(e) => setSearch(e.target.value)} />
            </label>
            {canCreate && (
              <Button variant="primary" onClick={() => setCreating(true)}>
                <PlusIcon /> New project
              </Button>
            )}
          </>
        }
      />
      <div className="page-body">
        <Summary />

        {projects.isPending ? (
          <SkeletonCards label="projects" />
        ) : projects.isError ? (
          <ErrorState error={projects.error} onRetry={() => void projects.refetch()} what="the projects" />
        ) : projects.data.length === 0 ? (
          <Card>
            <EmptyState
              title="No projects yet"
              action={
                canCreate ? (
                  <Button variant="primary" onClick={() => setCreating(true)}>
                    New project
                  </Button>
                ) : undefined
              }
            >
              {canCreate
                ? "Create a project, then upload a .zip of its code to scan it."
                : "You aren't a member of any project. Ask a project owner or a security lead to add you."}
            </EmptyState>
          </Card>
        ) : shown.length === 0 ? (
          <Card>
            <EmptyState title="No matching projects">Nothing matches "{search}".</EmptyState>
          </Card>
        ) : (
          <div className="grid grid-cards">
            {shown.map((p) => (
              <ProjectCard key={p.id} project={p} />
            ))}
          </div>
        )}

        <p className="faint small">Only projects you are a member of are listed. Org admins and security leads see every project.</p>
      </div>

      <Dialog open={creating} onClose={() => setCreating(false)} title="New project">
        <NewProjectForm onDone={() => setCreating(false)} />
      </Dialog>
    </div>
  );
}

function Summary() {
  const { orgId } = useOrgCtx();
  const summary = useOrgSummary(orgId);
  if (summary.isError) return <ActionError always error={summary.error} />;
  const s = summary.data;
  const stats: { label: string; value?: number; danger?: boolean; to: string }[] = [
    { label: "Open issues", value: s?.open_issues, to: `/orgs/${orgId}/issues` },
    { label: "Critical + High open", value: s?.critical_high_open, to: `/orgs/${orgId}/issues?severity=critical&severity=high` },
    { label: "Past SLA", value: s?.past_sla, danger: true, to: `/orgs/${orgId}/issues?past_sla=true` },
    { label: "Exceptions to review", value: s?.exceptions_pending, to: `/orgs/${orgId}/exceptions` },
  ];
  return (
    <section aria-label="Organization summary" className="stat-strip">
      {stats.map((st) => (
        <div key={st.label} className="stat">
          <Link to={st.to} className="stat-label">
            {st.label}
          </Link>
          <div className={st.danger && (st.value ?? 0) > 0 ? "stat-value danger-text" : "stat-value"}>
            {st.value === undefined ? <Skeleton width={40} height={22} /> : st.value}
          </div>
        </div>
      ))}
    </section>
  );
}

function ProjectCard({ project: p }: { project: Project }) {
  const { orgId, org } = useOrgCtx();
  const base = `/orgs/${orgId}/projects/${p.id}`;
  const counts = SEVERITIES.filter((s) => p.open_by_severity[s] > 0);
  const head = (
    <div className="pc-head">
      <ProjectDot projectKey={p.key} />
      <h2>
        <Link to={base} className="stretched">
          {p.name}
        </Link>
      </h2>
      <span className="mono faint pc-key">{p.key}</span>
      {p.my_role && <Pill>{PROJECT_ROLE_LABELS[p.my_role]}</Pill>}
    </div>
  );

  if (!p.last_scan) {
    const canScan = can("run_scan", org.role, p.my_role);
    return (
      <article className="project-card dashed">
        {head}
        <p className="muted">No scan yet. Upload the first .zip to see issues here.</p>
        {canScan && (
          <div className="pc-action">
            <ButtonLink to={`${base}/scans`} size="sm">
              Upload code
            </ButtonLink>
          </div>
        )}
      </article>
    );
  }

  return (
    <article className="project-card">
      {head}
      <div className="pc-sev" aria-label="Open issues by severity">
        {counts.length === 0 ? (
          <span className="muted">No open issues</span>
        ) : (
          counts.map((s) => <SeverityMark key={s} severity={s} count={p.open_by_severity[s]} />)
        )}
      </div>
      <div className="pc-foot">
        <span>
          Last scan {relativeTime(p.last_scan.created_at)} · {SCAN_STATUS_LABELS[p.last_scan.status].toLowerCase()}
        </span>
        {p.past_sla > 0 ? <span className="danger-text">{p.past_sla} past SLA</span> : <span>On track</span>}
      </div>
    </article>
  );
}

const KEY_RE = /^[A-Z][A-Z0-9]{1,9}$/;

function NewProjectForm({ onDone }: { onDone: () => void }) {
  const { orgId } = useOrgCtx();
  const navigate = useNavigate();
  const create = useCreateProject(orgId);
  const [key, setKey] = useState("");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [tools, setTools] = useState<Tool[]>([...TOOLS]);
  const [touched, setTouched] = useState(false);

  const server = fieldErrors(create.error);
  const leftover = leftoverFieldErrors(create.error, ["key", "name", "description", "default_tools"]);
  const keyError =
    touched && !KEY_RE.test(key) ? "Use 2 to 10 capital letters or digits, starting with a letter (WEB, PAY2)." : server.key;
  const nameError = touched && !name.trim() ? "Enter a name." : server.name;
  const toolsError = touched && tools.length === 0 ? "Choose at least one scanner." : server.default_tools;

  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = e.currentTarget;
    setTouched(true);
    if (!KEY_RE.test(key) || !name.trim() || tools.length === 0) return focusFirstInvalid(form);
    const project = await create
      .mutateAsync({
        key,
        name: name.trim(),
        ...(description.trim() ? { description: description.trim() } : {}),
        default_tools: tools,
      })
      .catch(() => undefined);
    if (project) {
      showToast({ tone: "success", message: `Project ${project.key} created. Upload a .zip to run the first scan.` });
      onDone();
      navigate(`/orgs/${orgId}/projects/${project.id}/scans`);
    } else focusFirstInvalid(form);
  }

  return (
    <form className="form-grid" onSubmit={submit} noValidate>
      <ActionError
        error={create.error && Object.keys(server).length === 0 ? create.error : null}
        overrides={{ CONFLICT: `A project with key ${key} already exists.` }}
      />
      {leftover.length > 0 && (
        <div className="banner banner-error" role="alert">
          {leftover.join(" ")}
        </div>
      )}
      <div className="grid" style={{ gridTemplateColumns: "minmax(0, 1fr) minmax(0, 2fr)", gap: 12 }}>
        <TextField
          label="Key"
          value={key}
          onChange={(e) => setKey(e.target.value.toUpperCase())}
          error={keyError}
          maxLength={10}
          autoComplete="off"
          className="mono"
          required
        />
        <TextField label="Name" value={name} onChange={(e) => setName(e.target.value)} error={nameError} maxLength={200} required />
      </div>
      <p className="muted" style={{ fontSize: 12, marginTop: -8 }}>
        2 to 10 capital letters or digits, starting with a letter. Issue keys use it (WEB-41). It can't be changed later.
      </p>
      <TextArea
        label={
          <>
            Description <span className="muted" style={{ fontWeight: 400 }}>(optional)</span>
          </>
        }
        value={description}
        onChange={(e) => setDescription(e.target.value)}
        maxLength={2000}
      />
      <fieldset>
        <legend>
          Default scanners <span className="muted" style={{ fontWeight: 400 }}>(at least one; can be changed per scan)</span>
        </legend>
        <div className="checks-grid">
          {TOOLS.map((t) => (
            <label key={t} className="checkbox-card">
              <input
                type="checkbox"
                checked={tools.includes(t)}
                onChange={(e) => setTools(e.target.checked ? TOOLS.filter((x) => x === t || tools.includes(x)) : tools.filter((x) => x !== t))}
              />
              <span>
                <strong>{TOOL_LABELS[t]}</strong> <span className="muted">{TOOL_KIND[t]}</span>
              </span>
            </label>
          ))}
        </div>
        {toolsError && (
          <p className="field" style={{ marginTop: 8 }}>
            <span className="error">{toolsError}</span>
          </p>
        )}
      </fieldset>
      <div className="dialog-actions">
        <Button onClick={onDone}>Cancel</Button>
        <Button type="submit" variant="primary" busy={create.isPending}>
          Create project
        </Button>
      </div>
    </form>
  );
}
