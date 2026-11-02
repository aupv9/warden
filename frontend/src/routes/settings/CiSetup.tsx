import { useId, useRef, useState } from "react";
import type { KeyboardEvent } from "react";
import type { Project } from "../../api/types";
import { Card } from "../../components/Card";
import { CopyButton } from "../../components/CopyButton";
import { useOrgCtx } from "../../layout/OrgLayout";
import { githubActionsSnippet, gitlabCiSnippet, serverUrl } from "../../lib/ciSnippets";

type Ci = "github" | "gitlab";
const TABS: { id: Ci; label: string }[] = [
  { id: "github", label: "GitHub Actions" },
  { id: "gitlab", label: "GitLab CI" },
];

/** CI setup: a snippet per CI system with the org and project IDs filled in. The token is a
 *  CI secret variable (WARDEN_TOKEN) and never appears in a snippet. */
export function CiSetupCard({ project, canManage }: { project: Project; canManage: boolean }) {
  const { orgId } = useOrgCtx();
  const [tab, setTab] = useState<Ci>("github");
  // v0.4 wave 2: both switches only change the snippet; nothing is saved.
  const [comment, setComment] = useState(false);
  const [history, setHistory] = useState(false);
  const id = useId();
  const tabRefs = useRef<Record<Ci, HTMLButtonElement | null>>({ github: null, gitlab: null });
  const preRef = useRef<HTMLPreElement>(null);
  const params = { url: serverUrl(), orgId, projectId: project.id, comment, history };
  const snippet = tab === "github" ? githubActionsSnippet(params) : gitlabCiSnippet(params);

  // Tabs pattern: arrow keys move between tabs, the selected tab is the one in the tab order.
  const onKey = (e: KeyboardEvent<HTMLButtonElement>) => {
    if (e.key !== "ArrowLeft" && e.key !== "ArrowRight" && e.key !== "Home" && e.key !== "End") return;
    e.preventDefault();
    const i = TABS.findIndex((t) => t.id === tab);
    const next =
      e.key === "Home" ? TABS[0]! : e.key === "End" ? TABS[TABS.length - 1]! : TABS[(i + (e.key === "ArrowRight" ? 1 : TABS.length - 1)) % TABS.length]!;
    setTab(next.id);
    tabRefs.current[next.id]?.focus();
  };

  const selectSnippet = () => {
    const pre = preRef.current;
    if (!pre) return;
    const range = document.createRange();
    range.selectNodeContents(pre);
    const sel = window.getSelection();
    sel?.removeAllRanges();
    sel?.addRange(range);
  };

  return (
    <Card title="CI setup" titleId="ci-h" id="ci-setup">
      <ol className="steps">
        <li>
          {canManage ? "Create a token above" : "Ask a project owner or security lead for a token"} with the{" "}
          <code>scan:write</code> scope.
        </li>
        <li>
          Save it in your CI as a secret variable named <code>WARDEN_TOKEN</code>. Never commit it.
        </li>
        <li>Add this job. It uploads the repository, waits for the scan and checks the gate.</li>
      </ol>
      <ul className="pref-list ci-switches" aria-label="Snippet options">
        <li>
          <label className="pref-row">
            <span className="pref-text">
              <strong>Comment on pull requests / merge requests</strong>
              <span className="muted">
                Adds <code>--comment auto</code>: one comment with the counts and the blocking issues (severity, rule, file and line,
                a link), the new ones marked, updated in place on every run. It never contains code, descriptions or secrets.{" "}
                {tab === "github" ? (
                  <>
                    The job gets <code>pull-requests: write</code> and its own <code>GITHUB_TOKEN</code> posts the comment.
                  </>
                ) : (
                  <>
                    Needs a project access token with the <code>api</code> scope, stored as the masked variable{" "}
                    <code>WARDEN_GITLAB_TOKEN</code> (<code>CI_JOB_TOKEN</code> can't write notes); the job also runs in merge request
                    pipelines.
                  </>
                )}{" "}
                Warden itself keeps no GitHub or GitLab credentials.
              </span>
            </span>
            <span className="switch">
              <input type="checkbox" role="switch" checked={comment} onChange={(e) => setComment(e.target.checked)} />
              <span className="switch-track" aria-hidden="true" />
            </span>
          </label>
        </li>
        <li>
          <label className="pref-row">
            <span className="pref-text">
              <strong>Scan git history</strong>
              <span className="muted">
                Adds a nightly job on the default branch that checks out the full history (
                {tab === "github" ? <code>fetch-depth: 0</code> : <code>GIT_DEPTH: 0</code>}) and runs{" "}
                <code>warden scan --history</code>: Gitleaks reads every commit, so secrets deleted long ago are found too.
                {tab === "gitlab" && " Create a pipeline schedule for the default branch to run it."}
              </span>
            </span>
            <span className="switch">
              <input type="checkbox" role="switch" checked={history} onChange={(e) => setHistory(e.target.checked)} />
              <span className="switch-track" aria-hidden="true" />
            </span>
          </label>
        </li>
      </ul>
      <div className="snippet">
        <div className="snippet-bar">
          <div className="segmented" role="tablist" aria-label="CI system">
            {TABS.map((t) => (
              <button
                key={t.id}
                ref={(el) => {
                  tabRefs.current[t.id] = el;
                }}
                type="button"
                role="tab"
                id={`${id}-${t.id}`}
                aria-selected={tab === t.id}
                aria-controls={`${id}-panel`}
                tabIndex={tab === t.id ? 0 : -1}
                onClick={() => setTab(t.id)}
                onKeyDown={onKey}
              >
                {t.label}
              </button>
            ))}
          </div>
          <CopyButton text={snippet} label="Copy" copiedText="Snippet copied to the clipboard." onFailed={selectSnippet} />
        </div>
        <pre
          ref={preRef}
          id={`${id}-panel`}
          role="tabpanel"
          aria-labelledby={`${id}-${tab}`}
          className="snippet-code"
          tabIndex={0}
        >
          {snippet}
        </pre>
      </div>
      <p className="muted small" style={{ marginTop: 10 }}>
        The job fails when the scan has active issues at or above <code>--fail-on</code> (exit code 1), or when the scan can't
        finish (exit code 2). False positives and accepted risks never block. The CLI zips git-tracked and untracked, not-ignored
        files only.
      </p>
    </Card>
  );
}
