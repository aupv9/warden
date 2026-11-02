import { describe, expect, it } from "vitest";
import { githubActionsSnippet, gitlabCiSnippet } from "./ciSnippets";
import { commitsText, HISTORY_TARGET, historyWhere, isHistoryIssue, moreCommitsText, shortSha } from "./history";
import { describeFilters, DEFAULT_FILTERS, issueFiltersToApiQuery, parseIssueFilters } from "./issueFilters";
import { isRejected, scanErrorMessages } from "./scanErrors";
import { buildQuery } from "../api/client";

const SHA = Array.from({ length: 40 }, (_, i) => "0123456789abcdef"[(i * 7) % 16]).join("");

describe("secrets in git history", () => {
  it("history issues are the ones with the (history) target", () => {
    expect(isHistoryIssue({ target: HISTORY_TARGET })).toBe(true);
    expect(isHistoryIssue({ target: "" })).toBe(false);
    expect(isHistoryIssue({ target: "ghcr.io/acme/api" })).toBe(false);
  });

  it("shortens only a well-formed sha; anything else stays as it came (shown as text)", () => {
    expect(shortSha(SHA)).toBe(SHA.slice(0, 7));
    expect(shortSha(SHA + SHA.slice(0, 24))).toBe(SHA.slice(0, 7));
    const hostile = 'abc1234"><img src=x onerror=alert(1)>';
    expect(shortSha(hostile)).toBe(hostile);
    expect(shortSha(SHA.toUpperCase())).toBe(SHA.toUpperCase());
  });

  it("words: more commits, commits scanned, where", () => {
    expect(moreCommitsText(1)).toBeNull();
    expect(moreCommitsText(3)).toBe("and in 2 more commits");
    expect(moreCommitsText(2)).toBe("and in 1 more commit");
    expect(commitsText(2481)).toBe("2,481 commits");
    expect(commitsText(1)).toBe("1 commit");
    expect(historyWhere({ file_path: "scripts/deploy.sh", start_line: 7, commit: { sha: SHA, committed_at: null, count: 3 } })).toBe(
      `scripts/deploy.sh:7 in commit ${SHA.slice(0, 7)}`,
    );
    expect(historyWhere({ file_path: null, start_line: null, commit: null })).toBe("");
  });

  it("the Source filter takes history; a (history) target in the URL is not an image", () => {
    const f = parseIssueFilters(new URLSearchParams("source=history&target=(history)"));
    expect(f).toEqual({ ...DEFAULT_FILTERS, source: "history" });
    expect(buildQuery(issueFiltersToApiQuery(f))).toBe("?source=history&limit=50");
    expect(describeFilters(f)).toContain("Git history");
    expect(parseIssueFilters(new URLSearchParams("source=bundle")).source).toBe("");
  });

  it("BUNDLE_* rejections are Rejected, with their words", () => {
    for (const code of ["BUNDLE_INVALID", "BUNDLE_INCOMPLETE", "BUNDLE_TOO_LARGE"]) {
      expect(isRejected({ status: "failed", error_code: code })).toBe(true);
    }
    expect(isRejected({ status: "failed", error_code: "ALL_SCANNERS_FAILED" })).toBe(false);
    expect(scanErrorMessages("BUNDLE_INVALID").short).toBe("not a git bundle");
    expect(scanErrorMessages("BUNDLE_INCOMPLETE")).toEqual({ short: "shallow clone", full: expect.stringContaining("fetch-depth: 0 (GitHub) or GIT_DEPTH: 0 (GitLab)") });
    expect(scanErrorMessages("BUNDLE_TOO_LARGE").full).toMatch(/Ask your operator about the limit/);
  });
});

describe("CI setup snippets (v0.4 wave 2 switches)", () => {
  const p = { url: "https://warden.acme.example", orgId: "o-1", projectId: "p-1" };
  // A Warden token, a GitHub token or a GitLab token written out (not read from a variable).
  const TOKEN_LIKE = /wdn_[a-z2-7]{8}_|gh[pousr]_[A-Za-z0-9]{20,}|glpat-[A-Za-z0-9_-]{20,}|whsec_/;

  it("by default: no comment, no history job", () => {
    for (const s of [githubActionsSnippet(p), gitlabCiSnippet(p)]) {
      expect(s).not.toContain("--comment");
      expect(s).not.toContain("--history");
      expect(s).not.toMatch(TOKEN_LIKE);
    }
    expect(githubActionsSnippet(p)).not.toContain("pull-requests: write");
  });

  it("GitHub: the comment needs pull-requests: write and the job's own GITHUB_TOKEN", () => {
    const s = githubActionsSnippet({ ...p, comment: true });
    expect(s).toContain("--comment auto");
    expect(s).toContain("pull-requests: write");
    expect(s).toContain("GITHUB_TOKEN: ${{ github.token }}");
    expect(s).toContain("WARDEN_TOKEN: ${{ secrets.WARDEN_TOKEN }}");
    expect(s).not.toMatch(TOKEN_LIKE);
  });

  it("GitLab: the comment needs WARDEN_GITLAB_TOKEN (CI_JOB_TOKEN can't write notes) and merge request pipelines", () => {
    const s = gitlabCiSnippet({ ...p, comment: true });
    expect(s).toContain("--comment auto");
    expect(s).toContain("WARDEN_GITLAB_TOKEN");
    expect(s).toContain("CI_JOB_TOKEN can't write merge request notes");
    expect(s).toContain('$CI_PIPELINE_SOURCE == "merge_request_event"');
    expect(s).not.toMatch(TOKEN_LIKE);
  });

  it("history: a nightly job on the default branch with the full history and warden scan --history", () => {
    const gh = githubActionsSnippet({ ...p, history: true });
    expect(gh).toMatch(/schedule:\n {4}- cron: "23 2 \* \* \*"/);
    expect(gh).toContain("fetch-depth: 0");
    expect(gh).toContain('"$RUNNER_TEMP/warden" scan --history');
    expect(gh).toContain("if: github.event_name == 'schedule'");
    expect(gh).toContain("if: github.event_name != 'schedule'");
    // The history job doesn't comment, even with both switches on.
    const both = githubActionsSnippet({ ...p, history: true, comment: true });
    expect(both.split("  history:")[1]).not.toContain("--comment");

    const gl = gitlabCiSnippet({ ...p, history: true });
    expect(gl).toContain("warden-history:");
    expect(gl).toContain("GIT_DEPTH: 0");
    expect(gl).toContain("./warden scan --history --url https://warden.acme.example --org o-1 --project p-1");
    expect(gl).toContain('$CI_PIPELINE_SOURCE == "schedule" && $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH');
    expect(gl).not.toMatch(TOKEN_LIKE);
  });
});
