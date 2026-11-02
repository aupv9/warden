import type { Issue, IssueSummary, Scan } from "../api/types";

// v0.4 wave 2: secrets found in git history. A history scan (`warden scan --history`, CLI only)
// uploads a `git bundle` and runs Gitleaks over every commit; its issues have the target
// `(history)`, so source scans and history scans never fix each other's issues.
//
// The UI doesn't know where the repository is hosted, so a commit sha is shown as text with a
// copy button, never as a link. Shas come from the scanned repository: anything that isn't a
// plain hex object id is shown as it is (text), never shortened into something it isn't.

/** The target of every history scan and its issues. Parentheses can't occur in an image
 *  repository, so it never collides with an image target. */
export const HISTORY_TARGET = "(history)";

export const HISTORY_ROTATE =
  "Rotate this secret. Deleting the file or the line doesn't remove it from history; anyone with a clone still has it.";

/** SHA-1 (40) or SHA-256 (64) object ids, lowercase hex as git prints them. */
const SHA_RE = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;

export function isHistoryIssue(i: Pick<IssueSummary, "target">): boolean {
  return i.target === HISTORY_TARGET;
}

export function isHistoryScan(s: Pick<Scan, "kind">): boolean {
  return s.kind === "history";
}

/** "abc1234" for a well-formed sha; anything else unchanged (it is rendered as text either way). */
export function shortSha(sha: string): string {
  return SHA_RE.test(sha) ? sha.slice(0, 7) : sha;
}

/** "in 3 commits" style count text for the "and in n more commits" line; null when only one. */
export function moreCommitsText(count: number): string | null {
  if (!Number.isFinite(count) || count <= 1) return null;
  const more = Math.floor(count) - 1;
  return `and in ${more.toLocaleString("en-US")} more commit${more === 1 ? "" : "s"}`;
}

/** "2,481 commits" for a finished history scan. */
export function commitsText(n: number): string {
  return `${n.toLocaleString("en-US")} commit${n === 1 ? "" : "s"}`;
}

/** Where a history issue is: "<file>:<line> in commit abc1234". */
export function historyWhere(i: Pick<Issue, "file_path" | "start_line" | "commit">): string {
  const loc = i.file_path ? `${i.file_path}${i.start_line ? `:${i.start_line}` : ""}` : "";
  const sha = i.commit ? shortSha(i.commit.sha) : "";
  return [loc, sha ? `in commit ${sha}` : ""].filter(Boolean).join(" ");
}
