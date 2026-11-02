-- Secrets in git history (v0.4 wave 2).
--
-- * scan.kind history: the upload is a `git bundle` of the repository
--   (`warden scan --history`), never a .git directory. scan/bundlecheck checks
--   it without unpacking it (header, ref count and names, size); git reads it
--   only inside the Gitleaks sandbox, fetching it into a fresh bare repository
--   with no system or global config, so nothing from the upload can configure
--   git (no config, hooks or filters travel in a bundle). Only Gitleaks runs.
-- * A history scan's target is always '(history)': parentheses never occur in
--   an image repository, so it can't collide with one. Auto-fix is per target,
--   so a source scan never fixes a history issue and vice versa. A history
--   issue is fixed only when a later history scan finds the secret in no
--   commit (history rewritten or the branch gone); it needs rotating either way.
-- * One issue per (rule, secret): the fingerprint is the Gitleaks key with file
--   path '(history)' and the HMAC of the secret, so a secret added in 50 commits
--   is one issue. issue.file_path, start_line, commit_sha and committed_at come
--   from the oldest commit that added it; commit_count is how many did. The
--   author, email and commit message are dropped inside the sandbox.
-- * scan.history_commits is how many commits Gitleaks read, history_truncated
--   whether scan.history_max_commits cut the history short (newest kept).

-- +goose Up
ALTER TABLE scan DROP CONSTRAINT scan_kind_check;
ALTER TABLE scan
  ADD CONSTRAINT scan_kind_check CHECK (kind IN ('source', 'image', 'history')),
  ADD CONSTRAINT scan_history_target CHECK ((kind = 'history') = (target = '(history)')),
  ADD CONSTRAINT scan_history_tools CHECK (kind <> 'history' OR tools = '{gitleaks}'),
  ADD COLUMN history_commits   int CHECK (history_commits >= 0),
  ADD COLUMN history_truncated boolean,
  ADD CONSTRAINT scan_history_stats CHECK (
    (history_commits IS NULL) = (history_truncated IS NULL) AND (history_commits IS NULL OR kind = 'history'));

ALTER TABLE issue
  ADD COLUMN commit_sha   text CHECK (commit_sha ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'),
  ADD COLUMN committed_at timestamptz,
  ADD COLUMN commit_count int CHECK (commit_count >= 1),
  ADD CONSTRAINT issue_commit_all_or_none CHECK ((commit_sha IS NULL) = (commit_count IS NULL)),
  ADD CONSTRAINT issue_commit_history CHECK (commit_sha IS NULL OR target = '(history)');

-- +goose Down
-- Fails while history scans exist: delete them first.
ALTER TABLE issue DROP CONSTRAINT issue_commit_history, DROP CONSTRAINT issue_commit_all_or_none,
  DROP COLUMN commit_count, DROP COLUMN committed_at, DROP COLUMN commit_sha;
ALTER TABLE scan DROP CONSTRAINT scan_history_stats, DROP COLUMN history_truncated, DROP COLUMN history_commits,
  DROP CONSTRAINT scan_history_tools, DROP CONSTRAINT scan_history_target, DROP CONSTRAINT scan_kind_check;
ALTER TABLE scan ADD CONSTRAINT scan_kind_check CHECK (kind IN ('source', 'image'));
