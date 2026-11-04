-- Imported SARIF (v0.8 wave 1): findings of another tool (CodeQL, GitLab SAST,
-- Semgrep, …) managed like Warden's own: SLA, exceptions, audit, gate.
--
-- * scan.kind import: the upload is a SARIF 2.1.0 file, or a GitLab SAST report
--   (import_format gitlab-sast) converted by the worker. Nothing is unpacked or
--   run; the worker parses it as hostile input and screens every kept string
--   with Gitleaks in the sandbox before anything is stored.
-- * import_tool names the tool: a fixed list or external.<key>. It can never
--   be a Warden scanner: an import's issues have tool 'external', so no import
--   can set or fix an issue of gitleaks, opengrep, trivy or checkov.
-- * import_category separates runs of the same tool (CodeQL runs once per
--   language: "/language:python/"), like GitHub's category. The target is
--   '(import) <tool>' plus ' <category>' when there is one: auto-fix is per
--   target, so an import only fixes issues of the same tool and category, and
--   the parentheses never occur in an image repository.
-- * import_tool_version, import_results (results read), import_dropped
--   (results refused: path outside the source root, limits) and
--   import_screened (strings Gitleaks matched and Warden dropped) are set when
--   the scan finishes.
-- * issue.external_tool is the import tool of an imported issue, NULL for
--   every other issue.

-- +goose Up
ALTER TABLE scan DROP CONSTRAINT scan_kind_check;
ALTER TABLE scan
  ADD CONSTRAINT scan_kind_check CHECK (kind IN ('source', 'image', 'history', 'import')),
  ADD COLUMN import_tool         text CHECK (import_tool ~ '^(codeql|gitlab-sast|semgrep|snyk-code|sonarqube|external\.[a-z0-9-]{1,32})$'),
  ADD COLUMN import_category     text CHECK (import_category ~ '^[A-Za-z0-9/:._=+-]{0,100}$'),
  ADD COLUMN import_format       text CHECK (import_format IN ('sarif', 'gitlab-sast')),
  ADD COLUMN import_tool_version text CHECK (length(import_tool_version) <= 100),
  ADD COLUMN import_results      int CHECK (import_results >= 0),
  ADD COLUMN import_dropped      int CHECK (import_dropped >= 0),
  ADD COLUMN import_screened     int CHECK (import_screened >= 0),
  ADD CONSTRAINT scan_import_fields CHECK (
    (kind = 'import') = (import_tool IS NOT NULL) AND
    (import_tool IS NULL) = (import_category IS NULL) AND
    (import_tool IS NULL) = (import_format IS NULL) AND
    (import_tool IS NOT NULL OR (import_tool_version IS NULL AND import_results IS NULL AND
                                 import_dropped IS NULL AND import_screened IS NULL))),
  ADD CONSTRAINT scan_import_target CHECK (
    kind <> 'import' OR
    target = '(import) ' || import_tool || CASE WHEN import_category = '' THEN '' ELSE ' ' || import_category END),
  ADD CONSTRAINT scan_import_tools CHECK (kind <> 'import' OR tools = '{external}'),
  ADD CONSTRAINT scan_external_tool CHECK (kind = 'import' OR NOT ('external' = ANY (tools)));

ALTER TABLE issue
  ADD COLUMN external_tool text CHECK (external_tool ~ '^(codeql|gitlab-sast|semgrep|snyk-code|sonarqube|external\.[a-z0-9-]{1,32})$'),
  ADD CONSTRAINT issue_external_tool CHECK ((tool = 'external') = (external_tool IS NOT NULL)),
  ADD CONSTRAINT issue_external_target CHECK (tool <> 'external' OR target LIKE '(import) %');

-- +goose Down
-- Fails while import scans exist: delete them first.
ALTER TABLE issue DROP CONSTRAINT issue_external_target, DROP CONSTRAINT issue_external_tool,
  DROP COLUMN external_tool;
ALTER TABLE scan DROP CONSTRAINT scan_external_tool, DROP CONSTRAINT scan_import_tools,
  DROP CONSTRAINT scan_import_target, DROP CONSTRAINT scan_import_fields,
  DROP COLUMN import_screened, DROP COLUMN import_dropped, DROP COLUMN import_results,
  DROP COLUMN import_tool_version, DROP COLUMN import_format, DROP COLUMN import_category,
  DROP COLUMN import_tool, DROP CONSTRAINT scan_kind_check;
ALTER TABLE scan ADD CONSTRAINT scan_kind_check CHECK (kind IN ('source', 'image', 'history'));
