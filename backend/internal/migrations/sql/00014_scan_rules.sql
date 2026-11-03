-- An org's own scan rules (v0.6 wave 1): Opengrep and Gitleaks rules written by
-- org admins and security leads (manage_rules), run by every scan of the org.
--
-- * scan_rule is the current state of one rule. body_canonical is the body as
--   internal/rules rendered it from the parsed rule, never the text submitted;
--   sha256 is of body_canonical. key is the id inside the body: findings carry
--   it as org.<key>, so it is unique per org and tool among live rules (a
--   deleted key can be reused). project_ids NULL means every project of the
--   org; the service checks the ids are the org's projects (an array can't
--   have a foreign key). Rules are soft-deleted (deleted_at) and never removed:
--   their versions and the issues they found stay, and the app can't DELETE.
-- * scan_rule_version is append-only for the app (no UPDATE or DELETE, see
--   grants.sql): one row per version of a rule, version 1 when it is created,
--   then one per change of body, name, enabled or project_ids. A scan records
--   the (rule, version, sha256) it ran in scan.org_rules, so what a scan looked
--   for can always be shown. The composite foreign key keeps a version in its
--   rule's org (foreign key checks don't go through RLS).
-- * scan_rule_test is a draft rule run against a snippet in the sandbox (job
--   test_rules). The snippet is cleared when the run ends (the CHECK makes a
--   finished row without one); findings hold lines and the rule's message,
--   never matched text. The worker prunes rows after 24 hours.
-- * scan.org_rules: [{rule_id, tool, version, sha256}] of the org rules a scan
--   ran, written by the worker; '[]' for every scan before this one.
-- * Sizes: 64 KiB per body and per snippet (rules.MaxBodyBytes).

-- +goose Up
CREATE TABLE scan_rule (
  id             uuid PRIMARY KEY,
  org_id         uuid NOT NULL REFERENCES organization(id),
  tool           text NOT NULL CHECK (tool IN ('opengrep', 'gitleaks')),
  key            text NOT NULL CHECK (key ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
  name           text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  body_canonical text NOT NULL CHECK (octet_length(body_canonical) BETWEEN 1 AND 65536),
  sha256         text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  severity       severity NOT NULL,
  enabled        boolean NOT NULL DEFAULT true,
  project_ids    uuid[] CHECK (project_ids IS NULL OR cardinality(project_ids) BETWEEN 1 AND 200),
  version        int NOT NULL DEFAULT 1 CHECK (version >= 1),
  created_by     uuid REFERENCES app_user(id),
  updated_by     uuid REFERENCES app_user(id),
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  deleted_at     timestamptz,
  CONSTRAINT scan_rule_org_id UNIQUE (org_id, id)
);
CREATE UNIQUE INDEX scan_rule_key ON scan_rule (org_id, tool, key) WHERE deleted_at IS NULL;
-- Issue.org_rule looks rules up by (org, tool, key), deleted ones included.
CREATE INDEX scan_rule_lookup ON scan_rule (org_id, tool, key, deleted_at);

ALTER TABLE scan_rule ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_rule FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON scan_rule USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid) WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);

CREATE TABLE scan_rule_version (
  org_id         uuid NOT NULL,
  scan_rule_id   uuid NOT NULL,
  version        int NOT NULL CHECK (version >= 1),
  name           text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  body_canonical text NOT NULL CHECK (octet_length(body_canonical) BETWEEN 1 AND 65536),
  sha256         text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  severity       severity NOT NULL,
  enabled        boolean NOT NULL,
  project_ids    uuid[] CHECK (project_ids IS NULL OR cardinality(project_ids) BETWEEN 1 AND 200),
  created_by     uuid REFERENCES app_user(id),
  created_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (scan_rule_id, version),
  CONSTRAINT scan_rule_version_rule FOREIGN KEY (org_id, scan_rule_id) REFERENCES scan_rule (org_id, id)
);

ALTER TABLE scan_rule_version ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_rule_version FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON scan_rule_version USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid) WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);

CREATE TABLE scan_rule_test (
  id             uuid PRIMARY KEY,
  org_id         uuid NOT NULL REFERENCES organization(id),
  created_by     uuid NOT NULL REFERENCES app_user(id),
  tool           text NOT NULL CHECK (tool IN ('opengrep', 'gitleaks')),
  body_canonical text NOT NULL CHECK (octet_length(body_canonical) BETWEEN 1 AND 65536),
  -- One plain file name: no directories, and not "." or "..".
  filename       text NOT NULL CHECK (filename ~ '^[A-Za-z0-9._-]{1,255}$' AND filename !~ '^\.+$'),
  snippet        text CHECK (octet_length(snippet) <= 65536),
  state          text NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'running', 'done', 'failed')),
  findings       jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(findings) = 'array' AND octet_length(findings::text) <= 262144),
  error          text CHECK (error IN ('timeout', 'scanner_failed', 'rule_invalid')),
  created_at     timestamptz NOT NULL DEFAULT now(),
  finished_at    timestamptz,
  CONSTRAINT scan_rule_test_finished CHECK ((state IN ('done', 'failed')) = (finished_at IS NOT NULL)),
  CONSTRAINT scan_rule_test_snippet CHECK (finished_at IS NULL OR snippet IS NULL),
  CONSTRAINT scan_rule_test_error CHECK ((state = 'failed') = (error IS NOT NULL))
);
-- The rate limit (per user per hour) and the 24-hour prune.
CREATE INDEX scan_rule_test_user ON scan_rule_test (created_by, created_at);
CREATE INDEX scan_rule_test_created ON scan_rule_test (org_id, created_at);

ALTER TABLE scan_rule_test ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_rule_test FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON scan_rule_test USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid) WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);

ALTER TABLE scan ADD COLUMN org_rules jsonb NOT NULL DEFAULT '[]'
  CHECK (jsonb_typeof(org_rules) = 'array' AND octet_length(org_rules::text) <= 262144);

-- +goose Down
ALTER TABLE scan DROP COLUMN org_rules;
DROP TABLE scan_rule_test;
DROP TABLE scan_rule_version;
DROP TABLE scan_rule;
