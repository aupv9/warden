-- Component inventory, SPDX SBOMs and the license category (v0.4).
--
-- * component holds the packages of each (project, target)'s current scan: the
--   latest completed or partial scan where Trivy succeeded. results.Process
--   replaces a (project, target)'s rows in the scan's results transaction
--   (keeping first_seen for rows that stay); a failed Trivy run leaves them.
--   Names, versions and paths come from the scanned code (untrusted) and are
--   capped by scan/trivyjson. match_name is the ecosystem-normalised name
--   (domain/ecosystem) that searches and OSV advisories match on.
-- * scan.sbom_spdx_* point at the SPDX JSON SBOM (sboms/<org>/<scan>.spdx.json),
--   which shares sbom_expires_at with the CycloneDX one.
-- * issue.license_category is the Trivy category of a license-policy issue.
--   Existing issues are backfilled from their titles ("pkg uses X (category)").

-- +goose Up
CREATE TABLE component (
  org_id     uuid NOT NULL REFERENCES organization(id),
  project_id uuid NOT NULL REFERENCES project(id),
  target     text NOT NULL DEFAULT '' CHECK (length(target) <= 255),
  scan_id    uuid NOT NULL REFERENCES scan(id),
  ecosystem  text NOT NULL CHECK (ecosystem ~ '^[A-Za-z0-9.+_-]{1,32}$'),
  name       text NOT NULL CHECK (length(name) BETWEEN 1 AND 256),
  match_name text NOT NULL CHECK (length(match_name) BETWEEN 1 AND 256),
  version    text NOT NULL CHECK (length(version) <= 128),
  purl       text CHECK (length(purl) <= 512),
  path       text NOT NULL DEFAULT '' CHECK (length(path) <= 2048),
  licenses   text[] NOT NULL DEFAULT '{}',
  first_seen timestamptz NOT NULL DEFAULT now(),
  UNIQUE (project_id, target, ecosystem, match_name, version, path)
);
CREATE INDEX component_match ON component (org_id, ecosystem, match_name, version);
CREATE INDEX component_prefix ON component (org_id, match_name text_pattern_ops);
CREATE INDEX component_project_target ON component (project_id, target);

ALTER TABLE component ENABLE ROW LEVEL SECURITY;
ALTER TABLE component FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON component USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid) WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);

ALTER TABLE scan
  ADD COLUMN sbom_spdx_key    text,
  ADD COLUMN sbom_spdx_size   bigint,
  ADD COLUMN sbom_spdx_sha256 char(64),
  ADD CONSTRAINT scan_sbom_spdx_all_or_none CHECK (
    (sbom_spdx_key IS NULL) = (sbom_spdx_size IS NULL) AND (sbom_spdx_key IS NULL) = (sbom_spdx_sha256 IS NULL)
    AND (sbom_spdx_key IS NULL OR sbom_key IS NOT NULL));

ALTER TABLE issue ADD COLUMN license_category text CHECK (license_category IN
  ('forbidden', 'restricted', 'reciprocal', 'notice', 'permissive', 'unencumbered', 'unknown'));
-- FORCEd RLS applies to the table owner too, and migrations set no app.org_id,
-- so lift it for this one backfill (inside the migration's transaction).
ALTER TABLE issue NO FORCE ROW LEVEL SECURITY;
UPDATE issue SET license_category = substring(title FROM '\((forbidden|restricted|reciprocal|notice|permissive|unencumbered|unknown)\)$')
  WHERE tool = 'trivy' AND rule_id LIKE 'license:%';
ALTER TABLE issue FORCE ROW LEVEL SECURITY;

-- +goose Down
ALTER TABLE issue DROP COLUMN license_category;
ALTER TABLE scan DROP CONSTRAINT scan_sbom_spdx_all_or_none,
  DROP COLUMN sbom_spdx_sha256, DROP COLUMN sbom_spdx_size, DROP COLUMN sbom_spdx_key;
DROP TABLE component;
