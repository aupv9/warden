-- Malicious-package advisories (v0.4): OSV MAL- entries per ecosystem, loaded
-- by the worker's load_vuln_intel job from the mirror (intel/osv/<eco>.zip).
--
-- Public data, so no org_id and no RLS, like vuln_intel. Unlike KEV/EPSS, a
-- match is a finding: results.Process creates a Critical trivy issue
-- (rule malicious:<id>) for a scanned package that matches, and the
-- match_malicious job creates or reopens one for components already in the
-- inventory when an advisory arrives. Feeds never close, hide or downgrade an
-- issue. all_versions is an advisory whose only range event is introduced 0;
-- otherwise versions lists the affected versions. Other range forms are
-- skipped by the parser and counted in vuln_intel_source.unsupported.

-- +goose Up
CREATE TABLE malicious_package (
  id           text NOT NULL CHECK (id ~ '^MAL-[0-9]{4}-[0-9]{1,8}$'),
  ecosystem    text NOT NULL CHECK (ecosystem ~ '^[A-Za-z0-9.+_-]{1,32}$'),
  name         text NOT NULL CHECK (length(name) BETWEEN 1 AND 256),
  match_name   text NOT NULL CHECK (length(match_name) BETWEEN 1 AND 256),
  all_versions boolean NOT NULL,
  versions     text[] NOT NULL DEFAULT '{}' CHECK (cardinality(versions) <= 10000),
  summary      text NOT NULL DEFAULT '' CHECK (length(summary) <= 1024),
  published    timestamptz,
  modified     timestamptz NOT NULL,
  PRIMARY KEY (id, ecosystem, match_name),
  CHECK (all_versions OR cardinality(versions) > 0)
);
CREATE INDEX malicious_package_match ON malicious_package (ecosystem, match_name);

ALTER TABLE vuln_intel_source DROP CONSTRAINT vuln_intel_source_name_check;
ALTER TABLE vuln_intel_source
  ADD CONSTRAINT vuln_intel_source_name_check CHECK (name ~ '^(trivy_db|kev|epss|osv_mal:[A-Za-z.]+)$'),
  ADD COLUMN unsupported int;

-- +goose Down
DELETE FROM vuln_intel_source WHERE name LIKE 'osv_mal:%';
ALTER TABLE vuln_intel_source DROP COLUMN unsupported, DROP CONSTRAINT vuln_intel_source_name_check;
ALTER TABLE vuln_intel_source ADD CONSTRAINT vuln_intel_source_name_check CHECK (name IN ('trivy_db', 'kev', 'epss'));
DROP TABLE malicious_package;
