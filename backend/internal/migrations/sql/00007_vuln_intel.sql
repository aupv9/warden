-- Exploit intelligence (v0.3): CISA KEV and FIRST EPSS, loaded by the worker's
-- load_vuln_intel job from the mirror (scripts/sync-mirror.sh).
--
-- These are public data about CVEs, not about any org, so they have no org_id
-- and no RLS. They only rank issues (joined on issue.cve at read time): they
-- never change an issue's severity or status, and never hide one.
-- vuln_intel_source records what was loaded (and the Trivy DB's own date) so
-- the UI can say how fresh the data is; sha256 lets the loader skip unchanged
-- feeds.

-- +goose Up
CREATE TABLE vuln_intel (
  cve             text PRIMARY KEY CHECK (cve ~ '^CVE-[0-9]{4}-[0-9]{4,7}$'),
  kev_added       date,
  kev_due         date,
  kev_ransomware  boolean NOT NULL DEFAULT false,
  epss            real CHECK (epss BETWEEN 0 AND 1),
  epss_percentile real CHECK (epss_percentile BETWEEN 0 AND 1),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  CHECK (kev_added IS NOT NULL OR epss IS NOT NULL)
);
CREATE INDEX vuln_intel_kev ON vuln_intel (cve) WHERE kev_added IS NOT NULL;

CREATE TABLE vuln_intel_source (
  name       text PRIMARY KEY CHECK (name IN ('trivy_db', 'kev', 'epss')),
  updated_at timestamptz,
  loaded_at  timestamptz,
  records    int,
  sha256     char(64)
);

-- issue.cve lookups for the KEV filter and counts.
CREATE INDEX issue_cve ON issue USING gin (cve);

-- +goose Down
DROP INDEX issue_cve;
DROP TABLE vuln_intel_source;
DROP TABLE vuln_intel;
