-- SBOM per scan and the org license policy (v0.3).
--
-- * scan.sbom_* point at the CycloneDX SBOM the worker stored for the scan
--   (sboms/<org>/<scan>.cdx.json). Trivy produces it from the scanned code, so
--   its content is untrusted: it is only ever served as a download. The
--   columns are all set or all null, and cleared when the SBOM expires
--   (scan.sbom_retention).
-- * organization.license_policy is the security lead's license rule
--   (licensepolicy.Policy as JSON). '{}' means off: no license issues.

-- +goose Up
ALTER TABLE scan
  ADD COLUMN sbom_key        text,
  ADD COLUMN sbom_size       bigint,
  ADD COLUMN sbom_sha256     char(64),
  ADD COLUMN sbom_components int,
  ADD COLUMN sbom_expires_at timestamptz,
  ADD CONSTRAINT scan_sbom_all_or_none CHECK (
    (sbom_key IS NULL) = (sbom_size IS NULL) AND (sbom_key IS NULL) = (sbom_sha256 IS NULL)
    AND (sbom_key IS NULL) = (sbom_components IS NULL) AND (sbom_key IS NULL) = (sbom_expires_at IS NULL));
CREATE INDEX scan_sbom_expiry ON scan (sbom_expires_at) WHERE sbom_key IS NOT NULL;

ALTER TABLE organization
  ADD COLUMN license_policy jsonb NOT NULL DEFAULT '{}'
    CONSTRAINT organization_license_policy_object CHECK (jsonb_typeof(license_policy) = 'object');

-- +goose Down
ALTER TABLE organization DROP COLUMN license_policy;
DROP INDEX scan_sbom_expiry;
ALTER TABLE scan DROP CONSTRAINT scan_sbom_all_or_none,
  DROP COLUMN sbom_expires_at, DROP COLUMN sbom_components, DROP COLUMN sbom_sha256,
  DROP COLUMN sbom_size, DROP COLUMN sbom_key;
