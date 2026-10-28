-- Container image scans (v0.3): a `docker save` tarball scanned by Trivy.
--
-- * scan.kind is source (a zip of code) or image. scan.target is the image
--   repository without tag ('' for source scans); image_ref is the reference
--   given at upload, for display only.
-- * issue.target scopes an issue to what was scanned. Auto-fix only considers
--   issues with the scan's target, so an image scan never fixes source issues
--   (or another image's) and vice versa.

-- +goose Up
ALTER TABLE scan
  ADD COLUMN kind      text NOT NULL DEFAULT 'source' CHECK (kind IN ('source', 'image')),
  ADD COLUMN target    text NOT NULL DEFAULT '' CHECK (length(target) <= 255),
  ADD COLUMN image_ref text CHECK (length(image_ref) <= 512),
  ADD CONSTRAINT scan_kind_target CHECK ((kind = 'source') = (target = '')),
  ADD CONSTRAINT scan_image_ref_kind CHECK (image_ref IS NULL OR kind = 'image');

ALTER TABLE issue ADD COLUMN target text NOT NULL DEFAULT '' CHECK (length(target) <= 255);
CREATE INDEX issue_project_target ON issue (project_id, target);

-- +goose Down
DROP INDEX issue_project_target;
ALTER TABLE issue DROP COLUMN target;
ALTER TABLE scan DROP CONSTRAINT scan_image_ref_kind, DROP CONSTRAINT scan_kind_target,
  DROP COLUMN image_ref, DROP COLUMN target, DROP COLUMN kind;
