-- Registry pulls and secrets in image layers (v0.7 wave 2).
--
-- * registry_credential is what Warden pulls an org's private images with: one
--   row per registry host (and port), at most 20 per org (the service holds the
--   cap). Managed by org admins and security leads (manage_registries), never
--   by API tokens. The password (or access token) has to be sent in clear, so
--   like a webhook URL it is stored AES-256-GCM-encrypted under secrets.key
--   (domain/registry.SealPassword): the additional data binds it to the org,
--   the row and the column, and key_id names the key, so secrets.old_keys still
--   open it after a rotation. It is never returned or logged; the audit log
--   holds the host and username only. host is the registry's host name, lower
--   case, with an optional port: never a scheme, path or IP literal. The app
--   may update only the credential and its last outcome, not the host, org or
--   creator (grants.sql).
-- * last_used_at is the last pull or test that authenticated with the row;
--   last_error the outcome of the last one that failed (unauthorized,
--   unreachable, blocked: a private address or a redirect to one), cleared by
--   a success or a change of credentials.
-- * scan.pulled: the worker pulls the image itself (POST …/scans/pull) instead
--   of reading an upload. Only image scans with an image_ref (pinned by digest,
--   checked by the API) are pulled; the scan is queued when it is created.
-- * issue.image_layer_*: for a secret Gitleaks finds in an image's layers, the
--   lowest layer that holds it (digest and 0-based index, 0 being the base)
--   and how many layers do. Set even when a later layer deletes the file: it
--   is still in the image. All three or none, and only on image issues.

-- +goose Up
CREATE TABLE registry_credential (
  id           uuid PRIMARY KEY,
  org_id       uuid NOT NULL REFERENCES organization(id),
  host         text NOT NULL CHECK (length(host) <= 253 AND
                 host ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+(:[0-9]{1,5})?$'),
  username     text NOT NULL CHECK (length(username) BETWEEN 1 AND 256),
  password_enc bytea NOT NULL CHECK (octet_length(password_enc) BETWEEN 1 AND 16640),
  key_id       text NOT NULL CHECK (key_id ~ '^[a-z0-9_-]{1,32}$'),
  created_by   uuid NOT NULL REFERENCES app_user(id),
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  last_error   text CHECK (last_error IN ('unauthorized', 'unreachable', 'blocked')),
  CONSTRAINT registry_credential_host UNIQUE (org_id, host)
);

ALTER TABLE registry_credential ENABLE ROW LEVEL SECURITY;
ALTER TABLE registry_credential FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON registry_credential USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid) WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);

ALTER TABLE scan
  ADD COLUMN pulled boolean NOT NULL DEFAULT false,
  ADD CONSTRAINT scan_pulled_image CHECK (NOT pulled OR (kind = 'image' AND image_ref IS NOT NULL));

ALTER TABLE issue
  ADD COLUMN image_layer_digest text CHECK (image_layer_digest ~ '^sha256:[0-9a-f]{64}$'),
  ADD COLUMN image_layer_index  int CHECK (image_layer_index >= 0),
  ADD COLUMN image_layer_count  int CHECK (image_layer_count >= 1),
  ADD CONSTRAINT issue_image_layer_all_or_none CHECK (
    (image_layer_digest IS NULL) = (image_layer_index IS NULL) AND (image_layer_digest IS NULL) = (image_layer_count IS NULL)),
  ADD CONSTRAINT issue_image_layer_image CHECK (image_layer_digest IS NULL OR (target <> '' AND target <> '(history)'));

-- +goose Down
ALTER TABLE issue DROP CONSTRAINT issue_image_layer_image, DROP CONSTRAINT issue_image_layer_all_or_none,
  DROP COLUMN image_layer_count, DROP COLUMN image_layer_index, DROP COLUMN image_layer_digest;
ALTER TABLE scan DROP CONSTRAINT scan_pulled_image, DROP COLUMN pulled;
DROP TABLE registry_credential;
