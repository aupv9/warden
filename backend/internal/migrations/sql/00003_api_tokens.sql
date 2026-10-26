-- API tokens: machine credentials for CI, bound to one project and acting as
-- the user who created them. Only sha256(secret) is stored; the full token is
-- shown once, at creation.
--
-- * api_token gets org_id under forced RLS like every business table. v0.1 had
--   no way to create tokens, so the table is empty and the NOT NULL columns need
--   no default.
-- * Token lookup happens before the request's org is known (the token is the
--   only credential), so it can't run under app.org_id. Rather than giving
--   warden_app a way around RLS, warden_lookup_token() is a SECURITY DEFINER
--   function owned by the schema owner (this migration runs as warden_owner):
--     - it returns at most one row, for an exact 8-character prefix: no wildcard,
--       no listing, NULL in → nothing out (STRICT);
--     - EXECUTE is revoked from PUBLIC; grants.sql grants it to warden_app only;
--     - search_path is pinned (pg_catalog, then pg_temp last) and the table is
--       schema-qualified, so a caller can't shadow api_token or an operator with
--       objects of its own;
--     - the token_lookup policy lets the owner (and only the owner) read every
--       row, which FORCEd RLS would otherwise hide from it. The owner can alter
--       the table anyway, so that grants it nothing new.
--   The API compares the hash in constant time, checks expiry and revocation,
--   and does everything after the lookup under app.org_id = the token's org.
-- * scan.via_token records which token created a scan.

-- +goose Up
ALTER TABLE api_token
  ADD COLUMN org_id     uuid NOT NULL REFERENCES organization(id),
  ADD COLUMN project_id uuid NOT NULL REFERENCES project(id),
  ADD COLUMN name       text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80),
  ADD COLUMN prefix     char(8) NOT NULL UNIQUE CHECK (prefix ~ '^[a-z2-7]{8}$'),
  ADD COLUMN created_by uuid NOT NULL REFERENCES app_user(id),
  ADD COLUMN created_at timestamptz NOT NULL DEFAULT now(),
  ADD CONSTRAINT api_token_user_is_creator CHECK (user_id = created_by),
  ADD CONSTRAINT api_token_scopes CHECK (cardinality(scopes) >= 1 AND scopes <@ ARRAY['scan:write','issues:read']::text[]),
  ADD CONSTRAINT api_token_hash_hex CHECK (token_hash ~ '^[0-9a-f]{64}$');
CREATE INDEX api_token_project ON api_token (project_id, created_at DESC);

ALTER TABLE api_token ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_token FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON api_token USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid) WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);
CREATE POLICY token_lookup ON api_token FOR SELECT TO CURRENT_USER USING (true);

ALTER TABLE scan ADD COLUMN via_token uuid REFERENCES api_token(id);
-- The scan gate selects the issues seen in one scan.
CREATE INDEX occurrence_scan ON occurrence (scan_id);

-- +goose StatementBegin
CREATE FUNCTION warden_lookup_token(p_prefix text)
RETURNS TABLE (id uuid, org_id uuid, project_id uuid, user_id uuid, token_hash char(64), scopes text[],
               expires_at timestamptz, revoked_at timestamptz)
LANGUAGE sql STABLE STRICT SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT t.id, t.org_id, t.project_id, t.user_id, t.token_hash, t.scopes, t.expires_at, t.revoked_at
  FROM public.api_token t
  WHERE p_prefix ~ '^[a-z2-7]{8}$' AND t.prefix = p_prefix::pg_catalog.bpchar
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION warden_lookup_token(text) FROM PUBLIC;

-- +goose Down
DROP FUNCTION warden_lookup_token(text);
DROP INDEX occurrence_scan;
ALTER TABLE scan DROP COLUMN via_token;
DROP POLICY token_lookup ON api_token;
DROP POLICY org_isolation ON api_token;
ALTER TABLE api_token NO FORCE ROW LEVEL SECURITY;
ALTER TABLE api_token DISABLE ROW LEVEL SECURITY;
DROP INDEX api_token_project;
ALTER TABLE api_token
  DROP CONSTRAINT api_token_hash_hex,
  DROP CONSTRAINT api_token_scopes,
  DROP CONSTRAINT api_token_user_is_creator,
  DROP COLUMN created_at,
  DROP COLUMN created_by,
  DROP COLUMN prefix,
  DROP COLUMN name,
  DROP COLUMN project_id,
  DROP COLUMN org_id;
