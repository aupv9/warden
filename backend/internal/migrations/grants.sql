-- Applied after every migration run (idempotent), so tables added by later
-- migrations and by River are covered. warden_app gets DML only; it can't touch
-- migration bookkeeping, and audit_log is append-only for it.
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'warden_app') THEN
    GRANT USAGE ON SCHEMA public TO warden_app;
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO warden_app;
    GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO warden_app;
    REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM warden_app;
    REVOKE ALL ON goose_db_version FROM warden_app;
    REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON river_migration FROM warden_app;
    -- API tokens are never deleted (scans reference them), and the app may only
    -- revoke them or record their use, not change their hash, scopes or expiry.
    REVOKE UPDATE, DELETE, TRUNCATE ON api_token FROM warden_app;
    GRANT UPDATE (last_used_at, revoked_at) ON api_token TO warden_app;
    -- Token lookup before the org is known (see 00003_api_tokens.sql).
    GRANT EXECUTE ON FUNCTION warden_lookup_token(text) TO warden_app;
  END IF;
END $$;
