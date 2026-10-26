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
    -- The outbox and notifications are only ever appended and marked
    -- (dispatched, read, emailed); the app never deletes them.
    REVOKE DELETE, TRUNCATE ON outbox_event, notification FROM warden_app;
  END IF;
END $$;
