-- Notifications, SLA policy and project automation (v0.2).
--
-- * outbox_event is written in the same transaction as the change it describes
--   and consumed by the worker's dispatch_notifications job, one org at a time
--   with app.org_id set. It gets FORCEd RLS on org_id like every business
--   table. dedupe_key makes digest rows idempotent; it is unique per org, not
--   globally, so one org's row can never suppress (or reveal) another org's.
-- * notification gains org_id under FORCEd RLS. A user reads their own
--   notifications across orgs (GET /me/notifications) in a transaction with
--   app.user_id set and app.org_id unset; the two extra policies allow exactly
--   that (select, and update of their own rows) and nothing else: inserts
--   still need app.org_id. Rows are unique per (event, user), so a retried
--   dispatch can't duplicate them. Email delivery state is kept per row;
--   email_next_at doubles as a lease, so a crashed sender's rows are retried.
-- * notification_pref is per user, not per org (like app_user): it holds no
--   business data, and every query filters on the caller's user id.

-- +goose Up
-- notification was never written before v0.2; clear it so org_id can be NOT NULL.
DELETE FROM notification;
ALTER TABLE notification
  ADD COLUMN org_id         uuid NOT NULL REFERENCES organization(id),
  ADD COLUMN event_id       bigint NOT NULL REFERENCES outbox_event(id),
  ADD COLUMN title          text NOT NULL,
  ADD COLUMN link           text NOT NULL,
  ADD COLUMN actor_id       uuid REFERENCES app_user(id),
  ADD COLUMN email_state    text NOT NULL DEFAULT 'none' CHECK (email_state IN ('none', 'pending', 'sent', 'failed')),
  ADD COLUMN email_attempts int NOT NULL DEFAULT 0,
  ADD COLUMN email_next_at  timestamptz,
  ADD COLUMN emailed_at     timestamptz;
CREATE UNIQUE INDEX notification_event_user ON notification (event_id, user_id);
CREATE INDEX notification_user_created ON notification (user_id, created_at DESC, id DESC);
CREATE INDEX notification_email_due ON notification (org_id, email_next_at) WHERE email_state = 'pending';

ALTER TABLE notification ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON notification USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid) WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);
CREATE POLICY own_select ON notification FOR SELECT USING (user_id = nullif(current_setting('app.user_id', true), '')::uuid);
CREATE POLICY own_update ON notification FOR UPDATE USING (user_id = nullif(current_setting('app.user_id', true), '')::uuid) WITH CHECK (user_id = nullif(current_setting('app.user_id', true), '')::uuid);

ALTER TABLE outbox_event ADD COLUMN dedupe_key text;
ALTER TABLE outbox_event ADD CONSTRAINT outbox_event_dedupe UNIQUE (org_id, dedupe_key);
DROP INDEX outbox_event_id_idx;
CREATE INDEX outbox_event_pending ON outbox_event (org_id, id) WHERE dispatched_at IS NULL;
ALTER TABLE outbox_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbox_event FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON outbox_event USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid) WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);

CREATE TABLE notification_pref (
  user_id uuid NOT NULL REFERENCES app_user(id),
  type    text NOT NULL CHECK (type ~ '^[a-z_.]{1,40}$'),
  email   boolean NOT NULL,
  PRIMARY KEY (user_id, type)
);

-- Metrics: issues created / fixed per day and status history per org.
CREATE INDEX issue_org_created ON issue (org_id, created_at);
CREATE INDEX issue_event_org_type ON issue_event (org_id, type, created_at);

-- +goose Down
DROP INDEX issue_event_org_type;
DROP INDEX issue_org_created;
DROP TABLE notification_pref;
DROP POLICY org_isolation ON outbox_event;
ALTER TABLE outbox_event NO FORCE ROW LEVEL SECURITY;
ALTER TABLE outbox_event DISABLE ROW LEVEL SECURITY;
DROP INDEX outbox_event_pending;
CREATE INDEX ON outbox_event (id) WHERE dispatched_at IS NULL;
ALTER TABLE outbox_event DROP CONSTRAINT outbox_event_dedupe;
ALTER TABLE outbox_event DROP COLUMN dedupe_key;
DROP POLICY own_update ON notification;
DROP POLICY own_select ON notification;
DROP POLICY org_isolation ON notification;
ALTER TABLE notification NO FORCE ROW LEVEL SECURITY;
ALTER TABLE notification DISABLE ROW LEVEL SECURITY;
DROP INDEX notification_email_due;
DROP INDEX notification_user_created;
DROP INDEX notification_event_user;
ALTER TABLE notification DROP COLUMN emailed_at, DROP COLUMN email_next_at, DROP COLUMN email_attempts,
  DROP COLUMN email_state, DROP COLUMN actor_id, DROP COLUMN link, DROP COLUMN title, DROP COLUMN event_id, DROP COLUMN org_id;
