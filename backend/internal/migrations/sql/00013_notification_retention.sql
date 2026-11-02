-- Notification retention (v0.5 wave 2): the worker's prune_notifications job
-- deletes old in-app notifications and the outbox events nothing refers to any
-- more (notify.read_retention / notify.unread_retention).
--
-- * warden_app still can't DELETE from notification or outbox_event
--   (grants.sql): a compromised app could otherwise erase what was just
--   written, or drop an outbox event before it is dispatched. Pruning goes
--   through warden_prune_notifications(), a SECURITY DEFINER function owned by
--   the schema owner, like warden_lookup_token():
--     - it works only in the caller's org (app.org_id, required) and filters on
--       it explicitly: the owner may bypass RLS (it is a superuser in the
--       Compose deployment);
--     - it refuses cutoffs newer than 23 hours ago (notify.*_retention is at
--       least 24h; an hour of slack for clock skew between worker and
--       database), so nothing recent can be deleted through it;
--     - it never deletes a notification whose email is being sent (pending),
--       an undispatched outbox event, or an event a notification or webhook
--       delivery still references (FKs);
--     - one call deletes at most 5000 rows of each table, so a run is a series
--       of short transactions;
--     - search_path is pinned and tables are schema-qualified; EXECUTE is
--       revoked from PUBLIC and granted to warden_app in grants.sql.
-- * Age is created_at for both read and unread notifications: a notification
--   older than the read retention goes once it has been read.
-- * The audit log, scans and issues are never pruned.

-- +goose Up
CREATE INDEX notification_org_created ON notification (org_id, created_at);
CREATE INDEX outbox_event_dispatched ON outbox_event (org_id, created_at) WHERE dispatched_at IS NOT NULL;
-- An outbox event can only go when no delivery refers to it.
CREATE INDEX webhook_delivery_event_id ON webhook_delivery (event_id) WHERE event_id IS NOT NULL;

-- +goose StatementBegin
CREATE FUNCTION warden_prune_notifications(p_read_before timestamptz, p_unread_before timestamptz, p_limit int,
                                           OUT notifications bigint, OUT events bigint)
LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_org uuid := nullif(current_setting('app.org_id', true), '')::uuid;
  v_floor timestamptz := now() - interval '23 hours';
BEGIN
  IF v_org IS NULL THEN
    RAISE EXCEPTION 'warden_prune_notifications: app.org_id is not set' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF p_read_before > v_floor OR p_unread_before > v_floor THEN
    RAISE EXCEPTION 'warden_prune_notifications: retention under one day' USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF p_limit < 1 OR p_limit > 5000 THEN
    RAISE EXCEPTION 'warden_prune_notifications: limit out of range' USING ERRCODE = 'invalid_parameter_value';
  END IF;

  DELETE FROM public.notification n
  WHERE n.id IN (
    SELECT x.id FROM public.notification x
    WHERE x.org_id = v_org AND x.email_state <> 'pending'
      AND x.created_at < CASE WHEN x.read_at IS NULL THEN p_unread_before ELSE p_read_before END
    LIMIT p_limit);
  GET DIAGNOSTICS notifications = ROW_COUNT;

  DELETE FROM public.outbox_event o
  WHERE o.id IN (
    SELECT e.id FROM public.outbox_event e
    WHERE e.org_id = v_org AND e.dispatched_at IS NOT NULL AND e.created_at < p_read_before
      AND NOT EXISTS (SELECT 1 FROM public.notification n WHERE n.event_id = e.id)
      AND NOT EXISTS (SELECT 1 FROM public.webhook_delivery d WHERE d.event_id = e.id)
    LIMIT p_limit);
  GET DIAGNOSTICS events = ROW_COUNT;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION warden_prune_notifications(timestamptz, timestamptz, int) FROM PUBLIC;

-- +goose Down
DROP FUNCTION warden_prune_notifications(timestamptz, timestamptz, int);
DROP INDEX webhook_delivery_event_id;
DROP INDEX outbox_event_dispatched;
DROP INDEX notification_org_created;
