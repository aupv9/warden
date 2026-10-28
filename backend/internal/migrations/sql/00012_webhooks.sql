-- Webhooks and Slack (v0.4 wave 2): outbox events sent to an org's endpoints.
--
-- * webhook is an org's endpoint: kind generic (a signed JSON POST, Standard
--   Webhooks headers) or slack (an Incoming Webhook URL; the URL is the
--   credential). Managed by org admins and security leads (manage_integrations).
-- * The URL and the signing secret are needed in clear to send, so unlike API
--   tokens they are stored encrypted: AES-256-GCM under the server key
--   secrets.key (WARDEN_SECRETS__KEY, "<key id>:<base64 of 32 bytes>"), with
--   the org id, webhook id and column name as additional data, so a ciphertext
--   can't be moved to another row or column. key_id names the key; keys in
--   secrets.old_keys still decrypt, for rotation. Without secrets.key the
--   webhook API reports webhooks as unavailable. url_hint (scheme and host) is
--   the only part of the URL ever returned.
-- * events lists outbox event types (notify.WebhookTypes); project_ids empty
--   means every project; min_severity filters issue events.
-- * webhook_delivery is one event for one webhook, written by the dispatcher
--   in the transaction that dispatches the outbox event (unique per webhook and
--   event, so a retried dispatch can't duplicate it). payload is the exact body
--   sent, built from the same columns an email may show. next_at doubles as a
--   lease, like notification.email_next_at. The response body is never stored.
--   A delivery ending failed bumps webhook.consecutive_failures, a delivered
--   one resets it; at the limit (or on 410 Gone) the webhook is turned off with
--   disabled_reason 'failures'. Deliveries are pruned after 30 days.

-- +goose Up
CREATE TABLE webhook (
  id                   uuid PRIMARY KEY,
  org_id               uuid NOT NULL REFERENCES organization(id),
  kind                 text NOT NULL CHECK (kind IN ('generic', 'slack')),
  name                 text NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
  url_hint             text NOT NULL CHECK (length(url_hint) BETWEEN 1 AND 300),
  url_enc              bytea NOT NULL CHECK (octet_length(url_enc) <= 4096),
  secret_enc           bytea CHECK (octet_length(secret_enc) <= 256),
  key_id               text NOT NULL CHECK (key_id ~ '^[a-z0-9_-]{1,32}$'),
  events               text[] NOT NULL CHECK (cardinality(events) BETWEEN 1 AND 16),
  project_ids          uuid[] NOT NULL DEFAULT '{}' CHECK (cardinality(project_ids) <= 100),
  min_severity         severity,
  enabled              boolean NOT NULL DEFAULT true,
  disabled_reason      text CHECK (disabled_reason IN ('failures')),
  consecutive_failures int NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
  created_by           uuid NOT NULL REFERENCES app_user(id),
  created_at           timestamptz NOT NULL DEFAULT now(),
  updated_at           timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT webhook_secret_kind CHECK ((kind = 'generic') = (secret_enc IS NOT NULL)),
  CONSTRAINT webhook_disabled_reason CHECK (disabled_reason IS NULL OR NOT enabled)
);
CREATE INDEX webhook_org ON webhook (org_id, created_at);

ALTER TABLE webhook ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON webhook USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid) WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);

CREATE TABLE webhook_delivery (
  id              uuid PRIMARY KEY,
  org_id          uuid NOT NULL REFERENCES organization(id),
  webhook_id      uuid NOT NULL REFERENCES webhook(id) ON DELETE CASCADE,
  event_id        bigint REFERENCES outbox_event(id), -- NULL for a test delivery
  type            text NOT NULL CHECK (type ~ '^[a-z_.]{1,40}$'),
  payload         jsonb NOT NULL CHECK (octet_length(payload::text) <= 65536),
  state           text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'delivered', 'failed')),
  attempts        int NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  status_code     int CHECK (status_code BETWEEN 100 AND 599),
  error           text CHECK (error IN ('timeout', 'dns', 'connect', 'tls', 'blocked_address', 'redirect',
                                        'http_status', 'disabled', 'key_unavailable')),
  next_at         timestamptz,
  last_attempt_at timestamptz,
  delivered_at    timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT webhook_delivery_event UNIQUE (webhook_id, event_id),
  CONSTRAINT webhook_delivery_pending CHECK ((state = 'pending') = (next_at IS NOT NULL))
);
CREATE INDEX webhook_delivery_list ON webhook_delivery (webhook_id, created_at DESC, id DESC);
CREATE INDEX webhook_delivery_due ON webhook_delivery (org_id, next_at) WHERE state = 'pending';
CREATE INDEX webhook_delivery_created ON webhook_delivery (org_id, created_at);

ALTER TABLE webhook_delivery ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_delivery FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON webhook_delivery USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid) WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);

-- +goose Down
DROP TABLE webhook_delivery;
DROP TABLE webhook;
