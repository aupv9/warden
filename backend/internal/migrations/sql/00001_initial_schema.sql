-- Baseline schema. Every business table carries org_id under FORCEd row-level
-- security; CHECK constraints enforce exception rules (risk acceptance expires
-- within 180 days, the decider differs from the requester) and project keys.
-- Grants for warden_app are applied by grants.sql after every migration run.

-- +goose Up
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TYPE org_role         AS ENUM ('org_admin','security_lead','member');
CREATE TYPE project_role     AS ENUM ('owner','developer','viewer');
CREATE TYPE scan_status      AS ENUM ('pending_upload','queued','running','completed','partial','failed','cancelled');
CREATE TYPE tool_status      AS ENUM ('queued','running','succeeded','failed','timeout','skipped');
CREATE TYPE severity         AS ENUM ('critical','high','medium','low','info');
CREATE TYPE issue_status     AS ENUM ('open','assigned','in_progress','fixed','verified','reopened','false_positive','risk_accepted');
CREATE TYPE exception_type   AS ENUM ('false_positive','risk_accepted');
CREATE TYPE exception_status AS ENUM ('pending','approved','rejected','expired');

CREATE TABLE organization (
  id          uuid PRIMARY KEY,
  name        text NOT NULL,
  sla_days    jsonb NOT NULL DEFAULT '{"critical":7,"high":30,"medium":90,"low":180}',
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE app_user (
  id           uuid PRIMARY KEY,
  keycloak_sub text NOT NULL UNIQUE,
  email        citext NOT NULL UNIQUE,
  display_name text NOT NULL,
  is_active    boolean NOT NULL DEFAULT true,
  created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE org_member (
  org_id   uuid REFERENCES organization(id),
  user_id  uuid REFERENCES app_user(id),
  role     org_role NOT NULL,
  PRIMARY KEY (org_id, user_id)
);

CREATE TABLE project (
  id            uuid PRIMARY KEY,
  org_id        uuid NOT NULL REFERENCES organization(id),
  key           text NOT NULL CHECK (key ~ '^[A-Z][A-Z0-9]{1,9}$'),
  name          text NOT NULL,
  description   text,
  default_tools text[] NOT NULL DEFAULT '{gitleaks,opengrep,trivy,checkov}',
  assign_rules  jsonb NOT NULL DEFAULT '[]',
  issue_seq     int NOT NULL DEFAULT 0,
  archived_at   timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, key)
);

CREATE TABLE project_member (
  org_id     uuid NOT NULL REFERENCES organization(id),
  project_id uuid REFERENCES project(id),
  user_id    uuid REFERENCES app_user(id),
  role       project_role NOT NULL,
  PRIMARY KEY (project_id, user_id)
);

CREATE TABLE scan (
  id                 uuid PRIMARY KEY,
  org_id             uuid NOT NULL REFERENCES organization(id),
  project_id         uuid NOT NULL REFERENCES project(id),
  created_by         uuid NOT NULL REFERENCES app_user(id),
  status             scan_status NOT NULL DEFAULT 'pending_upload',
  file_name          text NOT NULL,
  object_key         text,
  file_size          bigint,
  sha256             char(64),
  tools              text[] NOT NULL CHECK (cardinality(tools) >= 1),
  error_code         text,
  stats              jsonb NOT NULL DEFAULT '{}',
  needs_confirmation boolean NOT NULL DEFAULT false,
  queued_at          timestamptz,
  started_at         timestamptz,
  finished_at        timestamptz,
  source_deleted_at  timestamptz,
  created_at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON scan (project_id, created_at DESC);
CREATE INDEX ON scan (finished_at) WHERE source_deleted_at IS NULL;

CREATE TABLE scan_tool_run (
  id             uuid PRIMARY KEY,
  org_id         uuid NOT NULL REFERENCES organization(id),
  scan_id        uuid NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
  tool           text NOT NULL,
  tool_version   text NOT NULL,
  image_digest   text NOT NULL,
  status         tool_status NOT NULL DEFAULT 'queued',
  findings_count int,
  duration_ms    int,
  error          text,
  UNIQUE (scan_id, tool)
);

CREATE TABLE issue (
  id                  uuid PRIMARY KEY,
  org_id              uuid NOT NULL REFERENCES organization(id),
  project_id          uuid NOT NULL REFERENCES project(id),
  number              int NOT NULL,
  fingerprint         char(64) NOT NULL,
  tool                text NOT NULL,
  rule_id             text NOT NULL,
  title               text NOT NULL,
  description         text,
  remediation         text,
  severity            severity NOT NULL,
  severity_overridden boolean NOT NULL DEFAULT false,
  status              issue_status NOT NULL DEFAULT 'open',
  assignee_id         uuid REFERENCES app_user(id),
  file_path           text,
  start_line          int,
  end_line            int,
  snippet             text,
  cwe                 text[],
  cve                 text[],
  package_name        text,
  package_version     text,
  fixed_version       text,
  first_seen_scan_id  uuid NOT NULL REFERENCES scan(id),
  last_seen_scan_id   uuid NOT NULL REFERENCES scan(id),
  due_at              timestamptz,
  version             int NOT NULL DEFAULT 1,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  UNIQUE (project_id, fingerprint),
  UNIQUE (project_id, number)
);
CREATE INDEX ON issue (project_id, status, severity);
CREATE INDEX ON issue (assignee_id) WHERE status IN ('assigned','in_progress','reopened');
CREATE INDEX ON issue (due_at) WHERE status NOT IN ('verified','false_positive','risk_accepted');

CREATE TABLE occurrence (
  org_id     uuid NOT NULL REFERENCES organization(id),
  issue_id   uuid REFERENCES issue(id) ON DELETE CASCADE,
  scan_id    uuid REFERENCES scan(id) ON DELETE CASCADE,
  file_path  text,
  start_line int,
  raw        jsonb NOT NULL,
  PRIMARY KEY (issue_id, scan_id)
);

CREATE TABLE issue_event (
  id         bigserial PRIMARY KEY,
  org_id     uuid NOT NULL REFERENCES organization(id),
  issue_id   uuid NOT NULL REFERENCES issue(id) ON DELETE CASCADE,
  actor_id   uuid REFERENCES app_user(id),
  type       text NOT NULL,
  from_value text,
  to_value   text,
  note       text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON issue_event (issue_id, created_at);

CREATE TABLE comment (
  id         uuid PRIMARY KEY,
  org_id     uuid NOT NULL REFERENCES organization(id),
  issue_id   uuid NOT NULL REFERENCES issue(id) ON DELETE CASCADE,
  author_id  uuid NOT NULL REFERENCES app_user(id),
  body       text NOT NULL,
  mentions   uuid[] NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now(),
  edited_at  timestamptz
);

CREATE TABLE exception_request (
  id           uuid PRIMARY KEY,
  org_id       uuid NOT NULL REFERENCES organization(id),
  issue_id     uuid NOT NULL REFERENCES issue(id) ON DELETE CASCADE,
  type         exception_type NOT NULL,
  reason       text NOT NULL CHECK (length(reason) >= 20),
  requested_by uuid NOT NULL REFERENCES app_user(id),
  decided_by   uuid REFERENCES app_user(id),
  status       exception_status NOT NULL DEFAULT 'pending',
  expires_at   timestamptz,
  decided_at   timestamptz,
  created_at   timestamptz NOT NULL DEFAULT now(),
  CHECK (type <> 'risk_accepted' OR expires_at IS NOT NULL),
  CHECK (expires_at IS NULL OR expires_at <= created_at + interval '180 days'),
  CHECK (decided_by IS NULL OR decided_by <> requested_by)
);
CREATE INDEX ON exception_request (status) WHERE status = 'pending';

CREATE TABLE outbox_event (
  id            bigserial PRIMARY KEY,
  org_id        uuid NOT NULL,
  type          text NOT NULL,
  payload       jsonb NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  dispatched_at timestamptz
);
CREATE INDEX ON outbox_event (id) WHERE dispatched_at IS NULL;

CREATE TABLE notification (
  id         uuid PRIMARY KEY,
  user_id    uuid NOT NULL REFERENCES app_user(id),
  type       text NOT NULL,
  payload    jsonb NOT NULL,
  read_at    timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON notification (user_id, created_at DESC) WHERE read_at IS NULL;

CREATE TABLE api_token (
  id           uuid PRIMARY KEY,
  user_id      uuid NOT NULL REFERENCES app_user(id),
  token_hash   char(64) NOT NULL UNIQUE,
  scopes       text[] NOT NULL,
  expires_at   timestamptz NOT NULL,
  last_used_at timestamptz,
  revoked_at   timestamptz
);

CREATE TABLE audit_log (
  id          bigserial PRIMARY KEY,
  org_id      uuid,
  actor_id    uuid,
  action      text NOT NULL,
  target_type text,
  target_id   text,
  ip          inet,
  user_agent  text,
  data        jsonb NOT NULL DEFAULT '{}',
  prev_hash   char(64),
  hash        char(64) NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON audit_log (org_id, created_at DESC);

-- Row-level security: an unset app.org_id matches no rows (fail closed), and
-- WITH CHECK rejects writes into another org.
ALTER TABLE project ENABLE ROW LEVEL SECURITY;
ALTER TABLE project FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON project USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid) WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);

ALTER TABLE project_member ENABLE ROW LEVEL SECURITY;
ALTER TABLE project_member FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON project_member USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid) WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);

ALTER TABLE scan ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON scan USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid) WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);

ALTER TABLE scan_tool_run ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_tool_run FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON scan_tool_run USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid) WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);

ALTER TABLE issue ENABLE ROW LEVEL SECURITY;
ALTER TABLE issue FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON issue USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid) WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);

ALTER TABLE occurrence ENABLE ROW LEVEL SECURITY;
ALTER TABLE occurrence FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON occurrence USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid) WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);

ALTER TABLE issue_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE issue_event FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON issue_event USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid) WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);

ALTER TABLE comment ENABLE ROW LEVEL SECURITY;
ALTER TABLE comment FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON comment USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid) WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);

ALTER TABLE exception_request ENABLE ROW LEVEL SECURITY;
ALTER TABLE exception_request FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON exception_request USING (org_id = nullif(current_setting('app.org_id', true), '')::uuid) WITH CHECK (org_id = nullif(current_setting('app.org_id', true), '')::uuid);

-- +goose Down
-- 00001 is the baseline; restore from backup instead of downgrading.
SELECT 'down migration not supported'::int;
