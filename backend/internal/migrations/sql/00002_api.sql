-- Columns and indexes for the v0.1 REST API.
--
-- * exception_request.decision_note: the decider's note. Required to reject, so a
--   rejection always says why (the API checks it too).
-- * app_user.last_mfa: whether the user's most recent token carried a second
--   factor (NULL until the user calls the API). Shown to org admins.
-- * One pending exception per issue, enforced here so two concurrent requests
--   can't both pass the API's check.

-- +goose Up
ALTER TABLE exception_request ADD COLUMN decision_note text;
ALTER TABLE exception_request ADD CONSTRAINT exception_request_reject_note
  CHECK (status <> 'rejected' OR length(btrim(coalesce(decision_note, ''))) > 0);
CREATE UNIQUE INDEX exception_request_one_pending ON exception_request (issue_id) WHERE status = 'pending';
CREATE INDEX exception_request_requester ON exception_request (requested_by, created_at DESC);
CREATE INDEX exception_request_created ON exception_request (created_at DESC, id DESC);

ALTER TABLE app_user ADD COLUMN last_mfa boolean;

CREATE INDEX org_member_user ON org_member (user_id);
CREATE INDEX project_member_user ON project_member (user_id);
-- Per-user scan rate limit.
CREATE INDEX scan_created_by ON scan (created_by, created_at);
CREATE INDEX comment_issue ON comment (issue_id, created_at);
CREATE INDEX occurrence_issue ON occurrence (issue_id);
-- Audit log pages (newest first) and the hash chain's "last entry" lookup.
CREATE INDEX audit_log_org_id ON audit_log (org_id, id DESC);

-- +goose Down
DROP INDEX audit_log_org_id;
DROP INDEX occurrence_issue;
DROP INDEX comment_issue;
DROP INDEX scan_created_by;
DROP INDEX project_member_user;
DROP INDEX org_member_user;
ALTER TABLE app_user DROP COLUMN last_mfa;
DROP INDEX exception_request_created;
DROP INDEX exception_request_requester;
DROP INDEX exception_request_one_pending;
ALTER TABLE exception_request DROP CONSTRAINT exception_request_reject_note;
ALTER TABLE exception_request DROP COLUMN decision_note;
