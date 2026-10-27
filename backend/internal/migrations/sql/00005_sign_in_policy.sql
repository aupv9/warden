-- Org sign-in policy and operator relink.
--
-- * organization.mfa_roles adds roles that must sign in with a second factor on
--   top of the server's oidc.require_mfa_roles; an org can tighten the server's
--   rule, never loosen it.
-- * organization.allowed_email_domains limits who can be added as a member
--   (empty = any domain). Existing members are not affected.
-- * app_user.relink_until is set by `warden-admin user relink --next-sign-in`:
--   until then, the next sign-in with this verified email and an unknown
--   subject takes over the account (moving to another identity provider).

-- +goose Up
ALTER TABLE organization
  ADD COLUMN mfa_roles org_role[] NOT NULL DEFAULT '{}',
  ADD COLUMN allowed_email_domains text[] NOT NULL DEFAULT '{}',
  ADD CONSTRAINT organization_allowed_email_domains_max CHECK (cardinality(allowed_email_domains) <= 20);
ALTER TABLE app_user ADD COLUMN relink_until timestamptz;

-- +goose Down
ALTER TABLE app_user DROP COLUMN relink_until;
ALTER TABLE organization DROP CONSTRAINT organization_allowed_email_domains_max,
  DROP COLUMN allowed_email_domains, DROP COLUMN mfa_roles;
