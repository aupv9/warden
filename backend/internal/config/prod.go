package config

import (
	"errors"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// EnvProd is the app.env value that turns on the production guardrails.
const EnvProd = "prod"

// placeholder matches the forms deployment templates use for "fill me in":
// CHANGE_ME… (any case) and __NAME__.
var placeholder = regexp.MustCompile(`^(?i:change_me)|^__[A-Z0-9_]+__$`)

// dsnPassword finds the password of a keyword/value connection string
// ("host=db password=s3cret"), quoted or not.
var dsnPassword = regexp.MustCompile(`(?:^|\s)password\s*=\s*(?:'((?:[^'\\]|\\.)*)'|(\S*))`)

// checkProd refuses settings that are fine on a laptop but not in production
// (app.env=prod): a sandbox without gVisor, plain-http links and endpoints
// that carry tokens or uploads, and secrets still holding a template
// placeholder (scanner images are the worker's check: MissingImages). Every error
// names the setting, never its value: these are often secrets. All problems
// are reported at once so an operator fixes them in one round.
func (c *Config) checkProd() error {
	if c.App.Env != EnvProd {
		return nil
	}
	var errs []error
	fail := func(msg string) { errs = append(errs, errors.New("config: app.env=prod: "+msg)) }

	if c.Scan.SandboxRuntime != "runsc" {
		fail("scan.sandbox_runtime must be runsc (gVisor); runc is for local development only")
	}
	if !isHTTPS(c.OIDC.Issuer) {
		fail("oidc.issuer must be an https URL")
	}
	if !isHTTPS(c.SMTP.PublicBaseURL) {
		fail("smtp.public_base_url must be an https URL")
	}
	if c.Storage.PublicEndpoint != "" && !isHTTPS(c.Storage.PublicEndpoint) {
		fail("storage.public_endpoint must be an https URL")
	}
	// Empty: the AWS default endpoint, which is https.
	if c.Storage.Endpoint != "" && !internalOrHTTPS(c.Storage.Endpoint) {
		fail("storage.endpoint must be an https URL, or http to a host name without a dot (an internal network name)")
	}

	secrets := []struct {
		name, value string
	}{
		{"database.password", c.Database.Password},
		{"database.dsn", DSNPassword(c.Database.DSN)},
		{"migrate.dsn", DSNPassword(c.Migrate.DSN.Reveal())},
		{"storage.access_key", c.Storage.AccessKey.Reveal()},
		{"storage.secret_key", c.Storage.SecretKey.Reveal()},
		{"scan.hmac_key", c.Scan.HMACKey.Reveal()},
		{"secrets.key", c.Secrets.Key.Reveal()},
		{"smtp.password", c.SMTP.Password.Reveal()},
	}
	for _, k := range strings.Split(c.Secrets.OldKeys.Reveal(), ",") {
		secrets = append(secrets, struct{ name, value string }{"secrets.old_keys", k})
	}
	seen := map[string]bool{}
	for _, s := range secrets {
		if !seen[s.name] && IsPlaceholder(s.value) {
			seen[s.name] = true
			fail(s.name + " still holds a placeholder value; set a real secret")
		}
	}
	return errors.Join(errs...)
}

// MissingImages lists the scanners with no image. In prod the worker refuses
// to start with any (a scan would silently skip that scanner); the check lives
// there, not in Load, so warden-api, warden-migrate and warden-admin don't
// need scanner settings.
func (c *Config) MissingImages() []string {
	var out []string
	for _, t := range Scanners {
		if c.Scan.Images[t] == "" {
			out = append(out, t)
		}
	}
	return out
}

// IsPlaceholder reports whether a secret is a template placeholder. A
// secrets.key's "<id>:" prefix doesn't hide one.
func IsPlaceholder(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	if placeholder.MatchString(v) {
		return true
	}
	if _, after, ok := strings.Cut(v, ":"); ok && !strings.Contains(v, "://") {
		return placeholder.MatchString(strings.TrimSpace(after))
	}
	return false
}

// DSNPassword returns the password in a postgres URL or keyword/value
// connection string ("" when there is none or it can't be parsed).
func DSNPassword(dsn string) string {
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil || u.User == nil {
			return ""
		}
		p, _ := u.User.Password()
		return p
	}
	m := dsnPassword.FindStringSubmatch(dsn)
	if m == nil {
		return ""
	}
	if m[1] != "" {
		return strings.NewReplacer(`\'`, `'`, `\\`, `\`).Replace(m[1])
	}
	return m[2]
}

func isHTTPS(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

// internalOrHTTPS: https, or http to a single-label host name such as a
// Compose or Kubernetes service ("seaweedfs"), which only resolves inside the
// deployment's network. An IP literal or a dotted name may be routed anywhere,
// so it needs TLS.
func internalOrHTTPS(raw string) bool {
	if isHTTPS(raw) {
		return true
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.Host == "" {
		return false
	}
	h := u.Hostname()
	return h != "" && !strings.Contains(h, ".") && net.ParseIP(h) == nil
}
