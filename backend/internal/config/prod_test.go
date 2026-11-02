package config

import (
	"encoding/base64"
	"strings"
	"testing"
)

// validProd is a production configuration that passes every guardrail.
// Secrets are built at test time, never committed.
func validProd() *Config {
	secret := strings.Repeat("k", 40)
	key := "k1:" + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
	c := &Config{AppConfig: *appDefaults(), Settings: *settingsDefaults()}
	c.App.Env = EnvProd
	c.Database.DSN = "postgres://warden_app:" + secret + "@db:5432/warden?sslmode=verify-full"
	c.Migrate.DSN = Secret("host=db user=warden_owner password='" + secret + "' dbname=warden")
	c.OIDC.Issuer = "https://sso.example.com/realms/warden"
	c.SMTP.PublicBaseURL = "https://warden.example.com"
	c.SMTP.Password = Secret(secret)
	c.Storage.Endpoint = "http://seaweedfs:8333"
	c.Storage.PublicEndpoint = "https://files.example.com"
	c.Storage.AccessKey, c.Storage.SecretKey = Secret(secret), Secret(secret)
	c.Scan.SandboxRuntime = "runsc"
	c.Scan.HMACKey = Secret(secret)
	c.Secrets.Key = Secret(key)
	c.Scan.Images = map[string]string{}
	for _, t := range Scanners {
		c.Scan.Images[t] = "registry.internal/warden/" + t + "@sha256:" + strings.Repeat("a", 64)
	}
	return c
}

func TestProdAcceptsAValidConfig(t *testing.T) {
	if err := validProd().checkProd(); err != nil {
		t.Fatal(err)
	}
	c := validProd()
	c.Storage.Endpoint = "" // AWS default (https)
	c.Storage.PublicEndpoint = ""
	c.SMTP.Password = ""
	if err := c.checkProd(); err != nil {
		t.Fatal(err)
	}
	c.Storage.Endpoint = "https://s3.eu-west-1.amazonaws.com"
	if err := c.checkProd(); err != nil {
		t.Fatal(err)
	}
}

func TestProdRefusals(t *testing.T) {
	const placeholderValue = "CHANGE_ME_please"
	for _, tc := range []struct {
		name    string
		mutate  func(*Config)
		setting string
		value   string // must not appear in the error
	}{
		{"runc", func(c *Config) { c.Scan.SandboxRuntime = "runc" }, "scan.sandbox_runtime", ""},
		{"http issuer", func(c *Config) { c.OIDC.Issuer = "http://sso.example.com/realms/w" }, "oidc.issuer", "sso.example.com"},
		{"http public base url", func(c *Config) { c.SMTP.PublicBaseURL = "http://warden.example.com" }, "smtp.public_base_url", "warden.example.com"},
		{"empty public base url", func(c *Config) { c.SMTP.PublicBaseURL = "" }, "smtp.public_base_url", ""},
		{"http public storage", func(c *Config) { c.Storage.PublicEndpoint = "http://files.example.com" }, "storage.public_endpoint", "files.example.com"},
		{"http public storage dotless", func(c *Config) { c.Storage.PublicEndpoint = "http://seaweedfs:8333" }, "storage.public_endpoint", "seaweedfs"},
		{"http storage with a dot", func(c *Config) { c.Storage.Endpoint = "http://s3.example.com" }, "storage.endpoint", "s3.example.com"},
		{"http storage IPv4", func(c *Config) { c.Storage.Endpoint = "http://10.0.0.5:8333" }, "storage.endpoint", "10.0.0.5"},
		{"http storage IPv6", func(c *Config) { c.Storage.Endpoint = "http://[fd00::5]:8333" }, "storage.endpoint", "fd00::5"},
		{"storage other scheme", func(c *Config) { c.Storage.Endpoint = "ftp://seaweedfs" }, "storage.endpoint", "seaweedfs"},
		{"db password", func(c *Config) { c.Database.DSN = ""; c.Database.Password = placeholderValue }, "database.password", placeholderValue},
		{"db dsn url", func(c *Config) { c.Database.DSN = "postgres://warden_app:" + placeholderValue + "@db/warden" }, "database.dsn", placeholderValue},
		{"db dsn keyword", func(c *Config) { c.Database.DSN = "host=db password=__DB_PASSWORD__ dbname=warden" }, "database.dsn", "__DB_PASSWORD__"},
		{"migrate dsn", func(c *Config) { c.Migrate.DSN = "postgresql://warden_owner:__OWNER_PASSWORD__@db/warden" }, "migrate.dsn", "__OWNER_PASSWORD__"},
		{"migrate dsn quoted", func(c *Config) { c.Migrate.DSN = "password='change_me' host=db" }, "migrate.dsn", "change_me"},
		{"storage access key", func(c *Config) { c.Storage.AccessKey = placeholderValue }, "storage.access_key", placeholderValue},
		{"storage secret key", func(c *Config) { c.Storage.SecretKey = "__S3_SECRET__" }, "storage.secret_key", "__S3_SECRET__"},
		{"hmac key", func(c *Config) { c.Scan.HMACKey = placeholderValue }, "scan.hmac_key", placeholderValue},
		{"secrets key", func(c *Config) { c.Secrets.Key = "k1:" + placeholderValue }, "secrets.key", placeholderValue},
		{"secrets key whole", func(c *Config) { c.Secrets.Key = "__WARDEN_SECRETS_KEY__" }, "secrets.key", "__WARDEN_SECRETS_KEY__"},
		{"old keys", func(c *Config) { c.Secrets.OldKeys = Secret(c.Secrets.Key.Reveal() + ",k0:CHANGE_ME") }, "secrets.old_keys", "CHANGE_ME"},
		{"smtp password", func(c *Config) { c.SMTP.Password = "  CHANGE_ME  " }, "smtp.password", "CHANGE_ME"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := validProd()
			tc.mutate(c)
			err := c.checkProd()
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.setting) {
				t.Fatalf("error doesn't name %s: %v", tc.setting, err)
			}
			if tc.value != "" && strings.Contains(err.Error(), tc.value) {
				t.Fatalf("error shows the value: %v", err)
			}
			if strings.Count(err.Error(), "app.env=prod") != 1 {
				t.Fatalf("want exactly one refusal: %v", err)
			}
			// Outside prod none of this applies.
			c.App.Env = "staging"
			if err := c.checkProd(); err != nil {
				t.Fatalf("non-prod refused: %v", err)
			}
		})
	}
}

func TestProdReportsEveryProblem(t *testing.T) {
	c := validProd()
	c.Scan.SandboxRuntime = "runc"
	c.Scan.HMACKey = "CHANGE_ME"
	err := c.checkProd()
	if err == nil || !strings.Contains(err.Error(), "scan.sandbox_runtime") || !strings.Contains(err.Error(), "scan.hmac_key") {
		t.Fatal(err)
	}
}

func TestIsPlaceholder(t *testing.T) {
	for v, want := range map[string]bool{
		"CHANGE_ME": true, "change_me_now": true, "Change_Me": true, "__X__": true, "__DB_PASSWORD_1__": true,
		"k1:__KEY__": true, "": false, "__lower__": false, "__X__suffix": false, "not-CHANGE_ME": false,
		"https://x/CHANGE_ME": false, strings.Repeat("z", 32): false,
	} {
		if got := IsPlaceholder(v); got != want {
			t.Errorf("IsPlaceholder(%q) = %v", v, got)
		}
	}
}

func TestDSNPassword(t *testing.T) {
	for dsn, want := range map[string]string{
		"postgres://u:p%40ss@h/db":               "p@ss",
		"postgres://u@h/db":                      "",
		"host=h password=abc dbname=d":           "abc",
		"password='a b\\'c' host=h":              "a b'c",
		"host=h user=u":                          "",
		"host=h  password = spaced dbname=d":     "spaced",
		"postgresql://u:__PW__@h:5432/db?ssl=on": "__PW__",
	} {
		if got := DSNPassword(dsn); got != want {
			t.Errorf("DSNPassword(%q) = %q, want %q", dsn, got, want)
		}
	}
}

// Load applies the guardrails: the development defaults are not a production
// configuration.
func TestLoadRefusesDevDefaultsInProd(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("WARDEN_APP__ENV", "prod")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "oidc.issuer") || strings.Contains(err.Error(), "scan.images") {
		t.Fatal(err)
	}
}

func TestMissingImages(t *testing.T) {
	c := validProd()
	if got := c.MissingImages(); len(got) != 0 {
		t.Fatal(got)
	}
	delete(c.Scan.Images, "checkov")
	c.Scan.Images["trivy"] = ""
	if got := c.MissingImages(); strings.Join(got, ",") != "trivy,checkov" {
		t.Fatal(got)
	}
}
