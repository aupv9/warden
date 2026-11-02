package webui

import (
	"strings"
	"testing"
)

func fixed(s string) func() string { return func() string { return s } }

func TestCSP(t *testing.T) {
	got, err := Policy{Issuer: "https://SSO.example.com/realms/warden", Storage: "https://s3.example.com:8443/"}.CSP()
	if err != nil {
		t.Fatal(err)
	}
	want := "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; " +
		"connect-src 'self' https://sso.example.com https://s3.example.com:8443; frame-src 'self' https://sso.example.com; " +
		"frame-ancestors 'none'; base-uri 'none'; form-action 'self' https://sso.example.com; object-src 'none'"
	if got != want {
		t.Fatalf("\n got %s\nwant %s", got, want)
	}
	for _, s := range []string{"unsafe-inline", "unsafe-eval", "*", "blob:", "/realms"} {
		if strings.Contains(got, s) {
			t.Fatalf("policy has %s", s)
		}
	}
	if got, _ := (Policy{Issuer: "http://[::1]:8180/realms/warden"}).CSP(); !strings.Contains(got, "connect-src 'self' http://[::1]:8180;") {
		t.Fatal(got)
	}
}

// A provider whose endpoints live on other hosts (Google: issuer
// accounts.google.com, token endpoint oauth2.googleapis.com).
func TestCSPWithDiscoveredEndpoints(t *testing.T) {
	got, err := Policy{
		Issuer:        "https://accounts.google.com",
		Storage:       "https://s3.warden.example",
		Authorization: "https://accounts.google.com/o/oauth2/v2/auth",
		Token:         "https://oauth2.googleapis.com/token",
		UserInfo:      "https://openidconnect.googleapis.com/v1/userinfo",
		EndSession:    "https://logout.example.com/end?x=1",
	}.CSP()
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{
		"connect-src 'self' https://accounts.google.com https://oauth2.googleapis.com https://openidconnect.googleapis.com https://logout.example.com https://s3.warden.example;",
		"frame-src 'self' https://accounts.google.com;",
		"form-action 'self' https://accounts.google.com https://logout.example.com;",
	} {
		if !strings.Contains(got, d) {
			t.Errorf("missing %q in %s", d, got)
		}
	}
	// A discovered value that isn't a plain origin is dropped, never pasted in.
	got, err = Policy{Issuer: "https://sso.example.com", Token: "https://evil.example; script-src *", UserInfo: "javascript:x"}.CSP()
	if err != nil || strings.Contains(got, "evil") || strings.Contains(got, "javascript") ||
		!strings.Contains(got, "connect-src 'self' https://sso.example.com;") {
		t.Fatalf("%v %s", err, got)
	}
}

// Configuration values are pasted into a header: nothing may add a directive or a source.
func TestCSPRefusesInjection(t *testing.T) {
	for _, bad := range []string{
		"",
		"sso.example.com",
		"javascript:alert(1)",
		"ftp://sso.example.com",
		"https://sso.example.com; script-src *",
		"https://sso.example.com%3B%20script-src%20*",
		"https://sso.example.com,evil.example",
		"https://user:pw@sso.example.com",
		"https://*.example.com",
		"https://sso.example.com:99999999",
		"https://sso.example.com 'unsafe-inline'",
	} {
		if p, err := (Policy{Issuer: bad}).CSP(); err == nil {
			t.Errorf("issuer %q accepted: %s", bad, p)
		}
		if p, err := (Policy{Issuer: "https://sso.example.com", Storage: bad}).CSP(); err == nil && bad != "" {
			t.Errorf("storage %q accepted: %s", bad, p)
		}
	}
}
