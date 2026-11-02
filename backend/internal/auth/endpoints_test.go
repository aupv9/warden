package auth

import (
	"context"
	"testing"
	"time"
)

// Discovery's browser-facing endpoints are kept for the web UI's CSP; one on
// plain http elsewhere is dropped, and Warm fetches once while fresh.
func TestBrowserEndpointsFromDiscovery(t *testing.T) {
	srv, hits := provider(t, func(b string) map[string]any {
		d := oktaDoc(b)
		d["authorization_endpoint"] = b + "/oauth2/default/v1/authorize"
		d["token_endpoint"] = "https://oauth2.googleapis.example/token"
		d["userinfo_endpoint"] = "http://evil.example/userinfo"
		d["end_session_endpoint"] = "https://u:p@evil.example/logout"
		return d
	}, jwkOf("k1", &testKey.PublicKey, "sig"))
	iss := srv.URL + "/oauth2/default"
	j := NewJWKS(iss, "", time.Minute, []string{"RS256"})
	if (j.BrowserEndpoints() != BrowserEndpoints{}) {
		t.Fatal("endpoints before discovery")
	}
	if err := j.Warm(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := BrowserEndpoints{Authorization: srv.URL + "/oauth2/default/v1/authorize", Token: "https://oauth2.googleapis.example/token"}
	if got := j.BrowserEndpoints(); got != want {
		t.Fatalf("%+v", got)
	}
	n := hits.Load()
	if err := j.Warm(context.Background()); err != nil || hits.Load() != n {
		t.Fatalf("fresh cache refetched: %v", err)
	}
	// A pinned key URL skips discovery: no endpoints.
	pinned := NewJWKS(iss, srv.URL+"/oauth2/default/v1/keys", time.Minute, []string{"RS256"})
	if err := pinned.Warm(context.Background()); err != nil || (pinned.BrowserEndpoints() != BrowserEndpoints{}) {
		t.Fatalf("%v %+v", err, pinned.BrowserEndpoints())
	}
}
