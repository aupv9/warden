package storage

import (
	"context"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aupv9/warden/backend/internal/config"
)

// Presigned URLs name the public endpoint (and sign its host); everything the
// server does itself still goes to the internal one.
func TestPublicEndpointOnlyForPresignedURLs(t *testing.T) {
	ctx := context.Background()
	f := &fakeS3{objects: map[string]string{"k": "hello"}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c, err := New(FromSection(config.StorageSection{Endpoint: srv.URL, PublicEndpoint: "https://s3.warden.example/",
		Bucket: "bucket", AccessKey: "ak", SecretKey: "sk"}))
	if err != nil {
		t.Fatal(err)
	}
	put, _, err := c.PresignPut(ctx, "scans/o/s.zip", 5, okSum, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	get, err := c.PresignGet(ctx, "sboms/o/s.json", time.Minute, "sbom.json", "application/json")
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{put, get} {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Host != "s3.warden.example" || !strings.HasPrefix(u.Path, "/bucket/") ||
			!strings.Contains(u.Query().Get("X-Amz-SignedHeaders"), "host") {
			t.Fatalf("presigned URL %s", raw)
		}
	}
	if o, err := c.PublicOrigin(ctx); err != nil || o != "https://s3.warden.example" {
		t.Fatalf("origin %q %v", o, err)
	}
	if n, err := c.Head(ctx, "k"); err != nil || n != 5 {
		t.Fatalf("head %d %v", n, err)
	}
	if err := c.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	if len(f.reqs) != 2 {
		t.Fatalf("internal endpoint saw %v", f.reqs)
	}
}

func TestPublicOrigin(t *testing.T) {
	for _, tc := range []struct {
		cfg  Config
		want string
	}{
		{Config{Endpoint: "http://s3:8333"}, "http://s3:8333"},
		{Config{Region: "eu-west-1"}, "https://uploads.s3.eu-west-1.amazonaws.com"},
		{Config{Endpoint: "https://s3.eu-west-1.amazonaws.com"}, "https://uploads.s3.eu-west-1.amazonaws.com"},
		{Config{Endpoint: "http://s3:8333", PublicEndpoint: "https://files.warden.example:8443"}, "https://files.warden.example:8443"},
	} {
		cfg := tc.cfg
		cfg.Bucket, cfg.AccessKey, cfg.SecretKey = "uploads", "ak", "sk"
		c, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := c.PublicOrigin(context.Background()); err != nil || got != tc.want {
			t.Errorf("%+v: %q %v, want %q", tc.cfg, got, err, tc.want)
		}
	}
	for _, bad := range []string{"ftp://x", "https://", "s3.example.com", "https://user:pw@s3.example.com"} {
		if _, err := New(Config{Endpoint: "http://s3:8333", PublicEndpoint: bad, Bucket: "b", AccessKey: "a", SecretKey: "s"}); err == nil {
			t.Errorf("public endpoint %q accepted", bad)
		}
	}
}
