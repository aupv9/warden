package api

import (
	"encoding/json"
	"log/slog"
	"regexp"
	"strings"
	"testing"

	"github.com/aupv9/common-go/transport/httpserver"

	"github.com/aupv9/warden/backend/internal/service"
	"github.com/aupv9/warden/backend/internal/service/servicetest"
)

// The OpenAPI document must describe exactly the routes the server serves, and
// every $ref must resolve.
func TestOpenAPIMatchesRoutes(t *testing.T) {
	var doc struct {
		OpenAPI    string                    `json:"openapi"`
		Paths      map[string]map[string]any `json:"paths"`
		Components struct {
			Schemas map[string]any `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(openAPI, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.OpenAPI != "3.1.0" {
		t.Fatal(doc.OpenAPI)
	}
	documented := map[string]bool{}
	for path, ops := range doc.Paths {
		for method := range ops {
			if method != "parameters" {
				documented[strings.ToUpper(method)+" "+path] = true
			}
		}
	}

	srv, err := httpserver.New(slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	Register(srv.Engine(), verifier(), service.New(servicetest.New(), nil, service.Config{}, nil))
	param := regexp.MustCompile(`:([a-z_]+)`)
	served := map[string]bool{}
	for _, r := range srv.Engine().Routes() {
		if !strings.HasPrefix(r.Path, Prefix+"/") || r.Path == Prefix+"/openapi.json" {
			continue
		}
		key := r.Method + " " + param.ReplaceAllString(strings.TrimPrefix(r.Path, Prefix), "{$1}")
		served[key] = true
		if !documented[key] {
			t.Errorf("route not documented: %s", key)
		}
	}
	for key := range documented {
		if !served[key] {
			t.Errorf("documented but not served: %s", key)
		}
	}

	for _, m := range regexp.MustCompile(`"\$ref": ?"#/components/schemas/([A-Za-z]+)"`).FindAllSubmatch(openAPI, -1) {
		if _, ok := doc.Components.Schemas[string(m[1])]; !ok {
			t.Errorf("dangling $ref %s", m[1])
		}
	}
}
