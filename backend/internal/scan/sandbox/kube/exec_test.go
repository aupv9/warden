package kube

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// The worker's Role grants pods/exec "create" only. A WebSocket exec is a GET,
// which API servers before 1.35 authorize as "get": RemoteExecer must then
// fall back to SPDY, a POST ("create"), instead of failing.
func TestRemoteExecFallsBackToPOST(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path)
		mu.Unlock()
		if r.Method == http.MethodGet {
			// RBAC: the upgrade is a "get" the Role doesn't grant.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Forbidden","code":403}`))
			return
		}
		http.Error(w, "no SPDY here", http.StatusBadRequest)
	}))
	defer srv.Close()
	rc := &rest.Config{Host: srv.URL}
	cs, err := kubernetes.NewForConfig(rc)
	if err != nil {
		t.Fatal(err)
	}
	err = RemoteExecer{Config: rc, Client: cs}.Exec(context.Background(), "ns", "pod", "io-out", []string{ioBinary, "send"}, nil, &tail{n: 10}, &tail{n: 10})
	if err == nil {
		t.Fatal("exec succeeded against a server without exec")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 || !strings.HasPrefix(seen[0], "GET /api/v1/namespaces/ns/pods/pod/exec") ||
		!strings.HasPrefix(seen[1], "POST /api/v1/namespaces/ns/pods/pod/exec") {
		t.Fatalf("requests %v: want the WebSocket GET, then the SPDY POST", seen)
	}
}
