package api

import (
	"net/http"
	"slices"
	"sync"
	"time"

	apperrors "github.com/aupv9/common-go/errors"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/service"
)

const (
	tokenKey = "warden.api_token"
	// tokenRequestsPerMinute is the per-token rate limit.
	tokenRequestsPerMinute = 60
)

// tokenRoutes is the only place that decides what an API token may call: the
// route (method and gin path) and the scopes that allow it (any one is
// enough). Anything else is 403 TOKEN_SCOPE, including routes added later.
// Which project a token may reach is enforced by the service (projectAccess):
// its own, else 404.
var tokenRoutes = map[string][]string{
	"POST " + Prefix + "/orgs/:org_id/projects/:project_id/scans": {service.ScopeScanWrite},
	"POST " + Prefix + "/orgs/:org_id/scans/:scan_id/start":       {service.ScopeScanWrite},
	"POST " + Prefix + "/orgs/:org_id/scans/:scan_id/cancel":      {service.ScopeScanWrite},
	"GET " + Prefix + "/orgs/:org_id/scans/:scan_id":              {service.ScopeScanWrite},
	"GET " + Prefix + "/orgs/:org_id/scans/:scan_id/gate":         {service.ScopeScanWrite},
	// The CLI fetches the SBOM after its scan; a reporting job may too.
	"GET " + Prefix + "/orgs/:org_id/scans/:scan_id/sbom": {service.ScopeScanWrite, service.ScopeIssuesRead},
	"GET " + Prefix + "/orgs/:org_id/issues":              {service.ScopeIssuesRead},
	"GET " + Prefix + "/orgs/:org_id/issues/:issue_id":    {service.ScopeIssuesRead},
	// The project's own inventory and targets; the org-wide component search
	// spans projects, so no token may call it.
	"GET " + Prefix + "/orgs/:org_id/projects/:project_id/components": {service.ScopeIssuesRead},
	"GET " + Prefix + "/orgs/:org_id/projects/:project_id/targets":    {service.ScopeIssuesRead},
}

func errTokenScope() error {
	return apperrors.Forbidden("TOKEN_SCOPE", "this API token can't be used for this request")
}

func errTokenRateLimited(retryAfter time.Duration) error {
	secs := int64((retryAfter + time.Second - 1) / time.Second)
	if secs < 1 {
		secs = 1
	}
	return apperrors.Invalid("RATE_LIMITED", "too many requests with this API token; try again later").
		WithHTTPStatus(http.StatusTooManyRequests).WithMetadata("retry_after", secs)
}

// tokenAuth authenticates an API token, applies its rate limit and the route
// allow-list. A bad token gets the same 401 as a bad access token. The limit is
// keyed by token id after authentication, so knowing a token's (non-secret)
// prefix doesn't let anyone exhaust its quota.
func tokenAuth(c *gin.Context, svc *service.Service, lim *rateLimiter, raw string) bool {
	t, err := svc.AuthenticateToken(c.Request.Context(), raw)
	if err != nil {
		fail(c, err)
		return false
	}
	if ok, retry := lim.allow(t.ID); !ok {
		fail(c, errTokenRateLimited(retry))
		return false
	}
	if scopes := tokenRoutes[c.Request.Method+" "+c.FullPath()]; !slices.ContainsFunc(scopes, t.Has) {
		fail(c, errTokenScope())
		return false
	}
	c.Set(tokenKey, t)
	c.Set(userKey, t.User)
	return true
}

// apiToken returns the request's API token, or nil for an OIDC sign-in.
func apiToken(c *gin.Context) *service.TokenAuth {
	t, _ := c.Get(tokenKey)
	tok, _ := t.(*service.TokenAuth)
	return tok
}

// rateLimiter is a sliding-window limit per key, in memory: each API instance
// counts on its own, so N instances allow up to N times the limit.
type rateLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	now    func() time.Time
	hits   map[uuid.UUID][]time.Time
}

// sweepAt bounds the limiter's memory: past this many keys, idle ones are dropped.
const sweepAt = 1024

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{limit: limit, window: window, now: time.Now, hits: map[uuid.UUID][]time.Time{}}
}

// allow records a request for key, or says how long to wait.
func (l *rateLimiter) allow(key uuid.UUID) (bool, time.Duration) {
	now := l.now()
	cutoff := now.Add(-l.window)
	l.mu.Lock()
	defer l.mu.Unlock()
	h, ok := l.hits[key]
	if !ok && len(l.hits) >= sweepAt {
		for k, v := range l.hits {
			if !v[len(v)-1].After(cutoff) {
				delete(l.hits, k)
			}
		}
	}
	i := 0
	for i < len(h) && !h[i].After(cutoff) {
		i++
	}
	h = h[i:]
	if len(h) >= l.limit {
		l.hits[key] = h
		return false, h[0].Sub(cutoff)
	}
	l.hits[key] = append(h, now)
	return true, 0
}

type tokenHandlers struct{ svc *service.Service }

// registerTokenRoutes mounts the API-token management routes and the scan gate
// on the org group.
func registerTokenRoutes(o *gin.RouterGroup, svc *service.Service) {
	h := tokenHandlers{svc: svc}
	o.GET("/projects/:project_id/tokens", h.list)
	o.POST("/projects/:project_id/tokens", h.create)
	o.DELETE("/projects/:project_id/tokens/:token_id", h.revoke)
	o.GET("/scans/:scan_id/gate", h.gate)
}

func (h tokenHandlers) list(c *gin.Context) {
	projectID, ok := pathID(c, "project_id")
	if !ok {
		return
	}
	out, err := h.svc.Tokens(c.Request.Context(), actor(c), projectID)
	reply(c, false, out, err)
}

func (h tokenHandlers) create(c *gin.Context) {
	projectID, ok := pathID(c, "project_id")
	if !ok {
		return
	}
	var in service.CreateTokenInput
	if !bind(c, &in) {
		return
	}
	out, err := h.svc.CreateToken(c.Request.Context(), actor(c), projectID, in)
	reply(c, true, out, err)
}

func (h tokenHandlers) revoke(c *gin.Context) {
	projectID, ok := pathID(c, "project_id")
	if !ok {
		return
	}
	tokenID, ok := pathID(c, "token_id")
	if !ok {
		return
	}
	noContent(c, h.svc.RevokeToken(c.Request.Context(), actor(c), projectID, tokenID))
}

func (h tokenHandlers) gate(c *gin.Context) {
	scanID, ok := pathID(c, "scan_id")
	if !ok {
		return
	}
	out, err := h.svc.Gate(c.Request.Context(), actor(c), scanID, c.Query("fail_on"), c.Query("fail_on_kev"))
	reply(c, false, out, err)
}
