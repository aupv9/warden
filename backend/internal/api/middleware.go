package api

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	cgauth "github.com/aupv9/common-go/auth"
	apperrors "github.com/aupv9/common-go/errors"
	"github.com/aupv9/common-go/logger"
	"github.com/aupv9/common-go/response"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/auth"
	"github.com/aupv9/warden/backend/internal/service"
)

const (
	userKey     = "warden.user"
	identityKey = "warden.identity"
	actorKey    = "warden.actor"
)

// fail renders err. Expected errors (*AppError other than internal) are shown
// as they are; anything else is logged and becomes a generic 500, so SQL and
// driver messages never reach the client.
func fail(c *gin.Context, err error) {
	c.Abort()
	if ae, ok := apperrors.As(err); ok && ae.Kind != apperrors.KindInternal {
		if ae.Kind == apperrors.KindUnauthorized {
			c.Header("WWW-Authenticate", `Bearer realm="warden"`)
		}
		if secs, ok := ae.Metadata["retry_after"].(int64); ok && ae.HTTPStatus() == http.StatusTooManyRequests {
			c.Header("Retry-After", strconv.FormatInt(secs, 10))
		}
		response.Error(c.Writer, c.Request, ae)
		return
	}
	logger.FromContext(c.Request.Context()).Error("request failed",
		slog.String("method", c.Request.Method), slog.String("route", c.FullPath()), slog.Any("error", err))
	response.Error(c.Writer, c.Request, apperrors.Internal("INTERNAL", "internal server error"))
}

func identityFrom(p *cgauth.Principal) service.Identity {
	id := service.Identity{Sub: p.Subject, Email: auth.Email(p), Name: auth.Name(p), MFA: auth.MFA(p)}
	if v, ok := p.Claims["email_verified"].(bool); ok {
		id.EmailVerified = &v
	}
	return id
}

// identify maps the verified token to an active app_user (provisioning it on
// first sight). Inactive users get 403 on every endpoint.
func identify(svc *service.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		p, ok := cgauth.FromContext(c.Request.Context())
		if !ok {
			fail(c, apperrors.Unauthorized("UNAUTHORIZED", "invalid or expired token"))
			return
		}
		id := identityFrom(p)
		u, err := svc.Authenticate(c.Request.Context(), id)
		if err != nil {
			fail(c, err)
			return
		}
		c.Set(userKey, u)
		c.Set(identityKey, id)
		c.Next()
	}
}

func currentUser(c *gin.Context) service.User {
	u, _ := c.Get(userKey)
	return u.(service.User)
}

// orgScope requires the caller to be a member of the path's org. Non-members
// (and malformed ids) get 404, so org ids can't be probed. The service re-checks
// membership inside each transaction and sets app.org_id for RLS.
func orgScope(svc *service.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		orgID, err := uuid.Parse(c.Param("org_id"))
		if err != nil {
			fail(c, apperrors.NotFound("NOT_FOUND", "not found"))
			return
		}
		u := currentUser(c)
		role, err := svc.OrgRole(c.Request.Context(), u.ID, orgID)
		if err != nil {
			fail(c, err)
			return
		}
		c.Set(actorKey, &service.Actor{
			UserID: u.ID, OrgID: orgID, OrgRole: role,
			// RemoteIP, not ClientIP: X-Forwarded-For is client-controlled
			// unless a trusted proxy is configured, and this goes in the audit log.
			IP: c.RemoteIP(), UserAgent: c.Request.UserAgent(),
		})
		c.Next()
	}
}

func actor(c *gin.Context) *service.Actor {
	a, _ := c.Get(actorKey)
	return a.(*service.Actor)
}

// pathID parses a UUID path parameter; a malformed id is a 404, like a missing object.
func pathID(c *gin.Context, name string) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param(name))
	if err != nil {
		fail(c, apperrors.NotFound("NOT_FOUND", "not found"))
		return uuid.Nil, false
	}
	return id, true
}

// bind decodes a JSON body strictly: unknown fields, trailing data, wrong types
// and malformed JSON are 422 VALIDATION_FAILED.
func bind(c *gin.Context, dst any) bool {
	dec := json.NewDecoder(c.Request.Body)
	dec.DisallowUnknownFields()
	err := dec.Decode(dst)
	if err == nil && dec.More() {
		err = errors.New("trailing data")
	}
	if err == nil {
		if _, terr := dec.Token(); terr != io.EOF {
			err = errors.New("trailing data")
		}
	}
	if err == nil {
		return true
	}
	var (
		mbe *http.MaxBytesError
		ute *json.UnmarshalTypeError
	)
	switch {
	case errors.As(err, &mbe):
		fail(c, apperrors.Invalid("PAYLOAD_TOO_LARGE", "request body too large").WithHTTPStatus(http.StatusRequestEntityTooLarge))
	case errors.As(err, &ute) && ute.Field != "":
		fail(c, service.ErrValidation(map[string]string{ute.Field: "has the wrong type"}))
	case strings.HasPrefix(err.Error(), "json: unknown field "):
		field := strings.Trim(strings.TrimPrefix(err.Error(), "json: unknown field "), `"`)
		fail(c, service.ErrValidation(map[string]string{field: "unknown field"}))
	case errors.Is(err, io.EOF):
		fail(c, service.ErrValidation(map[string]string{"body": "a JSON body is required"}))
	default:
		fail(c, service.ErrValidation(map[string]string{"body": "must be a valid JSON object"}))
	}
	return false
}

func page(c *gin.Context) service.PageParams {
	return service.PageParams{Limit: c.Query("limit"), Cursor: c.Query("cursor")}
}
