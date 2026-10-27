package api

import (
	"github.com/gin-gonic/gin"

	"github.com/aupv9/warden/backend/internal/service"
)

// Sign-in settings: a read-only view of the server's identity-provider
// settings plus the org's sign-in policy, which can only tighten them.
func (h handlers) signInRoutes(o *gin.RouterGroup) {
	o.GET("/sign-in", h.signInSettings)
	o.PUT("/sign-in-policy", h.setSignInPolicy)
}

func (h handlers) signInSettings(c *gin.Context) {
	out, err := h.svc.SignInSettings(c.Request.Context(), actor(c))
	reply(c, false, out, err)
}

func (h handlers) setSignInPolicy(c *gin.Context) {
	var in service.SignInPolicyInput
	if !bind(c, &in) {
		return
	}
	out, err := h.svc.SetSignInPolicy(c.Request.Context(), actor(c), in)
	reply(c, false, out, err)
}
