package api

import (
	"github.com/gin-gonic/gin"
)

// v0.5 routes: org-wide targets and ecosystem counts. None is in tokenRoutes:
// API tokens can't call them.
func (h handlers) v05Routes(o *gin.RouterGroup) {
	o.GET("/targets", h.orgTargets)
	o.GET("/components/ecosystems", h.componentEcosystems)
}

func (h handlers) orgTargets(c *gin.Context) {
	out, err := h.svc.OrgTargets(c.Request.Context(), actor(c), c.Query("kind"))
	reply(c, false, out, err)
}

func (h handlers) componentEcosystems(c *gin.Context) {
	out, err := h.svc.ComponentEcosystems(c.Request.Context(), actor(c))
	reply(c, false, out, err)
}
