package api

import (
	"github.com/gin-gonic/gin"

	"github.com/aupv9/warden/backend/internal/service"
)

// v0.4 routes: the component inventory and a project's scan targets.
func (h handlers) v04Routes(o *gin.RouterGroup) {
	o.GET("/components", h.components)
	o.GET("/components/usage", h.componentUsage)
	o.GET("/projects/:project_id/components", h.projectComponents)
	o.GET("/projects/:project_id/targets", h.projectTargets)
}

func componentFilter(c *gin.Context) service.ComponentFilter {
	target, hasTarget := c.GetQuery("target")
	return service.ComponentFilter{Q: c.Query("q"), Ecosystem: c.Query("ecosystem"), Version: c.Query("version"),
		ProjectID: c.Query("project_id"), Malicious: c.Query("malicious"), Target: target, HasTarget: hasTarget, PageParams: page(c)}
}

func (h handlers) components(c *gin.Context) {
	out, err := h.svc.Components(c.Request.Context(), actor(c), componentFilter(c))
	reply(c, false, out, err)
}

func (h handlers) componentUsage(c *gin.Context) {
	f := service.UsageFilter{Ecosystem: c.Query("ecosystem"), Name: c.Query("name"), Version: c.Query("version"), PageParams: page(c)}
	out, err := h.svc.ComponentUsage(c.Request.Context(), actor(c), f)
	reply(c, false, out, err)
}

func (h handlers) projectComponents(c *gin.Context) {
	id, ok := pathID(c, "project_id")
	if !ok {
		return
	}
	out, err := h.svc.ProjectComponents(c.Request.Context(), actor(c), id, componentFilter(c))
	reply(c, false, out, err)
}

func (h handlers) projectTargets(c *gin.Context) {
	id, ok := pathID(c, "project_id")
	if !ok {
		return
	}
	out, err := h.svc.ProjectTargets(c.Request.Context(), actor(c), id)
	reply(c, false, out, err)
}
