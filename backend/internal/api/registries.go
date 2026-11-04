package api

import (
	"github.com/gin-gonic/gin"

	"github.com/aupv9/warden/backend/internal/service"
)

// Registry credentials and pulled image scans (v0.7 wave 2). Only the pull
// route is in tokenRoutes: API tokens can't manage credentials.
func (h handlers) registryRoutes(o *gin.RouterGroup) {
	o.GET("/registries", h.registries)
	o.POST("/registries", h.createRegistry)
	o.PATCH("/registries/:registry_id", h.updateRegistry)
	o.DELETE("/registries/:registry_id", h.deleteRegistry)
	o.POST("/registries/:registry_id/test", h.testRegistry)
	o.POST("/projects/:project_id/scans/pull", h.createPullScan)
}

func (h handlers) registries(c *gin.Context) {
	out, err := h.svc.RegistryCredentials(c.Request.Context(), actor(c))
	reply(c, false, out, err)
}

func (h handlers) createRegistry(c *gin.Context) {
	var in service.CreateRegistryCredentialInput
	if !bind(c, &in) {
		return
	}
	out, err := h.svc.CreateRegistryCredential(c.Request.Context(), actor(c), in)
	reply(c, true, out, err)
}

func (h handlers) updateRegistry(c *gin.Context) {
	id, ok := pathID(c, "registry_id")
	if !ok {
		return
	}
	var in service.UpdateRegistryCredentialInput
	if !bind(c, &in) {
		return
	}
	out, err := h.svc.UpdateRegistryCredential(c.Request.Context(), actor(c), id, in)
	reply(c, false, out, err)
}

func (h handlers) deleteRegistry(c *gin.Context) {
	id, ok := pathID(c, "registry_id")
	if !ok {
		return
	}
	noContent(c, h.svc.DeleteRegistryCredential(c.Request.Context(), actor(c), id))
}

func (h handlers) testRegistry(c *gin.Context) {
	id, ok := pathID(c, "registry_id")
	if !ok {
		return
	}
	out, err := h.svc.TestRegistryCredential(c.Request.Context(), actor(c), id)
	reply(c, false, out, err)
}

func (h handlers) createPullScan(c *gin.Context) {
	projectID, ok := pathID(c, "project_id")
	if !ok {
		return
	}
	var in service.PullScanInput
	if !bind(c, &in) {
		return
	}
	out, err := h.svc.CreatePullScan(c.Request.Context(), actor(c), projectID, in)
	reply(c, true, out, err)
}
