package api

import (
	"github.com/gin-gonic/gin"

	"github.com/aupv9/warden/backend/internal/service"
)

// Imports of another tool's results (v0.8 wave 1). The route is in
// tokenRoutes with scan:write, like an upload; start, status and gate are the
// scan routes every scan uses.
func (h handlers) importRoutes(o *gin.RouterGroup) {
	o.POST("/projects/:project_id/scans/import", h.createImportScan)
}

func (h handlers) createImportScan(c *gin.Context) {
	projectID, ok := pathID(c, "project_id")
	if !ok {
		return
	}
	var in service.ImportScanInput
	if !bind(c, &in) {
		return
	}
	out, err := h.svc.CreateImportScan(c.Request.Context(), actor(c), projectID, in)
	reply(c, true, out, err)
}
