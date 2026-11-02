package api

import (
	"github.com/gin-gonic/gin"

	"github.com/aupv9/warden/backend/internal/service"
)

// v0.3 routes: a scan's SBOM download and the org's license policy.
func (h handlers) v03Routes(o *gin.RouterGroup) {
	o.GET("/scans/:scan_id/sbom", h.scanSBOM)
	o.GET("/license-policy", h.licensePolicy)
	o.PUT("/license-policy", h.setLicensePolicy)
}

func (h handlers) scanSBOM(c *gin.Context) {
	id, ok := pathID(c, "scan_id")
	if !ok {
		return
	}
	out, err := h.svc.ScanSBOM(c.Request.Context(), actor(c), id, c.Query("format"))
	reply(c, false, out, err)
}

func (h handlers) licensePolicy(c *gin.Context) {
	out, err := h.svc.LicensePolicy(c.Request.Context(), actor(c))
	reply(c, false, out, err)
}

func (h handlers) setLicensePolicy(c *gin.Context) {
	var in service.LicensePolicyInput
	if !bind(c, &in) {
		return
	}
	out, err := h.svc.SetLicensePolicy(c.Request.Context(), actor(c), in)
	reply(c, false, out, err)
}
