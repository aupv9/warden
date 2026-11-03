package api

import (
	"github.com/aupv9/common-go/response"
	"github.com/gin-gonic/gin"

	"github.com/aupv9/warden/backend/internal/service"
)

// An org's own scan rules (v0.6 wave 1). None of these routes is in
// tokenRoutes: API tokens can't read or change rules.
func (h handlers) scanRuleRoutes(o *gin.RouterGroup) {
	o.GET("/scan-rules", h.scanRules)
	o.POST("/scan-rules", h.createScanRule)
	o.POST("/scan-rules/validate", h.validateScanRule)
	o.POST("/scan-rules/tests", h.createRuleTest)
	o.GET("/scan-rules/tests/:test_id", h.ruleTest)
	o.GET("/scan-rules/:rule_id", h.scanRule)
	o.PATCH("/scan-rules/:rule_id", h.updateScanRule)
	o.DELETE("/scan-rules/:rule_id", h.deleteScanRule)
	o.GET("/scan-rules/:rule_id/versions", h.scanRuleVersions)
}

func (h handlers) scanRules(c *gin.Context) {
	out, err := h.svc.ScanRules(c.Request.Context(), actor(c), service.ScanRuleFilter{Tool: c.Query("tool")})
	reply(c, false, out, err)
}

func (h handlers) createScanRule(c *gin.Context) {
	var in service.CreateScanRuleInput
	if !bind(c, &in) {
		return
	}
	out, err := h.svc.CreateScanRule(c.Request.Context(), actor(c), in)
	reply(c, true, out, err)
}

func (h handlers) validateScanRule(c *gin.Context) {
	var in service.ValidateScanRuleInput
	if !bind(c, &in) {
		return
	}
	out, err := h.svc.ValidateScanRule(c.Request.Context(), actor(c), in)
	reply(c, false, out, err)
}

// createRuleTest answers 202: the run is queued, its result comes later.
func (h handlers) createRuleTest(c *gin.Context) {
	var in service.RuleTestInput
	if !bind(c, &in) {
		return
	}
	out, err := h.svc.CreateRuleTest(c.Request.Context(), actor(c), in)
	if err != nil {
		fail(c, err)
		return
	}
	response.OK(accepted{c.Writer}, c.Request, out)
}

func (h handlers) ruleTest(c *gin.Context) {
	id, ok := pathID(c, "test_id")
	if !ok {
		return
	}
	out, err := h.svc.RuleTest(c.Request.Context(), actor(c), id)
	reply(c, false, out, err)
}

func (h handlers) scanRule(c *gin.Context) {
	id, ok := pathID(c, "rule_id")
	if !ok {
		return
	}
	out, err := h.svc.ScanRule(c.Request.Context(), actor(c), id)
	reply(c, false, out, err)
}

func (h handlers) updateScanRule(c *gin.Context) {
	id, ok := pathID(c, "rule_id")
	if !ok {
		return
	}
	var in service.UpdateScanRuleInput
	if !bind(c, &in) {
		return
	}
	out, err := h.svc.UpdateScanRule(c.Request.Context(), actor(c), id, in)
	reply(c, false, out, err)
}

func (h handlers) deleteScanRule(c *gin.Context) {
	id, ok := pathID(c, "rule_id")
	if !ok {
		return
	}
	noContent(c, h.svc.DeleteScanRule(c.Request.Context(), actor(c), id, c.Query("version")))
}

func (h handlers) scanRuleVersions(c *gin.Context) {
	id, ok := pathID(c, "rule_id")
	if !ok {
		return
	}
	out, err := h.svc.ScanRuleVersions(c.Request.Context(), actor(c), id, page(c))
	reply(c, false, out, err)
}
