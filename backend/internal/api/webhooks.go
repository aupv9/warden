package api

import (
	"net/http"

	"github.com/aupv9/common-go/response"
	"github.com/gin-gonic/gin"

	"github.com/aupv9/warden/backend/internal/service"
)

// Webhooks and Slack (v0.4 wave 2). None of these routes is in tokenRoutes:
// API tokens can't manage integrations.
func (h handlers) webhookRoutes(o *gin.RouterGroup) {
	o.GET("/webhooks", h.webhooks)
	o.POST("/webhooks", h.createWebhook)
	o.GET("/webhooks/:webhook_id", h.webhook)
	o.PATCH("/webhooks/:webhook_id", h.updateWebhook)
	o.DELETE("/webhooks/:webhook_id", h.deleteWebhook)
	o.POST("/webhooks/:webhook_id/rotate-secret", h.rotateWebhookSecret)
	o.POST("/webhooks/:webhook_id/test", h.testWebhook)
	o.GET("/webhooks/:webhook_id/deliveries", h.webhookDeliveries)
}

func (h handlers) webhooks(c *gin.Context) {
	out, err := h.svc.Webhooks(c.Request.Context(), actor(c))
	reply(c, false, out, err)
}

func (h handlers) createWebhook(c *gin.Context) {
	var in service.CreateWebhookInput
	if !bind(c, &in) {
		return
	}
	out, err := h.svc.CreateWebhook(c.Request.Context(), actor(c), in)
	reply(c, true, out, err)
}

func (h handlers) webhook(c *gin.Context) {
	id, ok := pathID(c, "webhook_id")
	if !ok {
		return
	}
	out, err := h.svc.Webhook(c.Request.Context(), actor(c), id)
	reply(c, false, out, err)
}

func (h handlers) updateWebhook(c *gin.Context) {
	id, ok := pathID(c, "webhook_id")
	if !ok {
		return
	}
	var in service.UpdateWebhookInput
	if !bind(c, &in) {
		return
	}
	out, err := h.svc.UpdateWebhook(c.Request.Context(), actor(c), id, in)
	reply(c, false, out, err)
}

func (h handlers) deleteWebhook(c *gin.Context) {
	id, ok := pathID(c, "webhook_id")
	if !ok {
		return
	}
	noContent(c, h.svc.DeleteWebhook(c.Request.Context(), actor(c), id))
}

func (h handlers) rotateWebhookSecret(c *gin.Context) {
	id, ok := pathID(c, "webhook_id")
	if !ok {
		return
	}
	out, err := h.svc.RotateWebhookSecret(c.Request.Context(), actor(c), id)
	reply(c, false, out, err)
}

// testWebhook answers 202: the delivery is queued, its result comes later.
func (h handlers) testWebhook(c *gin.Context) {
	id, ok := pathID(c, "webhook_id")
	if !ok {
		return
	}
	out, err := h.svc.TestWebhook(c.Request.Context(), actor(c), id)
	if err != nil {
		fail(c, err)
		return
	}
	response.OK(accepted{c.Writer}, c.Request, out)
}

func (h handlers) webhookDeliveries(c *gin.Context) {
	id, ok := pathID(c, "webhook_id")
	if !ok {
		return
	}
	out, err := h.svc.WebhookDeliveries(c.Request.Context(), actor(c), id, page(c))
	reply(c, false, out, err)
}

// accepted turns the 200 that response.OK writes into a 202, keeping its
// envelope and meta.
type accepted struct{ http.ResponseWriter }

func (w accepted) WriteHeader(code int) {
	if code == http.StatusOK {
		code = http.StatusAccepted
	}
	w.ResponseWriter.WriteHeader(code)
}
