package api

import (
	"github.com/gin-gonic/gin"

	"github.com/aupv9/warden/backend/internal/service"
)

// v02Routes mounts the v0.2 notification, policy/automation and metrics routes.
func (h handlers) v02Routes(v1, o *gin.RouterGroup) {
	v1.GET("/me/notifications", h.notifications)
	v1.GET("/me/notifications/unread-count", h.unreadCount)
	v1.POST("/me/notifications/read", h.markRead)
	v1.GET("/me/notification-prefs", h.notificationPrefs)
	v1.PUT("/me/notification-prefs", h.setNotificationPrefs)

	o.PATCH("", h.setOrgPolicy)
	o.GET("/metrics", h.metrics)
	o.GET("/issues/counts", h.issueCounts)
	o.GET("/projects/:project_id/assign-rules", h.assignRules)
	o.PUT("/projects/:project_id/assign-rules", h.setAssignRules)
	o.POST("/projects/:project_id/archive", h.archiveProject(true))
	o.POST("/projects/:project_id/unarchive", h.archiveProject(false))
}

func (h handlers) notifications(c *gin.Context) {
	f := service.NotificationFilter{Unread: c.Query("unread"), PageParams: page(c)}
	out, err := h.svc.Notifications(c.Request.Context(), currentUser(c).ID, f)
	reply(c, false, out, err)
}

func (h handlers) unreadCount(c *gin.Context) {
	out, err := h.svc.UnreadNotifications(c.Request.Context(), currentUser(c).ID)
	reply(c, false, out, err)
}

func (h handlers) markRead(c *gin.Context) {
	var in service.MarkReadInput
	if !bind(c, &in) {
		return
	}
	noContent(c, h.svc.MarkNotificationsRead(c.Request.Context(), currentUser(c).ID, in))
}

func (h handlers) notificationPrefs(c *gin.Context) {
	out, err := h.svc.NotificationPrefs(c.Request.Context(), currentUser(c).ID)
	reply(c, false, out, err)
}

func (h handlers) setNotificationPrefs(c *gin.Context) {
	var in service.NotificationPrefsInput
	if !bind(c, &in) {
		return
	}
	out, err := h.svc.SetNotificationPrefs(c.Request.Context(), currentUser(c).ID, in)
	reply(c, false, out, err)
}

func (h handlers) setOrgPolicy(c *gin.Context) {
	var in service.OrgPolicyInput
	if !bind(c, &in) {
		return
	}
	out, err := h.svc.SetOrgPolicy(c.Request.Context(), actor(c), in)
	reply(c, false, out, err)
}

func (h handlers) metrics(c *gin.Context) {
	out, err := h.svc.Metrics(c.Request.Context(), actor(c), service.MetricsFilter{Days: c.Query("days"), ProjectID: c.Query("project_id")})
	reply(c, false, out, err)
}

func (h handlers) issueCounts(c *gin.Context) {
	out, err := h.svc.IssueTotals(c.Request.Context(), actor(c), c.Query("project_id"))
	reply(c, false, out, err)
}

func (h handlers) assignRules(c *gin.Context) {
	id, ok := pathID(c, "project_id")
	if !ok {
		return
	}
	out, err := h.svc.AssignRules(c.Request.Context(), actor(c), id)
	reply(c, false, out, err)
}

func (h handlers) setAssignRules(c *gin.Context) {
	id, ok := pathID(c, "project_id")
	if !ok {
		return
	}
	var in service.AssignRulesInput
	if !bind(c, &in) {
		return
	}
	out, err := h.svc.SetAssignRules(c.Request.Context(), actor(c), id, in)
	reply(c, false, out, err)
}

func (h handlers) archiveProject(archived bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, ok := pathID(c, "project_id")
		if !ok {
			return
		}
		out, err := h.svc.ArchiveProject(c.Request.Context(), actor(c), id, archived)
		reply(c, false, out, err)
	}
}
