package api

import (
	"github.com/aupv9/common-go/response"
	"github.com/gin-gonic/gin"

	"github.com/aupv9/warden/backend/internal/service"
)

type handlers struct{ svc *service.Service }

func (h handlers) routes(v1 *gin.RouterGroup) {
	v1.GET("/me", h.me)

	o := v1.Group("/orgs/:org_id", orgScope(h.svc))
	o.GET("", h.org)
	o.GET("/summary", h.summary)

	o.GET("/members", h.members)
	o.POST("/members", h.addMember)
	o.PATCH("/members/:user_id", h.setMemberRole)
	o.DELETE("/members/:user_id", h.removeMember)

	o.GET("/projects", h.projects)
	o.POST("/projects", h.createProject)
	o.GET("/projects/:project_id", h.project)
	o.GET("/projects/:project_id/members", h.projectMembers)
	o.PUT("/projects/:project_id/members/:user_id", h.setProjectMember)
	o.DELETE("/projects/:project_id/members/:user_id", h.removeProjectMember)
	o.POST("/projects/:project_id/scans", h.createScan)
	o.GET("/projects/:project_id/scans", h.scans)

	o.GET("/scans/:scan_id", h.scan)
	o.POST("/scans/:scan_id/start", h.startScan)
	o.POST("/scans/:scan_id/cancel", h.cancelScan)

	o.GET("/issues", h.issues)
	o.POST("/issues/assign", h.bulkAssign)
	o.GET("/issues/:issue_id", h.issue)
	o.POST("/issues/:issue_id/transitions", h.transition)
	o.GET("/issues/:issue_id/events", h.issueEvents)
	o.GET("/issues/:issue_id/comments", h.comments)
	o.POST("/issues/:issue_id/comments", h.addComment)
	o.POST("/issues/:issue_id/exceptions", h.createException)

	o.GET("/exceptions", h.exceptions)
	o.POST("/exceptions/:exception_id/decision", h.decide)

	o.GET("/audit-log", h.auditLog)
}

// reply renders a service result: data with status (200/201), or the error.
func reply[T any](c *gin.Context, created bool, v T, err error) {
	if err != nil {
		fail(c, err)
		return
	}
	if created {
		response.Created(c.Writer, c.Request, v)
		return
	}
	response.OK(c.Writer, c.Request, v)
}

func noContent(c *gin.Context, err error) {
	if err != nil {
		fail(c, err)
		return
	}
	response.NoContent(c.Writer)
}

func (h handlers) me(c *gin.Context) {
	id, _ := c.Get(identityKey)
	out, err := h.svc.Me(c.Request.Context(), currentUser(c), id.(service.Identity))
	reply(c, false, out, err)
}

func (h handlers) org(c *gin.Context) {
	out, err := h.svc.Org(c.Request.Context(), actor(c))
	reply(c, false, out, err)
}

func (h handlers) summary(c *gin.Context) {
	out, err := h.svc.Summary(c.Request.Context(), actor(c))
	reply(c, false, out, err)
}

func (h handlers) members(c *gin.Context) {
	out, err := h.svc.Members(c.Request.Context(), actor(c))
	reply(c, false, out, err)
}

func (h handlers) addMember(c *gin.Context) {
	var in service.AddMemberInput
	if !bind(c, &in) {
		return
	}
	out, err := h.svc.AddMember(c.Request.Context(), actor(c), in)
	reply(c, true, out, err)
}

func (h handlers) setMemberRole(c *gin.Context) {
	userID, ok := pathID(c, "user_id")
	if !ok {
		return
	}
	var in service.SetMemberRoleInput
	if !bind(c, &in) {
		return
	}
	out, err := h.svc.SetMemberRole(c.Request.Context(), actor(c), userID, in)
	reply(c, false, out, err)
}

func (h handlers) removeMember(c *gin.Context) {
	userID, ok := pathID(c, "user_id")
	if !ok {
		return
	}
	noContent(c, h.svc.RemoveMember(c.Request.Context(), actor(c), userID))
}

func (h handlers) projects(c *gin.Context) {
	out, err := h.svc.Projects(c.Request.Context(), actor(c))
	reply(c, false, out, err)
}

func (h handlers) createProject(c *gin.Context) {
	var in service.CreateProjectInput
	if !bind(c, &in) {
		return
	}
	out, err := h.svc.CreateProject(c.Request.Context(), actor(c), in)
	reply(c, true, out, err)
}

func (h handlers) project(c *gin.Context) {
	id, ok := pathID(c, "project_id")
	if !ok {
		return
	}
	out, err := h.svc.Project(c.Request.Context(), actor(c), id)
	reply(c, false, out, err)
}

func (h handlers) projectMembers(c *gin.Context) {
	id, ok := pathID(c, "project_id")
	if !ok {
		return
	}
	out, err := h.svc.ProjectMembers(c.Request.Context(), actor(c), id)
	reply(c, false, out, err)
}

func (h handlers) setProjectMember(c *gin.Context) {
	projectID, ok := pathID(c, "project_id")
	if !ok {
		return
	}
	userID, ok := pathID(c, "user_id")
	if !ok {
		return
	}
	var in service.SetProjectMemberInput
	if !bind(c, &in) {
		return
	}
	out, err := h.svc.SetProjectMember(c.Request.Context(), actor(c), projectID, userID, in)
	reply(c, false, out, err)
}

func (h handlers) removeProjectMember(c *gin.Context) {
	projectID, ok := pathID(c, "project_id")
	if !ok {
		return
	}
	userID, ok := pathID(c, "user_id")
	if !ok {
		return
	}
	noContent(c, h.svc.RemoveProjectMember(c.Request.Context(), actor(c), projectID, userID))
}

func (h handlers) createScan(c *gin.Context) {
	projectID, ok := pathID(c, "project_id")
	if !ok {
		return
	}
	var in service.CreateScanInput
	if !bind(c, &in) {
		return
	}
	out, err := h.svc.CreateScan(c.Request.Context(), actor(c), projectID, in)
	reply(c, true, out, err)
}

func (h handlers) scans(c *gin.Context) {
	projectID, ok := pathID(c, "project_id")
	if !ok {
		return
	}
	out, err := h.svc.Scans(c.Request.Context(), actor(c), projectID, page(c))
	reply(c, false, out, err)
}

func (h handlers) scan(c *gin.Context) {
	id, ok := pathID(c, "scan_id")
	if !ok {
		return
	}
	out, err := h.svc.Scan(c.Request.Context(), actor(c), id)
	reply(c, false, out, err)
}

func (h handlers) startScan(c *gin.Context) {
	id, ok := pathID(c, "scan_id")
	if !ok {
		return
	}
	out, err := h.svc.StartScan(c.Request.Context(), actor(c), id)
	reply(c, false, out, err)
}

func (h handlers) cancelScan(c *gin.Context) {
	id, ok := pathID(c, "scan_id")
	if !ok {
		return
	}
	out, err := h.svc.CancelScan(c.Request.Context(), actor(c), id)
	reply(c, false, out, err)
}

func (h handlers) issues(c *gin.Context) {
	f := service.IssueFilter{
		ProjectID: c.Query("project_id"), Status: c.QueryArray("status"), Severity: c.QueryArray("severity"),
		Assignee: c.Query("assignee"), Tool: c.Query("tool"), PastSLA: c.Query("past_sla"), Q: c.Query("q"),
		Sort: c.Query("sort"), PageParams: page(c),
	}
	out, err := h.svc.Issues(c.Request.Context(), actor(c), f)
	reply(c, false, out, err)
}

func (h handlers) bulkAssign(c *gin.Context) {
	var in service.BulkAssignInput
	if !bind(c, &in) {
		return
	}
	out, err := h.svc.BulkAssign(c.Request.Context(), actor(c), in)
	reply(c, false, out, err)
}

func (h handlers) issue(c *gin.Context) {
	id, ok := pathID(c, "issue_id")
	if !ok {
		return
	}
	out, err := h.svc.Issue(c.Request.Context(), actor(c), id)
	reply(c, false, out, err)
}

func (h handlers) transition(c *gin.Context) {
	id, ok := pathID(c, "issue_id")
	if !ok {
		return
	}
	var in service.TransitionInput
	if !bind(c, &in) {
		return
	}
	out, err := h.svc.Transition(c.Request.Context(), actor(c), id, in)
	reply(c, false, out, err)
}

func (h handlers) issueEvents(c *gin.Context) {
	id, ok := pathID(c, "issue_id")
	if !ok {
		return
	}
	out, err := h.svc.IssueEvents(c.Request.Context(), actor(c), id)
	reply(c, false, out, err)
}

func (h handlers) comments(c *gin.Context) {
	id, ok := pathID(c, "issue_id")
	if !ok {
		return
	}
	out, err := h.svc.Comments(c.Request.Context(), actor(c), id)
	reply(c, false, out, err)
}

func (h handlers) addComment(c *gin.Context) {
	id, ok := pathID(c, "issue_id")
	if !ok {
		return
	}
	var in service.CommentInput
	if !bind(c, &in) {
		return
	}
	out, err := h.svc.AddComment(c.Request.Context(), actor(c), id, in)
	reply(c, true, out, err)
}

func (h handlers) createException(c *gin.Context) {
	id, ok := pathID(c, "issue_id")
	if !ok {
		return
	}
	var in service.CreateExceptionInput
	if !bind(c, &in) {
		return
	}
	out, err := h.svc.CreateException(c.Request.Context(), actor(c), id, in)
	reply(c, true, out, err)
}

func (h handlers) exceptions(c *gin.Context) {
	out, err := h.svc.Exceptions(c.Request.Context(), actor(c), service.ExceptionFilter{Status: c.Query("status"), PageParams: page(c)})
	reply(c, false, out, err)
}

func (h handlers) decide(c *gin.Context) {
	id, ok := pathID(c, "exception_id")
	if !ok {
		return
	}
	var in service.DecisionInput
	if !bind(c, &in) {
		return
	}
	out, err := h.svc.Decide(c.Request.Context(), actor(c), id, in)
	reply(c, false, out, err)
}

func (h handlers) auditLog(c *gin.Context) {
	f := service.AuditFilter{Action: c.Query("action"), ActorID: c.Query("actor_id"), From: c.Query("from"), To: c.Query("to"), PageParams: page(c)}
	out, err := h.svc.AuditLog(c.Request.Context(), actor(c), f)
	reply(c, false, out, err)
}
