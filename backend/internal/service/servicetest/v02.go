package servicetest

import (
	"cmp"
	"context"
	"errors"
	"maps"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/autoassign"
	"github.com/aupv9/warden/backend/internal/ids"
	"github.com/aupv9/warden/backend/internal/notify"
	"github.com/aupv9/warden/backend/internal/service"
)

// NotificationRow is a stored notification.
type NotificationRow struct {
	service.Notification
	UserID uuid.UUID
}

// extState holds the v0.2 tables.
type extState struct {
	Outbox        []notify.Event
	Notifications []NotificationRow
	Prefs         map[uuid.UUID]map[string]bool
	Rules         map[uuid.UUID][]autoassign.Rule
	Metrics       service.MetricsData
	MetricsCalls  int
	// user is app.user_id of the open InUser transaction.
	user uuid.UUID
}

func (e extState) clone() extState {
	c := e
	c.Outbox = slices.Clone(e.Outbox)
	c.Notifications = slices.Clone(e.Notifications)
	c.Prefs = map[uuid.UUID]map[string]bool{}
	for k, v := range e.Prefs {
		c.Prefs[k] = maps.Clone(v)
	}
	c.Rules = maps.Clone(e.Rules)
	return c
}

func (f *Fake) InUser(_ context.Context, userID uuid.UUID, fn func(service.Repo) error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.Fail["InUser"]; err != nil {
		return err
	}
	saved := f.st.clone()
	f.org, f.st.ext.user = uuid.Nil, userID
	err := fn(f)
	f.st.ext.user = uuid.Nil
	if err != nil {
		f.st = saved
	}
	return err
}

// Seeding and inspection helpers.

// Outbox returns the outbox events written so far.
func (f *Fake) Outbox() []notify.Event { return slices.Clone(f.st.ext.Outbox) }

// AddNotification stores a notification for user in org.
func (f *Fake) AddNotification(org, user uuid.UUID, typ, title string) uuid.UUID {
	id := ids.New()
	f.st.ext.Notifications = append(f.st.ext.Notifications, NotificationRow{UserID: user, Notification: service.Notification{
		ID: id, OrgID: org, Type: typ, Title: title, Link: "/orgs/" + org.String(), CreatedAt: service.Time(f.tick())}})
	return id
}

// NotificationRead reports whether the notification is read.
func (f *Fake) NotificationRead(id uuid.UUID) bool {
	for _, n := range f.st.ext.Notifications {
		if n.ID == id {
			return n.ReadAt != nil
		}
	}
	return false
}

// SetMetrics sets what Metrics returns; MetricsCalls counts the calls.
func (f *Fake) SetMetrics(d service.MetricsData) { f.st.ext.Metrics = d }

func (f *Fake) MetricsCalls() int { return f.st.ext.MetricsCalls }

// Rules returns a project's stored assign rules.
func (f *Fake) Rules(project uuid.UUID) []autoassign.Rule { return f.st.ext.Rules[project] }

// OrgSLA returns an org's SLA days.
func (f *Fake) OrgSLA(org uuid.UUID) service.SLADays { return f.st.Orgs[org].SLA }

// Repo: outbox and notifications.

func (f *Fake) AppendOutbox(_ context.Context, e notify.Event) error {
	if err := f.fail("AppendOutbox"); err != nil {
		return err
	}
	if e.OrgID != f.org || f.org == uuid.Nil {
		return errors.New("new row violates row-level security policy")
	}
	f.st.ext.Outbox = append(f.st.ext.Outbox, e)
	return nil
}

// ownRow emulates notification RLS in an InUser transaction plus the
// current-membership join.
func (f *Fake) ownRow(n NotificationRow, user uuid.UUID) bool {
	if n.UserID != user || f.st.ext.user != user {
		return false
	}
	_, member := f.st.Members[[2]uuid.UUID{n.OrgID, user}]
	return member
}

func (f *Fake) Notifications(_ context.Context, q service.NotificationQuery) ([]service.Notification, error) {
	if err := f.fail("Notifications"); err != nil {
		return nil, err
	}
	var out []service.Notification
	for _, n := range f.st.ext.Notifications {
		if !f.ownRow(n, q.UserID) || q.Unread && n.ReadAt != nil {
			continue
		}
		if c := q.After; c != nil && !(n.CreatedAt.T().Before(c.CreatedAt) || n.CreatedAt.T().Equal(c.CreatedAt) && n.ID.String() < c.ID.String()) {
			continue
		}
		out = append(out, n.Notification)
	}
	slices.SortFunc(out, func(a, b service.Notification) int {
		return cmp.Or(b.CreatedAt.T().Compare(a.CreatedAt.T()), cmp.Compare(b.ID.String(), a.ID.String()))
	})
	if len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}

func (f *Fake) UnreadCount(_ context.Context, userID uuid.UUID) (int, error) {
	if err := f.fail("UnreadCount"); err != nil {
		return 0, err
	}
	n := 0
	for _, r := range f.st.ext.Notifications {
		if f.ownRow(r, userID) && r.ReadAt == nil {
			n++
		}
	}
	return n, nil
}

func (f *Fake) MarkRead(_ context.Context, userID uuid.UUID, idList []uuid.UUID) error {
	if err := f.fail("MarkRead"); err != nil {
		return err
	}
	now := service.Time(f.Now)
	for i, r := range f.st.ext.Notifications {
		if r.UserID == userID && f.st.ext.user == userID && r.ReadAt == nil && (idList == nil || slices.Contains(idList, r.ID)) {
			f.st.ext.Notifications[i].ReadAt = &now
		}
	}
	return nil
}

func (f *Fake) NotificationPrefs(_ context.Context, userID uuid.UUID) (map[string]bool, error) {
	if err := f.fail("NotificationPrefs"); err != nil {
		return nil, err
	}
	return maps.Clone(f.st.ext.Prefs[userID]), nil
}

func (f *Fake) SetNotificationPref(_ context.Context, userID uuid.UUID, typ string, email bool) error {
	if err := f.fail("SetNotificationPref"); err != nil {
		return err
	}
	if f.st.ext.Prefs == nil {
		f.st.ext.Prefs = map[uuid.UUID]map[string]bool{}
	}
	if f.st.ext.Prefs[userID] == nil {
		f.st.ext.Prefs[userID] = map[string]bool{}
	}
	f.st.ext.Prefs[userID][typ] = email
	return nil
}

// Repo: policy.

func (f *Fake) SetOrgSLA(_ context.Context, orgID uuid.UUID, sla service.SLADays) error {
	if err := f.fail("SetOrgSLA"); err != nil {
		return err
	}
	o, ok := f.st.Orgs[orgID]
	if !ok {
		return service.ErrNotFound
	}
	o.SLA = sla
	f.st.Orgs[orgID] = o
	return nil
}

// RecomputeDueDates re-dates active issues; the fake has no created_at, so it
// counts from UpdatedAt.
func (f *Fake) RecomputeDueDates(_ context.Context, orgID uuid.UUID, sla service.SLADays) (int, error) {
	if err := f.fail("RecomputeDueDates"); err != nil {
		return 0, err
	}
	days := map[string]int{"critical": sla.Critical, "high": sla.High, "medium": sla.Medium, "low": sla.Low}
	n := 0
	for id, i := range f.st.Issues {
		d, ok := days[i.Severity]
		if i.OrgID != orgID || i.OrgID != f.org || !active(i.Status) || !ok {
			continue
		}
		due := i.UpdatedAt.Add(time.Duration(d) * 24 * time.Hour)
		i.DueAt = &due
		f.st.Issues[id] = i
		n++
	}
	return n, nil
}

func (f *Fake) projectInOrg(id uuid.UUID) bool {
	p, ok := f.st.Projects[id]
	return ok && p.OrgID == f.org
}

func (f *Fake) AssignRules(_ context.Context, projectID uuid.UUID) ([]autoassign.Rule, error) {
	if err := f.fail("AssignRules"); err != nil {
		return nil, err
	}
	if !f.projectInOrg(projectID) {
		return nil, service.ErrNotFound
	}
	return slices.Clone(f.st.ext.Rules[projectID]), nil
}

func (f *Fake) SetAssignRules(_ context.Context, projectID uuid.UUID, rules []autoassign.Rule) error {
	if err := f.fail("SetAssignRules"); err != nil {
		return err
	}
	if f.st.ext.Rules == nil {
		f.st.ext.Rules = map[uuid.UUID][]autoassign.Rule{}
	}
	f.st.ext.Rules[projectID] = slices.Clone(rules)
	return nil
}

func (f *Fake) SetProjectArchived(_ context.Context, projectID uuid.UUID, archived bool) (bool, error) {
	if err := f.fail("SetProjectArchived"); err != nil {
		return false, err
	}
	if !f.projectInOrg(projectID) {
		return false, service.ErrNotFound
	}
	p := f.st.Projects[projectID]
	if p.Archived == archived {
		return false, nil
	}
	p.Archived, p.ArchivedAt = archived, nil
	if archived {
		now := f.Now
		p.ArchivedAt = &now
	}
	f.st.Projects[projectID] = p
	return true, nil
}

func (f *Fake) ProjectArchived(_ context.Context, projectID uuid.UUID) (bool, error) {
	if err := f.fail("ProjectArchived"); err != nil {
		return false, err
	}
	if !f.projectInOrg(projectID) {
		return false, service.ErrNotFound
	}
	return f.st.Projects[projectID].Archived, nil
}

// Repo: metrics.

func (f *Fake) Metrics(_ context.Context, _ service.MetricsQuery) (service.MetricsData, error) {
	if err := f.fail("Metrics"); err != nil {
		return service.MetricsData{}, err
	}
	f.st.ext.MetricsCalls++
	return f.st.ext.Metrics, nil
}

func (f *Fake) IssueTotals(_ context.Context, q service.TotalsQuery) (service.IssueTotals, error) {
	var t service.IssueTotals
	if err := f.fail("IssueTotals"); err != nil {
		return t, err
	}
	for _, i := range f.st.Issues {
		if !f.visibleArchived(q.Vis, i.ProjectID, q.ProjectID != nil) || q.ProjectID != nil && *q.ProjectID != i.ProjectID || !active(i.Status) {
			continue
		}
		t.Active++
		if i.AssigneeID != nil && *i.AssigneeID == q.Vis.UserID {
			t.Mine++
		}
		if i.DueAt != nil && i.DueAt.Before(q.Now) {
			t.PastSLA++
		}
		if i.Tool == "gitleaks" {
			t.Secrets++
		}
		if f.intel(i.CVE).KEVAdded != nil {
			t.KEV++
		}
		if isLicense(i) {
			t.Licenses++
		}
	}
	return t, nil
}
