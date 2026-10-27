// Package servicetest is an in-memory service.DB for unit tests. It emulates
// transactions (state is restored when fn fails), org scoping (rows of other
// orgs are invisible, like RLS) and the unique constraints the service relies
// on. Fail injects errors per method name.
package servicetest

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/rbac"
	"github.com/aupv9/warden/backend/internal/ids"
	"github.com/aupv9/warden/backend/internal/service"
	"github.com/aupv9/warden/backend/internal/worker"
)

type orgRow struct {
	Name          string
	SLA           service.SLADays
	SignIn        service.SignInPolicy
	LicensePolicy []byte // JSON; nil reads as {}
}

type projectRow struct {
	OrgID        uuid.UUID
	Key, Name    string
	Description  *string
	DefaultTools []string
	Archived     bool
	ArchivedAt   *time.Time
	CreatedAt    time.Time
}

type pmRow struct {
	OrgID uuid.UUID
	Role  rbac.Role
}

type scanRow struct {
	service.Scan
	CreatedByID uuid.UUID
	ViaToken    *uuid.UUID
}

type IssueRow struct {
	OrgID      uuid.UUID
	ProjectID  uuid.UUID
	Number     int
	Title      string
	Severity   string
	Status     string
	Tool       string
	RuleID     string
	FilePath   *string
	AssigneeID *uuid.UUID
	DueAt      *time.Time
	Version    int
	ScanID     uuid.UUID
	UpdatedAt  time.Time
	CWE        []string
}

type eventRow struct {
	service.NewEvent
	ID        int64
	CreatedAt time.Time
}

type commentRow struct {
	service.NewComment
	CreatedAt time.Time
}

type excRow struct {
	service.NewException
	Status       string
	DecidedBy    *uuid.UUID
	DecisionNote *string
	DecidedAt    *time.Time
}

type state struct {
	Users      map[uuid.UUID]service.User
	Orgs       map[uuid.UUID]orgRow
	Members    map[[2]uuid.UUID]rbac.Role // org, user
	Projects   map[uuid.UUID]projectRow
	PMembers   map[[2]uuid.UUID]pmRow // project, user
	Scans      map[uuid.UUID]scanRow
	ToolRuns   map[uuid.UUID][]service.ToolRun
	Issues     map[uuid.UUID]IssueRow
	Events     []eventRow
	Comments   []commentRow
	Exceptions map[uuid.UUID]excRow
	Audit      []service.AuditRecord
	Jobs       []worker.ScanArgs
	Tokens     map[uuid.UUID]tokenRow
	Seen       map[[2]uuid.UUID]bool // issue, scan: occurrences
	nextID     int64
	ext        extState // v0.2 tables (v02.go)
}

func (s *state) clone() *state {
	c := *s
	c.Users = maps.Clone(s.Users)
	c.Orgs = maps.Clone(s.Orgs)
	c.Members = maps.Clone(s.Members)
	c.Projects = maps.Clone(s.Projects)
	c.PMembers = maps.Clone(s.PMembers)
	c.Scans = maps.Clone(s.Scans)
	c.ToolRuns = maps.Clone(s.ToolRuns)
	c.Issues = maps.Clone(s.Issues)
	c.Events = slices.Clone(s.Events)
	c.Comments = slices.Clone(s.Comments)
	c.Exceptions = maps.Clone(s.Exceptions)
	c.Audit = slices.Clone(s.Audit)
	c.Jobs = slices.Clone(s.Jobs)
	c.Tokens = maps.Clone(s.Tokens)
	c.Seen = maps.Clone(s.Seen)
	c.ext = s.ext.clone()
	return &c
}

// Fake implements service.DB and service.Repo.
type Fake struct {
	mu  sync.Mutex
	st  *state
	org uuid.UUID // app.org_id of the open transaction
	// Fail makes the named Repo method (or "InOrg") return the error.
	Fail map[string]error
	// Now is the fake database clock.
	Now time.Time
}

func New() *Fake {
	return &Fake{st: &state{
		Users: map[uuid.UUID]service.User{}, Orgs: map[uuid.UUID]orgRow{}, Members: map[[2]uuid.UUID]rbac.Role{},
		Projects: map[uuid.UUID]projectRow{}, PMembers: map[[2]uuid.UUID]pmRow{}, Scans: map[uuid.UUID]scanRow{},
		ToolRuns: map[uuid.UUID][]service.ToolRun{}, Issues: map[uuid.UUID]IssueRow{}, Exceptions: map[uuid.UUID]excRow{},
		Tokens: map[uuid.UUID]tokenRow{}, Seen: map[[2]uuid.UUID]bool{},
	}, Fail: map[string]error{}, Now: time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)}
}

var _ service.DB = (*Fake)(nil)
var _ service.Repo = (*Fake)(nil)

func (f *Fake) InOrg(ctx context.Context, orgID uuid.UUID, fn func(service.Repo) error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.Fail["InOrg"]; err != nil {
		return err
	}
	saved := f.st.clone()
	f.org = orgID
	err := fn(f)
	f.org = uuid.Nil
	if err != nil {
		f.st = saved
	}
	return err
}

func (f *Fake) fail(name string) error { return f.Fail[name] }

func (f *Fake) tick() time.Time {
	f.Now = f.Now.Add(time.Second)
	return f.Now
}

// Seeding helpers (outside transactions).

func (f *Fake) AddUser(email string) uuid.UUID {
	id := ids.New()
	f.st.Users[id] = service.User{ID: id, Sub: "sub-" + email, Email: email, DisplayName: strings.Split(email, "@")[0], IsActive: true}
	return id
}

func (f *Fake) SetUser(u service.User) { f.st.Users[u.ID] = u }

func (f *Fake) User(id uuid.UUID) service.User { return f.st.Users[id] }

func (f *Fake) AddOrg(name string) uuid.UUID {
	id := ids.New()
	f.st.Orgs[id] = orgRow{Name: name, SLA: service.SLADays{Critical: 7, High: 30, Medium: 90, Low: 180}}
	return id
}

func (f *Fake) AddMember(org, user uuid.UUID, role rbac.Role) {
	f.st.Members[[2]uuid.UUID{org, user}] = role
}

func (f *Fake) AddProject(org uuid.UUID, key string) uuid.UUID {
	id := ids.New()
	f.st.Projects[id] = projectRow{OrgID: org, Key: key, Name: key, DefaultTools: []string{"gitleaks", "opengrep", "trivy", "checkov"}, CreatedAt: f.tick()}
	return id
}

func (f *Fake) ArchiveProject(id uuid.UUID) {
	p := f.st.Projects[id]
	now := f.tick()
	p.Archived, p.ArchivedAt = true, &now
	f.st.Projects[id] = p
}

func (f *Fake) AddProjectMember(project, user uuid.UUID, role rbac.Role) {
	f.st.PMembers[[2]uuid.UUID{project, user}] = pmRow{OrgID: f.st.Projects[project].OrgID, Role: role}
}

// AddScan adds a scan in the given status.
func (f *Fake) AddScan(project, by uuid.UUID, status string, size int64) uuid.UUID {
	id := ids.New()
	org := f.st.Projects[project].OrgID
	f.st.Scans[id] = scanRow{CreatedByID: by, Scan: service.Scan{ID: id, OrgID: org, ProjectID: project, Status: status,
		FileName: "src.zip", FileSize: size, Tools: []string{"gitleaks"}, CreatedAt: service.Time(f.tick()), Kind: "source",
		ObjectKey: service.ObjectKey(org, id), SHA256: strings.Repeat("a", 64)}}
	return id
}

func (f *Fake) SetToolRuns(scan uuid.UUID, runs []service.ToolRun) { f.st.ToolRuns[scan] = runs }

func (f *Fake) ScanRow(id uuid.UUID) service.Scan { return f.st.Scans[id].Scan }

// AddIssue adds an issue with status and optional assignee.
func (f *Fake) AddIssue(project uuid.UUID, severity, status string, assignee *uuid.UUID) uuid.UUID {
	id := ids.New()
	p := f.st.Projects[project]
	n := 1
	for _, i := range f.st.Issues {
		if i.ProjectID == project && i.Number >= n {
			n = i.Number + 1
		}
	}
	var scan uuid.UUID
	for sid, s := range f.st.Scans {
		if s.ProjectID == project {
			scan = sid
		}
	}
	f.st.Issues[id] = IssueRow{OrgID: p.OrgID, ProjectID: project, Number: n, Title: "Issue " + severity, Severity: severity,
		Status: status, Tool: "opengrep", RuleID: "rule." + severity, AssigneeID: assignee, Version: 1, ScanID: scan, UpdatedAt: f.tick()}
	return id
}

func (f *Fake) SetIssue(id uuid.UUID, fn func(*IssueRow)) {
	r := f.st.Issues[id]
	fn(&r)
	f.st.Issues[id] = r
}

func (f *Fake) IssueRow(id uuid.UUID) IssueRow { return f.st.Issues[id] }

func (f *Fake) AuditLog() []service.AuditRecord { return slices.Clone(f.st.Audit) }

func (f *Fake) Jobs() []worker.ScanArgs { return slices.Clone(f.st.Jobs) }

func (f *Fake) EventTypes(issue uuid.UUID) []string {
	var out []string
	for _, e := range f.st.Events {
		if e.IssueID == issue {
			out = append(out, e.Type)
		}
	}
	return out
}

func (f *Fake) ExceptionStatus(id uuid.UUID) string { return f.st.Exceptions[id].Status }

// AddException adds a pending request.
func (f *Fake) AddException(issue, by uuid.UUID, typ string, expires *time.Time) uuid.UUID {
	id := ids.New()
	f.st.Exceptions[id] = excRow{Status: "pending", NewException: service.NewException{ID: id, OrgID: f.st.Issues[issue].OrgID,
		IssueID: issue, Type: typ, Reason: "a long enough reason for testing", RequestedBy: by, ExpiresAt: expires, CreatedAt: f.tick()}}
	return id
}

func (f *Fake) SetExceptionStatus(id uuid.UUID, status string) {
	e := f.st.Exceptions[id]
	e.Status = status
	f.st.Exceptions[id] = e
}

// Repo: users.

func (f *Fake) UserBySub(_ context.Context, sub string) (service.User, error) {
	if err := f.fail("UserBySub"); err != nil {
		return service.User{}, err
	}
	for _, u := range f.st.Users {
		if u.Sub == sub {
			return u, nil
		}
	}
	return service.User{}, service.ErrNotFound
}

func (f *Fake) UserByEmail(_ context.Context, email string) (service.User, error) {
	if err := f.fail("UserByEmail"); err != nil {
		return service.User{}, err
	}
	for _, u := range f.st.Users {
		if strings.EqualFold(u.Email, email) {
			return u, nil
		}
	}
	return service.User{}, service.ErrNotFound
}

func (f *Fake) InsertUser(_ context.Context, u service.User) error {
	if err := f.fail("InsertUser"); err != nil {
		return err
	}
	for _, x := range f.st.Users {
		if x.Sub == u.Sub || strings.EqualFold(x.Email, u.Email) {
			return service.ErrConflict
		}
	}
	f.st.Users[u.ID] = u
	return nil
}

func (f *Fake) UpdateUser(_ context.Context, u service.User) error {
	if err := f.fail("UpdateUser"); err != nil {
		return err
	}
	f.st.Users[u.ID] = u
	return nil
}

func (f *Fake) UserOrgs(_ context.Context, userID uuid.UUID) ([]service.OrgRef, error) {
	if err := f.fail("UserOrgs"); err != nil {
		return nil, err
	}
	var out []service.OrgRef
	for k, role := range f.st.Members {
		if k[1] == userID {
			o := f.st.Orgs[k[0]]
			out = append(out, service.OrgRef{ID: k[0], Name: o.Name, Role: role, MFARoles: slices.Clone(o.SignIn.MFARoles)})
		}
	}
	slices.SortFunc(out, func(a, b service.OrgRef) int { return cmp.Compare(a.Name, b.Name) })
	return out, nil
}

func (f *Fake) MemberRole(_ context.Context, orgID, userID uuid.UUID) (rbac.Role, error) {
	if err := f.fail("MemberRole"); err != nil {
		return "", err
	}
	role, ok := f.st.Members[[2]uuid.UUID{orgID, userID}]
	if !ok {
		return "", service.ErrNotFound
	}
	return role, nil
}

func (f *Fake) ref(id uuid.UUID) service.UserRef {
	u := f.st.Users[id]
	return service.UserRef{ID: u.ID, Email: u.Email, DisplayName: u.DisplayName}
}

func (f *Fake) refp(id *uuid.UUID) *service.UserRef {
	if id == nil {
		return nil
	}
	r := f.ref(*id)
	return &r
}

func (f *Fake) UserRef(_ context.Context, userID uuid.UUID) (service.UserRef, error) {
	if err := f.fail("UserRef"); err != nil {
		return service.UserRef{}, err
	}
	if _, ok := f.st.Users[userID]; !ok {
		return service.UserRef{}, service.ErrNotFound
	}
	return f.ref(userID), nil
}

func (f *Fake) Org(_ context.Context, orgID uuid.UUID) (service.Org, error) {
	if err := f.fail("Org"); err != nil {
		return service.Org{}, err
	}
	o, ok := f.st.Orgs[orgID]
	if !ok {
		return service.Org{}, service.ErrNotFound
	}
	return service.Org{ID: orgID, Name: o.Name, SLADays: o.SLA}, nil
}

// visible emulates RLS plus the visibility predicate (archived projects excluded).
func (f *Fake) visible(v service.Visibility, projectID uuid.UUID) bool {
	return f.visibleArchived(v, projectID, false)
}

func (f *Fake) visibleArchived(v service.Visibility, projectID uuid.UUID, archived bool) bool {
	p, ok := f.st.Projects[projectID]
	if !ok || p.OrgID != f.org || p.OrgID != v.OrgID || (p.Archived && !archived) {
		return false
	}
	if v.All {
		return true
	}
	_, ok = f.st.PMembers[[2]uuid.UUID{projectID, v.UserID}]
	return ok
}

func active(status string) bool {
	return slices.Contains([]string{"open", "assigned", "in_progress", "reopened"}, status)
}

func (f *Fake) Summary(_ context.Context, v service.Visibility, now time.Time) (service.Summary, error) {
	if err := f.fail("Summary"); err != nil {
		return service.Summary{}, err
	}
	var s service.Summary
	for _, i := range f.st.Issues {
		if !f.visible(v, i.ProjectID) || !active(i.Status) {
			continue
		}
		s.OpenIssues++
		if i.Severity == "critical" || i.Severity == "high" {
			s.CriticalHighOpen++
		}
		if i.DueAt != nil && i.DueAt.Before(now) {
			s.PastSLA++
		}
	}
	return s, nil
}

func (f *Fake) CountPendingExceptions(context.Context) (int, error) {
	if err := f.fail("CountPendingExceptions"); err != nil {
		return 0, err
	}
	n := 0
	for _, e := range f.st.Exceptions {
		if e.OrgID == f.org && e.Status == "pending" {
			n++
		}
	}
	return n, nil
}

func (f *Fake) member(orgID, userID uuid.UUID) service.OrgMember {
	u := f.st.Users[userID]
	m := service.OrgMember{User: service.MemberUser{UserRef: f.ref(userID), IsActive: u.IsActive},
		Role: f.st.Members[[2]uuid.UUID{orgID, userID}], MFA: u.MFA, Projects: []service.MemberProject{}}
	for k, pm := range f.st.PMembers {
		if k[1] == userID && pm.OrgID == orgID {
			m.Projects = append(m.Projects, service.MemberProject{ID: k[0], Key: f.st.Projects[k[0]].Key, Role: pm.Role})
		}
	}
	return m
}

func (f *Fake) OrgMembers(_ context.Context, orgID uuid.UUID) ([]service.OrgMember, error) {
	if err := f.fail("OrgMembers"); err != nil {
		return nil, err
	}
	var out []service.OrgMember
	for k := range f.st.Members {
		if k[0] == orgID {
			out = append(out, f.member(orgID, k[1]))
		}
	}
	slices.SortFunc(out, func(a, b service.OrgMember) int { return cmp.Compare(a.User.Email, b.User.Email) })
	return out, nil
}

func (f *Fake) OrgMember(_ context.Context, orgID, userID uuid.UUID) (service.OrgMember, error) {
	if err := f.fail("OrgMember"); err != nil {
		return service.OrgMember{}, err
	}
	if _, ok := f.st.Members[[2]uuid.UUID{orgID, userID}]; !ok {
		return service.OrgMember{}, service.ErrNotFound
	}
	return f.member(orgID, userID), nil
}

func (f *Fake) InsertOrgMember(_ context.Context, orgID, userID uuid.UUID, role rbac.Role) error {
	if err := f.fail("InsertOrgMember"); err != nil {
		return err
	}
	k := [2]uuid.UUID{orgID, userID}
	if _, ok := f.st.Members[k]; ok {
		return service.ErrConflict
	}
	f.st.Members[k] = role
	return nil
}

func (f *Fake) LockOrgAdmins(_ context.Context, orgID uuid.UUID) ([]uuid.UUID, error) {
	if err := f.fail("LockOrgAdmins"); err != nil {
		return nil, err
	}
	var out []uuid.UUID
	for k, r := range f.st.Members {
		if k[0] == orgID && r == rbac.OrgAdmin {
			out = append(out, k[1])
		}
	}
	return out, nil
}

func (f *Fake) SetOrgMemberRole(_ context.Context, orgID, userID uuid.UUID, role rbac.Role) error {
	if err := f.fail("SetOrgMemberRole"); err != nil {
		return err
	}
	f.st.Members[[2]uuid.UUID{orgID, userID}] = role
	return nil
}

func (f *Fake) DeleteOrgMember(_ context.Context, orgID, userID uuid.UUID) error {
	if err := f.fail("DeleteOrgMember"); err != nil {
		return err
	}
	for k, pm := range f.st.PMembers {
		if k[1] == userID && pm.OrgID == orgID {
			delete(f.st.PMembers, k)
		}
	}
	delete(f.st.Members, [2]uuid.UUID{orgID, userID})
	return nil
}

// Projects.

func (f *Fake) project(v service.Visibility, id uuid.UUID, now time.Time) service.Project {
	p := f.st.Projects[id]
	out := service.Project{ID: id, Key: p.Key, Name: p.Name, Description: p.Description, DefaultTools: p.DefaultTools,
		CreatedAt: service.Time(p.CreatedAt)}
	if p.ArchivedAt != nil {
		t := service.Time(*p.ArchivedAt)
		out.ArchivedAt = &t
	}
	if pm, ok := f.st.PMembers[[2]uuid.UUID{id, v.UserID}]; ok {
		r := pm.Role
		out.MyRole = &r
	}
	for _, i := range f.st.Issues {
		if i.ProjectID == id && active(i.Status) {
			out.OpenBySeverity.Add(i.Severity, 1)
			if i.DueAt != nil && i.DueAt.Before(now) {
				out.PastSLA++
			}
		}
	}
	for _, s := range f.st.Scans {
		if s.ProjectID == id && (out.LastScan == nil || s.CreatedAt.T().After(out.LastScan.CreatedAt.T())) {
			out.LastScan = &service.LastScan{ID: s.ID, Status: s.Status, CreatedAt: s.CreatedAt, FinishedAt: s.FinishedAt}
		}
	}
	return out
}

func (f *Fake) Projects(_ context.Context, v service.Visibility, now time.Time, includeArchived bool) ([]service.Project, error) {
	if err := f.fail("Projects"); err != nil {
		return nil, err
	}
	var out []service.Project
	for id := range f.st.Projects {
		if f.visibleArchived(v, id, includeArchived) {
			out = append(out, f.project(v, id, now))
		}
	}
	slices.SortFunc(out, func(a, b service.Project) int { return cmp.Compare(a.Key, b.Key) })
	return out, nil
}

func (f *Fake) Project(_ context.Context, v service.Visibility, id uuid.UUID, now time.Time) (service.Project, error) {
	if err := f.fail("Project"); err != nil {
		return service.Project{}, err
	}
	if !f.visibleArchived(v, id, true) {
		return service.Project{}, service.ErrNotFound
	}
	return f.project(v, id, now), nil
}

func (f *Fake) ProjectRole(_ context.Context, projectID, userID uuid.UUID) (rbac.Role, error) {
	if err := f.fail("ProjectRole"); err != nil {
		return "", err
	}
	p, ok := f.st.Projects[projectID]
	if !ok || p.OrgID != f.org {
		return "", service.ErrNotFound
	}
	return f.st.PMembers[[2]uuid.UUID{projectID, userID}].Role, nil
}

func (f *Fake) InsertProject(_ context.Context, p service.NewProject) error {
	if err := f.fail("InsertProject"); err != nil {
		return err
	}
	for _, x := range f.st.Projects {
		if x.OrgID == p.OrgID && x.Key == p.Key {
			return service.ErrConflict
		}
	}
	f.st.Projects[p.ID] = projectRow{OrgID: p.OrgID, Key: p.Key, Name: p.Name, Description: p.Description,
		DefaultTools: p.DefaultTools, CreatedAt: f.tick()}
	return nil
}

func (f *Fake) ProjectMembers(_ context.Context, projectID uuid.UUID) ([]service.ProjectMember, error) {
	if err := f.fail("ProjectMembers"); err != nil {
		return nil, err
	}
	var out []service.ProjectMember
	for k, pm := range f.st.PMembers {
		if k[0] == projectID {
			out = append(out, service.ProjectMember{User: f.ref(k[1]), Role: pm.Role})
		}
	}
	return out, nil
}

func (f *Fake) UpsertProjectMember(_ context.Context, orgID, projectID, userID uuid.UUID, role rbac.Role) error {
	if err := f.fail("UpsertProjectMember"); err != nil {
		return err
	}
	f.st.PMembers[[2]uuid.UUID{projectID, userID}] = pmRow{OrgID: orgID, Role: role}
	return nil
}

func (f *Fake) DeleteProjectMember(_ context.Context, projectID, userID uuid.UUID) (bool, error) {
	if err := f.fail("DeleteProjectMember"); err != nil {
		return false, err
	}
	k := [2]uuid.UUID{projectID, userID}
	_, ok := f.st.PMembers[k]
	delete(f.st.PMembers, k)
	return ok, nil
}

func (f *Fake) OwnsAnyProject(_ context.Context, userID uuid.UUID) (bool, error) {
	if err := f.fail("OwnsAnyProject"); err != nil {
		return false, err
	}
	for k, pm := range f.st.PMembers {
		if k[1] == userID && pm.OrgID == f.org && pm.Role == rbac.Owner {
			return true, nil
		}
	}
	return false, nil
}

// Scans.

func (f *Fake) LockScanRate(context.Context, uuid.UUID) error { return f.fail("LockScanRate") }

func (f *Fake) ScansSince(_ context.Context, userID uuid.UUID, since time.Time) (int, time.Time, error) {
	if err := f.fail("ScansSince"); err != nil {
		return 0, time.Time{}, err
	}
	n, oldest := 0, time.Time{}
	for _, s := range f.st.Scans {
		if s.CreatedByID == userID && s.OrgID == f.org && s.CreatedAt.T().After(since) {
			n++
			if oldest.IsZero() || s.CreatedAt.T().Before(oldest) {
				oldest = s.CreatedAt.T()
			}
		}
	}
	return n, oldest, nil
}

func (f *Fake) InsertScan(_ context.Context, s service.NewScan) error {
	if err := f.fail("InsertScan"); err != nil {
		return err
	}
	f.st.Scans[s.ID] = scanRow{CreatedByID: s.CreatedBy, Scan: service.Scan{ID: s.ID, OrgID: s.OrgID, ProjectID: s.ProjectID,
		Status: "pending_upload", FileName: s.FileName, FileSize: s.FileSize, Tools: s.Tools, CreatedAt: service.Time(f.Now),
		ObjectKey: s.ObjectKey, SHA256: s.SHA256, Kind: cmp.Or(s.Kind, "source"), Target: s.Target, ImageRef: s.ImageRef}, ViaToken: s.ViaToken}
	return nil
}

func (f *Fake) scan(id uuid.UUID) (service.Scan, bool) {
	s, ok := f.st.Scans[id]
	if !ok || s.OrgID != f.org {
		return service.Scan{}, false
	}
	out := s.Scan
	out.CreatedBy = f.ref(s.CreatedByID)
	if s.ViaToken != nil {
		t := f.st.Tokens[*s.ViaToken]
		out.ViaToken = &service.TokenRef{ID: t.ID, Name: t.Name, Prefix: t.Prefix}
	}
	return out, true
}

func (f *Fake) Scan(_ context.Context, id uuid.UUID, _ bool) (service.Scan, error) {
	if err := f.fail("Scan"); err != nil {
		return service.Scan{}, err
	}
	s, ok := f.scan(id)
	if !ok {
		return service.Scan{}, service.ErrNotFound
	}
	return s, nil
}

func (f *Fake) Scans(_ context.Context, projectID uuid.UUID, after *service.ScanCursor, limit int) ([]service.Scan, error) {
	if err := f.fail("Scans"); err != nil {
		return nil, err
	}
	var out []service.Scan
	for id, s := range f.st.Scans {
		if s.ProjectID != projectID {
			continue
		}
		if after != nil && !(s.CreatedAt.T().Before(after.CreatedAt) || s.CreatedAt.T().Equal(after.CreatedAt) && s.ID.String() < after.ID.String()) {
			continue
		}
		sc, _ := f.scan(id)
		out = append(out, sc)
	}
	slices.SortFunc(out, func(a, b service.Scan) int {
		return cmp.Or(b.CreatedAt.T().Compare(a.CreatedAt.T()), cmp.Compare(b.ID.String(), a.ID.String()))
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (f *Fake) ToolRuns(_ context.Context, scanID uuid.UUID) ([]service.ToolRun, error) {
	if err := f.fail("ToolRuns"); err != nil {
		return nil, err
	}
	return f.st.ToolRuns[scanID], nil
}

func (f *Fake) setScan(id uuid.UUID, fn func(*scanRow)) {
	s := f.st.Scans[id]
	fn(&s)
	f.st.Scans[id] = s
}

func (f *Fake) MarkScanQueued(_ context.Context, id uuid.UUID) error {
	if err := f.fail("MarkScanQueued"); err != nil {
		return err
	}
	now := service.Time(f.Now)
	f.setScan(id, func(s *scanRow) { s.Status, s.QueuedAt = "queued", &now })
	return nil
}

func (f *Fake) MarkScanCancelled(_ context.Context, id uuid.UUID) error {
	if err := f.fail("MarkScanCancelled"); err != nil {
		return err
	}
	now := service.Time(f.Now)
	f.setScan(id, func(s *scanRow) { s.Status, s.FinishedAt = "cancelled", &now })
	return nil
}

func (f *Fake) EnqueueScan(_ context.Context, args worker.ScanArgs) error {
	if err := f.fail("EnqueueScan"); err != nil {
		return err
	}
	f.st.Jobs = append(f.st.Jobs, args)
	return nil
}

// Issues.

func (f *Fake) summary(id uuid.UUID, now time.Time) service.IssueSummary {
	i := f.st.Issues[id]
	out := service.IssueSummary{ID: id, Key: f.st.Projects[i.ProjectID].Key + "-" + itoa(i.Number), ProjectID: i.ProjectID,
		Title: i.Title, Severity: i.Severity, Status: i.Status, Tool: i.Tool, RuleID: i.RuleID, FilePath: i.FilePath,
		Assignee: f.refp(i.AssigneeID), UpdatedAt: service.Time(i.UpdatedAt)}
	if i.DueAt != nil {
		t := service.Time(*i.DueAt)
		out.DueAt = &t
		out.PastSLA = i.DueAt.Before(now) && active(i.Status)
	}
	return out
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

var sevRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

func (f *Fake) match(q service.IssueQuery, id uuid.UUID, i IssueRow) bool {
	switch {
	case !f.visibleArchived(q.Vis, i.ProjectID, q.ProjectID != nil),
		q.ProjectID != nil && *q.ProjectID != i.ProjectID,
		len(q.Statuses) > 0 && !slices.Contains(q.Statuses, i.Status),
		len(q.Severities) > 0 && !slices.Contains(q.Severities, i.Severity),
		q.AssigneeNone && i.AssigneeID != nil,
		q.AssigneeID != nil && (i.AssigneeID == nil || *i.AssigneeID != *q.AssigneeID),
		q.Tool != "" && q.Tool != i.Tool,
		q.PastSLA && (i.DueAt == nil || !i.DueAt.Before(q.Now) || !active(i.Status)),
		q.KeyProject != "" && (f.st.Projects[i.ProjectID].Key != q.KeyProject || i.Number != q.KeyNumber),
		q.Text != "" && !strings.Contains(strings.ToLower(i.Title+" "+i.RuleID), strings.ToLower(q.Text)):
		return false
	}
	return true
}

func (f *Fake) Issues(_ context.Context, q service.IssueQuery) ([]service.IssueSummary, error) {
	if err := f.fail("Issues"); err != nil {
		return nil, err
	}
	var out []service.IssueSummary
	for id, i := range f.st.Issues {
		if f.match(q, id, i) {
			out = append(out, f.summary(id, q.Now))
		}
	}
	slices.SortFunc(out, func(a, b service.IssueSummary) int {
		switch q.Sort {
		case service.SortSeverity:
			return cmp.Or(cmp.Compare(sevRank[a.Severity], sevRank[b.Severity]), cmp.Compare(a.ID.String(), b.ID.String()))
		case service.SortUpdatedAt:
			return cmp.Or(b.UpdatedAt.T().Compare(a.UpdatedAt.T()), cmp.Compare(b.ID.String(), a.ID.String()))
		}
		return cmp.Compare(a.ID.String(), b.ID.String())
	})
	if q.After != nil {
		for k, s := range out {
			if s.ID == q.After.ID {
				out = out[k+1:]
				break
			}
		}
	}
	if len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}

func (f *Fake) IssueCounts(_ context.Context, q service.IssueQuery) (service.SeverityCounts, error) {
	var c service.SeverityCounts
	if err := f.fail("IssueCounts"); err != nil {
		return c, err
	}
	for id, i := range f.st.Issues {
		if f.match(q, id, i) {
			c.Add(i.Severity, 1)
		}
	}
	return c, nil
}

func (f *Fake) Issue(_ context.Context, id uuid.UUID, _ bool, now time.Time) (service.Issue, error) {
	if err := f.fail("Issue"); err != nil {
		return service.Issue{}, err
	}
	i, ok := f.st.Issues[id]
	if !ok || i.OrgID != f.org {
		return service.Issue{}, service.ErrNotFound
	}
	scan := service.ScanRef{ID: i.ScanID}
	return service.Issue{IssueSummary: f.summary(id, now), CWE: i.CWE, FirstSeenScan: scan, LastSeenScan: scan,
		Occurrences: 1, Version: i.Version, AssigneeID: i.AssigneeID, Number: i.Number, ProjectKey: f.st.Projects[i.ProjectID].Key}, nil
}

func (f *Fake) UpdateIssueState(_ context.Context, id uuid.UUID, status string, assignee *uuid.UUID) error {
	if err := f.fail("UpdateIssueState"); err != nil {
		return err
	}
	f.SetIssue(id, func(i *IssueRow) {
		i.Status, i.AssigneeID, i.Version, i.UpdatedAt = status, assignee, i.Version+1, f.Now
	})
	return nil
}

func (f *Fake) InsertIssueEvent(_ context.Context, e service.NewEvent) error {
	if err := f.fail("InsertIssueEvent"); err != nil {
		return err
	}
	f.st.nextID++
	f.st.Events = append(f.st.Events, eventRow{NewEvent: e, ID: f.st.nextID, CreatedAt: f.tick()})
	return nil
}

func (f *Fake) IssueEvents(_ context.Context, issueID uuid.UUID, limit int) ([]service.Event, error) {
	if err := f.fail("IssueEvents"); err != nil {
		return nil, err
	}
	var out []service.Event
	for k := len(f.st.Events) - 1; k >= 0 && len(out) < limit; k-- {
		e := f.st.Events[k]
		if e.IssueID == issueID {
			out = append(out, service.Event{ID: e.ID, Type: e.Type, Actor: f.refp(e.ActorID), FromValue: e.From, ToValue: e.To,
				Note: e.Note, CreatedAt: service.Time(e.CreatedAt)})
		}
	}
	return out, nil
}

func (f *Fake) Comments(_ context.Context, issueID uuid.UUID) ([]service.Comment, error) {
	if err := f.fail("Comments"); err != nil {
		return nil, err
	}
	var out []service.Comment
	for _, c := range f.st.Comments {
		if c.IssueID == issueID {
			out = append(out, service.Comment{ID: c.ID, Author: f.ref(c.AuthorID), Body: c.Body, CreatedAt: service.Time(c.CreatedAt)})
		}
	}
	return out, nil
}

func (f *Fake) InsertComment(_ context.Context, c service.NewComment) error {
	if err := f.fail("InsertComment"); err != nil {
		return err
	}
	f.st.Comments = append(f.st.Comments, commentRow{NewComment: c, CreatedAt: f.tick()})
	return nil
}

func (f *Fake) Comment(_ context.Context, id uuid.UUID) (service.Comment, error) {
	if err := f.fail("Comment"); err != nil {
		return service.Comment{}, err
	}
	for _, c := range f.st.Comments {
		if c.ID == id {
			return service.Comment{ID: c.ID, Author: f.ref(c.AuthorID), Body: c.Body, CreatedAt: service.Time(c.CreatedAt)}, nil
		}
	}
	return service.Comment{}, service.ErrNotFound
}

func (f *Fake) PendingExceptionID(_ context.Context, issueID uuid.UUID) (*uuid.UUID, error) {
	if err := f.fail("PendingExceptionID"); err != nil {
		return nil, err
	}
	for id, e := range f.st.Exceptions {
		if e.IssueID == issueID && e.Status == "pending" {
			return &id, nil
		}
	}
	return nil, nil
}

// Exceptions.

func (f *Fake) InsertException(_ context.Context, e service.NewException) error {
	if err := f.fail("InsertException"); err != nil {
		return err
	}
	for _, x := range f.st.Exceptions {
		if x.IssueID == e.IssueID && x.Status == "pending" {
			return service.ErrConflict
		}
	}
	f.st.Exceptions[e.ID] = excRow{NewException: e, Status: "pending"}
	return nil
}

func (f *Fake) exception(id uuid.UUID) service.ExceptionMeta {
	e := f.st.Exceptions[id]
	i := f.st.Issues[e.IssueID]
	s := f.summary(e.IssueID, f.Now)
	out := service.ExceptionMeta{OrgID: e.OrgID, IssueID: e.IssueID, RequestedByID: e.RequestedBy,
		ExceptionRequest: service.ExceptionRequest{ID: id, Issue: service.ExceptionIssue{ID: e.IssueID, Key: s.Key, Title: i.Title,
			Severity: i.Severity, Status: i.Status}, Type: e.Type, Reason: e.Reason, Status: e.Status,
			RequestedBy: f.ref(e.RequestedBy), DecidedBy: f.refp(e.DecidedBy), DecisionNote: e.DecisionNote,
			CreatedAt: service.Time(e.CreatedAt)}}
	if e.ExpiresAt != nil {
		t := service.Time(*e.ExpiresAt)
		out.ExpiresAt = &t
	}
	if e.DecidedAt != nil {
		t := service.Time(*e.DecidedAt)
		out.DecidedAt = &t
	}
	return out
}

func (f *Fake) Exception(_ context.Context, id uuid.UUID, _ bool) (service.ExceptionMeta, error) {
	if err := f.fail("Exception"); err != nil {
		return service.ExceptionMeta{}, err
	}
	e, ok := f.st.Exceptions[id]
	if !ok || e.OrgID != f.org {
		return service.ExceptionMeta{}, service.ErrNotFound
	}
	return f.exception(id), nil
}

func (f *Fake) Exceptions(_ context.Context, q service.ExceptionQuery) ([]service.ExceptionRequest, error) {
	if err := f.fail("Exceptions"); err != nil {
		return nil, err
	}
	var out []service.ExceptionRequest
	for id, e := range f.st.Exceptions {
		if e.OrgID != f.org || q.RequestedBy != nil && *q.RequestedBy != e.RequestedBy {
			continue
		}
		switch q.Status {
		case "pending", "approved", "rejected":
			if e.Status != q.Status {
				continue
			}
		case "expiring":
			if e.Status != "approved" || e.Type != "risk_accepted" || e.ExpiresAt == nil ||
				!e.ExpiresAt.After(q.Now) || e.ExpiresAt.After(q.Now.Add(14*24*time.Hour)) {
				continue
			}
		}
		if q.After != nil && !(e.CreatedAt.Before(q.After.CreatedAt) || e.CreatedAt.Equal(q.After.CreatedAt) && id.String() < q.After.ID.String()) {
			continue
		}
		out = append(out, f.exception(id).ExceptionRequest)
	}
	slices.SortFunc(out, func(a, b service.ExceptionRequest) int {
		return cmp.Or(b.CreatedAt.T().Compare(a.CreatedAt.T()), cmp.Compare(b.ID.String(), a.ID.String()))
	})
	if len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}

func (f *Fake) DecideException(_ context.Context, d service.Decision) error {
	if err := f.fail("DecideException"); err != nil {
		return err
	}
	e := f.st.Exceptions[d.ID]
	if e.RequestedBy == d.DecidedBy {
		return errors.New("check constraint: decided_by <> requested_by")
	}
	now := f.Now
	e.Status, e.DecidedBy, e.DecisionNote, e.DecidedAt = d.Status, &d.DecidedBy, d.Note, &now
	if d.ExpiresAt != nil {
		e.ExpiresAt = d.ExpiresAt
	}
	f.st.Exceptions[d.ID] = e
	return nil
}

// Audit.

func (f *Fake) AppendAudit(_ context.Context, r service.AuditRecord) error {
	if err := f.fail("AppendAudit"); err != nil {
		return err
	}
	f.st.Audit = append(f.st.Audit, r)
	return nil
}

func (f *Fake) AuditEntries(_ context.Context, q service.AuditQuery) ([]service.AuditEntry, error) {
	if err := f.fail("AuditEntries"); err != nil {
		return nil, err
	}
	var out []service.AuditEntry
	for k := len(f.st.Audit) - 1; k >= 0 && len(out) < q.Limit; k-- {
		r := f.st.Audit[k]
		id := int64(k + 1)
		if r.OrgID != q.OrgID || q.Action != "" && r.Action != q.Action || q.AfterID > 0 && id >= q.AfterID ||
			q.ActorSystem && r.ActorID != nil || q.ActorID != nil && (r.ActorID == nil || *r.ActorID != *q.ActorID) {
			continue
		}
		data, _ := json.Marshal(r.Data)
		tt, ti := r.TargetType, r.TargetID
		out = append(out, service.AuditEntry{ID: id, Actor: f.refp(r.ActorID), Action: r.Action, TargetType: &tt, TargetID: &ti,
			Data: data, CreatedAt: service.Time(f.Now)})
	}
	return out, nil
}
