package service_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	apperrors "github.com/aupv9/common-go/errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/aupv9/warden/backend/internal/domain/rbac"
	"github.com/aupv9/warden/backend/internal/service"
	"github.com/aupv9/warden/backend/internal/service/servicetest"
)

func status(err error) int {
	if ae, ok := apperrors.As(err); ok {
		return ae.HTTPStatus()
	}
	return 0
}

func TestTimeIsUTC(t *testing.T) {
	var tm service.Time
	loc := time.FixedZone("ICT", 7*3600)
	if err := tm.ScanTimestamptz(pgtype.Timestamptz{Time: time.Date(2026, 10, 26, 17, 0, 0, 0, loc), Valid: true}); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(tm)
	if string(b) != `"2026-10-26T10:00:00Z"` {
		t.Fatal(string(b))
	}
}

func TestSeverityCounts(t *testing.T) {
	var c service.SeverityCounts
	for _, s := range []string{"critical", "high", "medium", "low", "info", "bogus"} {
		c.Add(s, 2)
	}
	if c != (service.SeverityCounts{Critical: 2, High: 2, Medium: 2, Low: 2, Info: 2}) {
		t.Fatal(c)
	}
}

type setup struct {
	f   *servicetest.Fake
	s   *service.Service
	org uuid.UUID
	p   uuid.UUID
	u   uuid.UUID
}

func newSetup(role rbac.Role) setup {
	f := servicetest.New()
	s := service.New(f, nil, service.Config{}, nil)
	s.SetClock(func() time.Time { return f.Now })
	org := f.AddOrg("Acme")
	p := f.AddProject(org, "WEB")
	u := f.AddUser("lead@acme.test")
	f.AddMember(org, u, role)
	return setup{f: f, s: s, org: org, p: p, u: u}
}

func (x setup) actor() *service.Actor { return &service.Actor{UserID: x.u, OrgID: x.org} }

func TestArchivedProjectsAreHidden(t *testing.T) {
	x := newSetup(rbac.SecurityLead)
	x.f.ArchiveProject(x.p)
	if _, err := x.s.Project(context.Background(), x.actor(), x.p); status(err) != http.StatusNotFound {
		t.Fatal(err)
	}
	if _, err := x.s.ProjectMembers(context.Background(), x.actor(), x.p); status(err) != http.StatusNotFound {
		t.Fatal(err)
	}
}

func TestScanToolRuns(t *testing.T) {
	x := newSetup(rbac.SecurityLead)
	sc := x.f.AddScan(x.p, x.u, "completed", 5)
	n := 3
	x.f.SetToolRuns(sc, []service.ToolRun{{Tool: "trivy", Status: "succeeded", FindingsCount: &n}})
	got, err := x.s.Scan(context.Background(), x.actor(), sc)
	if err != nil || len(*got.ToolRuns) != 1 {
		t.Fatal(got, err)
	}
	x.f.Fail["ToolRuns"] = errors.New("x")
	if _, err := x.s.Scan(context.Background(), x.actor(), sc); err == nil {
		t.Fatal("error swallowed")
	}
}

func TestMembershipIsRecheckedInTransaction(t *testing.T) {
	x := newSetup(rbac.SecurityLead)
	a := x.actor()
	a.OrgRole = rbac.OrgAdmin // whatever the middleware saw, the transaction decides
	stranger := &service.Actor{UserID: uuid.New(), OrgID: x.org, OrgRole: rbac.OrgAdmin}
	if _, err := x.s.Org(context.Background(), stranger); status(err) != http.StatusNotFound {
		t.Fatal(err)
	}
	if _, err := x.s.AuditLog(context.Background(), a, service.AuditFilter{}); err != nil || a.OrgRole != rbac.SecurityLead {
		t.Fatal(err, a.OrgRole)
	}
	x.f.Fail["MemberRole"] = errors.New("db")
	if _, err := x.s.Org(context.Background(), a); err == nil || status(err) != 0 {
		t.Fatal(err)
	}
	if _, err := x.s.OrgRole(context.Background(), x.u, x.org); err == nil {
		t.Fatal("error swallowed")
	}
}

func TestExceptionDecisionAuditAndInsertRace(t *testing.T) {
	x := newSetup(rbac.SecurityLead)
	dev := x.f.AddUser("dev@acme.test")
	x.f.AddMember(x.org, dev, rbac.Member)
	x.f.AddProjectMember(x.p, dev, rbac.Developer)
	iss := x.f.AddIssue(x.p, "high", "open", nil)
	ex := x.f.AddException(iss, dev, "false_positive", nil)
	note := "confirmed with the team"
	if _, err := x.s.Decide(context.Background(), x.actor(), ex, service.DecisionInput{Decision: "reject", Note: &note}); err != nil {
		t.Fatal(err)
	}
	if x.f.ExceptionStatus(ex) != "rejected" {
		t.Fatal(x.f.ExceptionStatus(ex))
	}
	a := x.f.AuditLog()
	if len(a) != 1 || a[0].Action != "exception.decided" || a[0].Data["decision"] != "reject" {
		t.Fatalf("%+v", a)
	}
	// The unique index catches a concurrent duplicate the pre-check missed.
	x.f.Fail["InsertException"] = service.ErrConflict
	devActor := &service.Actor{UserID: dev, OrgID: x.org}
	_, err := x.s.CreateException(context.Background(), devActor, iss, service.CreateExceptionInput{Type: "false_positive", Reason: "a sufficiently long reason"})
	if status(err) != http.StatusConflict {
		t.Fatal(err)
	}
}

func TestUserProvisioningRace(t *testing.T) {
	f := servicetest.New()
	s := service.New(f, nil, service.Config{}, nil)
	f.Fail["InsertUser"] = service.ErrConflict
	if _, err := s.Authenticate(context.Background(), service.Identity{Sub: "s", Email: "a@b.test"}); status(err) != http.StatusForbidden {
		t.Fatal(err)
	}
	f.Fail = map[string]error{"UserByEmail": errors.New("db")}
	if _, err := s.Authenticate(context.Background(), service.Identity{Sub: "s", Email: "a@b.test"}); err == nil || status(err) != 0 {
		t.Fatal(err)
	}
	f.Fail = map[string]error{"UserOrgs": errors.New("db")}
	if _, err := s.Me(context.Background(), service.User{}, service.Identity{}); err == nil {
		t.Fatal("error swallowed")
	}
}

func TestObjectKey(t *testing.T) {
	org, scan := uuid.New(), uuid.New()
	if service.ObjectKey(org, scan) != "scans/"+org.String()+"/"+scan.String()+".zip" {
		t.Fatal(service.ObjectKey(org, scan))
	}
}
