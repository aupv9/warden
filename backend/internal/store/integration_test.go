//go:build integration

package store_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	apperrors "github.com/aupv9/common-go/errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/aupv9/warden/backend/internal/domain/rbac"
	"github.com/aupv9/warden/backend/internal/ids"
	"github.com/aupv9/warden/backend/internal/migrations"
	"github.com/aupv9/warden/backend/internal/service"
	"github.com/aupv9/warden/backend/internal/store"
	"github.com/aupv9/warden/backend/internal/worker"
)

var ownerURL, appURL string

func TestMain(m *testing.M) {
	ctx := context.Background()
	c, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("warden"), tcpostgres.WithUsername("warden_owner"), tcpostgres.WithPassword("owner-test-pw"),
		testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(60*time.Second)),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "start postgres:", err)
		os.Exit(1)
	}
	code := func() int {
		defer func() { _ = testcontainers.TerminateContainer(c) }()
		if ownerURL, err = c.ConnectionString(ctx, "sslmode=disable"); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		conn, err := pgx.Connect(ctx, ownerURL)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		_, err = conn.Exec(ctx, "CREATE ROLE warden_app LOGIN PASSWORD 'app-test-pw' NOSUPERUSER NOBYPASSRLS")
		conn.Close(ctx)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if err := migrations.Up(ctx, ownerURL); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		host, _ := c.Host(ctx)
		port, _ := c.MappedPort(ctx, "5432/tcp")
		appURL = fmt.Sprintf("postgres://warden_app:app-test-pw@%s:%s/warden?sslmode=disable", host, port.Port())
		return m.Run()
	}()
	os.Exit(code)
}

type objects struct{ sizes map[string]int64 }

func (o *objects) PresignPut(_ context.Context, key string, size int64, _ string, _ time.Duration) (string, map[string]string, error) {
	return "https://s3.test/" + key, map[string]string{"Content-Length": fmt.Sprint(size)}, nil
}

func (o *objects) PresignGet(_ context.Context, key string, _ time.Duration, filename, _ string) (string, error) {
	return "https://s3.test/" + key + "?name=" + filename, nil
}

func (o *objects) Head(_ context.Context, key string) (int64, error) {
	if n, ok := o.sizes[key]; ok {
		return n, nil
	}
	return 0, service.ErrObjectNotFound
}

type world struct {
	t     *testing.T
	pool  *pgxpool.Pool
	db    *store.DB
	svc   *service.Service
	objs  *objects
	users map[string]service.User
}

var ctx = context.Background()

func newWorld(t *testing.T) *world {
	t.Helper()
	pool, err := pgxpool.New(ctx, appURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	jobs, err := worker.NewClient(pool, worker.Options{})
	if err != nil {
		t.Fatal(err)
	}
	d := store.New(pool, jobs)
	o := &objects{sizes: map[string]int64{}}
	return &world{t: t, pool: pool, db: d, objs: o, users: map[string]service.User{},
		svc: service.New(d, o, service.Config{UploadMaxBytes: 1 << 20, RateLimitPerHour: 5}, nil)}
}

// user signs a user in (provisioning them) with a unique email.
func (w *world) user(name string) service.User {
	w.t.Helper()
	email := fmt.Sprintf("%s-%s@test.example", name, uuid.NewString()[:8])
	u, err := w.svc.Authenticate(ctx, service.Identity{Sub: "sub-" + email, Email: email, Name: name, MFA: true})
	if err != nil {
		w.t.Fatal(err)
	}
	w.users[name] = u
	return u
}

func (w *world) actor(name string, org uuid.UUID) *service.Actor {
	return &service.Actor{UserID: w.users[name].ID, OrgID: org, IP: "192.0.2.10", UserAgent: "test"}
}

func code(err error) string {
	if ae, ok := apperrors.As(err); ok {
		return ae.Code
	}
	if err != nil {
		return "ERR: " + err.Error()
	}
	return ""
}

// must panics on error, which fails the running test with a stack trace.
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// ownerExec runs SQL as the schema owner with app.org_id set (seeding issues,
// which only the worker creates).
func ownerExec(t *testing.T, org uuid.UUID, sql string, args ...any) {
	t.Helper()
	conn, err := pgx.Connect(ctx, ownerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT set_config('app.org_id', $1, true)", org.String()); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, sql, args...)
		return err
	})
	if err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// org creates an org with name as admin, a lead, an owner and two developers in project key.
type orgFixture struct {
	id, project uuid.UUID
	scan        uuid.UUID
}

func (w *world) org(key string) orgFixture {
	t := w.t
	t.Helper()
	admin, lead, owner, dev, dev2 := w.user(key+"admin"), w.user(key+"lead"), w.user(key+"owner"), w.user(key+"dev"), w.user(key+"dev2")
	id := must(store.CreateOrg(ctx, w.db, "Org "+key, admin.Email))
	a := w.actor(key+"admin", id)
	for u, role := range map[service.User]string{lead: "security_lead", owner: "member", dev: "member", dev2: "member"} {
		must(w.svc.AddMember(ctx, a, service.AddMemberInput{Email: u.Email, Role: role}))
	}
	p := must(w.svc.CreateProject(ctx, w.actor(key+"lead", id), service.CreateProjectInput{Key: key, Name: "Project " + key}))
	for u, role := range map[service.User]string{owner: "owner", dev: "developer", dev2: "developer"} {
		must(w.svc.SetProjectMember(ctx, w.actor(key+"lead", id), p.ID, u.ID, service.SetProjectMemberInput{Role: role}))
	}
	sc := must(w.svc.CreateScan(ctx, w.actor(key+"dev", id), p.ID, service.CreateScanInput{FileName: "a.zip", FileSize: 10, SHA256: strings.Repeat("c", 64)}))
	return orgFixture{id: id, project: p.ID, scan: sc.Scan.ID}
}

func (w *world) issue(f orgFixture, n int, severity, status string, assignee *uuid.UUID, due *time.Time) uuid.UUID {
	id := ids.New()
	ownerExec(w.t, f.id, `INSERT INTO issue (id, org_id, project_id, number, fingerprint, tool, rule_id, title, severity, status,
		assignee_id, first_seen_scan_id, last_seen_scan_id, due_at, file_path, cwe)
		VALUES ($1, $2, $3, $4, $5, 'opengrep', 'python.sqli', 'SQL injection 50%', $6, $7, $8, $9, $9, $10, 'app/db.py', '{CWE-89}')`,
		id, f.id, f.project, n, fmt.Sprintf("%064d", n), severity, status, assignee, f.scan, due)
	return id
}

func TestRLSIsolatesOrgsAndNonMembersGet404(t *testing.T) {
	w := newWorld(t)
	a, b := w.org("AAA"), w.org("BBB")
	issB := w.issue(b, 1, "high", "open", nil, nil)

	// A member of A probing B's org, project, scan and issue gets 404 everywhere.
	leadA := w.actor("AAAlead", b.id)
	if _, err := w.svc.Org(ctx, leadA); code(err) != "NOT_FOUND" {
		t.Fatal(err)
	}
	if _, _, err := w.svc.OrgAccess(ctx, w.users["AAAlead"].ID, b.id); code(err) != "NOT_FOUND" {
		t.Fatal(err)
	}
	// Even inside A's org scope, B's objects don't exist (RLS).
	inA := w.actor("AAAlead", a.id)
	if _, err := w.svc.Project(ctx, inA, b.project); code(err) != "NOT_FOUND" {
		t.Fatal(err)
	}
	if _, err := w.svc.Scan(ctx, inA, b.scan); code(err) != "NOT_FOUND" {
		t.Fatal(err)
	}
	if _, err := w.svc.Issue(ctx, inA, issB); code(err) != "NOT_FOUND" {
		t.Fatal(err)
	}
	page := must(w.svc.Issues(ctx, inA, service.IssueFilter{}))
	if len(page.Items) != 0 {
		t.Fatal(page.Items)
	}
	// And the raw repository under A's app.org_id can't read B's rows either.
	err := w.db.InOrg(ctx, a.id, func(r service.Repo) error {
		_, err := r.Issue(ctx, issB, false, time.Now())
		return err
	})
	if !errors.Is(err, service.ErrNotFound) {
		t.Fatal(err)
	}
	// Developers don't see projects they aren't members of.
	other := must(w.svc.CreateProject(ctx, inA, service.CreateProjectInput{Key: "AAB", Name: "other"}))
	if _, err := w.svc.Project(ctx, w.actor("AAAdev", a.id), other.ID); code(err) != "NOT_FOUND" {
		t.Fatal(err)
	}
	if _, err := w.svc.Project(ctx, w.actor("AAAdev", a.id), a.project); err != nil {
		t.Fatal(err)
	}
}

func TestIssueWorkflowRules(t *testing.T) {
	w := newWorld(t)
	f := w.org("WFL")
	dev := w.users["WFLdev"].ID
	iss := w.issue(f, 1, "critical", "assigned", &dev, nil)

	// A developer can't transition someone else's issue.
	_, err := w.svc.Transition(ctx, w.actor("WFLdev2", f.id), iss, service.TransitionInput{To: "in_progress", Version: ptr(1)})
	if code(err) != "FORBIDDEN" {
		t.Fatal(err)
	}
	got := must(w.svc.Transition(ctx, w.actor("WFLdev", f.id), iss, service.TransitionInput{To: "in_progress", Version: ptr(1)}))
	if got.Status != "in_progress" || got.Version != 2 || len(got.CWE) != 1 || got.FirstSeenScan.ID != f.scan || got.Key != "WFL-1" {
		t.Fatalf("%+v", got)
	}
	// Stale version.
	_, err = w.svc.Transition(ctx, w.actor("WFLdev", f.id), iss, service.TransitionInput{To: "fixed", Version: ptr(1)})
	if code(err) != "VERSION_CONFLICT" {
		t.Fatal(err)
	}
	must(w.svc.Transition(ctx, w.actor("WFLdev", f.id), iss, service.TransitionInput{To: "fixed", Version: ptr(2)}))

	// Bulk assignment, comments, events.
	open := w.issue(f, 2, "high", "open", nil, ptr(time.Now().Add(-time.Hour)))
	res := must(w.svc.BulkAssign(ctx, w.actor("WFLowner", f.id), service.BulkAssignInput{IssueIDs: []string{open.String(), iss.String()}, AssigneeID: dev.String()}))
	if res.Updated != 1 {
		t.Fatal(res)
	}
	must(w.svc.AddComment(ctx, w.actor("WFLdev2", f.id), open, service.CommentInput{Body: "on it"}))
	if c := must(w.svc.Comments(ctx, w.actor("WFLdev", f.id), open)); len(c.Items) != 1 || c.Items[0].Body != "on it" {
		t.Fatal(c)
	}
	if ev := must(w.svc.IssueEvents(ctx, w.actor("WFLdev", f.id), open)); len(ev.Items) != 3 || ev.Items[0].Type != "commented" {
		t.Fatalf("%+v", ev)
	}

	// Lists with every filter and sort, including keyset pagination.
	lead := w.actor("WFLlead", f.id)
	for _, filt := range []service.IssueFilter{
		{Status: []string{"active", "fixed"}, Severity: []string{"critical", "high"}, Sort: "due_at"},
		{Assignee: "me", Tool: "opengrep", PastSLA: "true", Sort: "-severity"},
		{Assignee: "none", Q: "50%", Sort: "-updated_at", ProjectID: f.project.String()},
		{Q: "wfl-2"},
	} {
		if _, err := w.svc.Issues(ctx, lead, filt); err != nil {
			t.Fatalf("%+v: %v", filt, err)
		}
	}
	for _, sort := range []string{"due_at", "-severity", "-updated_at"} {
		seen := map[uuid.UUID]bool{}
		cursor := ""
		for range 5 {
			p := must(w.svc.Issues(ctx, lead, service.IssueFilter{Status: []string{"active", "fixed"}, Sort: sort,
				PageParams: service.PageParams{Limit: "1", Cursor: cursor}}))
			for _, it := range p.Items {
				if seen[it.ID] {
					t.Fatalf("%s: %s twice", sort, it.ID)
				}
				seen[it.ID] = true
			}
			if p.NextCursor == nil {
				break
			}
			cursor = *p.NextCursor
		}
		if len(seen) != 2 {
			t.Fatalf("%s: saw %d issues", sort, len(seen))
		}
	}
	if p := must(w.svc.Issues(ctx, lead, service.IssueFilter{Q: "WFL-2"})); len(p.Items) != 1 || p.Items[0].ID != open || !p.Items[0].PastSLA {
		t.Fatalf("%+v", p)
	}
	if p := must(w.svc.Issues(ctx, w.actor("WFLdev", f.id), service.IssueFilter{Assignee: "me", PastSLA: "true"})); len(p.Items) != 1 || p.CountsBySeverity.High != 1 {
		t.Fatalf("%+v", p)
	}
	sum := must(w.svc.Summary(ctx, lead))
	if sum.OpenIssues != 1 || sum.PastSLA != 1 {
		t.Fatalf("%+v", sum)
	}
	projects := must(w.svc.Projects(ctx, w.actor("WFLdev", f.id), ""))
	if len(projects.Items) != 1 || projects.Items[0].OpenBySeverity.High != 1 || projects.Items[0].LastScan == nil || *projects.Items[0].MyRole != rbac.Developer {
		t.Fatalf("%+v", projects)
	}
}

func TestExceptionsAndSelfApproval(t *testing.T) {
	w := newWorld(t)
	f := w.org("EXC")
	iss := w.issue(f, 1, "high", "open", nil, nil)
	reason := "this code path is only reachable by admins"

	// A security lead's own request can't be decided by themselves.
	own := must(w.svc.CreateException(ctx, w.actor("EXClead", f.id), iss, service.CreateExceptionInput{Type: "false_positive", Reason: reason}))
	if _, err := w.svc.Decide(ctx, w.actor("EXClead", f.id), own.ID, service.DecisionInput{Decision: "approve"}); code(err) != "FORBIDDEN" {
		t.Fatal(err)
	}
	// The database enforces it too, even if the service were bypassed.
	err := w.db.InOrg(ctx, f.id, func(r service.Repo) error {
		return r.DecideException(ctx, service.Decision{ID: own.ID, Status: "approved", DecidedBy: w.users["EXClead"].ID})
	})
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "23514" {
		t.Fatal(err)
	}
	// One pending request per issue.
	if _, err := w.svc.CreateException(ctx, w.actor("EXCdev", f.id), iss, service.CreateExceptionInput{Type: "false_positive", Reason: reason}); code(err) != "CONFLICT" {
		t.Fatal(err)
	}
	// Rejection needs a note (API and database).
	note := "please fix it properly"
	err = w.db.InOrg(ctx, f.id, func(r service.Repo) error {
		return r.DecideException(ctx, service.Decision{ID: own.ID, Status: "rejected", DecidedBy: w.users["EXCadmin"].ID})
	})
	if !errors.As(err, &pe) || pe.Code != "23514" {
		t.Fatal(err)
	}
	// Someone else creates a risk acceptance after the first is rejected by a second lead.
	lead2 := w.user("EXClead2")
	must(w.svc.AddMember(ctx, w.actor("EXCadmin", f.id), service.AddMemberInput{Email: lead2.Email, Role: "security_lead"}))
	rej := must(w.svc.Decide(ctx, w.actor("EXClead2", f.id), own.ID, service.DecisionInput{Decision: "reject", Note: &note}))
	if rej.Status != "rejected" || *rej.DecisionNote != note || rej.DecidedBy.ID != lead2.ID {
		t.Fatalf("%+v", rej)
	}
	exp := time.Now().Add(7 * 24 * time.Hour).UTC()
	ra := must(w.svc.CreateException(ctx, w.actor("EXCdev", f.id), iss, service.CreateExceptionInput{Type: "risk_accepted", Reason: reason, ExpiresAt: &exp}))
	if l := must(w.svc.Exceptions(ctx, w.actor("EXCdev", f.id), service.ExceptionFilter{})); len(l.Items) != 1 {
		t.Fatalf("%+v", l)
	}
	if l := must(w.svc.Exceptions(ctx, w.actor("EXClead", f.id), service.ExceptionFilter{Status: "pending"})); len(l.Items) != 1 {
		t.Fatalf("%+v", l)
	}
	ok := must(w.svc.Decide(ctx, w.actor("EXClead", f.id), ra.ID, service.DecisionInput{Decision: "approve"}))
	if ok.Status != "approved" || ok.Issue.Status != "risk_accepted" {
		t.Fatalf("%+v", ok)
	}
	if l := must(w.svc.Exceptions(ctx, w.actor("EXClead", f.id), service.ExceptionFilter{Status: "expiring", PageParams: service.PageParams{Limit: "1"}})); len(l.Items) != 1 {
		t.Fatalf("%+v", l)
	}
	if got := must(w.svc.Issue(ctx, w.actor("EXCdev", f.id), iss)); got.Status != "risk_accepted" || got.PendingExceptionID != nil {
		t.Fatalf("%+v", got)
	}
}

func TestScansMembersAndAuditChain(t *testing.T) {
	w := newWorld(t)
	f := w.org("SCN")
	dev := w.actor("SCNdev", f.id)

	// Start: missing upload, then the real thing (River job inserted in the same transaction).
	if _, err := w.svc.StartScan(ctx, dev, f.scan); code(err) != "UPLOAD_MISMATCH" {
		t.Fatal(err)
	}
	w.objs.sizes[service.ObjectKey(f.id, f.scan)] = 10
	sc := must(w.svc.StartScan(ctx, dev, f.scan))
	if sc.Status != "queued" || sc.QueuedAt == nil || sc.CreatedBy.ID != w.users["SCNdev"].ID {
		t.Fatalf("%+v", sc)
	}
	var jobs int
	if err := w.pool.QueryRow(ctx, `SELECT count(*) FROM river_job WHERE kind = 'run_scan' AND args->>'scan_id' = $1`, f.scan.String()).Scan(&jobs); err != nil || jobs != 1 {
		t.Fatal(jobs, err)
	}
	if c := must(w.svc.CancelScan(ctx, dev, f.scan)); c.Status != "cancelled" || c.FinishedAt == nil {
		t.Fatalf("%+v", c)
	}
	for range 4 {
		must(w.svc.CreateScan(ctx, dev, f.project, service.CreateScanInput{FileName: "b.zip", FileSize: 5, SHA256: strings.Repeat("d", 64), Tools: &[]string{"trivy"}}))
	}
	// The fixture's scan plus 4 = 5 = the limit.
	if _, err := w.svc.CreateScan(ctx, dev, f.project, service.CreateScanInput{FileName: "b.zip", FileSize: 5, SHA256: strings.Repeat("d", 64)}); code(err) != "RATE_LIMITED" {
		t.Fatal(err)
	}
	p1 := must(w.svc.Scans(ctx, dev, f.project, service.PageParams{Limit: "3"}))
	p2 := must(w.svc.Scans(ctx, dev, f.project, service.PageParams{Limit: "3", Cursor: *p1.NextCursor}))
	if len(p1.Items) != 3 || len(p2.Items) != 2 || p2.NextCursor != nil {
		t.Fatal(len(p1.Items), len(p2.Items))
	}
	if got := must(w.svc.Scan(ctx, dev, f.scan)); got.ToolRuns == nil {
		t.Fatal("tool runs")
	}

	// Members: list, role change, last-admin guard, removal.
	admin := w.actor("SCNadmin", f.id)
	members := must(w.svc.Members(ctx, admin))
	if len(members.Items) != 5 {
		t.Fatal(len(members.Items))
	}
	for _, m := range members.Items {
		if m.User.ID == w.users["SCNdev"].ID && (len(m.Projects) != 1 || m.Projects[0].Role != rbac.Developer || m.MFA == nil || !*m.MFA) {
			t.Fatalf("%+v", m)
		}
	}
	if _, err := w.svc.SetMemberRole(ctx, admin, w.users["SCNadmin"].ID, service.SetMemberRoleInput{Role: "member"}); code(err) != "CONFLICT" {
		t.Fatal(err)
	}
	must(w.svc.SetMemberRole(ctx, admin, w.users["SCNdev2"].ID, service.SetMemberRoleInput{Role: "security_lead"}))
	if pm := must(w.svc.ProjectMembers(ctx, dev, f.project)); len(pm.Items) != 3 {
		t.Fatal(pm)
	}
	if err := w.svc.RemoveProjectMember(ctx, admin, f.project, w.users["SCNdev2"].ID); err != nil {
		t.Fatal(err)
	}
	if err := w.svc.RemoveMember(ctx, admin, w.users["SCNdev"].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.Project(ctx, w.actor("SCNdev", f.id), f.project); code(err) != "NOT_FOUND" {
		t.Fatal(err)
	}
	if o := must(w.svc.Org(ctx, admin)); o.SLADays.Critical != 7 || o.MyRole != rbac.OrgAdmin {
		t.Fatalf("%+v", o)
	}
	me := must(w.svc.Me(ctx, w.users["SCNadmin"], service.Identity{}))
	if len(me.Orgs) != 1 || me.Orgs[0].Role != rbac.OrgAdmin {
		t.Fatalf("%+v", me)
	}

	// Audit: one entry per write, filterable, and the chain verifies.
	log := must(w.svc.AuditLog(ctx, admin, service.AuditFilter{PageParams: service.PageParams{Limit: "200"}}))
	actions := map[string]int{}
	for _, e := range log.Items {
		actions[e.Action]++
	}
	for _, a := range []string{"org.created", "member.added", "project.created", "project_member.set", "scan.created", "scan.started",
		"scan.cancelled", "member.role_changed", "project_member.removed", "member.removed"} {
		if actions[a] == 0 {
			t.Fatalf("no %s in %v", a, actions)
		}
	}
	sys := must(w.svc.AuditLog(ctx, admin, service.AuditFilter{ActorID: "system"}))
	if len(sys.Items) != 1 || sys.Items[0].Action != "org.created" {
		t.Fatalf("%+v", sys)
	}
	from := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	byDev := must(w.svc.AuditLog(ctx, admin, service.AuditFilter{ActorID: w.users["SCNdev"].ID.String(), Action: "scan.created", From: from}))
	if len(byDev.Items) != 5 || byDev.Items[0].IP == nil || *byDev.Items[0].IP != "192.0.2.10" {
		t.Fatalf("%+v", byDev)
	}
	n, err := store.VerifyOrgAudit(ctx, w.db, f.id)
	if err != nil || n != len(log.Items) {
		t.Fatal(n, len(log.Items), err)
	}

	// Tampering (only possible with owner rights) is detected.
	ownerExec(t, f.id, `UPDATE audit_log SET data = '{"role":"org_admin"}' WHERE org_id = $1 AND action = 'member.role_changed'`, f.id)
	if _, err := store.VerifyOrgAudit(ctx, w.db, f.id); !errors.Is(err, store.ErrChainBroken) {
		t.Fatal(err)
	}
	// And the app role can't do it at all.
	if _, err := w.pool.Exec(ctx, `UPDATE audit_log SET action = 'x' WHERE org_id = $1`, f.id); err == nil {
		t.Fatal("app role updated audit_log")
	}
}

func TestConcurrentAuditAppendsKeepTheChain(t *testing.T) {
	w := newWorld(t)
	f := w.org("CON")
	lead := w.actor("CONlead", f.id)
	errs := make(chan error, 10)
	for i := range 10 {
		go func() {
			_, err := w.svc.CreateProject(ctx, &service.Actor{UserID: lead.UserID, OrgID: f.id}, service.CreateProjectInput{Key: fmt.Sprintf("CP%d", i), Name: "p"})
			errs <- err
		}()
	}
	for range 10 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.VerifyOrgAudit(ctx, w.db, f.id); err != nil {
		t.Fatal(err)
	}
}

func TestCreateOrgNeedsKnownAdmin(t *testing.T) {
	w := newWorld(t)
	if _, err := store.CreateOrg(ctx, w.db, "X", "nobody@test.example"); !errors.Is(err, store.ErrAdminNotFound) {
		t.Fatal(err)
	}
	if _, err := store.CreateOrg(ctx, w.db, " ", "nobody@test.example"); err == nil {
		t.Fatal("empty name")
	}
}

func ptr[T any](v T) *T { return &v }
