package store

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/aupv9/warden/backend/internal/domain/rbac"
	"github.com/aupv9/warden/backend/internal/service"
	"github.com/aupv9/warden/backend/internal/worker"
)

// scriptTx is a pgx.Tx whose queries answer from a script. It lets unit tests
// run every repository method (row mapping, error mapping); the SQL itself is
// checked against Postgres by the integration tests.
type scriptTx struct {
	pgx.Tx
	// answer returns the rows for a query (matched on SQL text).
	answer func(sql string, args []any) ([][]any, error)
	sqls   []string
}

func (s *scriptTx) rows(sql string, args []any) ([][]any, error) {
	s.sqls = append(s.sqls, sql)
	if s.answer == nil {
		return nil, nil
	}
	return s.answer(sql, args)
}

func (s *scriptTx) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	rows, err := s.rows(sql, args)
	return pgconn.NewCommandTag(fmt.Sprintf("DELETE %d", len(rows))), err
}

func (s *scriptTx) Query(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
	rows, err := s.rows(sql, args)
	return &scriptRows{data: rows, err: err, i: -1}, err
}

func (s *scriptTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	r, _ := s.Query(ctx, sql, args...)
	return &oneRow{r.(*scriptRows)}
}

type scriptRows struct {
	pgx.Rows
	data [][]any
	err  error
	i    int
}

func (r *scriptRows) Close()     {}
func (r *scriptRows) Err() error { return r.err }
func (r *scriptRows) Next() bool {
	if r.err != nil {
		return false
	}
	r.i++
	return r.i < len(r.data)
}
func (r *scriptRows) CommandTag() pgconn.CommandTag                { return pgconn.NewCommandTag("SELECT") }
func (r *scriptRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *scriptRows) Values() ([]any, error)                       { return r.data[r.i], nil }

func (r *scriptRows) Scan(dest ...any) error {
	row := r.data[r.i]
	if len(row) != len(dest) {
		return fmt.Errorf("scan: %d values for %d destinations", len(row), len(dest))
	}
	for k, d := range dest {
		if err := assign(reflect.ValueOf(d).Elem(), row[k]); err != nil {
			return fmt.Errorf("column %d: %w", k, err)
		}
	}
	return nil
}

type oneRow struct{ r *scriptRows }

func (o *oneRow) Scan(dest ...any) error {
	if o.r.err != nil {
		return o.r.err
	}
	if !o.r.Next() {
		return pgx.ErrNoRows
	}
	return o.r.Scan(dest...)
}

func assign(dst reflect.Value, v any) error {
	if v == nil {
		dst.Set(reflect.Zero(dst.Type()))
		return nil
	}
	src := reflect.ValueOf(v)
	if dst.Kind() == reflect.Pointer && src.Kind() != reflect.Pointer {
		p := reflect.New(dst.Type().Elem())
		if err := assign(p.Elem(), v); err != nil {
			return err
		}
		dst.Set(p)
		return nil
	}
	switch {
	case src.Type().AssignableTo(dst.Type()):
		dst.Set(src)
	case src.Type().ConvertibleTo(dst.Type()) && src.Kind() != reflect.Int:
		dst.Set(src.Convert(dst.Type()))
	case src.Kind() == reflect.Int && dst.Kind() == src.Kind():
		dst.SetInt(src.Int())
	case src.Kind() == reflect.Int && dst.Kind() == reflect.Int64:
		dst.SetInt(src.Int())
	default:
		return fmt.Errorf("can't assign %s to %s", src.Type(), dst.Type())
	}
	return nil
}

func repoWith(answer func(sql string, args []any) ([][]any, error)) (*Repo, *scriptTx) {
	tx := &scriptTx{answer: answer}
	return NewRepo(tx, nil), tx
}

// on answers a query with the rows of the longest key it contains.
func on(m map[string][][]any) func(string, []any) ([][]any, error) {
	return func(sql string, _ []any) ([][]any, error) {
		best := ""
		for k := range m {
			if strings.Contains(sql, k) && len(k) > len(best) {
				best = k
			}
		}
		if best == "" {
			return nil, nil
		}
		return m[best], nil
	}
}

var (
	ctx   = context.Background()
	now   = time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC)
	errDB = errors.New("db down")
)

func failing(string, []any) ([][]any, error) { return nil, errDB }

func TestRepoUsers(t *testing.T) {
	id, org := uuid.New(), uuid.New()
	mfa := true
	r, _ := repoWith(on(map[string][][]any{
		"FROM app_user WHERE":    {{id, "sub", "a@b.c", "A", true, &mfa, nil}},
		"FROM org_member m\n":    {{org, "Acme", "org_admin", []string{"member"}}},
		"SELECT role::text":      {{"member"}},
		"FROM organization":      {{org, "Acme", service.SLADays{Critical: 7}}},
		"SELECT id, email::text": {{id, "a@b.c", "A"}},
	}))
	if u, err := r.UserBySub(ctx, "sub"); err != nil || u.ID != id || !*u.MFA {
		t.Fatal(u, err)
	}
	if u, err := r.UserByEmail(ctx, "a@b.c"); err != nil || u.Email != "a@b.c" {
		t.Fatal(u, err)
	}
	if err := r.InsertUser(ctx, service.User{ID: id}); err != nil {
		t.Fatal(err)
	}
	if err := r.UpdateUser(ctx, service.User{ID: id}); err != nil {
		t.Fatal(err)
	}
	if o, err := r.UserOrgs(ctx, id); err != nil || len(o) != 1 || o[0].Role != rbac.OrgAdmin || len(o[0].MFARoles) != 1 {
		t.Fatal(o, err)
	}
	if role, err := r.MemberRole(ctx, org, id); err != nil || role != rbac.Member {
		t.Fatal(role, err)
	}
	if u, err := r.UserRef(ctx, id); err != nil || u.ID != id {
		t.Fatal(u, err)
	}
	if o, err := r.Org(ctx, org); err != nil || o.SLADays.Critical != 7 {
		t.Fatal(o, err)
	}

	empty, _ := repoWith(nil)
	if _, err := empty.UserBySub(ctx, "x"); !errors.Is(err, service.ErrNotFound) {
		t.Fatal(err)
	}
	if o, err := empty.UserOrgs(ctx, id); err != nil || o == nil {
		t.Fatal("want empty non-nil slice", o, err)
	}
	bad, _ := repoWith(failing)
	if _, err := bad.UserOrgs(ctx, id); !errors.Is(err, errDB) {
		t.Fatal(err)
	}
	if err := bad.InsertUser(ctx, service.User{}); !errors.Is(err, errDB) {
		t.Fatal(err)
	}
}

func TestRepoMembers(t *testing.T) {
	org, user, proj := uuid.New(), uuid.New(), uuid.New()
	member := []any{user, "a@b.c", "A", true, "org_admin", nil, []service.MemberProject{{ID: proj, Key: "WEB", Role: rbac.Owner}}}
	r, tx := repoWith(on(map[string][][]any{
		"count(*), count(*) FILTER": {{3, 2, 1}},
		"status = 'pending'":        {{4}},
		"FROM org_member m JOIN":    {member},
		"SELECT user_id FROM":       {{user}},
	}))
	if s, err := r.Summary(ctx, service.Visibility{OrgID: org, UserID: user}, now); err != nil || s.OpenIssues != 3 || s.PastSLA != 1 {
		t.Fatal(s, err)
	}
	if !strings.Contains(tx.sqls[0], "project_member vm") {
		t.Fatal(tx.sqls[0])
	}
	if n, err := r.CountPendingExceptions(ctx); err != nil || n != 4 {
		t.Fatal(n, err)
	}
	if m, err := r.OrgMembers(ctx, org); err != nil || len(m) != 1 || m[0].Projects[0].Key != "WEB" {
		t.Fatal(m, err)
	}
	if m, err := r.OrgMember(ctx, org, user); err != nil || m.Role != rbac.OrgAdmin || m.MFA != nil {
		t.Fatal(m, err)
	}
	if a, err := r.LockOrgAdmins(ctx, org); err != nil || len(a) != 1 {
		t.Fatal(a, err)
	}
	for _, err := range []error{
		r.InsertOrgMember(ctx, org, user, rbac.Member),
		r.SetOrgMemberRole(ctx, org, user, rbac.Member),
		r.DeleteOrgMember(ctx, org, user),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	noProjects, _ := repoWith(on(map[string][][]any{"FROM org_member m JOIN": {{user, "a@b.c", "A", true, "member", nil, nil}}}))
	if m, _ := noProjects.OrgMember(ctx, org, user); m.Projects == nil {
		t.Fatal("projects must be []")
	}
	bad, _ := repoWith(failing)
	if err := bad.DeleteOrgMember(ctx, org, user); !errors.Is(err, errDB) {
		t.Fatal(err)
	}
	dup, _ := repoWith(func(string, []any) ([][]any, error) { return nil, &pgconn.PgError{Code: uniqueViolation} })
	if err := dup.InsertOrgMember(ctx, org, user, rbac.Member); !errors.Is(err, service.ErrConflict) {
		t.Fatal(err)
	}
}

func TestRepoProjectsAndScans(t *testing.T) {
	org, user, proj, scan := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	desc := "d"
	projRow := []any{proj, "WEB", "Web", &desc, []string{"trivy"}, "owner", now, 1, 2, 3, 4, 5, 6, scan, "completed", now, now, nil}
	scanRow := []any{scan, org, proj, "queued", "a.zip", int64(10), []string{"trivy"}, nil, service.ScanStats{Total: 2},
		now, now, nil, nil, "key", "sum", user, "a@b.c", "A", nil, nil, nil, "source", "", nil, "sboms/k", int64(9), "abc", 4}
	r, _ := repoWith(on(map[string][][]any{
		"LEFT JOIN LATERAL":                           {projRow},
		"SELECT (SELECT pm.role":                      {{"developer"}},
		"FROM project_member pm\n":                    {{user, "a@b.c", "A", "viewer"}},
		"SELECT EXISTS":                               {{true}},
		"min(created_at)":                             {{2, now}},
		"FROM scan s JOIN app_user":                   {scanRow},
		"FROM scan_tool_run":                          {{"trivy", "0.1", "succeeded", 3, 100, nil}},
		"DELETE FROM project_member WHERE project_id": {{1}},
	}))
	v := service.Visibility{OrgID: org, UserID: user}
	if p, err := r.Projects(ctx, v, now, false); err != nil || len(p) != 1 || *p[0].MyRole != rbac.Owner || p[0].LastScan.ID != scan || p[0].PastSLA != 6 {
		t.Fatal(p, err)
	}
	if p, err := r.Project(ctx, v, proj, now); err != nil || p.OpenBySeverity.Info != 5 {
		t.Fatal(p, err)
	}
	if role, err := r.ProjectRole(ctx, proj, user); err != nil || role != rbac.Developer {
		t.Fatal(role, err)
	}
	if m, err := r.ProjectMembers(ctx, proj); err != nil || len(m) != 1 || m[0].Role != rbac.Viewer {
		t.Fatal(m, err)
	}
	if ok, err := r.DeleteProjectMember(ctx, proj, user); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if ok, err := r.OwnsAnyProject(ctx, user); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if n, oldest, err := r.ScansSince(ctx, user, now); err != nil || n != 2 || !oldest.Equal(now) {
		t.Fatal(n, oldest, err)
	}
	if s, err := r.Scan(ctx, scan, true); err != nil || s.Stats.Total != 2 || s.CreatedBy.ID != user || s.QueuedAt == nil ||
		s.Kind != "source" || s.SBOM == nil || s.SBOM.Components != 4 || s.SBOM.Key != "sboms/k" {
		t.Fatal(s, err)
	}
	if s, err := r.Scans(ctx, proj, &service.ScanCursor{CreatedAt: now, ID: scan}, 10); err != nil || len(s) != 1 {
		t.Fatal(s, err)
	}
	if tr, err := r.ToolRuns(ctx, scan); err != nil || *tr[0].FindingsCount != 3 {
		t.Fatal(tr, err)
	}
	for _, err := range []error{
		r.InsertProject(ctx, service.NewProject{}), r.UpsertProjectMember(ctx, org, proj, user, rbac.Owner),
		r.LockScanRate(ctx, user), r.InsertScan(ctx, service.NewScan{}), r.MarkScanQueued(ctx, scan), r.MarkScanCancelled(ctx, scan),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := r.EnqueueScan(ctx, worker.ScanArgs{}); err == nil {
		t.Fatal("no queue configured")
	}

	empty, _ := repoWith(nil)
	if _, err := empty.Project(ctx, v, proj, now); !errors.Is(err, service.ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := empty.ProjectRole(ctx, proj, user); !errors.Is(err, service.ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := empty.Scan(ctx, scan, false); !errors.Is(err, service.ErrNotFound) {
		t.Fatal(err)
	}
	if n, oldest, err := empty.ScansSince(ctx, user, now); err == nil || n != 0 || !oldest.IsZero() {
		// QueryRow on no rows: ErrNoRows mapped to ErrNotFound.
		t.Fatal(n, oldest, err)
	}
	nullRole, _ := repoWith(on(map[string][][]any{"SELECT (SELECT pm.role": {{nil}}, "LEFT JOIN LATERAL": {{proj, "WEB", "Web", nil, nil, nil, now, 0, 0, 0, 0, 0, 0, nil, nil, nil, nil, nil}}}))
	if role, err := nullRole.ProjectRole(ctx, proj, user); err != nil || role != "" {
		t.Fatal(role, err)
	}
	if p, err := nullRole.Project(ctx, v, proj, now); err != nil || p.MyRole != nil || p.LastScan != nil || p.DefaultTools == nil {
		t.Fatal(p, err)
	}
}

func issueRow(id, proj, scan uuid.UUID, withDetail bool) []any {
	row := []any{id, "WEB-1", proj, "t", "high", "open", "opengrep", "r", nil, nil, nil, nil, nil,
		uuid.New(), "a@b.c", "A", now, true, now}
	if withDetail {
		row = append(row, nil, nil, nil, nil, []string{"CWE-79"}, nil, scan, now, scan, now, 2, 3, nil, 1, "WEB")
	}
	return row
}

func TestRepoIssues(t *testing.T) {
	org, user, proj, scan, iss := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	r, _ := repoWith(on(map[string][][]any{
		"fs.created_at":            {issueRow(iss, proj, scan, true)},
		"GROUP BY 1":               {{"high", 2}, {"low", 1}},
		"LIMIT":                    {issueRow(iss, proj, scan, false)},
		"FROM comment c JOIN":      {{uuid.New(), user, "a@b.c", "A", "hi", now, nil}},
		"SELECT id FROM exception": {{iss}},
	}))
	q := service.IssueQuery{Vis: service.Visibility{OrgID: org, UserID: user}, Now: now, Limit: 5}
	if l, err := r.Issues(ctx, q); err != nil || len(l) != 1 || l[0].Assignee == nil || !l[0].PastSLA {
		t.Fatal(l, err)
	}
	if c, err := r.IssueCounts(ctx, q); err != nil || c.High != 2 || c.Low != 1 {
		t.Fatal(c, err)
	}
	if i, err := r.Issue(ctx, iss, true, now); err != nil || i.Version != 3 || i.CWE[0] != "CWE-79" || i.Occurrences != 2 {
		t.Fatal(i, err)
	}
	if c, err := r.Comments(ctx, iss); err != nil || len(c) != 1 {
		t.Fatal(c, err)
	}
	if c, err := r.Comment(ctx, iss); err != nil || c.Body != "hi" {
		t.Fatal(c, err)
	}
	if p, err := r.PendingExceptionID(ctx, iss); err != nil || *p != iss {
		t.Fatal(p, err)
	}
	for _, err := range []error{
		r.UpdateIssueState(ctx, iss, "fixed", nil), r.InsertIssueEvent(ctx, service.NewEvent{}), r.InsertComment(ctx, service.NewComment{}),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	ev, _ := repoWith(on(map[string][][]any{"FROM issue_event e": {{int64(7), "status_changed", nil, nil, nil, nil, nil, nil, now}}}))
	if e, err := ev.IssueEvents(ctx, iss, 10); err != nil || len(e) != 1 || e[0].Actor != nil || e[0].ID != 7 {
		t.Fatal(e, err)
	}
	empty, _ := repoWith(nil)
	if p, err := empty.PendingExceptionID(ctx, iss); err != nil || p != nil {
		t.Fatal(p, err)
	}
	if _, err := empty.Issue(ctx, iss, false, now); !errors.Is(err, service.ErrNotFound) {
		t.Fatal(err)
	}
	bad, _ := repoWith(failing)
	if _, err := bad.PendingExceptionID(ctx, iss); !errors.Is(err, errDB) {
		t.Fatal(err)
	}
	if _, err := bad.IssueCounts(ctx, q); !errors.Is(err, errDB) {
		t.Fatal(err)
	}
}

func TestRepoExceptions(t *testing.T) {
	org, user, iss, ex := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	row := []any{ex, org, iss, user, iss, "WEB-1", "t", "high", "open", "risk_accepted", "reason", "approved",
		user, "a@b.c", "A", uuid.New(), "l@b.c", "L", "ok", now, now, now}
	r, _ := repoWith(on(map[string][][]any{"FROM exception_request e": {row}}))
	if e, err := r.Exception(ctx, ex, true); err != nil || e.DecidedBy == nil || e.RequestedByID != user || e.Issue.Key != "WEB-1" {
		t.Fatal(e, err)
	}
	if l, err := r.Exceptions(ctx, service.ExceptionQuery{Status: "approved", Limit: 5}); err != nil || len(l) != 1 {
		t.Fatal(l, err)
	}
	if err := r.InsertException(ctx, service.NewException{}); err != nil {
		t.Fatal(err)
	}
	if err := r.DecideException(ctx, service.Decision{}); err != nil {
		t.Fatal(err)
	}
	empty, _ := repoWith(nil)
	if _, err := empty.Exception(ctx, ex, false); !errors.Is(err, service.ErrNotFound) {
		t.Fatal(err)
	}
}

func TestRepoAudit(t *testing.T) {
	org, actor := uuid.New(), uuid.New()
	var inserted []any
	prev := strings.Repeat("a", 64)
	r, tx := repoWith(func(sql string, args []any) ([][]any, error) {
		switch {
		case strings.Contains(sql, "SELECT hash FROM audit_log"):
			return [][]any{{prev}}, nil
		case strings.Contains(sql, "INSERT INTO audit_log"):
			inserted = args
		}
		return nil, nil
	})
	rec := service.AuditRecord{OrgID: org, ActorID: &actor, Action: "scan.created", TargetType: "scan", TargetID: "x",
		IP: "::ffff:192.0.2.1", UserAgent: "curl\x00", Data: map[string]any{"n": 1}}
	if err := r.AppendAudit(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(tx.sqls[0], "pg_advisory_xact_lock") {
		t.Fatal("chain not serialized:", tx.sqls[0])
	}
	if *inserted[5].(*string) != "192.0.2.1" || *inserted[6].(*string) != "curl" || *inserted[8].(*string) != prev {
		t.Fatal(inserted)
	}
	// The stored hash is reproducible from the stored columns.
	row := AuditRow{OrgID: org, ActorID: &actor, Action: rec.Action, TargetType: inserted[3].(*string), TargetID: inserted[4].(*string),
		IP: inserted[5].(*string), UserAgent: inserted[6].(*string), Data: []byte(inserted[7].(string)), CreatedAt: inserted[10].(time.Time)}
	if h, _ := ChainHash(prev, row); h != inserted[9] {
		t.Fatal("hash mismatch")
	}
	if err := r.AppendAudit(ctx, service.AuditRecord{}); err == nil {
		t.Fatal("org required")
	}
	if err := r.AppendAudit(ctx, service.AuditRecord{OrgID: org, Data: map[string]any{"bad": func() {}}}); err == nil {
		t.Fatal("unmarshalable data accepted")
	}
	bad, _ := repoWith(failing)
	if err := bad.AppendAudit(ctx, rec); !errors.Is(err, errDB) {
		t.Fatal(err)
	}

	list, _ := repoWith(on(map[string][][]any{"FROM audit_log l": {{int64(3), nil, nil, nil, "org.created", nil, nil, nil, []byte(`{"a":1}`), now}}}))
	if l, err := list.AuditEntries(ctx, service.AuditQuery{OrgID: org, Limit: 2}); err != nil || len(l) != 1 || l[0].Actor != nil || string(l[0].Data) != `{"a":1}` {
		t.Fatal(l, err)
	}
}

func TestVerifyAuditChain(t *testing.T) {
	org, actor := uuid.New(), uuid.New()
	ip := "10.0.0.1"
	mk := func(prev, data string, at time.Time) []any {
		row := AuditRow{OrgID: org, ActorID: &actor, Action: "a", IP: &ip, Data: []byte(data), CreatedAt: at}
		h, _ := ChainHash(prev, row)
		return []any{int64(1), &actor, "a", nil, nil, &ip, nil, data, prev, h, at}
	}
	r1 := mk("", `{"x": 1}`, now)
	r2 := mk(r1[9].(string), `{}`, now.Add(time.Second))
	q := &scriptTx{answer: func(string, []any) ([][]any, error) { return [][]any{r1, r2}, nil }}
	if n, err := VerifyAuditChain(ctx, q, org); err != nil || n != 2 {
		t.Fatal(n, err)
	}
	tampered := append([]any{}, r2...)
	tampered[7] = `{"x": 2}`
	q.answer = func(string, []any) ([][]any, error) { return [][]any{r1, tampered}, nil }
	if n, err := VerifyAuditChain(ctx, q, org); !errors.Is(err, ErrChainBroken) || n != 1 {
		t.Fatal(n, err)
	}
	unlinked := mk("bogus", `{}`, now)
	q.answer = func(string, []any) ([][]any, error) { return [][]any{unlinked}, nil }
	if _, err := VerifyAuditChain(ctx, q, org); !errors.Is(err, ErrChainBroken) {
		t.Fatal(err)
	}
	q.answer = failing
	if _, err := VerifyAuditChain(ctx, q, org); !errors.Is(err, errDB) {
		t.Fatal(err)
	}
}
