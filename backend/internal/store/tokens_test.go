package store

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/service"
)

func TestRepoTokens(t *testing.T) {
	org, user, proj, tok, scan, iss := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	hash := strings.Repeat("f", 64)
	tokRow := []any{tok, "CI", "abcdefgh", []string{"scan:write"}, user, "a@b.c", "A", now, now, nil, nil}
	r, tx := repoWith(on(map[string][][]any{
		"FROM warden_lookup_token":        {{tok, org, proj, user, hash, []string{"scan:write"}, now, nil}},
		"FROM app_user WHERE id":          {{user, "sub", "a@b.c", "A", true, nil}},
		"FROM api_token t JOIN app_user":  {tokRow},
		"SELECT i.severity::text, count(": {{"critical", 2}, {"low", 1}},
		"JOIN occurrence o":               {issueRow(iss, proj, scan, false)},
	}))
	rec, err := r.LookupToken(ctx, "abcdefgh")
	if err != nil || rec.Hash != hash || rec.OrgID != org || rec.UserID != user || rec.RevokedAt != nil {
		t.Fatal(rec, err)
	}
	if u, err := r.UserByID(ctx, user); err != nil || !u.IsActive {
		t.Fatal(u, err)
	}
	if l, err := r.Tokens(ctx, proj); err != nil || len(l) != 1 || l[0].Prefix != "abcdefgh" || l[0].CreatedBy.ID != user {
		t.Fatal(l, err)
	}
	if one, err := r.Token(ctx, proj, tok); err != nil || one.ID != tok {
		t.Fatal(one, err)
	}
	for _, err := range []error{
		r.TouchToken(ctx, tok, now), r.RevokeToken(ctx, tok, now),
		r.InsertToken(ctx, service.NewToken{ID: tok, OrgID: org, ProjectID: proj, CreatedBy: user, Prefix: "abcdefgh", Hash: hash}),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	// The lookup goes through the SECURITY DEFINER function, never the table.
	for _, sql := range tx.sqls {
		if strings.Contains(sql, "token_hash") && !strings.Contains(sql, "warden_lookup_token") && !strings.HasPrefix(sql, "INSERT") {
			t.Fatalf("token hash read outside the lookup function: %s", sql)
		}
	}
	if c, err := r.ScanIssueCounts(ctx, scan); err != nil || c.Critical != 2 || c.Low != 1 {
		t.Fatal(c, err)
	}
	if l, err := r.ScanIssues(ctx, scan, []string{"critical", "high"}, now, 100); err != nil || len(l) != 1 || l[0].ID != iss {
		t.Fatal(l, err)
	}

	empty, _ := repoWith(nil)
	if _, err := empty.LookupToken(ctx, "abcdefgh"); !errors.Is(err, service.ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := empty.Token(ctx, proj, tok); !errors.Is(err, service.ErrNotFound) {
		t.Fatal(err)
	}
	if l, err := empty.Tokens(ctx, proj); err != nil || l == nil {
		t.Fatal(l, err)
	}
	bad, _ := repoWith(failing)
	if _, err := bad.ScanIssueCounts(ctx, scan); !errors.Is(err, errDB) {
		t.Fatal(err)
	}
	if _, err := bad.ScanIssues(ctx, scan, nil, now, 1); !errors.Is(err, errDB) {
		t.Fatal(err)
	}
	if err := bad.TouchToken(ctx, tok, now); !errors.Is(err, errDB) {
		t.Fatal(err)
	}
}
