package servicetest

import (
	"cmp"
	"context"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/service"
)

type tokenRow struct {
	service.NewToken
	CreatedAt  time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}

// TokenRow returns a stored token (tests).
func (f *Fake) TokenRow(id uuid.UUID) (service.NewToken, *time.Time, *time.Time) {
	t := f.st.Tokens[id]
	return t.NewToken, t.LastUsedAt, t.RevokedAt
}

// SetTokenExpiry changes a token's expiry (tests).
func (f *Fake) SetTokenExpiry(id uuid.UUID, at time.Time) {
	t := f.st.Tokens[id]
	t.ExpiresAt = at
	f.st.Tokens[id] = t
}

// SetUserActive (de)activates a user (tests).
func (f *Fake) SetUserActive(id uuid.UUID, active bool) {
	u := f.st.Users[id]
	u.IsActive = active
	f.st.Users[id] = u
}

// AddOccurrence records that issue was seen in scan.
func (f *Fake) AddOccurrence(issue, scan uuid.UUID) { f.st.Seen[[2]uuid.UUID{issue, scan}] = true }

// LookupToken crosses orgs, like the SECURITY DEFINER function.
func (f *Fake) LookupToken(_ context.Context, prefix string) (service.TokenRecord, error) {
	if err := f.fail("LookupToken"); err != nil {
		return service.TokenRecord{}, err
	}
	for _, t := range f.st.Tokens {
		if t.Prefix == prefix {
			return service.TokenRecord{ID: t.ID, OrgID: t.OrgID, ProjectID: t.ProjectID, UserID: t.CreatedBy, Hash: t.Hash,
				Scopes: t.Scopes, ExpiresAt: t.ExpiresAt, RevokedAt: t.RevokedAt}, nil
		}
	}
	return service.TokenRecord{}, service.ErrNotFound
}

func (f *Fake) UserByID(_ context.Context, id uuid.UUID) (service.User, error) {
	if err := f.fail("UserByID"); err != nil {
		return service.User{}, err
	}
	u, ok := f.st.Users[id]
	if !ok {
		return service.User{}, service.ErrNotFound
	}
	return u, nil
}

func (f *Fake) TouchToken(_ context.Context, id uuid.UUID, now time.Time) error {
	if err := f.fail("TouchToken"); err != nil {
		return err
	}
	t, ok := f.st.Tokens[id]
	if !ok || t.OrgID != f.org {
		return nil
	}
	if t.LastUsedAt == nil || !t.LastUsedAt.After(now.Add(-time.Minute)) {
		t.LastUsedAt = &now
		f.st.Tokens[id] = t
	}
	return nil
}

func (f *Fake) InsertToken(_ context.Context, t service.NewToken) error {
	if err := f.fail("InsertToken"); err != nil {
		return err
	}
	for _, x := range f.st.Tokens {
		if x.Prefix == t.Prefix || x.Hash == t.Hash {
			return service.ErrConflict
		}
	}
	f.st.Tokens[t.ID] = tokenRow{NewToken: t, CreatedAt: f.tick()}
	return nil
}

func ptime(t *time.Time) *service.Time {
	if t == nil {
		return nil
	}
	v := service.Time(*t)
	return &v
}

func (f *Fake) apiToken(t tokenRow) service.ApiToken {
	return service.ApiToken{ID: t.ID, Name: t.Name, Prefix: t.Prefix, Scopes: t.Scopes, CreatedBy: f.ref(t.CreatedBy),
		CreatedAt: service.Time(t.CreatedAt), ExpiresAt: service.Time(t.ExpiresAt), LastUsedAt: ptime(t.LastUsedAt), RevokedAt: ptime(t.RevokedAt)}
}

func (f *Fake) Tokens(_ context.Context, projectID uuid.UUID) ([]service.ApiToken, error) {
	if err := f.fail("Tokens"); err != nil {
		return nil, err
	}
	var rows []tokenRow
	for _, t := range f.st.Tokens {
		if t.ProjectID == projectID && t.OrgID == f.org {
			rows = append(rows, t)
		}
	}
	slices.SortFunc(rows, func(a, b tokenRow) int { return cmp.Compare(b.CreatedAt.UnixNano(), a.CreatedAt.UnixNano()) })
	var out []service.ApiToken
	for _, t := range rows {
		out = append(out, f.apiToken(t))
	}
	return out, nil
}

func (f *Fake) Token(_ context.Context, projectID, id uuid.UUID) (service.ApiToken, error) {
	if err := f.fail("Token"); err != nil {
		return service.ApiToken{}, err
	}
	t, ok := f.st.Tokens[id]
	if !ok || t.OrgID != f.org || t.ProjectID != projectID {
		return service.ApiToken{}, service.ErrNotFound
	}
	return f.apiToken(t), nil
}

func (f *Fake) RevokeToken(_ context.Context, id uuid.UUID, at time.Time) error {
	if err := f.fail("RevokeToken"); err != nil {
		return err
	}
	t, ok := f.st.Tokens[id]
	if ok && t.OrgID == f.org && t.RevokedAt == nil {
		t.RevokedAt = &at
		f.st.Tokens[id] = t
	}
	return nil
}

// seen lists the active issues with an occurrence in scan (in the open org).
func (f *Fake) seen(scan uuid.UUID) []uuid.UUID {
	var out []uuid.UUID
	for id, i := range f.st.Issues {
		if i.OrgID == f.org && active(i.Status) && f.st.Seen[[2]uuid.UUID{id, scan}] {
			out = append(out, id)
		}
	}
	return out
}

func (f *Fake) ScanIssueCounts(_ context.Context, scan uuid.UUID) (service.SeverityCounts, int, error) {
	if err := f.fail("ScanIssueCounts"); err != nil {
		return service.SeverityCounts{}, 0, err
	}
	var c service.SeverityCounts
	kev := 0
	for _, id := range f.seen(scan) {
		c.Add(f.st.Issues[id].Severity, 1)
		if f.intel(f.st.Issues[id].CVE).KEVAdded != nil {
			kev++
		}
	}
	return c, kev, nil
}

func (f *Fake) ScanIssues(_ context.Context, scan uuid.UUID, severities []string, kev bool, now time.Time, limit int) ([]service.IssueSummary, error) {
	if err := f.fail("ScanIssues"); err != nil {
		return nil, err
	}
	var out []service.IssueSummary
	for _, id := range f.seen(scan) {
		i := f.st.Issues[id]
		if slices.Contains(severities, i.Severity) || kev && f.intel(i.CVE).KEVAdded != nil {
			out = append(out, f.summary(id, now))
		}
	}
	rank := func(s string) int { return slices.Index([]string{"critical", "high", "medium", "low", "info"}, s) }
	slices.SortFunc(out, func(a, b service.IssueSummary) int {
		return cmp.Or(cmp.Compare(rank(a.Severity), rank(b.Severity)), cmp.Compare(a.Key, b.Key))
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
