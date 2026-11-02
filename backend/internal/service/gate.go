package service

import (
	"context"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/rbac"
	"github.com/aupv9/warden/backend/internal/domain/severity"
)

// maxBlocking caps the blocking issues a gate lists (the counts are complete).
const maxBlocking = 100

// gateFailOn are the accepted fail_on levels; failing on info would make every
// finding blocking, which no CI pipeline wants.
var gateFailOn = []severity.Severity{severity.Critical, severity.High, severity.Medium, severity.Low}

// GateRepo is the scan-gate part of Repo. Both methods count only active issues
// (open, assigned, in_progress, reopened) that have an occurrence in the scan.
type GateRepo interface {
	// ScanIssueCounts counts those issues per severity, and those with a CVE
	// in KEV.
	ScanIssueCounts(ctx context.Context, scanID uuid.UUID) (SeverityCounts, int, error)
	// ScanIssues lists those issues with one of severities (or, with kev, a
	// CVE in KEV), most severe first.
	ScanIssues(ctx context.Context, scanID uuid.UUID, severities []string, kev bool, now time.Time, limit int) ([]IssueSummary, error)
	// ScanNewIssues returns those of issueIDs that the scan created
	// (first seen in it) or reopened, with the same truth as the scan's
	// stats: the issue's first_seen_scan_id and the events the scan wrote.
	ScanNewIssues(ctx context.Context, scanID uuid.UUID, issueIDs []uuid.UUID) ([]uuid.UUID, error)
}

// Gate is a CI verdict on one scan.
type Gate struct {
	ScanID    uuid.UUID      `json:"scan_id"`
	Status    string         `json:"status"`
	Finished  bool           `json:"finished"`
	FailOn    string         `json:"fail_on"`
	FailOnKEV bool           `json:"fail_on_kev"`
	Pass      bool           `json:"pass"`
	Counts    SeverityCounts `json:"counts"`
	KEV       int            `json:"kev"`
	Blocking  []IssueSummary `json:"blocking"`
	// BlockingNew: the ids from Blocking (in its order) that this scan
	// created or reopened; the rest were already open. `warden scan
	// --comment` marks them New on the pull request.
	BlockingNew []uuid.UUID `json:"blocking_new"`
}

func finishedStatus(s string) bool {
	return s == "completed" || s == "partial" || s == "failed" || s == "cancelled"
}

func (c SeverityCounts) of(s severity.Severity) int {
	switch s {
	case severity.Critical:
		return c.Critical
	case severity.High:
		return c.High
	case severity.Medium:
		return c.Medium
	case severity.Low:
		return c.Low
	case severity.Info:
		return c.Info
	}
	return 0
}

// Gate reports whether a scan passes: it must have finished (completed or
// partial; failed and cancelled scans never pass) with no active issue at or
// above failOn (default high) and, with failOnKEV ("true"), none with a CVE in
// KEV whatever its severity. false_positive and risk_accepted issues never
// block. Readable with view_results; for API tokens, scan:write.
func (s *Service) Gate(ctx context.Context, a *Actor, scanID uuid.UUID, failOn, failOnKEV string) (Gate, error) {
	if failOn == "" {
		failOn = string(severity.High)
	}
	level := severity.Severity(failOn)
	fe := fieldErrors{}
	if !slices.Contains(gateFailOn, level) {
		fe.add("fail_on", "must be critical, high, medium or low")
	}
	kev := false
	switch failOnKEV {
	case "", "false":
	case "true":
		kev = true
	default:
		fe.add("fail_on_kev", "must be true or false")
	}
	var out Gate
	err := s.inOrg(ctx, a, func(r Repo) error {
		sc, role, err := scanAccess(ctx, r, a, scanID, false)
		if err != nil {
			return err
		}
		if !rbac.Can(rbac.ViewResults, a.OrgRole, role, false) {
			return errForbidden()
		}
		if err := fe.err(); err != nil {
			return err
		}
		counts, kevCount, err := r.ScanIssueCounts(ctx, scanID)
		if err != nil {
			return err
		}
		var blockingLevels []string
		n := 0
		for _, sv := range severity.All[:severity.Rank(level)+1] {
			blockingLevels = append(blockingLevels, string(sv))
			n += counts.of(sv)
		}
		blocked := n > 0 || (kev && kevCount > 0)
		blocking, err := r.ScanIssues(ctx, scanID, blockingLevels, kev, s.now(), maxBlocking)
		if err != nil {
			return err
		}
		if blocking == nil {
			blocking = []IssueSummary{}
		}
		newIDs, err := blockingNew(ctx, r, scanID, blocking)
		if err != nil {
			return err
		}
		finished := finishedStatus(sc.Status)
		out = Gate{
			ScanID: scanID, Status: sc.Status, Finished: finished, FailOn: failOn, FailOnKEV: kev,
			Pass:   finished && (sc.Status == "completed" || sc.Status == "partial") && !blocked,
			Counts: counts, KEV: kevCount, Blocking: blocking, BlockingNew: newIDs,
		}
		return nil
	})
	return out, err
}

// blockingNew keeps blocking's order and lists each id once, whatever the
// repository returns, so the response always holds `blocking_new ⊆ blocking`.
func blockingNew(ctx context.Context, r Repo, scanID uuid.UUID, blocking []IssueSummary) ([]uuid.UUID, error) {
	out := []uuid.UUID{}
	if len(blocking) == 0 {
		return out, nil
	}
	ids := make([]uuid.UUID, len(blocking))
	for i, b := range blocking {
		ids[i] = b.ID
	}
	found, err := r.ScanNewIssues(ctx, scanID, ids)
	if err != nil {
		return nil, err
	}
	isNew := make(map[uuid.UUID]bool, len(found))
	for _, id := range found {
		isNew[id] = true
	}
	for _, id := range ids {
		if isNew[id] {
			out = append(out, id)
			delete(isNew, id)
		}
	}
	return out, nil
}
