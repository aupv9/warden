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
	ScanIssueCounts(ctx context.Context, scanID uuid.UUID) (SeverityCounts, error)
	// ScanIssues lists those issues with one of severities, most severe first.
	ScanIssues(ctx context.Context, scanID uuid.UUID, severities []string, now time.Time, limit int) ([]IssueSummary, error)
}

// Gate is a CI verdict on one scan.
type Gate struct {
	ScanID   uuid.UUID      `json:"scan_id"`
	Status   string         `json:"status"`
	Finished bool           `json:"finished"`
	FailOn   string         `json:"fail_on"`
	Pass     bool           `json:"pass"`
	Counts   SeverityCounts `json:"counts"`
	Blocking []IssueSummary `json:"blocking"`
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
// above failOn (default high). false_positive and risk_accepted issues never
// block. Readable with view_results; for API tokens, scan:write.
func (s *Service) Gate(ctx context.Context, a *Actor, scanID uuid.UUID, failOn string) (Gate, error) {
	if failOn == "" {
		failOn = string(severity.High)
	}
	level := severity.Severity(failOn)
	valid := slices.Contains(gateFailOn, level)
	var out Gate
	err := s.inOrg(ctx, a, func(r Repo) error {
		sc, role, err := scanAccess(ctx, r, a, scanID, false)
		if err != nil {
			return err
		}
		if !rbac.Can(rbac.ViewResults, a.OrgRole, role, false) {
			return errForbidden()
		}
		if !valid {
			return errField("fail_on", "must be critical, high, medium or low")
		}
		counts, err := r.ScanIssueCounts(ctx, scanID)
		if err != nil {
			return err
		}
		var blockingLevels []string
		n := 0
		for _, sv := range severity.All[:severity.Rank(level)+1] {
			blockingLevels = append(blockingLevels, string(sv))
			n += counts.of(sv)
		}
		blocking, err := r.ScanIssues(ctx, scanID, blockingLevels, s.now(), maxBlocking)
		if err != nil {
			return err
		}
		if blocking == nil {
			blocking = []IssueSummary{}
		}
		finished := finishedStatus(sc.Status)
		out = Gate{
			ScanID: scanID, Status: sc.Status, Finished: finished, FailOn: failOn,
			Pass:   finished && (sc.Status == "completed" || sc.Status == "partial") && n == 0,
			Counts: counts, Blocking: blocking,
		}
		return nil
	})
	return out, err
}
