package service

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/aupv9/warden/backend/internal/domain/rbac"
)

// The types below are both what the repository returns and what the API
// renders (JSON field names follow the API contract). Fields tagged `json:"-"`
// are internal.

// Time renders as an RFC 3339 string in UTC whatever the location the database
// driver decoded it in.
type Time time.Time

func (t Time) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Time(t).UTC().Format(time.RFC3339Nano))
}

// ScanTimestamptz lets pgx scan timestamptz columns straight into Time.
func (t *Time) ScanTimestamptz(v pgtype.Timestamptz) error {
	*t = Time(v.Time.UTC())
	return nil
}

func (t Time) T() time.Time { return time.Time(t) }

// User is an app_user row.
type User struct {
	ID          uuid.UUID
	Sub         string
	Email       string
	DisplayName string
	IsActive    bool
	MFA         *bool
	// RelinkUntil: until then, the next sign-in with this verified email and
	// an unknown subject takes over the account (warden-admin user relink).
	RelinkUntil *time.Time
}

type UserRef struct {
	ID          uuid.UUID `json:"id"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
}

type Me struct {
	ID     uuid.UUID `json:"id"`
	Sub    string    `json:"sub"`
	Email  string    `json:"email"`
	Name   *string   `json:"name"`
	MFA    bool      `json:"mfa"`
	Orgs   []OrgRef  `json:"orgs"`
	Limits Limits    `json:"limits"`
	// MFARequiredOrgs are the orgs this sign-in can't use because the caller's
	// role there requires a second factor and the token has none.
	MFARequiredOrgs []uuid.UUID `json:"mfa_required_orgs"`
}

// Limits are server settings the UI shows (and checks before uploading).
type Limits struct {
	UploadMaxMB        int `json:"upload_max_mb"`
	UnzipMaxMB         int `json:"unzip_max_mb"`
	UnzipMaxFiles      int `json:"unzip_max_files"`
	ScanTimeoutMinutes int `json:"scan_timeout_minutes"`
	ScansPerHour       int `json:"scans_per_hour"`
}

type OrgRef struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
	Role rbac.Role `json:"role"`
	// MFARoles: the org's added two-factor roles (SignInPolicy), for /me.
	MFARoles []rbac.Role `json:"-"`
}

type SLADays struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

type Org struct {
	ID      uuid.UUID `json:"id"`
	Name    string    `json:"name"`
	SLADays SLADays   `json:"sla_days"`
	MyRole  rbac.Role `json:"my_role"`
}

type Summary struct {
	OpenIssues        int `json:"open_issues"`
	CriticalHighOpen  int `json:"critical_high_open"`
	PastSLA           int `json:"past_sla"`
	ExceptionsPending int `json:"exceptions_pending"`
}

type MemberUser struct {
	UserRef
	IsActive bool `json:"is_active"`
}

type MemberProject struct {
	ID   uuid.UUID `json:"id"`
	Key  string    `json:"key"`
	Role rbac.Role `json:"role"`
}

type OrgMember struct {
	User     MemberUser      `json:"user"`
	Role     rbac.Role       `json:"role"`
	MFA      *bool           `json:"mfa"`
	Projects []MemberProject `json:"projects"`
}

type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// Add increments the counter for severity s.
func (c *SeverityCounts) Add(s string, n int) {
	switch s {
	case "critical":
		c.Critical += n
	case "high":
		c.High += n
	case "medium":
		c.Medium += n
	case "low":
		c.Low += n
	case "info":
		c.Info += n
	}
}

type LastScan struct {
	ID         uuid.UUID `json:"id"`
	Status     string    `json:"status"`
	CreatedAt  Time      `json:"created_at"`
	FinishedAt *Time     `json:"finished_at"`
}

type Project struct {
	ID             uuid.UUID      `json:"id"`
	Key            string         `json:"key"`
	Name           string         `json:"name"`
	Description    *string        `json:"description"`
	DefaultTools   []string       `json:"default_tools"`
	MyRole         *rbac.Role     `json:"my_role"`
	OpenBySeverity SeverityCounts `json:"open_by_severity"`
	PastSLA        int            `json:"past_sla"`
	LastScan       *LastScan      `json:"last_scan"`
	ArchivedAt     *Time          `json:"archived_at"`
	CreatedAt      Time           `json:"created_at"`
}

type ProjectMember struct {
	User UserRef   `json:"user"`
	Role rbac.Role `json:"role"`
}

type ScanStats struct {
	New      int `json:"new"`
	Fixed    int `json:"fixed"`
	Reopened int `json:"reopened"`
	Total    int `json:"total"`
}

type ToolRun struct {
	Tool          string  `json:"tool"`
	ToolVersion   string  `json:"tool_version"`
	Status        string  `json:"status"`
	FindingsCount *int    `json:"findings_count"`
	DurationMS    *int    `json:"duration_ms"`
	Error         *string `json:"error"`
}

type Scan struct {
	ID         uuid.UUID  `json:"id"`
	ProjectID  uuid.UUID  `json:"project_id"`
	Status     string     `json:"status"`
	FileName   string     `json:"file_name"`
	FileSize   int64      `json:"file_size"`
	Tools      []string   `json:"tools"`
	ErrorCode  *string    `json:"error_code"`
	Stats      ScanStats  `json:"stats"`
	CreatedBy  UserRef    `json:"created_by"`
	CreatedAt  Time       `json:"created_at"`
	QueuedAt   *Time      `json:"queued_at"`
	StartedAt  *Time      `json:"started_at"`
	FinishedAt *Time      `json:"finished_at"`
	ViaToken   *TokenRef  `json:"via_token"`
	ToolRuns   *[]ToolRun `json:"tool_runs,omitempty"`

	OrgID     uuid.UUID `json:"-"`
	ObjectKey string    `json:"-"`
	SHA256    string    `json:"-"`
}

type Upload struct {
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Headers   map[string]string `json:"headers"`
	ExpiresAt Time              `json:"expires_at"`
}

type CreatedScan struct {
	Scan   Scan   `json:"scan"`
	Upload Upload `json:"upload"`
}

type IssueSummary struct {
	ID             uuid.UUID `json:"id"`
	Key            string    `json:"key"`
	ProjectID      uuid.UUID `json:"project_id"`
	Title          string    `json:"title"`
	Severity       string    `json:"severity"`
	Status         string    `json:"status"`
	Tool           string    `json:"tool"`
	RuleID         string    `json:"rule_id"`
	FilePath       *string   `json:"file_path"`
	StartLine      *int      `json:"start_line"`
	PackageName    *string   `json:"package_name"`
	PackageVersion *string   `json:"package_version"`
	FixedVersion   *string   `json:"fixed_version"`
	Assignee       *UserRef  `json:"assignee"`
	DueAt          *Time     `json:"due_at"`
	PastSLA        bool      `json:"past_sla"`
	UpdatedAt      Time      `json:"updated_at"`
}

type ScanRef struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt Time      `json:"created_at"`
}

type Issue struct {
	IssueSummary
	Description         *string    `json:"description"`
	Remediation         *string    `json:"remediation"`
	Snippet             *string    `json:"snippet"`
	EndLine             *int       `json:"end_line"`
	CWE                 []string   `json:"cwe"`
	CVE                 []string   `json:"cve"`
	FirstSeenScan       ScanRef    `json:"first_seen_scan"`
	LastSeenScan        ScanRef    `json:"last_seen_scan"`
	Occurrences         int        `json:"occurrences"`
	Version             int        `json:"version"`
	AllowedTransitions  []string   `json:"allowed_transitions"`
	CanAssign           bool       `json:"can_assign"`
	CanRequestException bool       `json:"can_request_exception"`
	PendingExceptionID  *uuid.UUID `json:"pending_exception_id"`
	AssigneeID          *uuid.UUID `json:"-"`
	ProjectKey          string     `json:"-"`
	Number              int        `json:"-"`
}

type Event struct {
	ID        int64    `json:"id,string"`
	Type      string   `json:"type"`
	Actor     *UserRef `json:"actor"`
	FromValue *string  `json:"from_value"`
	ToValue   *string  `json:"to_value"`
	Note      *string  `json:"note"`
	CreatedAt Time     `json:"created_at"`
}

type Comment struct {
	ID        uuid.UUID `json:"id"`
	Author    UserRef   `json:"author"`
	Body      string    `json:"body"`
	CreatedAt Time      `json:"created_at"`
	EditedAt  *Time     `json:"edited_at"`
}

type ExceptionIssue struct {
	ID       uuid.UUID `json:"id"`
	Key      string    `json:"key"`
	Title    string    `json:"title"`
	Severity string    `json:"severity"`
	Status   string    `json:"status"`
}

type ExceptionRequest struct {
	ID           uuid.UUID      `json:"id"`
	Issue        ExceptionIssue `json:"issue"`
	Type         string         `json:"type"`
	Reason       string         `json:"reason"`
	Status       string         `json:"status"`
	RequestedBy  UserRef        `json:"requested_by"`
	DecidedBy    *UserRef       `json:"decided_by"`
	DecisionNote *string        `json:"decision_note"`
	ExpiresAt    *Time          `json:"expires_at"`
	DecidedAt    *Time          `json:"decided_at"`
	CreatedAt    Time           `json:"created_at"`
}

type AuditEntry struct {
	ID         int64           `json:"id,string"`
	Actor      *UserRef        `json:"actor"`
	Action     string          `json:"action"`
	TargetType *string         `json:"target_type"`
	TargetID   *string         `json:"target_id"`
	IP         *string         `json:"ip"`
	Data       json.RawMessage `json:"data"`
	CreatedAt  Time            `json:"created_at"`
}

// Page is a cursor-paginated list.
type Page[T any] struct {
	Items      []T     `json:"items"`
	NextCursor *string `json:"next_cursor"`
}

// Items is an unpaginated list.
type Items[T any] struct {
	Items []T `json:"items"`
}

type IssuePage struct {
	Items            []IssueSummary `json:"items"`
	NextCursor       *string        `json:"next_cursor"`
	CountsBySeverity SeverityCounts `json:"counts_by_severity"`
}
