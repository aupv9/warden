package service

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/rbac"
	"github.com/aupv9/warden/backend/internal/worker"
)

// Repository sentinels. Implementations return them (possibly wrapped) so the
// service never has to inspect driver errors.
var (
	ErrNotFound = errors.New("not found")
	// ErrConflict: a unique constraint was violated.
	ErrConflict = errors.New("conflict")
)

// DB opens transactions. InOrg runs fn in one transaction with app.org_id set to
// orgID for row-level security; uuid.Nil leaves it unset (every RLS table reads
// as empty), which is what user-level lookups use.
type DB interface {
	InOrg(ctx context.Context, orgID uuid.UUID, fn func(Repo) error) error
}

// Visibility says which projects a caller can see: all of the org's projects
// (org_admin, security_lead) or only those they are a member of.
type Visibility struct {
	OrgID  uuid.UUID
	UserID uuid.UUID
	All    bool
}

type NewProject struct {
	ID           uuid.UUID
	OrgID        uuid.UUID
	Key          string
	Name         string
	Description  *string
	DefaultTools []string
}

type NewScan struct {
	ID        uuid.UUID
	OrgID     uuid.UUID
	ProjectID uuid.UUID
	CreatedBy uuid.UUID
	FileName  string
	FileSize  int64
	SHA256    string
	ObjectKey string
	Tools     []string
	// ViaToken is the API token that created the scan, if any.
	ViaToken *uuid.UUID
}

// ScanCursor positions a newest-first scan list.
type ScanCursor struct {
	CreatedAt time.Time `json:"t"`
	ID        uuid.UUID `json:"id"`
}

// Issue list sorts.
const (
	SortDueAt     = "due_at"
	SortSeverity  = "-severity"
	SortUpdatedAt = "-updated_at"
)

// IssueCursor positions an issue list for one sort.
type IssueCursor struct {
	Sort      string     `json:"s"`
	DueAt     *time.Time `json:"d,omitempty"`
	Severity  string     `json:"v,omitempty"`
	UpdatedAt time.Time  `json:"u,omitzero"`
	ID        uuid.UUID  `json:"id"`
}

// IssueQuery is a validated issue filter.
type IssueQuery struct {
	Vis        Visibility
	ProjectID  *uuid.UUID
	Statuses   []string
	Severities []string
	// Assignee: AssigneeNone, or AssigneeID set.
	AssigneeNone bool
	AssigneeID   *uuid.UUID
	Tool         string
	PastSLA      bool
	// Text search (title, rule_id, file_path), or an issue key.
	Text       string
	KeyProject string
	KeyNumber  int
	Sort       string
	After      *IssueCursor
	Limit      int
	Now        time.Time
}

type NewEvent struct {
	OrgID   uuid.UUID
	IssueID uuid.UUID
	ActorID *uuid.UUID
	Type    string
	From    *string
	To      *string
	Note    *string
}

type NewComment struct {
	ID       uuid.UUID
	OrgID    uuid.UUID
	IssueID  uuid.UUID
	AuthorID uuid.UUID
	Body     string
}

type NewException struct {
	ID          uuid.UUID
	OrgID       uuid.UUID
	IssueID     uuid.UUID
	Type        string
	Reason      string
	RequestedBy uuid.UUID
	ExpiresAt   *time.Time
	CreatedAt   time.Time
}

// ExceptionMeta is what the decision logic needs beyond the rendered request.
type ExceptionMeta struct {
	ExceptionRequest
	OrgID         uuid.UUID
	IssueID       uuid.UUID
	RequestedByID uuid.UUID
}

type ExceptionCursor struct {
	CreatedAt time.Time `json:"t"`
	ID        uuid.UUID `json:"id"`
}

type ExceptionQuery struct {
	// Status: "", pending, approved, rejected or expiring.
	Status      string
	RequestedBy *uuid.UUID
	Now         time.Time
	After       *ExceptionCursor
	Limit       int
}

type Decision struct {
	ID        uuid.UUID
	Status    string
	DecidedBy uuid.UUID
	Note      *string
	ExpiresAt *time.Time
}

// AuditRecord is one audit_log entry to append.
type AuditRecord struct {
	OrgID      uuid.UUID
	ActorID    *uuid.UUID
	Action     string
	TargetType string
	TargetID   string
	IP         string
	UserAgent  string
	Data       map[string]any
}

type AuditQuery struct {
	OrgID  uuid.UUID
	Action string
	// ActorSystem selects entries without an actor (system and operator actions).
	ActorSystem bool
	ActorID     *uuid.UUID
	From, To    *time.Time
	AfterID     int64
	Limit       int
}

// Repo is the data access the service needs, bound to one transaction.
type Repo interface {
	// Users and memberships (tables without RLS).
	UserBySub(ctx context.Context, sub string) (User, error)
	UserByEmail(ctx context.Context, email string) (User, error)
	InsertUser(ctx context.Context, u User) error
	UpdateUser(ctx context.Context, u User) error
	UserOrgs(ctx context.Context, userID uuid.UUID) ([]OrgRef, error)
	MemberRole(ctx context.Context, orgID, userID uuid.UUID) (rbac.Role, error)
	UserRef(ctx context.Context, userID uuid.UUID) (UserRef, error)

	Org(ctx context.Context, orgID uuid.UUID) (Org, error)
	Summary(ctx context.Context, v Visibility, now time.Time) (Summary, error)
	CountPendingExceptions(ctx context.Context) (int, error)

	OrgMembers(ctx context.Context, orgID uuid.UUID) ([]OrgMember, error)
	OrgMember(ctx context.Context, orgID, userID uuid.UUID) (OrgMember, error)
	InsertOrgMember(ctx context.Context, orgID, userID uuid.UUID, role rbac.Role) error
	// LockOrgAdmins locks the org's admin memberships and returns their user ids.
	LockOrgAdmins(ctx context.Context, orgID uuid.UUID) ([]uuid.UUID, error)
	SetOrgMemberRole(ctx context.Context, orgID, userID uuid.UUID, role rbac.Role) error
	// DeleteOrgMember also removes the user's project memberships in the org.
	DeleteOrgMember(ctx context.Context, orgID, userID uuid.UUID) error

	Projects(ctx context.Context, v Visibility, now time.Time) ([]Project, error)
	Project(ctx context.Context, v Visibility, projectID uuid.UUID, now time.Time) (Project, error)
	// ProjectRole returns the user's role in the project, "" if not a member, and
	// ErrNotFound if the project doesn't exist (or is archived).
	ProjectRole(ctx context.Context, projectID, userID uuid.UUID) (rbac.Role, error)
	InsertProject(ctx context.Context, p NewProject) error
	ProjectMembers(ctx context.Context, projectID uuid.UUID) ([]ProjectMember, error)
	UpsertProjectMember(ctx context.Context, orgID, projectID, userID uuid.UUID, role rbac.Role) error
	DeleteProjectMember(ctx context.Context, projectID, userID uuid.UUID) (bool, error)
	// OwnsAnyProject reports whether the user is an owner of any project in the org.
	OwnsAnyProject(ctx context.Context, userID uuid.UUID) (bool, error)

	// LockScanRate serializes scan creation per user so the rate limit holds.
	LockScanRate(ctx context.Context, userID uuid.UUID) error
	// ScansSince counts the user's scans created after since and returns the
	// oldest one's creation time (zero if none).
	ScansSince(ctx context.Context, userID uuid.UUID, since time.Time) (int, time.Time, error)
	InsertScan(ctx context.Context, s NewScan) error
	Scan(ctx context.Context, scanID uuid.UUID, forUpdate bool) (Scan, error)
	Scans(ctx context.Context, projectID uuid.UUID, after *ScanCursor, limit int) ([]Scan, error)
	ToolRuns(ctx context.Context, scanID uuid.UUID) ([]ToolRun, error)
	MarkScanQueued(ctx context.Context, scanID uuid.UUID) error
	MarkScanCancelled(ctx context.Context, scanID uuid.UUID) error
	// EnqueueScan inserts the River job in the current transaction.
	EnqueueScan(ctx context.Context, args worker.ScanArgs) error

	Issues(ctx context.Context, q IssueQuery) ([]IssueSummary, error)
	IssueCounts(ctx context.Context, q IssueQuery) (SeverityCounts, error)
	Issue(ctx context.Context, issueID uuid.UUID, forUpdate bool, now time.Time) (Issue, error)
	// UpdateIssueState sets status and assignee and bumps the version.
	UpdateIssueState(ctx context.Context, issueID uuid.UUID, status string, assignee *uuid.UUID) error
	InsertIssueEvent(ctx context.Context, e NewEvent) error
	IssueEvents(ctx context.Context, issueID uuid.UUID, limit int) ([]Event, error)
	Comments(ctx context.Context, issueID uuid.UUID) ([]Comment, error)
	InsertComment(ctx context.Context, c NewComment) error
	Comment(ctx context.Context, id uuid.UUID) (Comment, error)
	PendingExceptionID(ctx context.Context, issueID uuid.UUID) (*uuid.UUID, error)

	InsertException(ctx context.Context, e NewException) error
	Exception(ctx context.Context, id uuid.UUID, forUpdate bool) (ExceptionMeta, error)
	Exceptions(ctx context.Context, q ExceptionQuery) ([]ExceptionRequest, error)
	DecideException(ctx context.Context, d Decision) error

	AppendAudit(ctx context.Context, r AuditRecord) error
	AuditEntries(ctx context.Context, q AuditQuery) ([]AuditEntry, error)

	TokenRepo
	GateRepo
}

// ObjectStore is the slice of object storage the API needs: a presigned PUT for
// the browser and a HEAD to check the upload before a scan starts.
type ObjectStore interface {
	// PresignPut returns a URL valid for ttl that accepts exactly size bytes
	// (and, if the store supports it, only content with that SHA-256), plus the
	// headers the client must send.
	PresignPut(ctx context.Context, key string, size int64, sha256Hex string, ttl time.Duration) (url string, headers map[string]string, err error)
	// Head returns the stored object's size, or ErrObjectNotFound.
	Head(ctx context.Context, key string) (size int64, err error)
}

// ErrObjectNotFound is returned by ObjectStore.Head for a missing object.
var ErrObjectNotFound = errors.New("object not found")
