package service

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/rbac"
	"github.com/aupv9/warden/backend/internal/ids"
)

// Imports (v0.8): another tool's SARIF file or GitLab SAST report, uploaded
// like a source archive and processed by the worker as hostile input. The API
// side only records what the scan is: the file goes to object storage and the
// worker never trusts these fields beyond what the database's checks (00016)
// also hold.

// KindImport is the kind of import scans.
const KindImport = "import"

// ToolExternal is the tool of every imported issue and the only tool of an
// import scan. It is never accepted where a scan's tools are chosen
// (validTools), so no Warden scan runs it and no import sets or fixes an issue
// of a Warden scanner.
const ToolExternal = "external"

// Import formats.
const (
	ImportSARIF      = "sarif"
	ImportGitLabSAST = "gitlab-sast"
)

// ImportToolPattern and ImportCategoryPattern are the OpenAPI patterns and the
// migration's CHECKs (00016): the target is built from them, so neither may
// hold a space, quote or anything an image repository could.
var (
	ImportToolPattern     = regexp.MustCompile(`^(codeql|gitlab-sast|semgrep|snyk-code|sonarqube|external\.[a-z0-9-]{1,32})$`)
	ImportCategoryPattern = regexp.MustCompile(`^[A-Za-z0-9/:._=+-]{0,100}$`)
	importFileName        = regexp.MustCompile(`^[^/\\]+\.([sS][aA][rR][iI][fF]|[jJ][sS][oO][nN])$`)
)

// ImportTargetPrefix starts every import target. Image targets never contain
// "(" and the history target is "(history)", so no other kind's issues can be
// auto-fixed by an import, nor the reverse.
const ImportTargetPrefix = "(import) "

// ImportTarget is an import scan's target, as the database checks it
// (scan_import_target): auto-fix is per target, so an import fixes only
// issues of its own tool and category.
func ImportTarget(tool, category string) string {
	if category == "" {
		return ImportTargetPrefix + tool
	}
	return ImportTargetPrefix + tool + " " + category
}

// ImportObjectKey is where an import scan's report lives in object storage.
func ImportObjectKey(orgID, scanID uuid.UUID) string {
	return fmt.Sprintf("scans/%s/%s.import.json", orgID, scanID)
}

// ImportScanInput is POST …/scans/import.
type ImportScanInput struct {
	Tool     string  `json:"tool"`
	Format   *string `json:"format"`
	Category *string `json:"category"`
	FileName string  `json:"file_name"`
	FileSize int64   `json:"file_size"`
	SHA256   string  `json:"sha256"`
}

const maxFileName = 255

func (s *Service) validateImportInput(in ImportScanInput) (tool, format, category string, fe fieldErrors) {
	fe = fieldErrors{}
	tool, format = in.Tool, ImportSARIF
	if !ImportToolPattern.MatchString(tool) {
		fe.add("tool", "must be codeql, gitlab-sast, semgrep, snyk-code, sonarqube or external.<key> (a-z, 0-9, -; at most 32)")
	}
	if in.Format != nil {
		format = *in.Format
		if format != ImportSARIF && format != ImportGitLabSAST {
			fe.add("format", "must be sarif or gitlab-sast")
		}
	}
	if in.Category != nil {
		category = *in.Category
		if !ImportCategoryPattern.MatchString(category) {
			fe.add("category", "must be at most 100 characters: letters, digits and / : . _ = + -")
		}
	}
	n := in.FileName
	if !importFileName.MatchString(n) || utf8.RuneCountInString(n) > maxFileName || !validText(n) || strings.ContainsFunc(n, isControl) {
		fe.add("file_name", "must be a .sarif or .json file name of at most 255 characters, without / or \\")
	}
	if in.FileSize < 1 || in.FileSize > s.cfg.ImportMaxBytes {
		fe.add("file_size", fmt.Sprintf("must be between 1 and %d bytes", s.cfg.ImportMaxBytes))
	}
	if !sha256Hex.MatchString(in.SHA256) {
		fe.add("sha256", "must be 64 hexadecimal characters")
	}
	return tool, format, category, fe
}

// CreateImportScan records an import scan in pending_upload and returns a
// presigned PUT URL for the report; POST …/scans/{id}/start queues it, as for
// an upload. It takes the permission, project checks and hourly limit of
// CreateScan. Its tools are always ['external'] and its target
// ImportTarget(tool, category).
func (s *Service) CreateImportScan(ctx context.Context, a *Actor, projectID uuid.UUID, in ImportScanInput) (CreatedScan, error) {
	tool, format, category, fe := s.validateImportInput(in)
	var out CreatedScan
	err := s.inOrg(ctx, a, func(r Repo) error {
		role, err := projectAccess(ctx, r, a, projectID)
		if err != nil {
			return err
		}
		if !rbac.Can(rbac.RunScan, a.OrgRole, role, false) {
			return errForbidden()
		}
		if err := fe.err(); err != nil {
			return err
		}
		if err := requireNotArchived(ctx, r, projectID); err != nil {
			return err
		}
		if err := s.checkScanRate(ctx, r, a); err != nil {
			return err
		}
		id, target, sum := ids.New(), ImportTarget(tool, category), strings.ToLower(in.SHA256)
		ns := NewScan{
			ID: id, OrgID: a.OrgID, ProjectID: projectID, CreatedBy: a.UserID,
			FileName: in.FileName, FileSize: in.FileSize, SHA256: sum, ObjectKey: ImportObjectKey(a.OrgID, id),
			Tools: []string{ToolExternal}, Kind: KindImport, Target: target,
			Import: &NewScanImport{Tool: tool, Category: category, Format: format},
		}
		if a.Token != nil {
			ns.ViaToken = &a.Token.ID
		}
		if err := r.InsertScan(ctx, ns); err != nil {
			return err
		}
		scan, err := r.Scan(ctx, id, false)
		if err != nil {
			return err
		}
		if err := s.audit(ctx, r, a, "scan.created", "scan", id.String(), map[string]any{
			"project_id": projectID.String(), "file_name": in.FileName, "file_size": in.FileSize, "sha256": sum,
			"kind": KindImport, "target": target, "import_tool": tool, "import_category": category, "import_format": format,
		}); err != nil {
			return err
		}
		up, err := s.presignUpload(ctx, ns.ObjectKey, in.FileSize, sum)
		if err != nil {
			return err
		}
		out = CreatedScan{Scan: scan, Upload: up}
		return nil
	})
	return out, err
}
