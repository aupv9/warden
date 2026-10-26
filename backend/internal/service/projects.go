package service

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/rbac"
	"github.com/aupv9/warden/backend/internal/ids"
)

var projectKey = regexp.MustCompile(`^[A-Z][A-Z0-9]{1,9}$`)

const (
	maxNameLen        = 200
	maxDescriptionLen = 2000
)

// Projects lists the projects the caller can see; archived ones only with
// include_archived=true.
func (s *Service) Projects(ctx context.Context, a *Actor, includeArchived string) (Items[Project], error) {
	withArchived, err := parseBool("include_archived", includeArchived)
	if err != nil {
		return Items[Project]{}, err
	}
	out := Items[Project]{Items: []Project{}}
	err = s.inOrg(ctx, a, func(r Repo) error {
		p, err := r.Projects(ctx, a.vis(), s.now(), withArchived)
		if err != nil {
			return err
		}
		if p != nil {
			out.Items = p
		}
		return nil
	})
	return out, err
}

func (s *Service) Project(ctx context.Context, a *Actor, projectID uuid.UUID) (Project, error) {
	var out Project
	err := s.inOrg(ctx, a, func(r Repo) error {
		p, err := r.Project(ctx, a.vis(), projectID, s.now())
		if err != nil {
			return notFound(err)
		}
		out = p
		return nil
	})
	return out, err
}

type CreateProjectInput struct {
	Key          string    `json:"key"`
	Name         string    `json:"name"`
	Description  *string   `json:"description"`
	DefaultTools *[]string `json:"default_tools"`
}

func (s *Service) CreateProject(ctx context.Context, a *Actor, in CreateProjectInput) (Project, error) {
	fe := fieldErrors{}
	if !projectKey.MatchString(in.Key) {
		fe.add("key", "must be 2-10 characters: an upper-case letter, then upper-case letters or digits")
	}
	name := strings.TrimSpace(in.Name)
	if name == "" || utf8.RuneCountInString(name) > maxNameLen || !validText(name) {
		fe.add("name", "must be 1-200 characters")
	}
	var desc *string
	if in.Description != nil {
		d := strings.TrimSpace(*in.Description)
		if utf8.RuneCountInString(d) > maxDescriptionLen || !validText(d) {
			fe.add("description", "must be at most 2000 characters")
		}
		if d != "" {
			desc = &d
		}
	}
	tools := allTools
	if in.DefaultTools != nil {
		tools = *in.DefaultTools
		if !validTools(tools) {
			fe.add("default_tools", "must be a non-empty list of distinct tools: gitleaks, opengrep, trivy, checkov")
		}
	}
	var out Project
	err := s.inOrg(ctx, a, func(r Repo) error {
		if !rbac.Can(rbac.CreateArchiveProject, a.OrgRole, "", false) {
			return errForbidden()
		}
		if err := fe.err(); err != nil {
			return err
		}
		id := ids.New()
		err := r.InsertProject(ctx, NewProject{ID: id, OrgID: a.OrgID, Key: in.Key, Name: name, Description: desc, DefaultTools: tools})
		if errors.Is(err, ErrConflict) {
			return errConflict("a project with this key already exists")
		}
		if err != nil {
			return err
		}
		if out, err = r.Project(ctx, a.vis(), id, s.now()); err != nil {
			return err
		}
		return s.audit(ctx, r, a, "project.created", "project", id.String(), map[string]any{"key": in.Key, "name": name})
	})
	return out, err
}

func (s *Service) ProjectMembers(ctx context.Context, a *Actor, projectID uuid.UUID) (Items[ProjectMember], error) {
	out := Items[ProjectMember]{Items: []ProjectMember{}}
	err := s.inOrg(ctx, a, func(r Repo) error {
		// Anyone who can see the project can see who works on it (the org
		// member list already shows every member's projects).
		if _, err := projectAccess(ctx, r, a, projectID); err != nil {
			return err
		}
		m, err := r.ProjectMembers(ctx, projectID)
		if err != nil {
			return err
		}
		if m != nil {
			out.Items = m
		}
		return nil
	})
	return out, err
}

type SetProjectMemberInput struct {
	Role string `json:"role"`
}

func (s *Service) SetProjectMember(ctx context.Context, a *Actor, projectID, userID uuid.UUID, in SetProjectMemberInput) (ProjectMember, error) {
	var out ProjectMember
	err := s.inOrg(ctx, a, func(r Repo) error {
		role, err := projectAccess(ctx, r, a, projectID)
		if err != nil {
			return err
		}
		if !rbac.Can(rbac.ManageProjectMembers, a.OrgRole, role, false) {
			return errForbidden()
		}
		if !validProjectRole(in.Role) {
			return errField("role", "must be one of owner, developer, viewer")
		}
		if _, err := r.MemberRole(ctx, a.OrgID, userID); errors.Is(err, ErrNotFound) {
			return errField("user_id", "the user is not a member of this organization")
		} else if err != nil {
			return err
		}
		if err := r.UpsertProjectMember(ctx, a.OrgID, projectID, userID, rbac.Role(in.Role)); err != nil {
			return err
		}
		ref, err := r.UserRef(ctx, userID)
		if err != nil {
			return err
		}
		out = ProjectMember{User: ref, Role: rbac.Role(in.Role)}
		return s.audit(ctx, r, a, "project_member.set", "project", projectID.String(),
			map[string]any{"user_id": userID.String(), "role": in.Role})
	})
	return out, err
}

func (s *Service) RemoveProjectMember(ctx context.Context, a *Actor, projectID, userID uuid.UUID) error {
	return s.inOrg(ctx, a, func(r Repo) error {
		role, err := projectAccess(ctx, r, a, projectID)
		if err != nil {
			return err
		}
		if !rbac.Can(rbac.ManageProjectMembers, a.OrgRole, role, false) {
			return errForbidden()
		}
		ok, err := r.DeleteProjectMember(ctx, projectID, userID)
		if err != nil {
			return err
		}
		if !ok {
			return errNotFound()
		}
		return s.audit(ctx, r, a, "project_member.removed", "project", projectID.String(),
			map[string]any{"user_id": userID.String()})
	})
}
