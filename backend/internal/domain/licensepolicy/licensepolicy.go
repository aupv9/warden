// Package licensepolicy decides which package licenses become issues. A
// security lead maps Trivy's license categories to actions and may deny or
// allow individual SPDX ids. An empty policy is off: no license issues. Pure:
// no I/O.
package licensepolicy

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/aupv9/warden/backend/internal/domain/severity"
)

// Category is Trivy's license classification (from Google's licenseclassifier).
type Category string

const (
	Forbidden    Category = "forbidden"
	Restricted   Category = "restricted"
	Reciprocal   Category = "reciprocal"
	Notice       Category = "notice"
	Permissive   Category = "permissive"
	Unencumbered Category = "unencumbered"
	Unknown      Category = "unknown"
)

// Categories is the canonical order, most to least restrictive, then unknown.
var Categories = []Category{Forbidden, Restricted, Reciprocal, Notice, Permissive, Unencumbered, Unknown}

// ParseCategory maps anything Trivy might print to a Category; what isn't one
// is Unknown.
func ParseCategory(s string) Category {
	if c := Category(s); slices.Contains(Categories, c) {
		return c
	}
	return Unknown
}

type Action string

const (
	Allow  Action = "allow"
	Review Action = "review"
	Block  Action = "block"
)

var Actions = []Action{Allow, Review, Block}

// Severity is the issue severity for an action: block is High, so it fails
// the default gate (fail_on=high); review is Medium. Allow creates no issue.
func (a Action) Severity() severity.Severity {
	switch a {
	case Block:
		return severity.High
	case Review:
		return severity.Medium
	}
	return ""
}

// MaxListed caps Deny and Allow.
const MaxListed = 100

// ID is an SPDX license id, or a LicenseRef- for licenses SPDX doesn't list.
var ID = regexp.MustCompile(`^(LicenseRef-)?[A-Za-z0-9][A-Za-z0-9.+-]{0,63}$`)

// Policy is stored as organization.license_policy ('{}' = off). Precedence:
// Allow, then Deny, then the category's action; a category not listed is
// allowed.
type Policy struct {
	Categories map[Category]Action `json:"categories,omitempty"`
	// Deny: ids always blocked, whatever their category.
	Deny []string `json:"deny,omitempty"`
	// Allow: ids never reported (overrides Deny and the category).
	Allow []string `json:"allow,omitempty"`
}

// Action returns the category's action (allow when unset).
func (p Policy) Action(c Category) Action {
	if a, ok := p.Categories[c]; ok {
		return a
	}
	return Allow
}

// Enabled: some category isn't allowed or some id is denied. Otherwise the
// policy can't produce an issue, and license scanning results are ignored.
func (p Policy) Enabled() bool {
	if len(p.Deny) > 0 {
		return true
	}
	for _, c := range Categories {
		if p.Action(c) != Allow {
			return true
		}
	}
	return false
}

// Recommended is the preset offered in the UI: block forbidden licenses,
// review restricted ones (GPL and the like), allow the rest.
func Recommended() Policy {
	return Normalize(Policy{Categories: map[Category]Action{Forbidden: Block, Restricted: Review}})
}

// Normalize lists every category and makes the lists non-nil, so two policies
// that mean the same compare equal.
func Normalize(p Policy) Policy {
	out := Policy{Categories: make(map[Category]Action, len(Categories)),
		Deny: append([]string{}, p.Deny...), Allow: append([]string{}, p.Allow...)}
	for _, c := range Categories {
		out.Categories[c] = p.Action(c)
	}
	return out
}

// Equal compares normalized policies (list order matters: it is shown as given).
func Equal(a, b Policy) bool {
	a, b = Normalize(a), Normalize(b)
	for _, c := range Categories {
		if a.Categories[c] != b.Categories[c] {
			return false
		}
	}
	return slices.Equal(a.Deny, b.Deny) && slices.Equal(a.Allow, b.Allow)
}

// FieldError is one validation failure; Field follows the API's request
// (categories.forbidden, deny[3], ...).
type FieldError struct {
	Field, Message string
}

// Validate checks a policy as a security lead submits it.
func (p Policy) Validate() []FieldError {
	var errs []FieldError
	for c, a := range p.Categories {
		if !slices.Contains(Categories, c) {
			errs = append(errs, FieldError{"categories", fmt.Sprintf("unknown category %q", c)})
		} else if !slices.Contains(Actions, a) {
			errs = append(errs, FieldError{"categories." + string(c), "must be allow, review or block"})
		}
	}
	errs = append(errs, validateList("deny", p.Deny, nil)...)
	errs = append(errs, validateList("allow", p.Allow, p.Deny)...)
	// Category errors come from a map: sort for a stable response.
	slices.SortStableFunc(errs, func(a, b FieldError) int { return strings.Compare(a.Field, b.Field) })
	return errs
}

func validateList(field string, ids, other []string) []FieldError {
	if len(ids) > MaxListed {
		return []FieldError{{field, fmt.Sprintf("must contain at most %d licenses", MaxListed)}}
	}
	var errs []FieldError
	for i, id := range ids {
		f := fmt.Sprintf("%s[%d]", field, i)
		switch {
		case !ID.MatchString(id):
			errs = append(errs, FieldError{f, "must be an SPDX license id such as GPL-3.0-only, or LicenseRef-..."})
		case slices.Contains(ids[:i], id):
			errs = append(errs, FieldError{f, "is listed twice"})
		case slices.Contains(other, id):
			errs = append(errs, FieldError{f, "is also in deny"})
		}
	}
	return errs
}

// Rule names what decided a license's action.
type Rule string

const (
	RuleAllowList Rule = "allow"
	RuleDenyList  Rule = "deny"
	RuleCategory  Rule = "category"
)

type Decision struct {
	Action Action
	Rule   Rule
	// ID is the denied id when Rule is RuleDenyList.
	ID string
}

// Evaluate applies the policy to one declared license. terms is the license
// as alternatives (an SPDX "OR": the user may pick any) of ids that all apply
// ("AND"); category is Trivy's classification of the whole declaration. The
// declaration is allowed if some alternative is entirely on the allow list,
// blocked if every alternative has a denied id, and otherwise gets its
// category's action.
func (p Policy) Evaluate(terms [][]string, category Category) Decision {
	for _, alt := range terms {
		if len(alt) > 0 && !slices.ContainsFunc(alt, func(id string) bool { return !slices.Contains(p.Allow, id) }) {
			return Decision{Action: Allow, Rule: RuleAllowList}
		}
	}
	denied := ""
	for i, alt := range terms {
		j := slices.IndexFunc(alt, func(id string) bool { return slices.Contains(p.Deny, id) })
		if j < 0 {
			denied = ""
			break
		}
		if i == 0 {
			denied = alt[j]
		}
	}
	if denied != "" {
		return Decision{Action: Block, Rule: RuleDenyList, ID: denied}
	}
	return Decision{Action: p.Action(ParseCategory(string(category))), Rule: RuleCategory}
}
