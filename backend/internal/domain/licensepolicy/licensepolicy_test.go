package licensepolicy

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/aupv9/warden/backend/internal/domain/severity"
)

func TestZeroPolicyIsOff(t *testing.T) {
	var p Policy
	if p.Enabled() {
		t.Fatal("zero policy enabled")
	}
	var stored Policy
	if err := json.Unmarshal([]byte(`{}`), &stored); err != nil || stored.Enabled() {
		t.Fatal(stored, err)
	}
	// Allow-only lists change nothing either.
	if (Policy{Allow: []string{"MIT"}}).Enabled() {
		t.Fatal("allow list alone enabled the policy")
	}
	if !(Policy{Deny: []string{"GPL-3.0-only"}}).Enabled() || !Recommended().Enabled() {
		t.Fatal("not enabled")
	}
	if d := p.Evaluate([][]string{{"GPL-3.0-only"}}, Forbidden); d.Action != Allow {
		t.Fatal(d)
	}
}

func TestRecommended(t *testing.T) {
	r := Recommended()
	if r.Action(Forbidden) != Block || r.Action(Restricted) != Review || r.Action(Reciprocal) != Allow ||
		len(r.Categories) != len(Categories) || r.Deny == nil || r.Allow == nil {
		t.Fatalf("%+v", r)
	}
	if errs := r.Validate(); errs != nil {
		t.Fatal(errs)
	}
}

func TestPrecedence(t *testing.T) {
	p := Policy{
		Categories: map[Category]Action{Restricted: Review, Forbidden: Block, Unknown: Review},
		Deny:       []string{"AGPL-3.0-only", "SSPL-1.0"},
		Allow:      []string{"LGPL-2.1-only", "MIT"},
	}
	cases := []struct {
		terms [][]string
		cat   Category
		want  Decision
	}{
		{[][]string{{"MIT"}}, Notice, Decision{Action: Allow, Rule: RuleAllowList}},
		{[][]string{{"BSD-3-Clause"}}, Notice, Decision{Action: Allow, Rule: RuleCategory}},
		{[][]string{{"GPL-3.0-only"}}, Restricted, Decision{Action: Review, Rule: RuleCategory}},
		// Allow beats the category.
		{[][]string{{"LGPL-2.1-only"}}, Restricted, Decision{Action: Allow, Rule: RuleAllowList}},
		// Deny beats the category, even a permissive one.
		{[][]string{{"AGPL-3.0-only"}}, Notice, Decision{Action: Block, Rule: RuleDenyList, ID: "AGPL-3.0-only"}},
		// OR: one acceptable alternative is enough to escape the deny list...
		{[][]string{{"AGPL-3.0-only"}, {"Apache-2.0"}}, Notice, Decision{Action: Allow, Rule: RuleCategory}},
		{[][]string{{"AGPL-3.0-only"}, {"MIT"}}, Restricted, Decision{Action: Allow, Rule: RuleAllowList}},
		// ...but if every alternative is denied, it is blocked.
		{[][]string{{"SSPL-1.0"}, {"AGPL-3.0-only"}}, Notice, Decision{Action: Block, Rule: RuleDenyList, ID: "SSPL-1.0"}},
		// AND: a denied id anywhere blocks; allowing needs every id allowed.
		{[][]string{{"MIT", "SSPL-1.0"}}, Notice, Decision{Action: Block, Rule: RuleDenyList, ID: "SSPL-1.0"}},
		{[][]string{{"MIT", "LGPL-2.1-only"}}, Restricted, Decision{Action: Allow, Rule: RuleAllowList}},
		{[][]string{{"MIT", "GPL-2.0-only"}}, Restricted, Decision{Action: Review, Rule: RuleCategory}},
		// Whatever Trivy prints that isn't a category is unknown.
		{[][]string{{"LicenseRef-unknown"}}, "weird", Decision{Action: Review, Rule: RuleCategory}},
		{nil, Forbidden, Decision{Action: Block, Rule: RuleCategory}},
	}
	for _, c := range cases {
		if got := p.Evaluate(c.terms, c.cat); got != c.want {
			t.Errorf("%v %s: got %+v, want %+v", c.terms, c.cat, got, c.want)
		}
	}
}

func TestSeverity(t *testing.T) {
	if Block.Severity() != severity.High || Review.Severity() != severity.Medium || Allow.Severity() != "" {
		t.Fatal("severity mapping")
	}
}

func TestValidate(t *testing.T) {
	ok := Policy{Categories: map[Category]Action{Forbidden: Block}, Deny: []string{"GPL-3.0-only", "LicenseRef-acme-eula"},
		Allow: []string{"MIT", "GPL-2.0+"}}
	if errs := ok.Validate(); errs != nil {
		t.Fatal(errs)
	}
	bad := Policy{
		Categories: map[Category]Action{"evil": Block, Notice: "deny"},
		Deny:       []string{"GPL-3.0-only", "not an id", "GPL-3.0-only", "<script>", strings.Repeat("a", 65), "-x"},
		Allow:      []string{"MIT", "GPL-3.0-only"},
	}
	got := map[string]string{}
	for _, e := range bad.Validate() {
		got[e.Field] = e.Message
	}
	for _, f := range []string{"categories", "categories.notice", "deny[1]", "deny[2]", "deny[3]", "deny[4]", "deny[5]", "allow[1]"} {
		if got[f] == "" {
			t.Errorf("no error for %s: %v", f, got)
		}
	}
	if got["deny[0]"] != "" || got["allow[0]"] != "" || got["allow[1]"] != "is also in deny" {
		t.Fatal(got)
	}
	long := Policy{Deny: make([]string, MaxListed+1)}
	for i := range long.Deny {
		long.Deny[i] = fmt.Sprintf("LicenseRef-x%d", i)
	}
	if errs := long.Validate(); len(errs) != 1 || errs[0].Field != "deny" {
		t.Fatal(errs)
	}
}

func TestNormalizeAndEqual(t *testing.T) {
	if !Equal(Policy{}, Policy{Categories: map[Category]Action{Notice: Allow}, Deny: []string{}}) {
		t.Fatal("same meaning, not equal")
	}
	if Equal(Policy{}, Recommended()) || Equal(Policy{Deny: []string{"A", "B"}}, Policy{Deny: []string{"B", "A"}}) {
		t.Fatal("different policies equal")
	}
	n := Normalize(Policy{})
	if len(n.Categories) != len(Categories) || n.Deny == nil || n.Allow == nil {
		t.Fatal(n)
	}
	raw, _ := json.Marshal(Policy{})
	if string(raw) != "{}" {
		t.Fatal(string(raw))
	}
}

func TestParseCategory(t *testing.T) {
	for _, c := range Categories {
		if ParseCategory(string(c)) != c {
			t.Fatal(c)
		}
	}
	if ParseCategory("FORBIDDEN") != Unknown || ParseCategory("") != Unknown || !slices.Contains(Categories, Unknown) {
		t.Fatal("unknown")
	}
}
