// Package issuestate is the issue workflow. Every status change goes
// through Check; the table below is the whole state machine.
package issuestate

import (
	"errors"
	"fmt"
	"slices"
)

type Status string

const (
	Open          Status = "open"
	Assigned      Status = "assigned"
	InProgress    Status = "in_progress"
	Fixed         Status = "fixed"
	Verified      Status = "verified"
	Reopened      Status = "reopened"
	FalsePositive Status = "false_positive"
	RiskAccepted  Status = "risk_accepted"
)

var AllStatuses = []Status{Open, Assigned, InProgress, Fixed, Verified, Reopened, FalsePositive, RiskAccepted}

type Actor string

const (
	System       Actor = "system"
	Assignee     Actor = "assignee"
	ProjectOwner Actor = "project_owner"
	SecurityLead Actor = "security_lead"
)

var AllActors = []Actor{System, Assignee, ProjectOwner, SecurityLead}

var (
	Active   = []Status{Open, Assigned, InProgress, Reopened}
	Terminal = []Status{Verified, FalsePositive, RiskAccepted}
)

const RiskAcceptedMaxDays = 180

type Transition struct {
	Actors                    []Actor
	RequiresMemberAssignee    bool
	ClearsAssignee            bool
	RequiresApprovedException bool
	RequiresReason            bool
}

var (
	ErrInvalidTransition = errors.New("INVALID_TRANSITION")
	ErrForbidden         = errors.New("FORBIDDEN")
)

type edge struct{ from, to Status }

var transitions = build()

func build() map[edge]Transition {
	ownerOrLead := []Actor{ProjectOwner, SecurityLead}
	t := map[edge]Transition{
		{Open, Assigned}:         {Actors: append([]Actor{System}, ownerOrLead...), RequiresMemberAssignee: true},
		{Assigned, Open}:         {Actors: ownerOrLead, ClearsAssignee: true},
		{Assigned, InProgress}:   {Actors: []Actor{Assignee}},
		{Fixed, Verified}:        {Actors: []Actor{System, SecurityLead}},
		{Fixed, Reopened}:        {Actors: []Actor{System}},
		{Verified, Reopened}:     {Actors: []Actor{System}},
		{Reopened, InProgress}:   {Actors: []Actor{Assignee}},
		{Reopened, Assigned}:     {Actors: ownerOrLead, RequiresMemberAssignee: true},
		{RiskAccepted, Reopened}: {Actors: []Actor{System}},
		{FalsePositive, Open}:    {Actors: []Actor{SecurityLead}, RequiresReason: true},
	}
	for _, src := range Active {
		t[edge{src, Fixed}] = Transition{Actors: []Actor{System}}
		for _, exc := range []Status{FalsePositive, RiskAccepted} {
			t[edge{src, exc}] = Transition{Actors: []Actor{SecurityLead}, RequiresApprovedException: true}
		}
	}
	// The assignee may also mark their own work fixed (the system confirms on rescan).
	t[edge{InProgress, Fixed}] = Transition{Actors: []Actor{Assignee, System}}
	return t
}

// Check returns the transition rule if any of actors may move an issue from src to dst.
func Check(src, dst Status, actors ...Actor) (Transition, error) {
	rule, ok := transitions[edge{src, dst}]
	if !ok {
		return Transition{}, fmt.Errorf("%w: %s → %s is not a valid transition", ErrInvalidTransition, src, dst)
	}
	for _, a := range actors {
		if slices.Contains(rule.Actors, a) {
			return rule, nil
		}
	}
	return Transition{}, fmt.Errorf("%w: %s → %s not allowed for %v", ErrForbidden, src, dst, actors)
}
