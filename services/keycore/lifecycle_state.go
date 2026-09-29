package main

import (
	"errors"
	"strings"
)

// Key lifecycle states. The set matches NIST SP 800-57 with two explicit
// additions: suspended (the auto-quarantine workflow) and disabled (an
// operator hold), which behave alike: use stops and an operator may resume.
const (
	StatePreActive   = "pre-active"
	StateActive      = "active"
	StateSuspended   = "suspended"
	StateDisabled    = "disabled"
	StateDeactivated = "deactivated"
	StateCompromised = "compromised"
	StateDestroyed   = "destroyed"
)

// LifecycleTransition captures one allowed move between states. Every
// status change consults this table: operator changes in SetKeyStatus
// (automated=false, refusals audited as audit.key.status_transition_refused)
// and compromise detection's automatic suspend (automated=true).
type LifecycleTransition struct {
	From       string
	To         string
	AllowAuto  bool // an automated path may apply this transition unattended
	AllowAdmin bool // operator may apply this transition with audit
}

// allowedLifecycleTransitions is the full state machine. Entries omitted
// from this list are rejected. Notes:
//   - Destroyed is terminal; no transitions out.
//   - Compromised only flows forward to destroyed.
//   - Deactivated may be re-activated by an operator, never automatically.
//   - Disabled is entered and left only by an operator, like a suspension.
var allowedLifecycleTransitions = []LifecycleTransition{
	{From: StatePreActive, To: StateActive, AllowAuto: true, AllowAdmin: true},
	{From: StatePreActive, To: StateDestroyed, AllowAdmin: true},
	{From: StatePreActive, To: StateCompromised, AllowAuto: true, AllowAdmin: true},
	{From: StateActive, To: StateSuspended, AllowAuto: true, AllowAdmin: true},
	{From: StateActive, To: StateDeactivated, AllowAuto: true, AllowAdmin: true},
	{From: StateActive, To: StateCompromised, AllowAuto: true, AllowAdmin: true},
	{From: StateActive, To: StateDisabled, AllowAdmin: true},
	{From: StateDisabled, To: StateActive, AllowAdmin: true},
	{From: StateDisabled, To: StateDeactivated, AllowAuto: true, AllowAdmin: true},
	{From: StateDisabled, To: StateCompromised, AllowAuto: true, AllowAdmin: true},
	{From: StateSuspended, To: StateActive, AllowAdmin: true},
	{From: StateSuspended, To: StateDeactivated, AllowAuto: true, AllowAdmin: true},
	{From: StateSuspended, To: StateCompromised, AllowAuto: true, AllowAdmin: true},
	{From: StateDeactivated, To: StateActive, AllowAdmin: true},
	{From: StateDeactivated, To: StateCompromised, AllowAuto: true, AllowAdmin: true},
	{From: StateDeactivated, To: StateDestroyed, AllowAuto: true, AllowAdmin: true},
	{From: StateCompromised, To: StateDestroyed, AllowAuto: true, AllowAdmin: true},
}

// CanTransition reports whether the move is permitted under the requested
// authority. Returns an error describing why the move is not allowed.
func CanTransition(from, to string, automated bool) error {
	from = strings.ToLower(strings.TrimSpace(from))
	to = strings.ToLower(strings.TrimSpace(to))
	if from == to {
		return errors.New("transition to the same state is a no-op")
	}
	for _, t := range allowedLifecycleTransitions {
		if t.From != from || t.To != to {
			continue
		}
		if automated && !t.AllowAuto {
			return errors.New("automated transition not permitted; operator action required")
		}
		if !automated && !t.AllowAdmin {
			return errors.New("operator transition not permitted")
		}
		return nil
	}
	return errors.New("transition not in lifecycle state machine")
}
