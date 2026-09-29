package main

import (
	"errors"
	"strings"
)

// Key lifecycle states. The set matches NIST SP 800-57 with one explicit
// addition (suspended) for the auto-quarantine workflow.
const (
	StatePreActive   = "pre-active"
	StateActive      = "active"
	StateSuspended   = "suspended"
	StateDeactivated = "deactivated"
	StateCompromised = "compromised"
	StateDestroyed   = "destroyed"
)

// LifecycleTransition captures one allowed move between states. Only
// compromise detection's automatic suspend (enterprise_audit_service.go)
// consults this table today; SetKeyStatus does not, so an operator's
// status change is not checked against it (docs/AUTOMATION_ALKM_PQC.md).
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
var allowedLifecycleTransitions = []LifecycleTransition{
	{From: StatePreActive, To: StateActive, AllowAuto: true, AllowAdmin: true},
	{From: StatePreActive, To: StateDestroyed, AllowAdmin: true},
	{From: StateActive, To: StateSuspended, AllowAuto: true, AllowAdmin: true},
	{From: StateActive, To: StateDeactivated, AllowAuto: true, AllowAdmin: true},
	{From: StateActive, To: StateCompromised, AllowAuto: true, AllowAdmin: true},
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
