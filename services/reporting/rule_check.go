package main

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"
)

// Checking an alert rule before it is saved (POST /alerts/rules/test).
// A detection rule that never fires, or fires on every login, is a
// security gap. The check runs the same matcher live alerting uses
// (ruleMatchesEvent / ruleFires) and changes nothing:
//
//   - validation: the rule as create/update would accept it;
//   - event: one event supplied by the caller, and whether the rule would
//     fire on it now (threshold rules read the live alert count);
//   - replay: the tenant's real audit events from the last N hours, read
//     from the audit service, and how often the rule would have fired.

const (
	maxReplayHours  = 168
	replayEventCap  = 5000
	replaySampleCap = 5
)

// RuleCheckInput is the body of POST /alerts/rules/test.
type RuleCheckInput struct {
	TenantID    string                 `json:"tenant_id"` // verified by the kernel
	Rule        AlertRule              `json:"rule"`
	Event       map[string]interface{} `json:"event,omitempty"`
	ReplayHours int                    `json:"replay_hours"`
}

// RuleCheck is the result. Nothing is stored or sent.
type RuleCheck struct {
	Valid       bool            `json:"valid"`
	Error       string          `json:"error,omitempty"`
	Event       *RuleEventCheck `json:"event,omitempty"`
	Replay      *RuleReplay     `json:"replay,omitempty"`
	ReplayError string          `json:"replay_error,omitempty"`
}

// RuleEventCheck is the decision for the supplied event.
type RuleEventCheck struct {
	Action  string `json:"action"`
	Matched bool   `json:"matched"`
	// FiresNow is what live alerting would decide for this event now.
	FiresNow bool `json:"fires_now"`
	// InWindow is the recorded alerts matching the pattern in the window
	// (threshold rules only); the event would be one more.
	InWindow int `json:"in_window,omitempty"`
}

// RuleReplay is the rule run over recorded audit events.
type RuleReplay struct {
	Hours         int       `json:"hours"`
	From          time.Time `json:"from"`
	To            time.Time `json:"to"`
	EventsScanned int       `json:"events_scanned"`
	Matched       int       `json:"matched"`
	Fired         int       `json:"fired"`
	// Truncated: the audit service returned its maximum, so From is the
	// oldest event read, later than asked for.
	Truncated bool               `json:"truncated"`
	Samples   []RuleReplaySample `json:"samples"`
	Basis     string             `json:"basis"`
}

// RuleReplaySample is one event the rule would have fired on.
type RuleReplaySample struct {
	EventID   string `json:"event_id"`
	Action    string `json:"action"`
	ActorID   string `json:"actor_id"`
	Timestamp string `json:"timestamp"`
}

// validateRule applies what CreateRule and UpdateRule require, and what a
// rule needs to be able to fire at all.
func validateRule(rule AlertRule) error {
	switch strings.ToLower(strings.TrimSpace(rule.Condition)) {
	case "threshold":
		if strings.TrimSpace(rule.EventPattern) == "" {
			return errors.New("event_pattern is required for a threshold rule")
		}
		if rule.Threshold < 0 || rule.WindowSecond < 0 {
			return errors.New("threshold and window_seconds can't be negative")
		}
	case "expression":
		if strings.TrimSpace(rule.Expression) == "" {
			return errors.New("expression is required")
		}
		if err := ValidateExpression(rule.Expression); err != nil {
			return errors.New("invalid expression: " + err.Error())
		}
	default:
		return errors.New("condition must be threshold or expression")
	}
	return nil
}

// CheckRule validates rule, decides the supplied event, and replays the
// tenant's recent audit events.
func (s *Service) CheckRule(ctx context.Context, tenantID string, in RuleCheckInput) RuleCheck {
	rule := in.Rule
	rule.TenantID = tenantID
	if err := validateRule(rule); err != nil {
		return RuleCheck{Valid: false, Error: err.Error()}
	}
	out := RuleCheck{Valid: true}
	if len(in.Event) > 0 {
		action := eventAction(in.Event)
		matched, _ := ruleMatchesEvent(rule, action, in.Event)
		fires, count, err := s.ruleFires(ctx, tenantID, rule, action, in.Event)
		if err != nil {
			out.Error = "event check: " + err.Error()
		}
		out.Event = &RuleEventCheck{Action: action, Matched: matched, FiresNow: fires, InWindow: count}
	}
	hours := in.ReplayHours
	if hours == 0 {
		hours = 24
	}
	if hours < 0 {
		return out // replay not asked for
	}
	if hours > maxReplayHours {
		hours = maxReplayHours
	}
	replay, err := s.replayRule(ctx, tenantID, rule, hours)
	if err != nil {
		out.ReplayError = err.Error()
	} else {
		out.Replay = replay
	}
	return out
}

// replayRule runs rule over the tenant's audit events from the last hours,
// oldest first. A threshold rule fires on each matching event once the
// matching events in its window reach the threshold, as live alerting does.
func (s *Service) replayRule(ctx context.Context, tenantID string, rule AlertRule, hours int) (*RuleReplay, error) {
	if s.audit == nil {
		return nil, errors.New("the audit service is not connected, so recent events can't be replayed")
	}
	events, err := s.audit.ListEvents(ctx, tenantID, replayEventCap)
	if err != nil {
		return nil, errors.New("audit events unavailable: " + err.Error())
	}
	to := time.Now().UTC()
	from := to.Add(-time.Duration(hours) * time.Hour)
	type stamped struct {
		at time.Time
		ev map[string]interface{}
	}
	var in []stamped
	oldest := to
	for _, ev := range events {
		at := parseTimeString(firstString(ev["timestamp"]))
		if at.IsZero() {
			continue
		}
		if at.Before(oldest) {
			oldest = at
		}
		if !at.Before(from) && !at.After(to) {
			in = append(in, stamped{at, ev})
		}
	}
	sort.Slice(in, func(i, j int) bool { return in[i].at.Before(in[j].at) })
	r := &RuleReplay{Hours: hours, From: from, To: to, EventsScanned: len(in), Samples: []RuleReplaySample{},
		Basis: "matching audit events per window; live alerting counts recorded alerts, which merge repeats of the same action and target within 60 seconds, so it can fire less often"}
	if len(events) >= replayEventCap && oldest.After(from) {
		r.Truncated, r.From = true, oldest
	}
	threshold := 1
	if strings.EqualFold(strings.TrimSpace(rule.Condition), "threshold") && rule.Threshold > 1 {
		threshold = rule.Threshold
	}
	window := ruleWindow(rule)
	var matchedAt []time.Time
	first := 0 // oldest matched event still inside the window
	for _, e := range in {
		ok, err := ruleMatchesEvent(rule, eventAction(e.ev), e.ev)
		if err != nil || !ok {
			continue
		}
		r.Matched++
		matchedAt = append(matchedAt, e.at)
		for e.at.Sub(matchedAt[first]) >= window {
			first++
		}
		if len(matchedAt)-first < threshold {
			continue
		}
		r.Fired++
		if len(r.Samples) < replaySampleCap {
			r.Samples = append(r.Samples, RuleReplaySample{
				EventID: firstString(e.ev["id"], e.ev["event_id"]), Action: eventAction(e.ev),
				ActorID: firstString(e.ev["actor_id"]), Timestamp: e.at.Format(time.RFC3339),
			})
		}
	}
	return r, nil
}
