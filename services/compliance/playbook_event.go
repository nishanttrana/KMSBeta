package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// RunEvent is the audit event a run responds to, as the run sees it:
// triggers filter on it, action conditions test it, and parameters template
// from it ({{event.target_id}}). A manual run may supply one; it is marked
// Supplied so nobody mistakes it for an observed event.
type RunEvent struct {
	Subject       string            `json:"subject,omitempty"`
	TenantID      string            `json:"tenant_id,omitempty"`
	Service       string            `json:"service,omitempty"`
	Result        string            `json:"result,omitempty"`
	Severity      string            `json:"severity,omitempty"`
	TargetType    string            `json:"target_type,omitempty"`
	TargetID      string            `json:"target_id,omitempty"`
	ActorID       string            `json:"actor_id,omitempty"`
	ActorType     string            `json:"actor_type,omitempty"`
	CorrelationID string            `json:"correlation_id,omitempty"`
	Timestamp     string            `json:"timestamp,omitempty"`
	Details       map[string]string `json:"details,omitempty"`
	Supplied      bool              `json:"supplied,omitempty"`
}

const (
	maxEventDetails   = 64
	maxEventDetailLen = 512
)

var detailKeyRE = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

// parseEvent reads an audit stream message. Scalar details are kept as
// strings (bounded), nested values are dropped: a run keeps what it can
// filter and template on, not whole payloads.
func parseEvent(subject string, data []byte) (RunEvent, bool) {
	var raw map[string]interface{}
	if json.Unmarshal(data, &raw) != nil {
		return RunEvent{}, false
	}
	str := func(v interface{}) string {
		switch x := v.(type) {
		case string:
			return x
		case float64:
			return strconv.FormatFloat(x, 'f', -1, 64)
		case bool:
			return strconv.FormatBool(x)
		}
		return ""
	}
	ev := RunEvent{
		Subject: subject, TenantID: str(raw["tenant_id"]), Service: str(raw["service"]), Result: str(raw["result"]),
		TargetType: str(raw["target_type"]), TargetID: str(raw["target_id"]), ActorID: str(raw["actor_id"]),
		ActorType: str(raw["actor_type"]), CorrelationID: str(raw["correlation_id"]), Timestamp: str(raw["timestamp"]),
	}
	details := map[string]string{}
	for _, src := range []interface{}{raw["data"], raw["details"]} {
		m, _ := src.(map[string]interface{})
		for k, v := range m {
			s := str(v)
			if s == "" || !detailKeyRE.MatchString(k) || len(details) >= maxEventDetails {
				continue
			}
			if len(s) > maxEventDetailLen {
				s = s[:maxEventDetailLen]
			}
			details[k] = s
		}
	}
	if len(details) > 0 {
		ev.Details = details
	}
	ev.Severity = strings.ToLower(firstNonEmpty(str(raw["severity"]), details["severity"]))
	if ev.TargetID == "" {
		ev.TargetID = firstNonEmpty(details["key_id"], details["alert_id"], details["incident_id"], details["cert_id"], details["user_id"])
	}
	return ev, true
}

// eventFields are the names filters, conditions and templates can use,
// besides details.<key>.
var eventFields = []string{"subject", "tenant_id", "service", "result", "severity", "target_type", "target_id", "actor_id", "actor_type", "correlation_id"}

func validEventField(name string) bool {
	if strings.HasPrefix(name, "details.") {
		return detailKeyRE.MatchString(strings.TrimPrefix(name, "details."))
	}
	for _, f := range eventFields {
		if f == name {
			return true
		}
	}
	return false
}

func (ev RunEvent) field(name string) string {
	switch name {
	case "subject":
		return ev.Subject
	case "tenant_id":
		return ev.TenantID
	case "service":
		return ev.Service
	case "result":
		return ev.Result
	case "severity":
		return ev.Severity
	case "target_type":
		return ev.TargetType
	case "target_id":
		return ev.TargetID
	case "actor_id":
		return ev.ActorID
	case "actor_type":
		return ev.ActorType
	case "correlation_id":
		return ev.CorrelationID
	}
	if k, ok := strings.CutPrefix(name, "details."); ok {
		return ev.Details[k]
	}
	return ""
}

// incidentID is the reporting incident the event concerns, if any.
func (ev RunEvent) incidentID() string {
	if ev.TargetType == "incident" {
		return ev.TargetID
	}
	return ev.Details["incident_id"]
}

// EventFilter is one test on an event field. Every filter of a trigger or
// condition must hold.
type EventFilter struct {
	Field string `json:"field"`
	Op    string `json:"op"`
	Value string `json:"value"`
}

var filterOps = map[string]bool{"eq": true, "neq": true, "in": true, "not_in": true, "contains": true, "prefix": true}

func validateFilters(fs []EventFilter, where string) error {
	if len(fs) > 16 {
		return fmt.Errorf("%s: at most 16 filters", where)
	}
	for i, f := range fs {
		if !validEventField(f.Field) {
			return fmt.Errorf("%s filter %d: unknown field %q (use %s or details.<key>)", where, i+1, f.Field, strings.Join(eventFields, ", "))
		}
		if !filterOps[f.Op] {
			return fmt.Errorf("%s filter %d: op must be eq, neq, in, not_in, contains or prefix", where, i+1)
		}
		if strings.TrimSpace(f.Value) == "" && f.Op != "eq" && f.Op != "neq" {
			return fmt.Errorf("%s filter %d: a value is required", where, i+1)
		}
	}
	return nil
}

func matchFilters(ev RunEvent, fs []EventFilter) bool {
	for _, f := range fs {
		v := strings.ToLower(ev.field(f.Field))
		want := strings.ToLower(strings.TrimSpace(f.Value))
		in := func() bool {
			for _, x := range strings.Split(want, ",") {
				if strings.TrimSpace(x) == v {
					return true
				}
			}
			return false
		}
		ok := false
		switch f.Op {
		case "eq":
			ok = v == want
		case "neq":
			ok = v != want
		case "in":
			ok = in()
		case "not_in":
			ok = !in()
		case "contains":
			ok = strings.Contains(v, want)
		case "prefix":
			ok = strings.HasPrefix(v, want)
		}
		if !ok {
			return false
		}
	}
	return true
}

// Templates: {{event.<field>}}, {{run.id}}, {{playbook.id}},
// {{playbook.name}}, {{trigger}}.
var templateRE = regexp.MustCompile(`\{\{\s*([a-z0-9_.]+)\s*\}\}`)

func validateTemplates(s string) error {
	if strings.Count(s, "{{") != len(templateRE.FindAllString(s, -1)) {
		return errors.New("malformed {{...}} template")
	}
	for _, m := range templateRE.FindAllStringSubmatch(s, -1) {
		name := m[1]
		switch {
		case name == "run.id", name == "playbook.id", name == "playbook.name", name == "trigger":
		case strings.HasPrefix(name, "event.") && validEventField(strings.TrimPrefix(name, "event.")):
		default:
			return fmt.Errorf("unknown template {{%s}}", name)
		}
	}
	return nil
}

func hasTemplate(s string) bool { return strings.Contains(s, "{{") }

// renderParams resolves every parameter against the run.
func renderParams(params map[string]string, ev RunEvent, pb Playbook, run PlaybookRun) map[string]string {
	out := make(map[string]string, len(params))
	for k, v := range params {
		out[k] = templateRE.ReplaceAllStringFunc(v, func(m string) string {
			name := templateRE.FindStringSubmatch(m)[1]
			switch name {
			case "run.id":
				return run.ID
			case "playbook.id":
				return pb.ID
			case "playbook.name":
				return pb.Name
			case "trigger":
				return run.TriggerEvent
			}
			return ev.field(strings.TrimPrefix(name, "event."))
		})
	}
	return out
}
