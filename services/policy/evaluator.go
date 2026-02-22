package main

import (
	"errors"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

var validPolicyTypes = map[string]struct{}{
	"algorithm":       {},
	"rotation":        {},
	"iv_mode":         {},
	"operation_limit": {},
	"purpose":         {},
}

func parsePolicyYAML(raw string) (PolicyDoc, map[string]any, error) {
	doc := PolicyDoc{}
	if strings.TrimSpace(raw) == "" {
		return doc, nil, errors.New("policy yaml is required")
	}
	if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
		return doc, nil, err
	}
	if strings.TrimSpace(doc.APIVersion) == "" {
		return doc, nil, errors.New("apiVersion is required")
	}
	if !strings.EqualFold(strings.TrimSpace(doc.Kind), "CryptoPolicy") {
		return doc, nil, errors.New("kind must be CryptoPolicy")
	}
	doc.Metadata.Name = strings.TrimSpace(doc.Metadata.Name)
	doc.Metadata.Tenant = strings.TrimSpace(doc.Metadata.Tenant)
	doc.Spec.Type = normalizePolicyType(doc.Spec.Type)
	if doc.Metadata.Name == "" {
		return doc, nil, errors.New("metadata.name is required")
	}
	if _, ok := validPolicyTypes[doc.Spec.Type]; !ok {
		return doc, nil, errors.New("unsupported spec.type")
	}
	if len(doc.Spec.Rules) == 0 {
		return doc, nil, errors.New("spec.rules must not be empty")
	}
	if doc.Metadata.Labels == nil {
		doc.Metadata.Labels = map[string]any{}
	}
	if doc.Spec.Targets.Selector == nil {
		doc.Spec.Targets.Selector = map[string]any{}
	}
	for i := range doc.Spec.Rules {
		doc.Spec.Rules[i].Action = strings.ToLower(strings.TrimSpace(doc.Spec.Rules[i].Action))
		if doc.Spec.Rules[i].Action == "" {
			doc.Spec.Rules[i].Action = "enforce"
		}
		doc.Spec.Rules[i].Name = strings.TrimSpace(doc.Spec.Rules[i].Name)
		if doc.Spec.Rules[i].Name == "" {
			doc.Spec.Rules[i].Name = "rule-" + strconv.Itoa(i+1)
		}
	}

	var parsed map[string]any
	if err := yaml.Unmarshal([]byte(raw), &parsed); err != nil {
		return doc, nil, err
	}
	return doc, parsed, nil
}

func normalizePolicyType(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.ReplaceAll(v, "-", "_")
	return v
}

func evaluatePolicy(doc PolicyDoc, policyID string, version int, req EvaluatePolicyRequest) (Decision, []RuleOutcome) {
	if !selectorMatches(doc.Spec.Targets.Selector, req) {
		return DecisionAllow, nil
	}
	decision := DecisionAllow
	outcomes := make([]RuleOutcome, 0)

	for _, rule := range doc.Spec.Rules {
		if !conditionMatches(rule.Condition, req) {
			continue
		}
		out := RuleOutcome{
			PolicyID:      policyID,
			PolicyVersion: version,
			RuleName:      rule.Name,
			Action:        rule.Action,
			Message:       strings.TrimSpace(rule.Message),
		}
		if out.Message == "" {
			out.Message = "policy rule matched"
		}
		outcomes = append(outcomes, out)

		switch rule.Action {
		case "warn":
			if decision == DecisionAllow {
				decision = DecisionWarn
			}
		case "auto-rotate":
			if decision == DecisionAllow {
				decision = DecisionWarn
			}
		default:
			decision = DecisionDeny
		}
	}
	return decision, outcomes
}

func selectorMatches(selector map[string]any, req EvaluatePolicyRequest) bool {
	if len(selector) == 0 {
		return true
	}
	for k, v := range selector {
		key := strings.ToLower(strings.TrimSpace(k))
		switch key {
		case "status", "key.status":
			if !matchesValue(req.KeyStatus, v) {
				return false
			}
		case "purpose", "key.purpose":
			if !matchesValue(req.Purpose, v) {
				return false
			}
		case "algorithm", "key.algorithm":
			if !matchesValue(req.Algorithm, v) {
				return false
			}
		case "iv_mode", "key.iv_mode":
			if !matchesValue(req.IVMode, v) {
				return false
			}
		case "operation", "operation.name":
			if !matchesValue(req.Operation, v) {
				return false
			}
		}
	}
	return true
}

func conditionMatches(condition string, req EvaluatePolicyRequest) bool {
	cond := strings.TrimSpace(condition)
	if cond == "" {
		return true
	}
	tokens := strings.Fields(cond)
	if len(tokens) < 3 {
		return false
	}
	left := strings.ToLower(strings.TrimSpace(tokens[0]))
	op := strings.ToLower(strings.TrimSpace(tokens[1]))
	right := strings.TrimSpace(strings.Join(tokens[2:], " "))

	lv, ok := getFieldValue(left, req)
	if !ok {
		return false
	}
	switch op {
	case "==", "=":
		return compareEqual(lv, stripQuotes(right))
	case "!=":
		return !compareEqual(lv, stripQuotes(right))
	case ">", ">=", "<", "<=":
		lf, lok := asFloat(lv)
		rf, rok := asFloat(stripQuotes(right))
		if !lok || !rok {
			return false
		}
		switch op {
		case ">":
			return lf > rf
		case ">=":
			return lf >= rf
		case "<":
			return lf < rf
		default:
			return lf <= rf
		}
	case "in":
		return inSet(lv, right)
	case "notin", "not_in":
		return !inSet(lv, right)
	default:
		return false
	}
}

func getFieldValue(path string, req EvaluatePolicyRequest) (any, bool) {
	switch path {
	case "operation", "operation.name":
		return req.Operation, true
	case "key.id":
		return req.KeyID, true
	case "key.algorithm":
		return req.Algorithm, true
	case "key.purpose":
		return req.Purpose, true
	case "key.iv_mode":
		return req.IVMode, true
	case "key.status":
		return req.KeyStatus, true
	case "key.days_since_rotation":
		return req.DaysSinceRotation, true
	case "key.ops_total", "operation.count":
		return req.OpsTotal, true
	case "key.ops_limit":
		return req.OpsLimit, true
	default:
		return nil, false
	}
}

func compareEqual(left any, right string) bool {
	switch v := left.(type) {
	case string:
		return strings.EqualFold(strings.TrimSpace(v), strings.TrimSpace(right))
	default:
		lf, lok := asFloat(v)
		rf, rok := asFloat(right)
		return lok && rok && lf == rf
	}
}

func inSet(left any, right string) bool {
	values := parseList(right)
	s := strings.TrimSpace(strings.ToLower(toString(left)))
	for _, item := range values {
		if strings.ToLower(strings.TrimSpace(item)) == s {
			return true
		}
	}
	return false
}

func parseList(raw string) []string {
	v := strings.TrimSpace(raw)
	v = strings.TrimPrefix(v, "[")
	v = strings.TrimSuffix(v, "]")
	if v == "" {
		return nil
	}
	items := strings.Split(v, ",")
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = stripQuotes(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func matchesValue(actual string, expected any) bool {
	actual = strings.TrimSpace(strings.ToLower(actual))
	switch v := expected.(type) {
	case string:
		return actual == strings.TrimSpace(strings.ToLower(v))
	case []any:
		for _, item := range v {
			if matchesValue(actual, item) {
				return true
			}
		}
		return false
	case []string:
		for _, item := range v {
			if matchesValue(actual, item) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func stripQuotes(v string) string {
	v = strings.TrimSpace(v)
	v = strings.Trim(v, "'")
	v = strings.Trim(v, "\"")
	return strings.TrimSpace(v)
}

func asFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case int:
		return float64(x), true
	case int32:
		return float64(x), true
	case int64:
		return float64(x), true
	case float32:
		return float64(x), true
	case float64:
		return x, true
	case string:
		n, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return n, err == nil
	default:
		return 0, false
	}
}

func toString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	default:
		return ""
	}
}
