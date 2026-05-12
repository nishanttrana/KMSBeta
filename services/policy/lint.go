package main

import (
	"strings"
)

// LintFinding is one issue found while statically analysing a policy YAML.
// Severities: "error" prevents the policy from being saved; "warning"
// surfaces in the UI but doesn't block; "info" is purely advisory.
type LintFinding struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Message  string `json:"message"`
	Path     string `json:"path,omitempty"`
}

// LintPolicy runs static checks against a parsed policy document. It is
// pure (no I/O, no shared state) so it can run in the lint endpoint and in
// the create/update path before persistence.
func LintPolicy(doc PolicyDoc) []LintFinding {
	var out []LintFinding
	if strings.TrimSpace(doc.Metadata.Name) == "" {
		out = append(out, LintFinding{
			Severity: "error", Code: "missing-name",
			Message: "metadata.name is required",
			Path:    "metadata.name",
		})
	}
	if _, ok := validPolicyTypes[doc.Spec.Type]; !ok {
		out = append(out, LintFinding{
			Severity: "error", Code: "unknown-type",
			Message: "spec.type is not in the supported set",
			Path:    "spec.type",
		})
	}
	if len(doc.Spec.Rules) == 0 {
		out = append(out, LintFinding{
			Severity: "error", Code: "no-rules",
			Message: "spec.rules must contain at least one rule",
			Path:    "spec.rules",
		})
	}
	seen := make(map[string]int)
	for i, r := range doc.Spec.Rules {
		if strings.TrimSpace(r.Name) == "" {
			out = append(out, LintFinding{
				Severity: "warning", Code: "unnamed-rule",
				Message: "rule has no name; defaults will be assigned",
				Path:    pathf("spec.rules", i, "name"),
			})
		}
		seen[r.Name]++
		if strings.TrimSpace(r.Condition) == "" && strings.ToLower(r.Action) != "warn" {
			out = append(out, LintFinding{
				Severity: "warning", Code: "unconditional-rule",
				Message: "rule has no condition and will match every targeted request",
				Path:    pathf("spec.rules", i, "condition"),
			})
		}
		switch strings.ToLower(strings.TrimSpace(r.Action)) {
		case "", "enforce", "deny", "warn", "auto-rotate", "require-approval":
		default:
			out = append(out, LintFinding{
				Severity: "error", Code: "unknown-action",
				Message: "rule action is not recognised",
				Path:    pathf("spec.rules", i, "action"),
			})
		}
	}
	for name, n := range seen {
		if n > 1 && name != "" {
			out = append(out, LintFinding{
				Severity: "warning", Code: "duplicate-rule-name",
				Message: "rule name appears more than once: " + name,
				Path:    "spec.rules",
			})
		}
	}
	if doc.Spec.DefaultAction == "" {
		out = append(out, LintFinding{
			Severity: "info", Code: "default-action-unset",
			Message: "spec.defaultAction not set; defaulting to 'allow'. Set to 'deny' under strict posture.",
			Path:    "spec.defaultAction",
		})
	}
	return out
}

func pathf(prefix string, index int, field string) string {
	return prefix + "[" + itoa(index) + "]." + field
}

func itoa(i int) string {
	// Avoid importing strconv just for this; the int values are small.
	if i == 0 {
		return "0"
	}
	out := ""
	for i > 0 {
		out = string(rune('0'+i%10)) + out
		i /= 10
	}
	return out
}
