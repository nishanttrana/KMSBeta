package main

import "strings"

type EventMeta struct {
	Severity string
	Category string
}

var auditEventCatalog = buildAuditEventCatalog()

func buildAuditEventCatalog() map[string]EventMeta {
	services := []string{
		"auth", "key", "secrets", "certs", "policy", "governance", "pqc", "audit", "byok", "ai",
		"discovery", "compliance", "hyok", "ekm", "reporting", "qkd", "cluster", "payment", "sbom",
		"mpc", "dataprotect", "kmip",
	}
	verbs := []string{
		"created", "imported", "rotated", "deactivated", "destroyed", "exported",
		"encrypt", "decrypt", "sign", "verify", "approval_required", "ops_limit_reached",
		"policy_violated", "config_changed", "login_failed",
	}

	catalog := make(map[string]EventMeta, len(services)*len(verbs))
	for _, svc := range services {
		for _, verb := range verbs {
			action := "audit." + svc + "." + verb
			catalog[action] = EventMeta{
				Severity: severityForVerb(verb),
				Category: svc,
			}
		}
	}

	overrides := map[string]EventMeta{
		"audit.audit.chain_broken":         {Severity: "CRITICAL", Category: "audit"},
		"audit.auth.mfa_failed":            {Severity: "HIGH", Category: "auth"},
		"audit.cluster.node_failed":        {Severity: "HIGH", Category: "cluster"},
		"audit.key.compromised":            {Severity: "CRITICAL", Category: "key"},
		"audit.key.fips.violation_blocked": {Severity: "CRITICAL", Category: "key"},
		"audit.fde.unlock_failed":          {Severity: "CRITICAL", Category: "dataprotect"},
		"audit.integrity_check_failed":     {Severity: "CRITICAL", Category: "audit"},
	}
	for action, meta := range overrides {
		catalog[action] = meta
	}
	return catalog
}

func severityForVerb(verb string) string {
	switch strings.ToLower(strings.TrimSpace(verb)) {
	case "destroyed":
		return "CRITICAL"
	case "exported", "policy_violated", "login_failed":
		return "HIGH"
	case "rotated", "deactivated", "approval_required", "ops_limit_reached", "config_changed":
		return "MEDIUM"
	case "created", "imported", "encrypt", "decrypt", "sign", "verify":
		return "LOW"
	default:
		return "INFO"
	}
}
