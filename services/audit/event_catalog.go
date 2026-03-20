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
		"workload", "confidential", "autokey",
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
		"audit.audit.chain_broken":                 {Severity: "CRITICAL", Category: "audit"},
		"audit.auth.mfa_failed":                    {Severity: "HIGH", Category: "auth"},
		"audit.auth.client_token_issued":          {Severity: "LOW", Category: "auth"},
		"audit.auth.mtls_binding_failed":          {Severity: "HIGH", Category: "auth"},
		"audit.auth.client_dpop_failed":           {Severity: "HIGH", Category: "auth"},
		"audit.auth.dpop_replay_detected":         {Severity: "HIGH", Category: "auth"},
		"audit.auth.client_http_signature_failed": {Severity: "HIGH", Category: "auth"},
		"audit.auth.http_signature_replay_detected": {Severity: "HIGH", Category: "auth"},
		"audit.auth.rest_client_security_viewed":  {Severity: "LOW", Category: "auth"},
		"audit.cluster.node_failed":                {Severity: "HIGH", Category: "cluster"},
		"audit.compliance.assessment_delta_viewed": {Severity: "LOW", Category: "compliance"},
		"audit.confidential.policy_updated":        {Severity: "MEDIUM", Category: "confidential"},
		"audit.confidential.key_release_evaluated": {Severity: "HIGH", Category: "confidential"},
		"audit.key.compromised":                    {Severity: "CRITICAL", Category: "key"},
		"audit.key.fips.violation_blocked":         {Severity: "CRITICAL", Category: "key"},
		"audit.key.rest_mtls_binding_failed":       {Severity: "HIGH", Category: "key"},
		"audit.key.rest_signature_failed":          {Severity: "HIGH", Category: "key"},
		"audit.key.rest_unsigned_blocked":          {Severity: "MEDIUM", Category: "key"},
		"audit.key.request_replay_detected":        {Severity: "HIGH", Category: "key"},
		"audit.fde.unlock_failed":                  {Severity: "CRITICAL", Category: "dataprotect"},
		"audit.integrity_check_failed":             {Severity: "CRITICAL", Category: "audit"},
		"audit.payment.policy_updated":             {Severity: "MEDIUM", Category: "payment"},
		"audit.payment.ap2_profile_updated":        {Severity: "MEDIUM", Category: "payment"},
		"audit.payment.ap2_evaluated":              {Severity: "LOW", Category: "payment"},
		"audit.autokey.settings_updated":           {Severity: "MEDIUM", Category: "autokey"},
		"audit.autokey.settings_viewed":            {Severity: "LOW", Category: "autokey"},
		"audit.autokey.template_upserted":          {Severity: "MEDIUM", Category: "autokey"},
		"audit.autokey.template_deleted":           {Severity: "MEDIUM", Category: "autokey"},
		"audit.autokey.templates_viewed":           {Severity: "LOW", Category: "autokey"},
		"audit.autokey.service_policy_upserted":    {Severity: "MEDIUM", Category: "autokey"},
		"audit.autokey.service_policy_deleted":     {Severity: "MEDIUM", Category: "autokey"},
		"audit.autokey.service_policies_viewed":    {Severity: "LOW", Category: "autokey"},
		"audit.autokey.request_created":            {Severity: "LOW", Category: "autokey"},
		"audit.autokey.request_reused":             {Severity: "LOW", Category: "autokey"},
		"audit.autokey.request_pending_approval":   {Severity: "MEDIUM", Category: "autokey"},
		"audit.autokey.request_provisioned":        {Severity: "HIGH", Category: "autokey"},
		"audit.autokey.request_denied":             {Severity: "MEDIUM", Category: "autokey"},
		"audit.autokey.request_failed":             {Severity: "HIGH", Category: "autokey"},
		"audit.autokey.summary_viewed":             {Severity: "LOW", Category: "autokey"},
		"audit.autokey.requests_viewed":            {Severity: "LOW", Category: "autokey"},
		"audit.autokey.handles_viewed":             {Severity: "LOW", Category: "autokey"},
		"audit.cert.renewal_schedule_viewed":       {Severity: "LOW", Category: "certs"},
		"audit.cert.renewal_window_missed":         {Severity: "HIGH", Category: "certs"},
		"audit.cert.emergency_rotation_started":    {Severity: "HIGH", Category: "certs"},
		"audit.cert.mass_renewal_risk_detected":    {Severity: "MEDIUM", Category: "certs"},
		"audit.posture.dashboard_viewed":           {Severity: "LOW", Category: "posture"},
		"audit.workload.settings_updated":          {Severity: "MEDIUM", Category: "workload"},
		"audit.workload.registration_upserted":     {Severity: "MEDIUM", Category: "workload"},
		"audit.workload.registration_deleted":      {Severity: "MEDIUM", Category: "workload"},
		"audit.workload.federation_bundle_upserted": {Severity: "MEDIUM", Category: "workload"},
		"audit.workload.federation_bundle_deleted": {Severity: "MEDIUM", Category: "workload"},
		"audit.workload.svid_issued":               {Severity: "HIGH", Category: "workload"},
		"audit.workload.token_exchanged":           {Severity: "HIGH", Category: "workload"},
		"audit.workload.registrations_viewed":      {Severity: "LOW", Category: "workload"},
		"audit.workload.federation_viewed":         {Severity: "LOW", Category: "workload"},
		"audit.workload.issuance_history_viewed":   {Severity: "LOW", Category: "workload"},
		"audit.workload.summary_viewed":            {Severity: "LOW", Category: "workload"},
		"audit.workload.key_usage_viewed":          {Severity: "LOW", Category: "workload"},
		"audit.workload.graph_viewed":              {Severity: "LOW", Category: "workload"},
		"audit.pqc.policy_viewed":                  {Severity: "LOW", Category: "pqc"},
		"audit.pqc.policy_updated":                 {Severity: "MEDIUM", Category: "pqc"},
		"audit.pqc.inventory_viewed":               {Severity: "LOW", Category: "pqc"},
		"audit.pqc.migration_report_viewed":        {Severity: "LOW", Category: "pqc"},
		"audit.reporting.evidence_pack_requested":  {Severity: "MEDIUM", Category: "reporting"},
		"audit.reporting.mttd_stats_viewed":        {Severity: "LOW", Category: "reporting"},
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
