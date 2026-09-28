package main

import "strings"

type EventMeta struct {
	Severity string
}

var auditEventCatalog = buildAuditEventCatalog()

func buildAuditEventCatalog() map[string]EventMeta {
	services := []string{
		"auth", "key", "keycore", "secrets", "certs", "policy", "governance", "pqc", "audit", "byok", "ai",
		"discovery", "compliance", "hyok", "ekm", "reporting", "cluster", "payment", "sbom",
		"workload", "confidential", "autokey", "signing", "keyaccess",
		"dataprotect", "kmip", "cloud",
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
			catalog[action] = EventMeta{Severity: severityForVerb(verb)}
		}
	}

	overrides := map[string]EventMeta{
		"audit.audit.chain_broken":                   {Severity: "CRITICAL"},
		"audit.auth.mfa_failed":                      {Severity: "HIGH"},
		"audit.auth.client_token_issued":             {Severity: "LOW"},
		"audit.auth.mtls_binding_failed":             {Severity: "HIGH"},
		"audit.auth.client_dpop_failed":              {Severity: "HIGH"},
		"audit.auth.dpop_replay_detected":            {Severity: "HIGH"},
		"audit.auth.client_http_signature_failed":    {Severity: "HIGH"},
		"audit.auth.http_signature_replay_detected":  {Severity: "HIGH"},
		"audit.auth.rest_client_security_viewed":     {Severity: "LOW"},
		"audit.auth.scim_settings_updated":           {Severity: "MEDIUM"},
		"audit.auth.scim_token_rotated":              {Severity: "HIGH"},
		"audit.auth.scim_summary_viewed":             {Severity: "LOW"},
		"audit.auth.scim_users_viewed":               {Severity: "LOW"},
		"audit.auth.scim_groups_viewed":              {Severity: "LOW"},
		"audit.auth.scim_user_provisioned":           {Severity: "MEDIUM"},
		"audit.auth.scim_user_updated":               {Severity: "MEDIUM"},
		"audit.auth.scim_user_disabled":              {Severity: "MEDIUM"},
		"audit.auth.scim_user_deprovisioned":         {Severity: "HIGH"},
		"audit.auth.scim_group_provisioned":          {Severity: "MEDIUM"},
		"audit.auth.scim_group_updated":              {Severity: "MEDIUM"},
		"audit.auth.scim_group_deleted":              {Severity: "MEDIUM"},
		"audit.cluster.node_failed":                  {Severity: "HIGH"},
		"audit.compliance.assessment_delta_viewed":   {Severity: "LOW"},
		"audit.confidential.policy_updated":          {Severity: "MEDIUM"},
		"audit.confidential.key_release_evaluated":   {Severity: "HIGH"},
		"audit.key.compromised":                      {Severity: "CRITICAL"},
		"audit.key.fips.violation_blocked":           {Severity: "CRITICAL"},
		"audit.key.rest_mtls_binding_failed":         {Severity: "HIGH"},
		"audit.key.rest_signature_failed":            {Severity: "HIGH"},
		"audit.key.rest_unsigned_blocked":            {Severity: "MEDIUM"},
		"audit.key.request_replay_detected":          {Severity: "HIGH"},
		"audit.fde.unlock_failed":                    {Severity: "CRITICAL"},
		"audit.integrity_check_failed":               {Severity: "CRITICAL"},
		"audit.payment.policy_updated":               {Severity: "MEDIUM"},
		"audit.payment.ap2_profile_updated":          {Severity: "MEDIUM"},
		"audit.payment.ap2_evaluated":                {Severity: "LOW"},
		"audit.autokey.settings_updated":             {Severity: "MEDIUM"},
		"audit.autokey.settings_viewed":              {Severity: "LOW"},
		"audit.autokey.template_upserted":            {Severity: "MEDIUM"},
		"audit.autokey.template_deleted":             {Severity: "MEDIUM"},
		"audit.autokey.templates_viewed":             {Severity: "LOW"},
		"audit.autokey.service_policy_upserted":      {Severity: "MEDIUM"},
		"audit.autokey.service_policy_deleted":       {Severity: "MEDIUM"},
		"audit.autokey.service_policies_viewed":      {Severity: "LOW"},
		"audit.autokey.request_created":              {Severity: "LOW"},
		"audit.autokey.request_reused":               {Severity: "LOW"},
		"audit.autokey.request_pending_approval":     {Severity: "MEDIUM"},
		"audit.autokey.request_provisioned":          {Severity: "HIGH"},
		"audit.autokey.request_denied":               {Severity: "MEDIUM"},
		"audit.autokey.request_failed":               {Severity: "HIGH"},
		"audit.autokey.summary_viewed":               {Severity: "LOW"},
		"audit.autokey.requests_viewed":              {Severity: "LOW"},
		"audit.autokey.handles_viewed":               {Severity: "LOW"},
		"audit.keyaccess.settings_updated":           {Severity: "MEDIUM"},
		"audit.keyaccess.settings_viewed":            {Severity: "LOW"},
		"audit.keyaccess.codes_viewed":               {Severity: "LOW"},
		"audit.keyaccess.code_upserted":              {Severity: "MEDIUM"},
		"audit.keyaccess.code_deleted":               {Severity: "MEDIUM"},
		"audit.keyaccess.summary_viewed":             {Severity: "LOW"},
		"audit.keyaccess.decisions_viewed":           {Severity: "LOW"},
		"audit.keyaccess.decision_evaluated":         {Severity: "HIGH"},
		"audit.keyaccess.approval_required":          {Severity: "MEDIUM"},
		"audit.signing.settings_viewed":              {Severity: "LOW"},
		"audit.signing.settings_updated":             {Severity: "MEDIUM"},
		"audit.signing.summary_viewed":               {Severity: "LOW"},
		"audit.signing.profiles_viewed":              {Severity: "LOW"},
		"audit.signing.profile_upserted":             {Severity: "MEDIUM"},
		"audit.signing.profile_deleted":              {Severity: "MEDIUM"},
		"audit.signing.records_viewed":               {Severity: "LOW"},
		"audit.signing.artifact_signed":              {Severity: "HIGH"},
		"audit.signing.artifact_verified":            {Severity: "MEDIUM"},
		"audit.cert.renewal_schedule_viewed":         {Severity: "LOW"},
		"audit.cert.renewal_window_missed":           {Severity: "HIGH"},
		"audit.cert.emergency_rotation_started":      {Severity: "HIGH"},
		"audit.cert.mass_renewal_risk_detected":      {Severity: "MEDIUM"},
		"audit.cert.star_summary_viewed":             {Severity: "LOW"},
		"audit.cert.star_subscription_created":       {Severity: "MEDIUM"},
		"audit.cert.star_subscription_renewed":       {Severity: "MEDIUM"},
		"audit.cert.star_subscription_deleted":       {Severity: "MEDIUM"},
		"audit.cert.star_subscription_failed":        {Severity: "HIGH"},
		"audit.cert.star_delegation_configured":      {Severity: "MEDIUM"},
		"audit.cert.star_mass_rollout_risk_detected": {Severity: "MEDIUM"},
		"audit.posture.dashboard_viewed":             {Severity: "LOW"},
		"audit.workload.settings_updated":            {Severity: "MEDIUM"},
		"audit.workload.registration_upserted":       {Severity: "MEDIUM"},
		"audit.workload.registration_deleted":        {Severity: "MEDIUM"},
		"audit.workload.federation_bundle_upserted":  {Severity: "MEDIUM"},
		"audit.workload.federation_bundle_deleted":   {Severity: "MEDIUM"},
		"audit.workload.svid_issued":                 {Severity: "HIGH"},
		"audit.workload.token_exchanged":             {Severity: "HIGH"},
		"audit.workload.registrations_viewed":        {Severity: "LOW"},
		"audit.workload.federation_viewed":           {Severity: "LOW"},
		"audit.workload.issuance_history_viewed":     {Severity: "LOW"},
		"audit.workload.summary_viewed":              {Severity: "LOW"},
		"audit.workload.key_usage_viewed":            {Severity: "LOW"},
		"audit.workload.graph_viewed":                {Severity: "LOW"},
		"audit.pqc.policy_viewed":                    {Severity: "LOW"},
		"audit.pqc.policy_updated":                   {Severity: "MEDIUM"},
		"audit.pqc.inventory_viewed":                 {Severity: "LOW"},
		"audit.pqc.migration_report_viewed":          {Severity: "LOW"},
		"audit.reporting.evidence_pack_requested":    {Severity: "MEDIUM"},
		"audit.reporting.mttd_stats_viewed":          {Severity: "LOW"},

		// cloud (BYOK/cloud connector sync)
		"audit.cloud.connector_configured": {Severity: "MEDIUM"},
		"audit.cloud.connector_deleted":    {Severity: "HIGH"},
		"audit.cloud.key_imported":         {Severity: "MEDIUM"},
		"audit.cloud.key_rotated":          {Severity: "MEDIUM"},
		"audit.cloud.key_access_denied":    {Severity: "HIGH"},
		"audit.cloud.approval_required":    {Severity: "MEDIUM"},
		"audit.cloud.sync_started":         {Severity: "LOW"},
		"audit.cloud.sync_completed":       {Severity: "LOW"},
		"audit.cloud.sync_failed":          {Severity: "HIGH"},

		// keycore (canary-specific events under keycore subject)
		"audit.keycore.canary_tripped": {Severity: "CRITICAL"},

		// Automation + ALKM + PQC events. These severities map operator
		// expectations: detection signals are MEDIUM (need review but
		// not paging), automatic remediations are HIGH (operator should
		// see the action took place), exhaustion / breach signals are
		// CRITICAL.
		"audit.security.hndl_pattern_detected":    {Severity: "HIGH"},
		"audit.security.auto_quarantined":         {Severity: "HIGH"},
		"audit.policy.quota_exceeded":             {Severity: "MEDIUM"},
		"audit.policy.crypto_floor_violation":     {Severity: "HIGH"},
		"audit.key.zeroization_verified":          {Severity: "LOW"},
		"audit.key.archive_requested":             {Severity: "LOW"},
		"audit.key.archive_completed":             {Severity: "LOW"},
		"audit.key.lifecycle_auto_transition":     {Severity: "MEDIUM"},
		"audit.key.predictive_rotation_scheduled": {Severity: "MEDIUM"},
		"audit.key.wake_kat_failed":               {Severity: "CRITICAL"},
		"audit.key.dependency_blocked_destroy":    {Severity: "MEDIUM"},
		"audit.key.hbs_exhausted":                 {Severity: "CRITICAL"},
		"audit.key.anomaly_scan_completed":        {Severity: "MEDIUM"},
		"audit.key.dspm_finding_upserted":         {Severity: "HIGH"},
		"audit.key.kdf_derived":                   {Severity: "MEDIUM"},
		"audit.governance.backup_key_split":       {Severity: "HIGH"},
		"audit.key.audit_chain_anchored":          {Severity: "MEDIUM"},
		"audit.key.material_fingerprint_verified": {Severity: "HIGH"},
		"audit.key.searchable_token_generated":    {Severity: "MEDIUM"},
		"audit.key.compliance_dashboard_viewed":   {Severity: "LOW"},
		"audit.key.cost_optimization_viewed":      {Severity: "LOW"},
		"audit.tenant.onboarded":                  {Severity: "LOW"},
		"audit.tenant.quota_set":                  {Severity: "LOW"},
		"audit.kmip.client_dormant":               {Severity: "LOW"},
		"audit.kmip.client_revoked":               {Severity: "HIGH"},
		"audit.kmip.attribute_mutation_denied":    {Severity: "MEDIUM"},
		"audit.kmip.authorization_denied":         {Severity: "HIGH"},
		"audit.health.incident":                   {Severity: "HIGH"},
		"audit.pqc.migration_plan_built":          {Severity: "LOW"},
		"audit.pqc.migration_step_executed":       {Severity: "MEDIUM"},
		"audit.pqc.attestation_recorded":          {Severity: "LOW"},
		"audit.cbom.inventory_viewed":             {Severity: "LOW"},
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
