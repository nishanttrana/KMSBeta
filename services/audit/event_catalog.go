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
		"workload", "confidential", "autokey", "signing", "keyaccess",
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
		"audit.audit.chain_broken":                  {Severity: "CRITICAL", Category: "audit"},
		"audit.auth.mfa_failed":                     {Severity: "HIGH", Category: "auth"},
		"audit.auth.client_token_issued":            {Severity: "LOW", Category: "auth"},
		"audit.auth.mtls_binding_failed":            {Severity: "HIGH", Category: "auth"},
		"audit.auth.client_dpop_failed":             {Severity: "HIGH", Category: "auth"},
		"audit.auth.dpop_replay_detected":           {Severity: "HIGH", Category: "auth"},
		"audit.auth.client_http_signature_failed":   {Severity: "HIGH", Category: "auth"},
		"audit.auth.http_signature_replay_detected": {Severity: "HIGH", Category: "auth"},
		"audit.auth.rest_client_security_viewed":    {Severity: "LOW", Category: "auth"},
		"audit.auth.scim_settings_updated":          {Severity: "MEDIUM", Category: "auth"},
		"audit.auth.scim_token_rotated":             {Severity: "HIGH", Category: "auth"},
		"audit.auth.scim_summary_viewed":            {Severity: "LOW", Category: "auth"},
		"audit.auth.scim_users_viewed":              {Severity: "LOW", Category: "auth"},
		"audit.auth.scim_groups_viewed":             {Severity: "LOW", Category: "auth"},
		"audit.auth.scim_user_provisioned":          {Severity: "MEDIUM", Category: "auth"},
		"audit.auth.scim_user_updated":              {Severity: "MEDIUM", Category: "auth"},
		"audit.auth.scim_user_disabled":             {Severity: "MEDIUM", Category: "auth"},
		"audit.auth.scim_user_deprovisioned":        {Severity: "HIGH", Category: "auth"},
		"audit.auth.scim_group_provisioned":         {Severity: "MEDIUM", Category: "auth"},
		"audit.auth.scim_group_updated":             {Severity: "MEDIUM", Category: "auth"},
		"audit.auth.scim_group_deleted":             {Severity: "MEDIUM", Category: "auth"},
		"audit.cluster.node_failed":                 {Severity: "HIGH", Category: "cluster"},
		"audit.compliance.assessment_delta_viewed":  {Severity: "LOW", Category: "compliance"},
		"audit.confidential.policy_updated":         {Severity: "MEDIUM", Category: "confidential"},
		"audit.confidential.key_release_evaluated":  {Severity: "HIGH", Category: "confidential"},
		"audit.key.compromised":                     {Severity: "CRITICAL", Category: "key"},
		"audit.key.fips.violation_blocked":          {Severity: "CRITICAL", Category: "key"},
		"audit.key.rest_mtls_binding_failed":        {Severity: "HIGH", Category: "key"},
		"audit.key.rest_signature_failed":           {Severity: "HIGH", Category: "key"},
		"audit.key.rest_unsigned_blocked":           {Severity: "MEDIUM", Category: "key"},
		"audit.key.request_replay_detected":         {Severity: "HIGH", Category: "key"},
		"audit.fde.unlock_failed":                   {Severity: "CRITICAL", Category: "dataprotect"},
		"audit.integrity_check_failed":              {Severity: "CRITICAL", Category: "audit"},
		"audit.payment.policy_updated":              {Severity: "MEDIUM", Category: "payment"},
		"audit.payment.ap2_profile_updated":         {Severity: "MEDIUM", Category: "payment"},
		"audit.payment.ap2_evaluated":               {Severity: "LOW", Category: "payment"},
		"audit.autokey.settings_updated":            {Severity: "MEDIUM", Category: "autokey"},
		"audit.autokey.settings_viewed":             {Severity: "LOW", Category: "autokey"},
		"audit.autokey.template_upserted":           {Severity: "MEDIUM", Category: "autokey"},
		"audit.autokey.template_deleted":            {Severity: "MEDIUM", Category: "autokey"},
		"audit.autokey.templates_viewed":            {Severity: "LOW", Category: "autokey"},
		"audit.autokey.service_policy_upserted":     {Severity: "MEDIUM", Category: "autokey"},
		"audit.autokey.service_policy_deleted":      {Severity: "MEDIUM", Category: "autokey"},
		"audit.autokey.service_policies_viewed":     {Severity: "LOW", Category: "autokey"},
		"audit.autokey.request_created":             {Severity: "LOW", Category: "autokey"},
		"audit.autokey.request_reused":              {Severity: "LOW", Category: "autokey"},
		"audit.autokey.request_pending_approval":    {Severity: "MEDIUM", Category: "autokey"},
		"audit.autokey.request_provisioned":         {Severity: "HIGH", Category: "autokey"},
		"audit.autokey.request_denied":              {Severity: "MEDIUM", Category: "autokey"},
		"audit.autokey.request_failed":              {Severity: "HIGH", Category: "autokey"},
		"audit.autokey.summary_viewed":              {Severity: "LOW", Category: "autokey"},
		"audit.autokey.requests_viewed":             {Severity: "LOW", Category: "autokey"},
		"audit.autokey.handles_viewed":              {Severity: "LOW", Category: "autokey"},
		"audit.keyaccess.settings_updated":          {Severity: "MEDIUM", Category: "keyaccess"},
		"audit.keyaccess.settings_viewed":           {Severity: "LOW", Category: "keyaccess"},
		"audit.keyaccess.codes_viewed":              {Severity: "LOW", Category: "keyaccess"},
		"audit.keyaccess.code_upserted":             {Severity: "MEDIUM", Category: "keyaccess"},
		"audit.keyaccess.code_deleted":              {Severity: "MEDIUM", Category: "keyaccess"},
		"audit.keyaccess.summary_viewed":            {Severity: "LOW", Category: "keyaccess"},
		"audit.keyaccess.decisions_viewed":          {Severity: "LOW", Category: "keyaccess"},
		"audit.keyaccess.decision_evaluated":        {Severity: "HIGH", Category: "keyaccess"},
		"audit.keyaccess.approval_required":         {Severity: "MEDIUM", Category: "keyaccess"},
		"audit.signing.settings_viewed":             {Severity: "LOW", Category: "signing"},
		"audit.signing.settings_updated":            {Severity: "MEDIUM", Category: "signing"},
		"audit.signing.summary_viewed":              {Severity: "LOW", Category: "signing"},
		"audit.signing.profiles_viewed":             {Severity: "LOW", Category: "signing"},
		"audit.signing.profile_upserted":            {Severity: "MEDIUM", Category: "signing"},
		"audit.signing.profile_deleted":             {Severity: "MEDIUM", Category: "signing"},
		"audit.signing.records_viewed":              {Severity: "LOW", Category: "signing"},
		"audit.signing.artifact_signed":             {Severity: "HIGH", Category: "signing"},
		"audit.signing.artifact_verified":           {Severity: "MEDIUM", Category: "signing"},
		"audit.mpc.dkg_initiated":                   {Severity: "MEDIUM", Category: "mpc"},
		"audit.mpc.dkg_completed":                   {Severity: "MEDIUM", Category: "mpc"},
		"audit.mpc.threshold_sign_initiated":        {Severity: "HIGH", Category: "mpc"},
		"audit.mpc.threshold_sign_completed":        {Severity: "HIGH", Category: "mpc"},
		"audit.mpc.threshold_sign_failed":           {Severity: "HIGH", Category: "mpc"},
		"audit.mpc.threshold_decrypt_initiated":     {Severity: "HIGH", Category: "mpc"},
		"audit.mpc.threshold_decrypt_completed":     {Severity: "HIGH", Category: "mpc"},
		"audit.mpc.share_refreshed":                 {Severity: "MEDIUM", Category: "mpc"},
		"audit.mpc.share_backed_up":                 {Severity: "HIGH", Category: "mpc"},
		"audit.mpc.key_rotated":                     {Severity: "MEDIUM", Category: "mpc"},
		"audit.mpc.participant_registered":          {Severity: "MEDIUM", Category: "mpc"},
		"audit.mpc.participant_updated":             {Severity: "MEDIUM", Category: "mpc"},
		"audit.mpc.participant_deleted":             {Severity: "MEDIUM", Category: "mpc"},
		"audit.mpc.policy_created":                  {Severity: "MEDIUM", Category: "mpc"},
		"audit.mpc.policy_updated":                  {Severity: "MEDIUM", Category: "mpc"},
		"audit.mpc.policy_deleted":                  {Severity: "MEDIUM", Category: "mpc"},
		"audit.mpc.key_revoked":                     {Severity: "HIGH", Category: "mpc"},
		"audit.mpc.key_group_set":                   {Severity: "MEDIUM", Category: "mpc"},
		"audit.cert.renewal_schedule_viewed":        {Severity: "LOW", Category: "certs"},
		"audit.cert.renewal_window_missed":          {Severity: "HIGH", Category: "certs"},
		"audit.cert.emergency_rotation_started":     {Severity: "HIGH", Category: "certs"},
		"audit.cert.mass_renewal_risk_detected":     {Severity: "MEDIUM", Category: "certs"},
		"audit.cert.star_summary_viewed":            {Severity: "LOW", Category: "certs"},
		"audit.cert.star_subscription_created":      {Severity: "MEDIUM", Category: "certs"},
		"audit.cert.star_subscription_renewed":      {Severity: "MEDIUM", Category: "certs"},
		"audit.cert.star_subscription_deleted":      {Severity: "MEDIUM", Category: "certs"},
		"audit.cert.star_subscription_failed":       {Severity: "HIGH", Category: "certs"},
		"audit.cert.star_delegation_configured":     {Severity: "MEDIUM", Category: "certs"},
		"audit.cert.star_mass_rollout_risk_detected": {Severity: "MEDIUM", Category: "certs"},
		"audit.posture.dashboard_viewed":            {Severity: "LOW", Category: "posture"},
		"audit.workload.settings_updated":           {Severity: "MEDIUM", Category: "workload"},
		"audit.workload.registration_upserted":      {Severity: "MEDIUM", Category: "workload"},
		"audit.workload.registration_deleted":       {Severity: "MEDIUM", Category: "workload"},
		"audit.workload.federation_bundle_upserted": {Severity: "MEDIUM", Category: "workload"},
		"audit.workload.federation_bundle_deleted":  {Severity: "MEDIUM", Category: "workload"},
		"audit.workload.svid_issued":                {Severity: "HIGH", Category: "workload"},
		"audit.workload.token_exchanged":            {Severity: "HIGH", Category: "workload"},
		"audit.workload.registrations_viewed":       {Severity: "LOW", Category: "workload"},
		"audit.workload.federation_viewed":          {Severity: "LOW", Category: "workload"},
		"audit.workload.issuance_history_viewed":    {Severity: "LOW", Category: "workload"},
		"audit.workload.summary_viewed":             {Severity: "LOW", Category: "workload"},
		"audit.workload.key_usage_viewed":           {Severity: "LOW", Category: "workload"},
		"audit.workload.graph_viewed":               {Severity: "LOW", Category: "workload"},
		"audit.pqc.policy_viewed":                   {Severity: "LOW", Category: "pqc"},
		"audit.pqc.policy_updated":                  {Severity: "MEDIUM", Category: "pqc"},
		"audit.pqc.inventory_viewed":                {Severity: "LOW", Category: "pqc"},
		"audit.pqc.migration_report_viewed":         {Severity: "LOW", Category: "pqc"},
		"audit.reporting.evidence_pack_requested":   {Severity: "MEDIUM", Category: "reporting"},
		"audit.reporting.mttd_stats_viewed":         {Severity: "LOW", Category: "reporting"},
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
