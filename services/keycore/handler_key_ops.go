package main

import "vecta-kms/pkg/route"

// keyOpsRouter puts the rest of keycore's non-crypto routes behind the route
// kernel (4.0.0-beta): ceremonies, compromise reporting, inventory and
// analytics writes, enterprise controls, scheduling, attestation and
// integrity checks. Before this, any verified token could, for example,
// report a compromise (which auto-suspends the key), rotate any key through
// an orchestration run, or read another key's KCV through the fingerprint
// check. Routes that name a key in the path also require the key to be
// visible to the caller (key_visibility.go). Handlers are unchanged; each
// route emits audit.key.<action>, refusals included.
//
// Left on the legacy mux, each guarded otherwise: crypto operations (per-key
// grants), cluster master-key transfer (cluster-manager identity), the
// attestation public key and RNG health (public facts, token required), and
// hash / random (no key involved, token required).
func (h *Handler) keyOpsRouter(audit route.Emitter) *route.Router {
	r := route.New("key", audit, nil)
	r.Handle("GET /ceremony/guardians", route.Spec{Action: "ceremony_guardians_listed", Permission: "key.ceremony.read", Resource: "key"}, legacy(h.handleListGuardians))
	r.Handle("POST /ceremony/guardians", route.Spec{Action: "ceremony_guardian_created", Permission: "key.ceremony.write", Resource: "key", Severity: "warning"}, legacy(h.handleCreateGuardian))
	r.Handle("DELETE /ceremony/guardians/{id}", route.Spec{Action: "ceremony_guardian_deleted", Permission: "key.ceremony.write", Resource: "key", TargetParam: "id", Severity: "warning"}, legacy(h.handleDeleteGuardian))
	r.Handle("GET /ceremony", route.Spec{Action: "ceremonies_listed", Permission: "key.ceremony.read", Resource: "key"}, legacy(h.handleListCeremonies))
	r.Handle("GET /ceremony/{id}", route.Spec{Action: "ceremony_read", Permission: "key.ceremony.read", Resource: "key", TargetParam: "id"}, legacy(h.handleGetCeremony))
	r.Handle("POST /ceremony", route.Spec{Action: "ceremony_created", Permission: "key.ceremony.write", Resource: "key", Severity: "warning"}, legacy(h.handleCreateCeremony))
	r.Handle("POST /ceremony/{id}/shares", route.Spec{Action: "ceremony_share_submitted", Permission: "key.ceremony.share", Resource: "key", TargetParam: "id", Severity: "warning"}, legacy(h.handleSubmitShare))
	r.Handle("POST /ceremony/{id}/complete", route.Spec{Action: "ceremony_completed", Permission: "key.ceremony.write", Resource: "key", TargetParam: "id", Severity: "critical"}, legacy(h.handleCompleteCeremony))
	r.Handle("POST /ceremony/{id}/abort", route.Spec{Action: "ceremony_aborted", Permission: "key.ceremony.write", Resource: "key", TargetParam: "id", Severity: "warning"}, legacy(h.handleAbortCeremony))
	r.Handle("POST /keys/{id}/usage/meter", route.Spec{Action: "usage_meter_requested", Permission: "key.usage.meter", Resource: "key", TargetParam: "id"}, legacy(h.handleMeterUsage))
	r.Handle("POST /keys/{id}/rotation-metrics", route.Spec{Action: "rotation_metric_recorded", Permission: "key.rotation.write", Resource: "key", TargetParam: "id"}, legacy(h.visibleKeyRoute(h.handleRecordKeyRotationMetric)))
	r.Handle("POST /keys/{id}/health/recalculate", route.Spec{Action: "health_recalculated", Permission: "key.health.write", Resource: "key", TargetParam: "id"}, legacy(h.visibleKeyRoute(h.handleRecalculateKeyHealth)))
	r.Handle("POST /inventory/sync", route.Spec{Action: "inventory_synced", Permission: "key.inventory.write", Resource: "key"}, legacy(h.handleSyncInventory))
	r.Handle("POST /inventory/dependencies", route.Spec{Action: "inventory_dependency_upserted", Permission: "key.inventory.write", Resource: "key"}, legacy(h.handleUpsertKeyDependencyRecord))
	r.Handle("POST /compromise/events", route.Spec{Action: "compromise_reported", Permission: "key.compromise", Resource: "key", Severity: "critical"}, legacy(h.handleReportCompromiseEvent))
	r.Handle("POST /compromise/events/{id}/status", route.Spec{Action: "compromise_status_updated", Permission: "key.compromise", Resource: "key", TargetParam: "id", Severity: "warning"}, legacy(h.handleUpdateCompromiseEventStatus))
	r.Handle("POST /compromise/advisories/ingest", route.Spec{Action: "compromise_advisories_ingested", Permission: "key.compromise", Resource: "key", Severity: "warning"}, legacy(h.handleIngestCompromiseAdvisories))
	r.Handle("POST /analytics/metrics", route.Spec{Action: "analytics_metric_recorded", Permission: "key.analytics.write", Resource: "key"}, legacy(h.handleRecordKeyAnalyticsMetric))
	r.Handle("GET /enterprise/controls", route.Spec{Action: "enterprise_controls_listed", Permission: "key.enterprise.read", Resource: "key"}, legacy(h.handleListEnterpriseControls))
	r.Handle("GET /enterprise/controls/{category}/{id}", route.Spec{Action: "enterprise_control_read", Permission: "key.enterprise.read", Resource: "key", TargetParam: "id"}, legacy(h.handleGetEnterpriseControl))
	r.Handle("POST /enterprise/controls", route.Spec{Action: "enterprise_control_upserted", Permission: "key.enterprise.write", Resource: "key"}, legacy(h.handleUpsertEnterpriseControl))
	r.Handle("POST /enterprise/anomaly/scan", route.Spec{Action: "enterprise_anomaly_scan", Permission: "key.enterprise.write", Resource: "key"}, legacy(h.handleRunEnterpriseAnomalyScan))
	r.Handle("POST /enterprise/dspm/findings", route.Spec{Action: "dspm_finding_upserted", Permission: "key.enterprise.write", Resource: "key"}, legacy(h.handleUpsertKeyDSPMFinding))
	r.Handle("POST /enterprise/kdf/derive", route.Spec{Action: "enterprise_kdf_derive", Permission: "key.enterprise.write", Resource: "key"}, legacy(h.handleEnterpriseKDFDerive))
	r.Handle("POST /enterprise/verification/fingerprint", route.Spec{Action: "fingerprint_verified", Permission: "key.enterprise.write", Resource: "key"}, legacy(h.handleVerifyKeyFingerprint))
	r.Handle("POST /enterprise/advanced-encryption/search-token", route.Spec{Action: "search_token_created", Permission: "key.enterprise.write", Resource: "key"}, legacy(h.handleCreateSearchableToken))
	r.Handle("POST /enterprise/advanced-encryption/modes", route.Spec{Action: "enterprise_advanced_encryption_upserted", Permission: "key.enterprise.write", Resource: "key"}, legacy(h.handleUpsertEnterpriseControlCategory(controlCategoryAdvancedEncryption)))
	r.Handle("POST /enterprise/orchestration/workflows", route.Spec{Action: "enterprise_orchestration_workflow_upserted", Permission: "key.enterprise.write", Resource: "key"}, legacy(h.handleUpsertEnterpriseControlCategory(controlCategoryOrchestrationWorkflow)))
	r.Handle("POST /enterprise/federation/providers", route.Spec{Action: "enterprise_federation_provider_upserted", Permission: "key.enterprise.write", Resource: "key"}, legacy(h.handleUpsertEnterpriseControlCategory(controlCategoryFederationProvider)))
	r.Handle("POST /enterprise/federation/mappings", route.Spec{Action: "enterprise_federation_mapping_upserted", Permission: "key.enterprise.write", Resource: "key"}, legacy(h.handleUpsertEnterpriseControlCategory(controlCategoryFederationMapping)))
	r.Handle("POST /enterprise/federation/failovers", route.Spec{Action: "enterprise_federation_failover_upserted", Permission: "key.enterprise.write", Resource: "key"}, legacy(h.handleUpsertEnterpriseControlCategory(controlCategoryFederationFailover)))
	r.Handle("POST /enterprise/binding/policies", route.Spec{Action: "enterprise_binding_policy_upserted", Permission: "key.enterprise.write", Resource: "key"}, legacy(h.handleUpsertEnterpriseControlCategory(controlCategoryBindingPolicy)))
	r.Handle("POST /enterprise/edge/agents", route.Spec{Action: "enterprise_edge_agent_upserted", Permission: "key.enterprise.write", Resource: "key"}, legacy(h.handleUpsertEnterpriseControlCategory(controlCategoryEdgeAgent)))
	r.Handle("POST /enterprise/edge/leases", route.Spec{Action: "enterprise_edge_lease_upserted", Permission: "key.enterprise.write", Resource: "key"}, legacy(h.handleUpsertEnterpriseControlCategory(controlCategoryEdgeLease)))
	r.Handle("POST /enterprise/edge/receipts", route.Spec{Action: "enterprise_edge_receipt_upserted", Permission: "key.enterprise.write", Resource: "key"}, legacy(h.handleUpsertEnterpriseControlCategory(controlCategoryEdgeReceipt)))
	r.Handle("POST /enterprise/sharing/grants", route.Spec{Action: "enterprise_sharing_grant_upserted", Permission: "key.enterprise.write", Resource: "key"}, legacy(h.handleUpsertEnterpriseControlCategory(controlCategorySharingGrant)))
	r.Handle("POST /enterprise/metadata/profiles", route.Spec{Action: "enterprise_metadata_profile_upserted", Permission: "key.enterprise.write", Resource: "key"}, legacy(h.handleUpsertEnterpriseControlCategory(controlCategoryMetadataProfile)))
	r.Handle("POST /enterprise/threat/signals", route.Spec{Action: "enterprise_threat_signal_upserted", Permission: "key.enterprise.write", Resource: "key"}, legacy(h.handleUpsertEnterpriseControlCategory(controlCategoryThreatSignal)))
	// An orchestration run rotates the keys it names, so it needs key.rotate.
	r.Handle("POST /enterprise/orchestration/runs", route.Spec{Action: "orchestration_run_requested", Permission: "key.rotate", Resource: "key", Severity: "warning"}, legacy(h.handleTriggerOrchestrationRun))
	r.Handle("GET /scheduling/jobs", route.Spec{Action: "scheduling_jobs_listed", Permission: "key.scheduling.read", Resource: "key"}, legacy(h.handleListSchedulingJobs))
	r.Handle("POST /scheduling/jobs", route.Spec{Action: "scheduling_job_created", Permission: "key.scheduling.write", Resource: "key"}, legacy(h.handleCreateSchedulingJob))
	r.Handle("PATCH /scheduling/jobs/{id}", route.Spec{Action: "scheduling_job_updated", Permission: "key.scheduling.write", Resource: "key", TargetParam: "id"}, legacy(h.handleUpdateSchedulingJob))
	r.Handle("DELETE /scheduling/jobs/{id}", route.Spec{Action: "scheduling_job_deleted", Permission: "key.scheduling.write", Resource: "key", TargetParam: "id", Severity: "warning"}, legacy(h.handleDeleteSchedulingJob))
	r.Handle("POST /keys/{id}/attest", route.Spec{Action: "attest_requested", Permission: "key.attest", Resource: "key", TargetParam: "id"}, legacy(h.visibleKeyRoute(h.handleAttestKey)))
	r.Handle("POST /keys/{id}/verify-material", route.Spec{Action: "verify_material_requested", Permission: "key.integrity.verify", Resource: "key", TargetParam: "id"}, legacy(h.visibleKeyRoute(h.handleVerifyKeyMaterial)))
	r.Handle("POST /keys/{id}/zeroize-verify", route.Spec{Action: "zeroize_verify_requested", Permission: "key.integrity.verify", Resource: "key", TargetParam: "id"}, legacy(h.visibleKeyRoute(h.handleZeroizeVerify)))
	r.Handle("POST /fips/self-test", route.Spec{Action: "fips_self_test_requested", Permission: "key.fips.selftest", Resource: "key"}, legacy(h.handleFIPSSelfTest))
	return r
}
