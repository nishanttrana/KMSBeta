package main

import (
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"vecta-kms/pkg/crypto"
)

func (h *Handler) handleListEnterpriseControls(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.store.ListEnterpriseControlRecords(r.Context(), tenantID, EnterpriseControlQuery{
		Category: strings.TrimSpace(r.URL.Query().Get("category")),
		KeyID:    strings.TrimSpace(r.URL.Query().Get("key_id")),
		Status:   strings.TrimSpace(r.URL.Query().Get("status")),
		Limit:    limitQuery(r, 200),
		Offset:   offsetQuery(r),
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "enterprise_controls_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "request_id": reqID})
}

func (h *Handler) handleGetEnterpriseControl(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	item, err := h.svc.store.GetEnterpriseControlRecord(r.Context(), tenantID, r.PathValue("category"), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "enterprise_control_not_found", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"control": item, "request_id": reqID})
}

func (h *Handler) handleUpsertEnterpriseControl(w http.ResponseWriter, r *http.Request) {
	h.upsertEnterpriseControl(w, r, "")
}

func (h *Handler) handleUpsertEnterpriseControlCategory(category string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.upsertEnterpriseControl(w, r, category)
	}
}

func (h *Handler) upsertEnterpriseControl(w http.ResponseWriter, r *http.Request, category string) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var record EnterpriseControlRecord
	if err := decodeJSON(r, &record); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	record.TenantID = tenantID
	if strings.TrimSpace(category) != "" {
		record.Category = category
	}
	if strings.TrimSpace(record.Category) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "category is required", reqID, tenantID)
		return
	}
	saved, err := h.svc.UpsertEnterpriseControl(r.Context(), record)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "enterprise_control_upsert_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"control": saved, "request_id": reqID})
}

func (h *Handler) handleRunEnterpriseAnomalyScan(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.RunEnterpriseAnomalyDetection(r.Context(), tenantID, daysQuery(r, 7))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "anomaly_scan_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "request_id": reqID})
}

func (h *Handler) handleListKeyDSPMFindings(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.store.ListDSPMFindings(r.Context(), tenantID, dspmQuery(r))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "dspm_findings_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "request_id": reqID})
}

func (h *Handler) handleUpsertKeyDSPMFinding(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var finding DSPMFinding
	if err := decodeJSON(r, &finding); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	finding.TenantID = tenantID
	saved, err := h.svc.UpsertDSPMFinding(r.Context(), finding)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "dspm_finding_upsert_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"finding": saved, "request_id": reqID})
}

func (h *Handler) handleExportKeyDSPMEvents(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.ExportDSPMPostureEvents(r.Context(), tenantID, dspmQuery(r))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "dspm_events_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "request_id": reqID})
}

func (h *Handler) handleEnterpriseKDFDerive(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var req KDFDeriveRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	req.TenantID = tenantID
	resp, err := h.svc.DeriveEnterpriseKDF(r.Context(), req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "kdf_derive_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"result": resp, "request_id": reqID})
}

func (h *Handler) handleEnterpriseShamirSplit(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var req ShamirSplitRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	req.TenantID = tenantID
	resp, err := h.svc.SplitShamirSecret(r.Context(), req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "shamir_split_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"result": resp, "request_id": reqID})
}

func (h *Handler) handleEnterpriseShamirVerify(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var req ShamirVerifyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	req.TenantID = tenantID
	resp, err := h.svc.VerifyShamirSecret(r.Context(), req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "shamir_verify_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"result": resp, "request_id": reqID})
}

func (h *Handler) handleCreateAuditChainAnchor(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var req struct {
		AnchorType        string         `json:"anchor_type"`
		ExternalReference string         `json:"external_reference"`
		Metadata          map[string]any `json:"metadata"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	anchor, err := h.svc.AnchorEnterpriseAuditChain(r.Context(), tenantID, req.AnchorType, req.ExternalReference, req.Metadata)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "audit_anchor_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"anchor": anchor, "request_id": reqID})
}

func (h *Handler) handleListAuditChainAnchors(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.store.ListAuditChainAnchors(r.Context(), tenantID, limitQuery(r, 100))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "audit_anchor_list_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "request_id": reqID})
}

func (h *Handler) handleEnterpriseComplianceDashboard(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	dash, err := h.svc.BuildEnterpriseComplianceDashboard(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "compliance_dashboard_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"dashboard": dash, "request_id": reqID})
}

func (h *Handler) handleEnterpriseCostOptimization(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	item, err := h.svc.BuildEnterpriseCostOptimization(r.Context(), tenantID, daysQuery(r, 30))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "cost_optimization_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"optimization": item, "request_id": reqID})
}

func (h *Handler) handleVerifyKeyFingerprint(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var req struct {
		KeyID       string `json:"key_id"`
		Fingerprint string `json:"fingerprint"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	record, err := h.svc.VerifyKeyMaterialFingerprint(r.Context(), tenantID, req.KeyID, req.Fingerprint)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "fingerprint_verification_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"verification": record, "request_id": reqID})
}

func (h *Handler) handleCreateSearchableToken(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var req struct {
		KeyID           string `json:"key_id"`
		SecretBase64    string `json:"secret_base64"`
		PlaintextBase64 string `json:"plaintext_base64"`
		Context         string `json:"context"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	secret, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.SecretBase64))
	if err != nil || len(secret) < 32 {
		writeErr(w, http.StatusBadRequest, "bad_request", "secret_base64 must decode to at least 32 bytes", reqID, tenantID)
		return
	}
	defer crypto.Zeroize(secret)
	plaintext, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.PlaintextBase64))
	if err != nil || len(plaintext) == 0 {
		writeErr(w, http.StatusBadRequest, "bad_request", "plaintext_base64 must be valid", reqID, tenantID)
		return
	}
	defer crypto.Zeroize(plaintext)
	token := searchableToken(secret, plaintext)
	tokenHash := sha256Hex([]byte(token))
	record, _ := h.svc.UpsertEnterpriseControl(r.Context(), EnterpriseControlRecord{
		TenantID:  tenantID,
		Category:  controlCategoryAdvancedEncryption,
		KeyID:     req.KeyID,
		Name:      "Searchable HMAC token generated",
		Status:    "completed",
		Severity:  "info",
		RiskScore: 0,
		Metadata: map[string]any{
			"mode":        "searchable_hmac_token",
			"context":     req.Context,
			"token_hash":  "sha256:" + tokenHash,
			"plaintext_n": len(plaintext),
		},
	})
	_ = h.svc.publishAudit(r.Context(), "audit.key.searchable_token_generated", tenantID, map[string]any{
		"key_id":     req.KeyID,
		"token_hash": "sha256:" + tokenHash,
		"context":    req.Context,
	})
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "control": record, "request_id": reqID})
}

func (h *Handler) handleTriggerOrchestrationRun(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var req struct {
		WorkflowID      string   `json:"workflow_id"`
		KeyIDs          []string `json:"key_ids"`
		Reason          string   `json:"reason"`
		ExecuteRotation bool     `json:"execute_rotation"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	run := EnterpriseControlRecord{
		TenantID:  tenantID,
		Category:  controlCategoryOrchestrationRun,
		Name:      "Orchestration run",
		Status:    "completed",
		Severity:  "info",
		RiskScore: 0,
		Metadata: map[string]any{
			"workflow_id":       req.WorkflowID,
			"key_ids":           req.KeyIDs,
			"reason":            req.Reason,
			"execute_rotation":  req.ExecuteRotation,
			"started_at":        time.Now().UTC().Format(time.RFC3339),
			"rotation_results":  []map[string]any{},
			"failed_operations": 0,
		},
	}
	results := make([]map[string]any, 0, len(req.KeyIDs))
	failures := 0
	if req.ExecuteRotation {
		for _, keyID := range req.KeyIDs {
			keyID = strings.TrimSpace(keyID)
			if keyID == "" {
				continue
			}
			_, err := h.svc.RotateKey(r.Context(), tenantID, keyID, firstNonEmpty(req.Reason, "enterprise_orchestration"), "deactivate")
			item := map[string]any{"key_id": keyID, "status": "completed"}
			if err != nil {
				failures++
				item["status"] = "failed"
				item["error"] = err.Error()
			}
			results = append(results, item)
		}
	}
	run.Metadata["rotation_results"] = results
	run.Metadata["failed_operations"] = failures
	if failures > 0 {
		run.Status = "failed"
		run.Severity = "high"
		run.RiskScore = 75
	}
	saved, err := h.svc.UpsertEnterpriseControl(r.Context(), run)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "orchestration_run_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"run": saved, "request_id": reqID})
}

func dspmQuery(r *http.Request) DSPMFindingQuery {
	return DSPMFindingQuery{
		Source:      strings.TrimSpace(r.URL.Query().Get("source")),
		FindingType: strings.TrimSpace(r.URL.Query().Get("finding_type")),
		Status:      strings.TrimSpace(r.URL.Query().Get("status")),
		Severity:    strings.TrimSpace(r.URL.Query().Get("severity")),
		KeyID:       strings.TrimSpace(r.URL.Query().Get("key_id")),
		Limit:       limitQuery(r, 200),
		Offset:      offsetQuery(r),
	}
}
