package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"vecta-kms/pkg/route"
	"vecta-kms/pkg/tenantcheck"
)

type Handler struct {
	svc    *Service
	router *route.Router
}

// NewHandler serves dataprotect through the route kernel (7.4.0-beta): every
// route has a permission (dataprotect.read | use | write | delete) and emits
// audit.dataprotect.<action>, refusals included. Which keys a caller may use
// is still decided by keycore from the caller's own grants (pkg/delegation).
func NewHandler(svc *Service, audit route.Emitter) *Handler {
	h := &Handler{svc: svc}
	h.router = h.routes(audit)
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if v := strings.TrimSpace(r.Header.Get(KDFVersionHeader)); v != "" {
		r = r.WithContext(withRequestedKDF(r.Context(), v))
	}
	h.router.ServeHTTP(w, r)
}

// legacy adapts a handler not yet rewritten onto route.Call.
func legacy(fn http.HandlerFunc) func(*route.Call) { return func(c *route.Call) { fn(c.W, c.R) } }

// wrapperOr serves a wrapper runtime route. A registered wrapper calls it
// with its X-Wrapper-Token (verified by the service against its
// registration), so the route is Public to the kernel; anyone else needs a
// platform token with perm.
func wrapperOr(perm string, fn http.HandlerFunc) func(*route.Call) {
	return func(c *route.Call) {
		if wrapperTokenFromRequest(c.R) == "" {
			if c.Claims == nil {
				c.Refuse(http.StatusUnauthorized, route.ReasonUnauthenticated, "authentication required")
				return
			}
			if !route.Allowed(c.Claims, perm) {
				c.Refuse(http.StatusForbidden, route.ReasonPermissionDenied, "missing permission "+perm)
				return
			}
		}
		fn(c.W, c.R)
	}
}

func (h *Handler) routes(audit route.Emitter) *route.Router {
	r := route.New("dataprotect", audit, nil)
	// Working-key derivation migration: docs/SECURITY/DATAPROTECT_KEY_DERIVATION.md.
	r.Handle("POST /tokenize", route.Spec{Action: "tokenize", Permission: "dataprotect.use", Resource: "dataprotect"}, legacy(h.handleTokenize))
	r.Handle("GET /kdf/keys", route.Spec{Action: "kdf_keys_list", Permission: "dataprotect.read", Resource: "dataprotect"}, legacy(h.handleListKeyKDF))
	r.Handle("POST /kdf/keys/{key_id}/start-migration", route.Spec{Action: "kdf_migration_start", Permission: "dataprotect.write", Resource: "dataprotect", TargetParam: "key_id"}, legacy(h.handleKDFTransition))
	r.Handle("POST /kdf/keys/{key_id}/reprotect-vault", route.Spec{Action: "kdf_vault_reprotect", Permission: "dataprotect.write", Resource: "dataprotect", TargetParam: "key_id"}, legacy(h.handleKDFReprotectVault))
	r.Handle("POST /kdf/keys/{key_id}/complete", route.Spec{Action: "kdf_migration_complete", Permission: "dataprotect.write", Resource: "dataprotect", TargetParam: "key_id", Severity: "warning"}, legacy(h.handleKDFTransition))
	r.Handle("POST /kdf/keys/{key_id}/abort", route.Spec{Action: "kdf_migration_abort", Permission: "dataprotect.write", Resource: "dataprotect", TargetParam: "key_id", Severity: "warning"}, legacy(h.handleKDFTransition))
	r.Handle("POST /detokenize", route.Spec{Action: "detokenize", Permission: "dataprotect.use", Resource: "dataprotect", Severity: "warning"}, legacy(h.handleDetokenize))
	r.Handle("POST /tokenize/batch", route.Spec{Action: "tokenize_batch", Permission: "dataprotect.use", Resource: "dataprotect"}, legacy(h.handleTokenize))
	r.Handle("POST /detokenize/batch", route.Spec{Action: "detokenize_batch", Permission: "dataprotect.use", Resource: "dataprotect", Severity: "warning"}, legacy(h.handleDetokenize))
	r.Handle("GET /token-vaults", route.Spec{Action: "token_vaults_list", Permission: "dataprotect.read", Resource: "dataprotect"}, legacy(h.handleListTokenVaults))
	r.Handle("POST /token-vaults", route.Spec{Action: "token_vault_create", Permission: "dataprotect.write", Resource: "dataprotect"}, legacy(h.handleCreateTokenVault))
	r.Handle("GET /token-vaults/external-schema", route.Spec{Action: "token_vault_schema_read", Permission: "dataprotect.read", Resource: "dataprotect"}, legacy(h.handleGetTokenVaultExternalSchema))
	r.Handle("GET /token-vaults/{id}", route.Spec{Action: "token_vault_read", Permission: "dataprotect.read", Resource: "dataprotect", TargetParam: "id"}, legacy(h.handleGetTokenVault))
	r.Handle("DELETE /token-vaults/{id}", route.Spec{Action: "token_vault_delete", Permission: "dataprotect.delete", Resource: "dataprotect", TargetParam: "id", Severity: "warning"}, legacy(h.handleDeleteTokenVault))
	r.Handle("POST /fpe/encrypt", route.Spec{Action: "fpe_encrypt", Permission: "dataprotect.use", Resource: "dataprotect"}, legacy(h.handleFPEEncrypt))
	r.Handle("POST /fpe/decrypt", route.Spec{Action: "fpe_decrypt", Permission: "dataprotect.use", Resource: "dataprotect", Severity: "warning"}, legacy(h.handleFPEDecrypt))
	r.Handle("POST /mask", route.Spec{Action: "mask", Permission: "dataprotect.use", Resource: "dataprotect"}, legacy(h.handleMask))
	r.Handle("POST /mask/preview", route.Spec{Action: "mask_preview", Permission: "dataprotect.use", Resource: "dataprotect"}, legacy(h.handleMaskPreview))
	r.Handle("GET /masking-policies", route.Spec{Action: "masking_policies_list", Permission: "dataprotect.read", Resource: "dataprotect"}, legacy(h.handleListMaskingPolicies))
	r.Handle("POST /masking-policies", route.Spec{Action: "masking_policy_create", Permission: "dataprotect.write", Resource: "dataprotect"}, legacy(h.handleCreateMaskingPolicy))
	r.Handle("PUT /masking-policies/{id}", route.Spec{Action: "masking_policy_update", Permission: "dataprotect.write", Resource: "dataprotect", TargetParam: "id"}, legacy(h.handleUpdateMaskingPolicy))
	r.Handle("DELETE /masking-policies/{id}", route.Spec{Action: "masking_policy_delete", Permission: "dataprotect.delete", Resource: "dataprotect", TargetParam: "id", Severity: "warning"}, legacy(h.handleDeleteMaskingPolicy))
	r.Handle("POST /redact", route.Spec{Action: "redact", Permission: "dataprotect.use", Resource: "dataprotect"}, legacy(h.handleRedact))
	r.Handle("POST /redact/detect", route.Spec{Action: "redact_detect", Permission: "dataprotect.use", Resource: "dataprotect"}, legacy(h.handleRedactDetect))
	r.Handle("GET /redaction-policies", route.Spec{Action: "redaction_policies_list", Permission: "dataprotect.read", Resource: "dataprotect"}, legacy(h.handleListRedactionPolicies))
	r.Handle("POST /redaction-policies", route.Spec{Action: "redaction_policy_create", Permission: "dataprotect.write", Resource: "dataprotect"}, legacy(h.handleCreateRedactionPolicy))
	r.Handle("POST /app/encrypt-fields", route.Spec{Action: "app_fields_encrypt", Permission: "dataprotect.use", Resource: "dataprotect"}, legacy(h.handleAppEncryptFields))
	r.Handle("POST /app/decrypt-fields", route.Spec{Action: "app_fields_decrypt", Permission: "dataprotect.use", Resource: "dataprotect", Severity: "warning"}, legacy(h.handleAppDecryptFields))
	r.Handle("POST /app/envelope-encrypt", route.Spec{Action: "app_envelope_encrypt", Permission: "dataprotect.use", Resource: "dataprotect"}, legacy(h.handleAppEnvelopeEncrypt))
	r.Handle("POST /app/envelope-decrypt", route.Spec{Action: "app_envelope_decrypt", Permission: "dataprotect.use", Resource: "dataprotect", Severity: "warning"}, legacy(h.handleAppEnvelopeDecrypt))
	r.Handle("POST /app/searchable-encrypt", route.Spec{Action: "app_searchable_encrypt", Permission: "dataprotect.use", Resource: "dataprotect"}, legacy(h.handleAppSearchableEncrypt))
	r.Handle("POST /app/searchable-decrypt", route.Spec{Action: "app_searchable_decrypt", Permission: "dataprotect.use", Resource: "dataprotect", Severity: "warning"}, legacy(h.handleAppSearchableDecrypt))
	r.Handle("GET /policy", route.Spec{Action: "policy_read", Permission: "dataprotect.read", Resource: "dataprotect"}, legacy(h.handleGetDataProtectionPolicy))
	r.Handle("PUT /policy", route.Spec{Action: "policy_update", Permission: "dataprotect.write", Resource: "dataprotect", Severity: "warning"}, legacy(h.handleSetDataProtectionPolicy))
	r.Handle("GET /field-protection/profiles", route.Spec{Action: "field_profiles_list", Permission: "dataprotect.read", Resource: "dataprotect"}, legacy(h.handleListFieldProtectionProfiles))
	r.Handle("POST /field-protection/profiles", route.Spec{Action: "field_profile_create", Permission: "dataprotect.write", Resource: "dataprotect"}, legacy(h.handleCreateFieldProtectionProfile))
	r.Handle("PUT /field-protection/profiles/{id}", route.Spec{Action: "field_profile_update", Permission: "dataprotect.write", Resource: "dataprotect", TargetParam: "id"}, legacy(h.handleUpdateFieldProtectionProfile))
	r.Handle("DELETE /field-protection/profiles/{id}", route.Spec{Action: "field_profile_delete", Permission: "dataprotect.delete", Resource: "dataprotect", TargetParam: "id", Severity: "warning"}, legacy(h.handleDeleteFieldProtectionProfile))
	r.Handle("GET /field-protection/resolve", route.Spec{Action: "field_policy_resolve", Public: true, Resource: "dataprotect"}, wrapperOr("dataprotect.read", h.handleResolveFieldProtectionPolicy))
	r.Handle("GET /field-encryption/wrappers", route.Spec{Action: "wrappers_list", Permission: "dataprotect.read", Resource: "dataprotect"}, legacy(h.handleListFieldEncryptionWrappers))
	r.Handle("POST /field-encryption/register/init", route.Spec{Action: "wrapper_register_init", Permission: "dataprotect.write", Resource: "dataprotect"}, legacy(h.handleInitFieldEncryptionWrapperRegistration))
	r.Handle("POST /field-encryption/register/complete", route.Spec{Action: "wrapper_register_complete", Permission: "dataprotect.write", Resource: "dataprotect", Severity: "warning"}, legacy(h.handleCompleteFieldEncryptionWrapperRegistration))
	r.Handle("GET /field-encryption/sdk/download", route.Spec{Action: "wrapper_sdk_download", Permission: "dataprotect.read", Resource: "dataprotect"}, legacy(h.handleDownloadFieldEncryptionWrapperSDK))
	r.Handle("POST /field-encryption/leases", route.Spec{Action: "lease_issue", Public: true, Resource: "dataprotect"}, wrapperOr("dataprotect.use", h.handleIssueFieldEncryptionLease))
	r.Handle("GET /field-encryption/leases", route.Spec{Action: "leases_list", Permission: "dataprotect.read", Resource: "dataprotect"}, legacy(h.handleListFieldEncryptionLeases))
	r.Handle("POST /field-encryption/receipts", route.Spec{Action: "receipt_submit", Public: true, Resource: "dataprotect"}, wrapperOr("dataprotect.use", h.handleSubmitFieldEncryptionReceipt))
	r.Handle("POST /field-encryption/leases/{id}/renew", route.Spec{Action: "lease_renew", Public: true, Resource: "dataprotect", TargetParam: "id"}, wrapperOr("dataprotect.use", h.handleRenewFieldEncryptionLease))
	r.Handle("POST /field-encryption/leases/{id}/revoke", route.Spec{Action: "lease_revoke", Permission: "dataprotect.write", Resource: "dataprotect", TargetParam: "id"}, legacy(h.handleRevokeFieldEncryptionLease))
	r.Handle("GET /audit-log", route.Spec{Action: "audit_log_list", Permission: "dataprotect.read", Resource: "dataprotect"}, legacy(h.handleListAuditLog))
	r.Handle("GET /stats", route.Spec{Action: "stats_read", Permission: "dataprotect.read", Resource: "dataprotect"}, legacy(h.handleGetStats))
	return r
}

func (h *Handler) handleTokenize(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req TokenizeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	items, err := h.svc.Tokenize(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	go h.svc.writeAudit(context.Background(), req.TenantID, "tokenize", "tokenization", actorFromRequest(r), fmt.Sprintf("tokenized %d value(s) mode=%s", len(items), req.Mode))
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleDetokenize(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req DetokenizeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	items, err := h.svc.Detokenize(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	go h.svc.writeAudit(context.Background(), req.TenantID, "detokenize", "tokenization", actorFromRequest(r), fmt.Sprintf("detokenized %d token(s)", len(items)))
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleListTokenVaults(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.ListTokenVaults(r.Context(), tenantID, atoi(r.URL.Query().Get("limit")), atoi(r.URL.Query().Get("offset")))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleCreateTokenVault(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var body TokenVault
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	tenantID := firstTenant(body.TenantID, tenantFromRequest(r))
	item, err := h.svc.CreateTokenVault(r.Context(), tenantID, body)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	go h.svc.writeAudit(context.Background(), tenantID, "create_vault", "tokenization", actorFromRequest(r), fmt.Sprintf("created token vault %s type=%s", item.Name, item.TokenType))
	writeJSON(w, http.StatusCreated, map[string]interface{}{"vault": item, "request_id": reqID})
}

func (h *Handler) handleGetTokenVault(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	item, err := h.svc.GetTokenVault(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"item": item, "request_id": reqID})
}

func (h *Handler) handleGetTokenVaultExternalSchema(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	provider := strings.TrimSpace(r.URL.Query().Get("provider"))
	item, err := h.svc.GetExternalTokenVaultSetup(provider)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"item": item, "request_id": reqID})
}

func (h *Handler) handleDeleteTokenVault(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	approved := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("governance_approved")), "true") ||
		strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Governance-Approved")), "true")
	vaultID := r.PathValue("id")
	if err := h.svc.DeleteTokenVault(r.Context(), tenantID, vaultID, approved); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	go h.svc.writeAudit(context.Background(), tenantID, "delete_vault", "tokenization", actorFromRequest(r), fmt.Sprintf("deleted token vault %s", vaultID))
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "request_id": reqID})
}

func (h *Handler) handleFPEEncrypt(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req FPERequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	out, err := h.svc.FPEEncrypt(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	go h.svc.writeAudit(context.Background(), req.TenantID, "fpe_encrypt", "encryption", actorFromRequest(r), fmt.Sprintf("FPE encrypt algo=%s", req.Algorithm))
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": out, "request_id": reqID})
}

func (h *Handler) handleFPEDecrypt(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req FPERequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	out, err := h.svc.FPEDecrypt(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	go h.svc.writeAudit(context.Background(), req.TenantID, "fpe_decrypt", "encryption", actorFromRequest(r), fmt.Sprintf("FPE decrypt algo=%s", req.Algorithm))
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": out, "request_id": reqID})
}

func (h *Handler) handleMask(w http.ResponseWriter, r *http.Request) {
	h.handleMaskWithMode(w, r, false)
}

func (h *Handler) handleMaskPreview(w http.ResponseWriter, r *http.Request) {
	h.handleMaskWithMode(w, r, true)
}

func (h *Handler) handleMaskWithMode(w http.ResponseWriter, r *http.Request, preview bool) {
	reqID := requestID(r)
	var req MaskRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.Preview = preview
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	out, err := h.svc.ApplyMask(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	go h.svc.writeAudit(context.Background(), req.TenantID, "mask", "masking", actorFromRequest(r), fmt.Sprintf("mask policy=%s preview=%v", req.PolicyID, preview))
	writeJSON(w, http.StatusOK, map[string]interface{}{"masked": out, "request_id": reqID})
}

func (h *Handler) handleListMaskingPolicies(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.ListMaskingPolicies(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleCreateMaskingPolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var body MaskingPolicy
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	tenantID := firstTenant(body.TenantID, tenantFromRequest(r))
	item, err := h.svc.CreateMaskingPolicy(r.Context(), tenantID, body)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"item": item, "request_id": reqID})
}

func (h *Handler) handleUpdateMaskingPolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var body MaskingPolicy
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	if err := h.svc.UpdateMaskingPolicy(r.Context(), tenantID, r.PathValue("id"), body); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "request_id": reqID})
}

func (h *Handler) handleDeleteMaskingPolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	if err := h.svc.DeleteMaskingPolicy(r.Context(), tenantID, r.PathValue("id")); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "request_id": reqID})
}

func (h *Handler) handleRedact(w http.ResponseWriter, r *http.Request) {
	h.handleRedactWithMode(w, r, false)
}

func (h *Handler) handleRedactDetect(w http.ResponseWriter, r *http.Request) {
	h.handleRedactWithMode(w, r, true)
}

func (h *Handler) handleRedactWithMode(w http.ResponseWriter, r *http.Request, detect bool) {
	reqID := requestID(r)
	var req RedactRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.DetectOnly = detect
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	out, err := h.svc.Redact(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	mode := "apply"
	if detect {
		mode = "detect"
	}
	go h.svc.writeAudit(context.Background(), req.TenantID, "redact", "redaction", actorFromRequest(r), fmt.Sprintf("redact mode=%s policy=%s", mode, req.PolicyID))
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": out, "request_id": reqID})
}

func (h *Handler) handleListRedactionPolicies(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.ListRedactionPolicies(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleCreateRedactionPolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var body RedactionPolicy
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	tenantID := firstTenant(body.TenantID, tenantFromRequest(r))
	item, err := h.svc.CreateRedactionPolicy(r.Context(), tenantID, body)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"item": item, "request_id": reqID})
}

func (h *Handler) handleAppEncryptFields(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req AppFieldRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	out, err := h.svc.EncryptFields(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	go h.svc.writeAudit(context.Background(), req.TenantID, "encrypt_fields", "encryption", actorFromRequest(r), fmt.Sprintf("field encrypt algo=%s fields=%d", req.Algorithm, len(req.Fields)))
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": out, "request_id": reqID})
}

func (h *Handler) handleAppDecryptFields(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req AppFieldRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	out, err := h.svc.DecryptFields(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	go h.svc.writeAudit(context.Background(), req.TenantID, "decrypt_fields", "encryption", actorFromRequest(r), fmt.Sprintf("field decrypt algo=%s fields=%d", req.Algorithm, len(req.Fields)))
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": out, "request_id": reqID})
}

func (h *Handler) handleAppEnvelopeEncrypt(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req EnvelopeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	out, err := h.svc.EnvelopeEncrypt(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	go h.svc.writeAudit(context.Background(), req.TenantID, "envelope_encrypt", "encryption", actorFromRequest(r), fmt.Sprintf("envelope encrypt algo=%s", req.Algorithm))
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": out, "request_id": reqID})
}

func (h *Handler) handleAppEnvelopeDecrypt(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req EnvelopeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	out, err := h.svc.EnvelopeDecrypt(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	go h.svc.writeAudit(context.Background(), req.TenantID, "envelope_decrypt", "encryption", actorFromRequest(r), "envelope decrypt")
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": out, "request_id": reqID})
}

func (h *Handler) handleAppSearchableEncrypt(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req SearchableRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	out, err := h.svc.SearchableEncrypt(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	go h.svc.writeAudit(context.Background(), req.TenantID, "searchable_encrypt", "encryption", actorFromRequest(r), "searchable encrypt AES-SIV")
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": out, "request_id": reqID})
}

func (h *Handler) handleAppSearchableDecrypt(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req SearchableRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	out, err := h.svc.SearchableDecrypt(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	go h.svc.writeAudit(context.Background(), req.TenantID, "searchable_decrypt", "encryption", actorFromRequest(r), "searchable decrypt AES-SIV")
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": out, "request_id": reqID})
}

func (h *Handler) handleListKeyKDF(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.ListKeyKDF(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleKDFTransition(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var req struct {
		Force bool `json:"force"`
	}
	if r.ContentLength != 0 {
		if err := decodeJSON(r, &req); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
			return
		}
	}
	keyID, actor := r.PathValue("key_id"), actorFromRequest(r)
	var (
		item KeyKDFState
		err  error
	)
	switch {
	case strings.HasSuffix(r.URL.Path, "/start-migration"):
		item, err = h.svc.StartKDFMigration(r.Context(), tenantID, keyID, actor)
	case strings.HasSuffix(r.URL.Path, "/complete"):
		item, err = h.svc.CompleteKDFMigration(r.Context(), tenantID, keyID, actor, req.Force)
	default:
		item, err = h.svc.AbortKDFMigration(r.Context(), tenantID, keyID, actor)
	}
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"item": item, "request_id": reqID})
}

func (h *Handler) handleKDFReprotectVault(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var req struct {
		Limit int `json:"limit"`
	}
	if r.ContentLength != 0 {
		if err := decodeJSON(r, &req); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
			return
		}
	}
	out, err := h.svc.ReprotectVaultTokens(r.Context(), tenantID, r.PathValue("key_id"), req.Limit, actorFromRequest(r))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	out["request_id"] = reqID
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) handleGetDataProtectionPolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	item, err := h.svc.GetDataProtectionPolicy(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"policy": item, "request_id": reqID})
}

func (h *Handler) handleSetDataProtectionPolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var req DataProtectionPolicy
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantID)
	if req.TenantID != tenantID {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant mismatch between request and session context", reqID, tenantID)
		return
	}
	item, err := h.svc.UpdateDataProtectionPolicy(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	go h.svc.writeAudit(context.Background(), tenantID, "update_policy", "policy", actorFromRequest(r), fmt.Sprintf("data protection policy updated by %s", req.UpdatedBy))
	writeJSON(w, http.StatusOK, map[string]interface{}{"policy": item, "request_id": reqID})
}

func (h *Handler) handleListFieldProtectionProfiles(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.ListFieldProtectionProfiles(
		r.Context(),
		tenantID,
		strings.TrimSpace(r.URL.Query().Get("app_id")),
		strings.TrimSpace(r.URL.Query().Get("wrapper_id")),
		strings.TrimSpace(r.URL.Query().Get("status")),
		atoi(r.URL.Query().Get("limit")),
		atoi(r.URL.Query().Get("offset")),
	)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleCreateFieldProtectionProfile(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var req FieldProtectionProfile
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantID)
	if req.TenantID != tenantID {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant mismatch between request and session context", reqID, tenantID)
		return
	}
	item, err := h.svc.UpsertFieldProtectionProfile(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"item": item, "request_id": reqID})
}

func (h *Handler) handleUpdateFieldProtectionProfile(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	profileID := strings.TrimSpace(r.PathValue("id"))
	if profileID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "profile id is required", reqID, tenantID)
		return
	}
	var req FieldProtectionProfile
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantID)
	if req.TenantID != tenantID {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant mismatch between request and session context", reqID, tenantID)
		return
	}
	if strings.TrimSpace(req.ProfileID) != "" && !strings.EqualFold(strings.TrimSpace(req.ProfileID), profileID) {
		writeErr(w, http.StatusBadRequest, "bad_request", "profile id mismatch between path and body", reqID, tenantID)
		return
	}
	req.ProfileID = profileID
	item, err := h.svc.UpsertFieldProtectionProfile(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"item": item, "request_id": reqID})
}

func (h *Handler) handleDeleteFieldProtectionProfile(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	profileID := strings.TrimSpace(r.PathValue("id"))
	if profileID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "profile id is required", reqID, tenantID)
		return
	}
	if err := h.svc.DeleteFieldProtectionProfile(r.Context(), tenantID, profileID); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "request_id": reqID})
}

func (h *Handler) handleResolveFieldProtectionPolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	req := FieldProtectionResolveRequest{
		TenantID:     tenantID,
		AppID:        strings.TrimSpace(r.URL.Query().Get("app_id")),
		WrapperID:    strings.TrimSpace(r.URL.Query().Get("wrapper_id")),
		Role:         strings.TrimSpace(r.URL.Query().Get("role")),
		Purpose:      strings.TrimSpace(r.URL.Query().Get("purpose")),
		Workflow:     strings.TrimSpace(r.URL.Query().Get("workflow")),
		AuthToken:    wrapperTokenFromRequest(r),
		ClientCertFP: wrapperCertFingerprintFromRequest(r),
	}
	bundle, err := h.svc.ResolveFieldProtectionPolicyBundle(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	etag := normalizedETag(bundle.ETag)
	if etag != "" {
		w.Header().Set("ETag", quotedETag(etag))
	}
	ttl := bundle.CacheTTLSeconds
	if ttl <= 0 {
		ttl = 300
	}
	w.Header().Set("Cache-Control", "private, max-age="+strconv.Itoa(ttl))
	if ifNoneMatchContains(r.Header.Get("If-None-Match"), etag) {
		w.Header().Set("X-Request-ID", reqID)
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"bundle": bundle, "request_id": reqID})
}

func (h *Handler) handleListFieldEncryptionWrappers(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.ListFieldEncryptionWrappers(r.Context(), tenantID, atoi(r.URL.Query().Get("limit")), atoi(r.URL.Query().Get("offset")))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleInitFieldEncryptionWrapperRegistration(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req FieldEncryptionRegisterInitRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	out, err := h.svc.InitFieldEncryptionWrapperRegistration(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"item": out, "request_id": reqID})
}

func (h *Handler) handleCompleteFieldEncryptionWrapperRegistration(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req FieldEncryptionRegisterCompleteRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	item, err := h.svc.CompleteFieldEncryptionWrapperRegistration(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"wrapper":      item.Wrapper,
		"auth_profile": item.AuthProfile,
		"certificate":  item.Certificate,
		"warnings":     item.Warnings,
		"request_id":   reqID,
	})
}

func (h *Handler) handleDownloadFieldEncryptionWrapperSDK(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	targetOS := strings.TrimSpace(r.URL.Query().Get("target_os"))
	artifact, err := h.svc.BuildFieldEncryptionWrapperSDKArtifact(r.Context(), tenantID, targetOS)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"artifact":   artifact,
		"request_id": reqID,
	})
}

func (h *Handler) handleIssueFieldEncryptionLease(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req FieldEncryptionLeaseRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	req.AuthToken = wrapperTokenFromRequest(r)
	req.ClientCertFP = wrapperCertFingerprintFromRequest(r)
	item, err := h.svc.IssueFieldEncryptionLease(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"lease": item, "request_id": reqID})
}

func (h *Handler) handleListFieldEncryptionLeases(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.ListFieldEncryptionLeases(
		r.Context(),
		tenantID,
		strings.TrimSpace(r.URL.Query().Get("wrapper_id")),
		atoi(r.URL.Query().Get("limit")),
		atoi(r.URL.Query().Get("offset")),
	)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleSubmitFieldEncryptionReceipt(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req FieldEncryptionReceiptRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	req.AuthToken = wrapperTokenFromRequest(r)
	req.ClientCertFP = wrapperCertFingerprintFromRequest(r)
	item, err := h.svc.SubmitFieldEncryptionUsageReceipt(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"receipt": item, "request_id": reqID})
}

func (h *Handler) handleRenewFieldEncryptionLease(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	leaseID := strings.TrimSpace(r.PathValue("id"))
	if leaseID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "lease id is required", reqID, tenantID)
		return
	}
	var req FieldEncryptionLeaseRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantID)
	if req.TenantID != tenantID {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant mismatch between request and session context", reqID, tenantID)
		return
	}
	req.AuthToken = wrapperTokenFromRequest(r)
	req.ClientCertFP = wrapperCertFingerprintFromRequest(r)
	item, err := h.svc.RenewFieldEncryptionLease(r.Context(), tenantID, leaseID, req)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"lease": item, "request_id": reqID})
}

func (h *Handler) handleRevokeFieldEncryptionLease(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	leaseID := strings.TrimSpace(r.PathValue("id"))
	if leaseID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "lease id is required", reqID, tenantID)
		return
	}
	body := map[string]interface{}{}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	reason := strings.TrimSpace(firstString(body["reason"]))
	if err := h.svc.RevokeFieldEncryptionLease(r.Context(), tenantID, leaseID, reason); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "request_id": reqID})
}

func (h *Handler) writeServiceError(w http.ResponseWriter, err error, reqID string, tenantID string) {
	var svcErr serviceError
	if errors.As(err, &svcErr) {
		writeErr(w, svcErr.HTTPStatus, svcErr.Code, svcErr.Message, reqID, tenantID)
		return
	}
	// A05: avoid leaking internal error details for 5xx responses
	status := httpStatusForErr(err)
	msg := err.Error()
	if status >= 500 {
		msg = "internal server error"
	}
	writeErr(w, status, "internal_error", msg, reqID, tenantID)
}

func decodeJSON(r *http.Request, out interface{}) error {
	defer r.Body.Close() //nolint:errcheck
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("request body is required")
		}
		return err
	}
	return nil
}

func requestID(r *http.Request) string {
	id := strings.TrimSpace(r.Header.Get("X-Request-ID"))
	if id != "" {
		return id
	}
	return newID("req")
}

func tenantFromRequest(r *http.Request) string {
	if v := strings.TrimSpace(r.URL.Query().Get("tenant_id")); v != "" {
		return v
	}
	return strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
}

func actorFromRequest(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get("X-Actor")); v != "" {
		return v
	}
	if v := strings.TrimSpace(r.Header.Get("X-Username")); v != "" {
		return v
	}
	return "dashboard"
}

func firstTenant(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func mustTenant(r *http.Request, reqID string, w http.ResponseWriter) string {
	tenantID := tenantFromRequest(r)
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required (query or X-Tenant-ID)", reqID, "")
		return ""
	}
	// A01 fix: verify the request tenant matches the authenticated JWT tenant
	if err := tenantcheck.Enforce(r, tenantID); err != nil {
		writeErr(w, http.StatusForbidden, "forbidden", "tenant_id does not match authenticated token", reqID, tenantID)
		return ""
	}
	return tenantID
}

func wrapperTokenFromRequest(r *http.Request) string {
	return strings.TrimSpace(r.Header.Get("X-Wrapper-Token"))
}

func wrapperCertFingerprintFromRequest(r *http.Request) string {
	if fp := strings.TrimSpace(r.Header.Get("X-Wrapper-Cert-Fingerprint")); fp != "" {
		return strings.ToLower(fp)
	}
	if fp := strings.TrimSpace(r.Header.Get("X-Client-Cert-Fingerprint")); fp != "" {
		return strings.ToLower(fp)
	}
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		sum := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
		return hex.EncodeToString(sum[:])
	}
	return ""
}

func normalizedETag(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "W/")
	v = strings.TrimSpace(v)
	v = strings.Trim(v, `"`)
	return strings.TrimSpace(v)
}

func quotedETag(v string) string {
	v = normalizedETag(v)
	if v == "" {
		return ""
	}
	return `"` + v + `"`
}

func ifNoneMatchContains(rawHeader string, currentETag string) bool {
	current := normalizedETag(currentETag)
	if current == "" {
		return false
	}
	raw := strings.TrimSpace(rawHeader)
	if raw == "" {
		return false
	}
	if raw == "*" {
		return true
	}
	for _, token := range strings.Split(raw, ",") {
		if normalizedETag(token) == current {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, payload map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeErr(w http.ResponseWriter, status int, code string, message string, requestID string, tenantID string) {
	writeJSON(w, status, map[string]interface{}{
		"error": map[string]interface{}{
			"code":       code,
			"message":    message,
			"request_id": requestID,
			"tenant_id":  tenantID,
		},
	})
}

func (h *Handler) handleListAuditLog(w http.ResponseWriter, r *http.Request) {
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if tenantID == "" {
		tenantID = "default"
	}
	category := strings.TrimSpace(r.URL.Query().Get("category"))
	limit := 100
	if v := strings.TrimSpace(r.URL.Query().Get("limit")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	offset := 0
	if v := strings.TrimSpace(r.URL.Query().Get("offset")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	entries, err := h.svc.ListAuditLog(r.Context(), tenantID, category, limit, offset)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "audit_log_failed", err.Error(), "", tenantID)
		return
	}
	if entries == nil {
		entries = []DataProtectAuditEntry{}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"items": entries})
}

func (h *Handler) handleGetStats(w http.ResponseWriter, r *http.Request) {
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if tenantID == "" {
		tenantID = "default"
	}
	stats, err := h.svc.GetStats(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "stats_failed", err.Error(), "", tenantID)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(stats)
}
