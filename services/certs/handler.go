package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	scepwire "github.com/smallstep/scep"
)

type Handler struct {
	svc *Service
	mux *http.ServeMux
}

func NewHandler(svc *Service) *Handler {
	h := &Handler{svc: svc}
	h.mux = h.routes()
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /certs/ca", h.handleCreateCA)
	mux.HandleFunc("GET /certs/ca", h.handleListCAs)
	mux.HandleFunc("POST /certs", h.handleIssueCert)
	mux.HandleFunc("POST /certs/sign-csr", h.handleSignCSR)
	mux.HandleFunc("GET /certs", h.handleListCerts)
	mux.HandleFunc("GET /certs/{id}", h.handleGetCert)
	mux.HandleFunc("DELETE /certs/{id}", h.handleDeleteCert)
	mux.HandleFunc("GET /certs/download/{id}", h.handleDownloadCert)
	mux.HandleFunc("POST /certs/{id}/renew", h.handleRenewCert)
	mux.HandleFunc("POST /certs/{id}/revoke", h.handleRevokeCert)
	mux.HandleFunc("POST /certs/profiles", h.handleCreateProfile)
	mux.HandleFunc("GET /certs/profiles", h.handleListProfiles)
	mux.HandleFunc("GET /certs/profiles/{id}", h.handleGetProfile)
	mux.HandleFunc("POST /certs/validate-pqc", h.handleValidatePQC)
	mux.HandleFunc("GET /certs/ots-status/{ca_id}", h.handleOTSStatus)
	mux.HandleFunc("POST /certs/pqc/migrate/{id}", h.handleMigratePQC)
	mux.HandleFunc("GET /certs/pqc-readiness", h.handlePQCReadiness)
	mux.HandleFunc("GET /certs/crl", h.handleCRL)
	mux.HandleFunc("GET /certs/ocsp", h.handleOCSP)
	mux.HandleFunc("POST /certs/ocsp", h.handleOCSP)
	mux.HandleFunc("GET /certs/inventory", h.handleInventory)
	mux.HandleFunc("GET /certs/alert-policy", h.handleGetAlertPolicy)
	mux.HandleFunc("PUT /certs/alert-policy", h.handleUpsertAlertPolicy)
	mux.HandleFunc("GET /certs/protocols", h.handleListProtocolConfigs)
	mux.HandleFunc("GET /certs/protocols/schema", h.handleListProtocolSchemas)
	mux.HandleFunc("PUT /certs/protocols/{protocol}", h.handleUpsertProtocolConfig)
	mux.HandleFunc("POST /certs/upload-3p", h.handleUploadThirdPartyCert)
	mux.HandleFunc("POST /certs/internal/mtls/{service}", h.handleIssueInternalMTLS)

	mux.HandleFunc("GET /acme/directory", h.handleACMEDirectory)
	mux.HandleFunc("POST /acme/new-nonce", h.handleACMENonce)
	mux.HandleFunc("POST /acme/new-account", h.handleACMENewAccount)
	mux.HandleFunc("POST /acme/new-order", h.handleACMENewOrder)
	mux.HandleFunc("POST /acme/challenge/{id}", h.handleACMEChallenge)
	mux.HandleFunc("POST /acme/finalize/{id}", h.handleACMEFinalize)
	mux.HandleFunc("GET /acme/cert/{id}", h.handleACMECertDownload)

	mux.HandleFunc("GET /est/.well-known/est/cacerts", h.handleESTCACerts)
	mux.HandleFunc("POST /est/.well-known/est/simpleenroll", h.handleESTSimpleEnroll)
	mux.HandleFunc("POST /est/.well-known/est/simplereenroll", h.handleESTSimpleReenroll)
	mux.HandleFunc("POST /est/.well-known/est/serverkeygen", h.handleESTServerKeygen)

	mux.HandleFunc("GET /scep/pkiclient.exe", h.handleSCEPGet)
	mux.HandleFunc("POST /scep/pkiclient.exe", h.handleSCEPPKIOperation)

	mux.HandleFunc("POST /cmpv2", h.handleCMPv2)
	return mux
}

func (h *Handler) handleCreateCA(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req CreateCARequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	out, err := h.svc.CreateCA(r.Context(), req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "create_ca_failed", err.Error(), reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"ca": out, "request_id": reqID})
}

func (h *Handler) handleListCAs(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	items, err := h.svc.ListCAs(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_ca_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleIssueCert(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req IssueCertificateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	out, keyPEM, err := h.svc.IssueCertificate(r.Context(), req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "issue_failed", err.Error(), reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"certificate":     out,
		"private_key_pem": keyPEM,
		"request_id":      reqID,
	})
}

func (h *Handler) handleSignCSR(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req IssueCertificateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.CSRPem = strings.TrimSpace(req.CSRPem)
	if req.CSRPem == "" {
		writeErr(w, http.StatusBadRequest, "sign_csr_failed", "csr_pem is required", reqID, req.TenantID)
		return
	}
	req.ServerKeygen = false
	req.Protocol = defaultString(strings.TrimSpace(req.Protocol), "csr-sign")
	out, _, err := h.svc.IssueCertificate(r.Context(), req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "sign_csr_failed", err.Error(), reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"certificate": out,
		"request_id":  reqID,
	})
}

func (h *Handler) handleListCerts(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	limit, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("limit")))
	offset, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("offset")))
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	certClass := strings.TrimSpace(r.URL.Query().Get("cert_class"))
	items, err := h.svc.ListCertificates(r.Context(), tenantID, status, certClass, limit, offset)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleGetCert(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	out, err := h.svc.GetCertificate(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, errStoreNotFound) {
			status = http.StatusNotFound
		}
		writeErr(w, status, "get_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"certificate": out, "request_id": reqID})
}

func (h *Handler) handleDownloadCert(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	includeChain, _ := strconv.ParseBool(strings.TrimSpace(r.URL.Query().Get("include_chain")))
	content, ct, err := h.svc.DownloadCertificate(r.Context(), DownloadCertificateRequest{
		TenantID:     tenantID,
		CertID:       r.PathValue("id"),
		Asset:        r.URL.Query().Get("asset"),
		Format:       r.URL.Query().Get("format"),
		Password:     r.URL.Query().Get("password"),
		IncludeChain: includeChain,
	})
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, errStoreNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "download_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"content":      content,
		"content_type": ct,
		"request_id":   reqID,
	})
}

func (h *Handler) handleRenewCert(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	var body struct {
		ValidityDays int64 `json:"validity_days"`
	}
	_ = decodeJSON(r, &body)
	out, err := h.svc.RenewCertificate(r.Context(), RenewCertificateRequest{
		TenantID:     tenantID,
		CertID:       r.PathValue("id"),
		ValidityDays: body.ValidityDays,
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, "renew_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"certificate": out, "request_id": reqID})
}

func (h *Handler) handleRevokeCert(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	_ = decodeJSON(r, &body)
	if err := h.svc.RevokeCertificate(r.Context(), RevokeCertificateRequest{
		TenantID: tenantID,
		CertID:   r.PathValue("id"),
		Reason:   body.Reason,
	}); err != nil {
		writeErr(w, http.StatusBadRequest, "revoke_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "revoked", "request_id": reqID})
}

func (h *Handler) handleDeleteCert(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	if err := h.svc.DeleteCertificate(r.Context(), tenantID, r.PathValue("id")); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errStoreNotFound) {
			status = http.StatusNotFound
		}
		writeErr(w, status, "delete_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "deleted", "request_id": reqID})
}

func (h *Handler) handleCreateProfile(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req CreateProfileRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	out, err := h.svc.CreateProfile(r.Context(), req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "create_profile_failed", err.Error(), reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"profile": out, "request_id": reqID})
}

func (h *Handler) handleListProfiles(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	items, err := h.svc.ListProfiles(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_profile_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	out, err := h.svc.GetProfile(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, errStoreNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "get_profile_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"profile": out, "request_id": reqID})
}

func (h *Handler) handleValidatePQC(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req ValidatePQCChainRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	valid, issues, err := h.svc.ValidatePQCChain(r.Context(), req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "validate_failed", err.Error(), reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"valid": valid, "issues": issues, "request_id": reqID})
}

func (h *Handler) handleOTSStatus(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	out, err := h.svc.GetOTSStatus(r.Context(), tenantID, r.PathValue("ca_id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ots_status_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": out, "request_id": reqID})
}

func (h *Handler) handleMigratePQC(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	var body struct {
		TargetAlgorithm string `json:"target_algorithm"`
		TargetProfileID string `json:"target_profile_id"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	out, err := h.svc.MigrateToPQC(r.Context(), MigrateToPQCRequest{
		TenantID:        tenantID,
		CertID:          r.PathValue("id"),
		TargetAlgorithm: body.TargetAlgorithm,
		TargetProfileID: body.TargetProfileID,
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, "migrate_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"certificate": out, "request_id": reqID})
}

func (h *Handler) handlePQCReadiness(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	out, err := h.svc.GetPQCReadiness(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "readiness_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"readiness": out, "request_id": reqID})
}

func (h *Handler) handleCRL(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	caID := strings.TrimSpace(r.URL.Query().Get("ca_id"))
	if caID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "ca_id query parameter is required", reqID, tenantID)
		return
	}
	crl, generated, err := h.svc.GenerateCRL(r.Context(), tenantID, caID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "crl_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"crl_pem":      crl,
		"generated_at": generated.Format(time.RFC3339),
		"request_id":   reqID,
	})
}

func (h *Handler) handleOCSP(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	if r.Method == http.MethodPost && isProtocolCSRRequest(r, "application/ocsp-request") {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
			return
		}
		der, status, reason, producedAt, err := h.svc.CheckOCSPDER(r.Context(), tenantID, raw)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "ocsp_failed", err.Error(), reqID, tenantID)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Header().Set("X-OCSP-Status", status)
		if strings.TrimSpace(reason) != "" {
			w.Header().Set("X-OCSP-Reason", reason)
		}
		w.Header().Set("X-OCSP-Produced-At", producedAt.Format(time.RFC3339))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(der)
		return
	}
	certID := strings.TrimSpace(r.URL.Query().Get("cert_id"))
	serial := strings.TrimSpace(r.URL.Query().Get("serial_number"))
	status, reason, producedAt, err := h.svc.CheckOCSP(r.Context(), tenantID, certID, serial)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ocsp_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":      status,
		"reason":      reason,
		"produced_at": producedAt.Format(time.RFC3339),
		"request_id":  reqID,
	})
}

func (h *Handler) handleInventory(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	items, err := h.svc.Inventory(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "inventory_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleGetAlertPolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	item, err := h.svc.GetCertExpiryAlertPolicy(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "get_alert_policy_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"policy": item, "request_id": reqID})
}

func (h *Handler) handleUpsertAlertPolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	var body struct {
		DaysBefore      int    `json:"days_before"`
		IncludeExternal bool   `json:"include_external"`
		UpdatedBy       string `json:"updated_by"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	item, err := h.svc.UpsertCertExpiryAlertPolicy(r.Context(), UpsertCertExpiryAlertPolicyRequest{
		TenantID:        tenantID,
		DaysBefore:      body.DaysBefore,
		IncludeExternal: body.IncludeExternal,
		UpdatedBy:       body.UpdatedBy,
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, "upsert_alert_policy_failed", err.Error(), reqID, tenantID)
		return
	}
	_ = h.svc.RunTenantExpiryAlertSweep(r.Context(), tenantID)
	writeJSON(w, http.StatusOK, map[string]interface{}{"policy": item, "request_id": reqID})
}

func (h *Handler) handleListProtocolConfigs(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	items, err := h.svc.ListProtocolConfigs(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "protocol_list_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleUpsertProtocolConfig(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	var body struct {
		Enabled    bool   `json:"enabled"`
		ConfigJSON string `json:"config_json"`
		UpdatedBy  string `json:"updated_by"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	out, err := h.svc.UpsertProtocolConfig(r.Context(), UpsertProtocolConfigRequest{
		TenantID:   tenantID,
		Protocol:   r.PathValue("protocol"),
		Enabled:    body.Enabled,
		ConfigJSON: body.ConfigJSON,
		UpdatedBy:  body.UpdatedBy,
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, "protocol_update_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"config": out, "request_id": reqID})
}

func (h *Handler) handleListProtocolSchemas(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items":      h.svc.ListProtocolSchemas(),
		"request_id": reqID,
	})
}

func (h *Handler) handleUploadThirdPartyCert(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req UploadThirdPartyCertificateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	out, err := h.svc.UploadThirdPartyCertificate(r.Context(), req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "upload_3p_failed", err.Error(), reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"certificate": out, "request_id": reqID})
}

func (h *Handler) handleIssueInternalMTLS(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var body InternalMTLSRequest
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	out, keyPEM, err := h.svc.IssueInternalMTLS(r.Context(), r.PathValue("service"), body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "internal_mtls_failed", err.Error(), reqID, body.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"certificate":     out,
		"private_key_pem": keyPEM,
		"request_id":      reqID,
	})
}

func (h *Handler) handleACMEDirectory(w http.ResponseWriter, r *http.Request) {
	base := baseURL(r)
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	options := defaultACMEProtocolOptions()
	if tenantID != "" {
		if cfg, err := h.svc.acmeOptions(r.Context(), tenantID); err == nil {
			options = cfg
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"newNonce":   base + "/acme/new-nonce",
		"newAccount": base + "/acme/new-account",
		"newOrder":   base + "/acme/new-order",
		"revokeCert": base + "/certs/{id}/revoke",
		"meta": map[string]interface{}{
			"externalAccountRequired": options.RequireEAB,
			"wildcardAllowed":         options.AllowWildcard,
			"ipIdentifiersAllowed":    options.AllowIPIdentifiers,
			"challengeTypes":          options.ChallengeTypes,
			"rateLimitPerHour":        options.RateLimitPerHour,
		},
	})
}

func (h *Handler) handleACMENonce(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", newID("nonce"))
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleACMENewAccount(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req ACMENewAccountRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	acct, err := h.svc.AcmeNewAccount(r.Context(), req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "acme_account_failed", err.Error(), reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"account_id": acct.ID,
		"status":     acct.Status,
		"request_id": reqID,
	})
}

func (h *Handler) handleACMENewOrder(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req ACMENewOrderRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	order, err := h.svc.AcmeNewOrder(r.Context(), req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "acme_order_failed", err.Error(), reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"order_id":     order.ID,
		"challenge_id": order.ChallengeID,
		"status":       order.Status,
		"finalize_url": baseURL(r) + "/acme/finalize/" + order.ID,
		"request_id":   reqID,
	})
}

func (h *Handler) handleACMEChallenge(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var body struct {
		TenantID string `json:"tenant_id"`
		OrderID  string `json:"order_id"`
		Success  bool   `json:"success"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	if err := h.svc.AcmeRespondChallenge(r.Context(), body.TenantID, body.OrderID, r.PathValue("id"), body.Success); err != nil {
		writeErr(w, http.StatusBadRequest, "acme_challenge_failed", err.Error(), reqID, body.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "request_id": reqID})
}

func (h *Handler) handleACMEFinalize(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req ACMEFinalizeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.OrderID = r.PathValue("id")
	out, keyPEM, err := h.svc.AcmeFinalize(r.Context(), req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "acme_finalize_failed", err.Error(), reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"certificate": out, "private_key_pem": keyPEM, "request_id": reqID})
}

func (h *Handler) handleACMECertDownload(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	content, ct, err := h.svc.DownloadCertificate(r.Context(), DownloadCertificateRequest{
		TenantID: tenantID,
		CertID:   r.PathValue("id"),
		Asset:    "certificate",
		Format:   "pem",
	})
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"content": content, "content_type": ct, "request_id": reqID})
}

func (h *Handler) handleESTCACerts(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	bundle, err := h.svc.CACertBundle(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "cacerts_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"cacerts": bundle, "request_id": reqID})
}

func (h *Handler) handleESTSimpleEnroll(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	if isProtocolCSRRequest(r, "application/pkcs10") {
		tenantID := mustTenant(r, w, reqID)
		if tenantID == "" {
			return
		}
		caID := strings.TrimSpace(r.URL.Query().Get("ca_id"))
		if caID == "" {
			writeErr(w, http.StatusBadRequest, "bad_request", "ca_id query parameter is required", reqID, tenantID)
			return
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
			return
		}
		csrPEM, err := decodeCSRFromBody(raw)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
			return
		}
		authMethod, authToken := estAuthFromHeaders(r)
		out, keyPEM, err := h.svc.ESTSimpleEnroll(r.Context(), ESTSimpleEnrollRequest{
			TenantID:   tenantID,
			CAID:       caID,
			CSRPem:     csrPEM,
			ProfileID:  strings.TrimSpace(r.URL.Query().Get("profile_id")),
			AuthMethod: authMethod,
			AuthToken:  authToken,
		})
		if err != nil {
			writeErr(w, http.StatusBadRequest, "est_enroll_failed", err.Error(), reqID, tenantID)
			return
		}
		if wantsJSONProtocolResponse(r) {
			writeJSON(w, http.StatusOK, map[string]interface{}{"certificate": out, "private_key_pem": keyPEM, "request_id": reqID})
			return
		}
		writeCertificateDER(w, out.CertPEM, "application/pkix-cert")
		return
	}
	var req ESTSimpleEnrollRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	out, keyPEM, err := h.svc.ESTSimpleEnroll(r.Context(), req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "est_enroll_failed", err.Error(), reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"certificate": out, "private_key_pem": keyPEM, "request_id": reqID})
}

func (h *Handler) handleESTSimpleReenroll(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	if isProtocolCSRRequest(r, "application/pkcs10") {
		tenantID := mustTenant(r, w, reqID)
		if tenantID == "" {
			return
		}
		certID := strings.TrimSpace(r.URL.Query().Get("cert_id"))
		if certID == "" {
			writeErr(w, http.StatusBadRequest, "bad_request", "cert_id query parameter is required", reqID, tenantID)
			return
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
			return
		}
		csrPEM, err := decodeCSRFromBody(raw)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
			return
		}
		authMethod, authToken := estAuthFromHeaders(r)
		out, keyPEM, err := h.svc.ESTSimpleReenroll(r.Context(), ESTSimpleReenrollRequest{
			TenantID:   tenantID,
			CertID:     certID,
			CSRPem:     csrPEM,
			AuthMethod: authMethod,
			AuthToken:  authToken,
		})
		if err != nil {
			writeErr(w, http.StatusBadRequest, "est_reenroll_failed", err.Error(), reqID, tenantID)
			return
		}
		if wantsJSONProtocolResponse(r) {
			writeJSON(w, http.StatusOK, map[string]interface{}{"certificate": out, "private_key_pem": keyPEM, "request_id": reqID})
			return
		}
		writeCertificateDER(w, out.CertPEM, "application/pkix-cert")
		return
	}
	var req ESTSimpleReenrollRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	out, keyPEM, err := h.svc.ESTSimpleReenroll(r.Context(), req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "est_reenroll_failed", err.Error(), reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"certificate": out, "private_key_pem": keyPEM, "request_id": reqID})
}

func (h *Handler) handleESTServerKeygen(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req ESTServerKeygenRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	out, keyPEM, err := h.svc.ESTServerKeygen(r.Context(), req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "est_serverkeygen_failed", err.Error(), reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"certificate": out, "private_key_pem": keyPEM, "request_id": reqID})
}

func (h *Handler) handleSCEPGet(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	op := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("operation")))
	if op == "getcacaps" {
		caps, err := h.svc.SCEPCapabilities(r.Context(), tenantID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "scep_failed", err.Error(), reqID, tenantID)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(caps))
		return
	}
	if op != "getcacert" {
		writeErr(w, http.StatusBadRequest, "bad_request", "unsupported scep operation", reqID, tenantID)
		return
	}
	bundle, err := h.svc.CACertBundle(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "scep_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ca_cert": bundle, "request_id": reqID})
}

func (h *Handler) handleSCEPPKIOperation(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	op := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("operation")))
	if op != "pkioperation" {
		writeErr(w, http.StatusBadRequest, "bad_request", "unsupported scep operation", reqID, "")
		return
	}
	if isProtocolCSRRequest(r, "application/x-pki-message") {
		tenantID := mustTenant(r, w, reqID)
		if tenantID == "" {
			return
		}
		caID := strings.TrimSpace(r.URL.Query().Get("ca_id"))
		if caID == "" {
			writeErr(w, http.StatusBadRequest, "bad_request", "ca_id query parameter is required", reqID, tenantID)
			return
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
			return
		}
		// Real SCEP path: parse and process PKIMessage with a standards-compliant OSS library.
		ca, err := h.svc.store.GetCA(r.Context(), tenantID, caID)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
			return
		}
		caCert, err := parseCertificatePEM(ca.CertPEM)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
			return
		}
		caSigner, err := h.svc.loadCASigner(ca)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
			return
		}
		if pkiMsg, parseErr := scepwire.ParsePKIMessage(raw); parseErr == nil {
			if _, ok := caSigner.(crypto.Decrypter); !ok {
				writeErr(w, http.StatusBadRequest, "scep_failed", "scep requires an rsa-capable ca key for message decryption", reqID, tenantID)
				return
			}
			if err := pkiMsg.DecryptPKIEnvelope(caCert, caSigner); err != nil {
				writeErr(w, http.StatusBadRequest, "scep_failed", err.Error(), reqID, tenantID)
				return
			}
			if pkiMsg.CSRReqMessage == nil || pkiMsg.CSRReqMessage.CSR == nil {
				writeErr(w, http.StatusBadRequest, "scep_failed", "scep request is missing csr payload", reqID, tenantID)
				return
			}
			csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: pkiMsg.CSRReqMessage.CSR.Raw}))
			req := SCEPPKIOperationRequest{
				TenantID:          tenantID,
				CAID:              caID,
				CSRPem:            csrPEM,
				TransactionID:     defaultString(strings.TrimSpace(string(pkiMsg.TransactionID)), strings.TrimSpace(r.URL.Query().Get("transaction_id"))),
				MessageType:       defaultString(scepMessageTypeToOperation(pkiMsg.MessageType), strings.TrimSpace(r.URL.Query().Get("message_type"))),
				ChallengePassword: defaultString(strings.TrimSpace(pkiMsg.CSRReqMessage.ChallengePassword), strings.TrimSpace(r.URL.Query().Get("challenge_password"))),
				CertID:            strings.TrimSpace(r.URL.Query().Get("cert_id")),
			}
			out, keyPEM, err := h.svc.SCEPPKIOperation(r.Context(), req)
			if err != nil {
				writeErr(w, http.StatusBadRequest, "scep_failed", err.Error(), reqID, tenantID)
				return
			}
			if wantsJSONProtocolResponse(r) {
				writeJSON(w, http.StatusOK, map[string]interface{}{"certificate": out, "private_key_pem": keyPEM, "request_id": reqID})
				return
			}
			issued, err := parseCertificatePEM(out.CertPEM)
			if err != nil {
				writeErr(w, http.StatusBadRequest, "scep_failed", err.Error(), reqID, tenantID)
				return
			}
			certRep, err := pkiMsg.Success(caCert, caSigner, issued)
			if err != nil {
				failRep, failErr := pkiMsg.Fail(caCert, caSigner, scepwire.BadRequest)
				if failErr == nil {
					w.Header().Set("Content-Type", "application/x-pki-message")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write(failRep.Raw)
					return
				}
				writeErr(w, http.StatusBadRequest, "scep_failed", err.Error(), reqID, tenantID)
				return
			}
			w.Header().Set("Content-Type", "application/x-pki-message")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(certRep.Raw)
			return
		}
		// Compatibility fallback for clients that still send plain CSR bytes with x-pki-message.
		csrPEM, err := decodeCSRFromBody(raw)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
			return
		}
		req := SCEPPKIOperationRequest{
			TenantID:          tenantID,
			CAID:              caID,
			CSRPem:            csrPEM,
			TransactionID:     strings.TrimSpace(r.URL.Query().Get("transaction_id")),
			MessageType:       strings.TrimSpace(r.URL.Query().Get("message_type")),
			ChallengePassword: strings.TrimSpace(r.URL.Query().Get("challenge_password")),
			CertID:            strings.TrimSpace(r.URL.Query().Get("cert_id")),
		}
		out, keyPEM, err := h.svc.SCEPPKIOperation(r.Context(), req)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "scep_failed", err.Error(), reqID, tenantID)
			return
		}
		if wantsJSONProtocolResponse(r) {
			writeJSON(w, http.StatusOK, map[string]interface{}{"certificate": out, "private_key_pem": keyPEM, "request_id": reqID})
			return
		}
		writeCertificateDER(w, out.CertPEM, "application/x-pki-message")
		return
	}
	var req SCEPPKIOperationRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	out, keyPEM, err := h.svc.SCEPPKIOperation(r.Context(), req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "scep_failed", err.Error(), reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"certificate": out, "private_key_pem": keyPEM, "request_id": reqID})
}

func (h *Handler) handleCMPv2(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	if isProtocolCSRRequest(r, "application/pkixcmp") {
		tenantID := mustTenant(r, w, reqID)
		if tenantID == "" {
			return
		}
		caID := strings.TrimSpace(r.URL.Query().Get("ca_id"))
		msgType := strings.TrimSpace(r.URL.Query().Get("message_type"))
		if caID == "" || msgType == "" {
			writeErr(w, http.StatusBadRequest, "bad_request", "ca_id and message_type query parameters are required", reqID, tenantID)
			return
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
			return
		}
		csrPEM := ""
		if len(bytes.TrimSpace(raw)) > 0 && !strings.EqualFold(msgType, "rr") {
			csrPEM, err = decodeCSRFromBody(raw)
			if err != nil {
				writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
				return
			}
		}
		req := CMPv2RequestMessage{
			TenantID:      tenantID,
			CAID:          caID,
			MessageType:   msgType,
			CSRPem:        csrPEM,
			CertID:        strings.TrimSpace(r.URL.Query().Get("cert_id")),
			TransactionID: strings.TrimSpace(r.URL.Query().Get("transaction_id")),
			Protected:     strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("protected")), "true") || strings.TrimSpace(r.URL.Query().Get("protected")) == "1",
			ProtectionAlg: strings.TrimSpace(r.URL.Query().Get("protection_alg")),
		}
		out, keyPEM, err := h.svc.CMPv2Request(r.Context(), req)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "cmpv2_failed", err.Error(), reqID, tenantID)
			return
		}
		if wantsJSONProtocolResponse(r) {
			writeJSON(w, http.StatusOK, map[string]interface{}{"certificate": out, "private_key_pem": keyPEM, "request_id": reqID})
			return
		}
		writeCertificateDER(w, out.CertPEM, "application/pkix-cert")
		return
	}
	var req CMPv2RequestMessage
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	out, keyPEM, err := h.svc.CMPv2Request(r.Context(), req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "cmpv2_failed", err.Error(), reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"certificate": out, "private_key_pem": keyPEM, "request_id": reqID})
}

func decodeJSON(r *http.Request, out interface{}) error {
	defer r.Body.Close() //nolint:errcheck
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}

func requestID(r *http.Request) string {
	id := strings.TrimSpace(r.Header.Get("X-Request-ID"))
	if id != "" {
		return id
	}
	return newID("req")
}

func mustTenant(r *http.Request, w http.ResponseWriter, reqID string) string {
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if tenantID == "" {
		tenantID = strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	}
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required (query or X-Tenant-ID)", reqID, "")
		return ""
	}
	return tenantID
}

func baseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if xf := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); xf != "" {
		scheme = xf
	}
	return scheme + "://" + r.Host
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

func isProtocolCSRRequest(r *http.Request, contentTypePrefix string) bool {
	contentType := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
	return strings.HasPrefix(contentType, strings.ToLower(strings.TrimSpace(contentTypePrefix)))
}

func wantsJSONProtocolResponse(r *http.Request) bool {
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	accept := strings.ToLower(strings.TrimSpace(r.Header.Get("Accept")))
	return format == "json" || strings.Contains(accept, "application/json")
}

func decodeCSRFromBody(raw []byte) (string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return "", errors.New("csr payload is required")
	}
	if bytes.HasPrefix(trimmed, []byte("-----BEGIN")) {
		if _, err := parseCSRPEM(string(trimmed)); err != nil {
			return "", err
		}
		return string(trimmed), nil
	}

	candidates := make([][]byte, 0, 5)
	candidates = append(candidates, trimmed)
	cleanBase64 := strings.Map(func(r rune) rune {
		switch r {
		case '\r', '\n', '\t', ' ':
			return -1
		default:
			return r
		}
	}, string(trimmed))
	for _, decoder := range []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
	} {
		if decoded, err := decoder(cleanBase64); err == nil && len(decoded) > 0 {
			candidates = append(candidates, decoded)
		}
	}

	for _, candidate := range candidates {
		csr, err := x509.ParseCertificateRequest(candidate)
		if err != nil {
			continue
		}
		if err := csr.CheckSignature(); err != nil {
			continue
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: candidate})), nil
	}
	return "", errors.New("invalid csr payload")
}

func estAuthFromHeaders(r *http.Request) (string, string) {
	authMethod := strings.ToLower(strings.TrimSpace(r.Header.Get("X-EST-Auth-Method")))
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	authToken := strings.TrimSpace(r.Header.Get("X-EST-Auth-Token"))
	if authMethod == "" && authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 {
			authMethod = strings.ToLower(strings.TrimSpace(parts[0]))
			authToken = strings.TrimSpace(parts[1])
		} else {
			authToken = authHeader
		}
	}
	if authMethod == "" {
		authMethod = "mtls"
	}
	return authMethod, authToken
}

func writeCertificateDER(w http.ResponseWriter, certPEM string, contentType string) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(certPEM))
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(block.Bytes)
}

func scepMessageTypeToOperation(mt scepwire.MessageType) string {
	switch mt {
	case scepwire.PKCSReq:
		return "pkcsreq"
	case scepwire.RenewalReq:
		return "renewalreq"
	case scepwire.UpdateReq:
		return "updatereq"
	default:
		return ""
	}
}
