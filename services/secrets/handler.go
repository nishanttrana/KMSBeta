package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
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
	mux.HandleFunc("POST /secrets", h.handleCreateSecret)
	mux.HandleFunc("GET /secrets", h.handleListSecrets)
	mux.HandleFunc("GET /secrets/{id}", h.handleGetSecret)
	mux.HandleFunc("GET /secrets/{id}/value", h.handleGetSecretValue)
	mux.HandleFunc("PUT /secrets/{id}", h.handleUpdateSecret)
	mux.HandleFunc("DELETE /secrets/{id}", h.handleDeleteSecret)
	mux.HandleFunc("POST /secrets/generate/ssh_key", h.handleGenerateSSHKey)

	// HashiCorp Vault / OpenBao compatibility (KV v1 + KV v2 subset)
	mux.HandleFunc("GET /v1/sys/health", h.handleVaultSysHealth)
	mux.HandleFunc("GET /v1/sys/seal-status", h.handleVaultSealStatus)
	mux.HandleFunc("POST /v1/auth/token/lookup-self", h.handleVaultTokenLookupSelf)
	mux.HandleFunc("GET /v1/{mount}/data/{path...}", h.handleVaultKV2Read)
	mux.HandleFunc("POST /v1/{mount}/data/{path...}", h.handleVaultKV2Write)
	mux.HandleFunc("DELETE /v1/{mount}/data/{path...}", h.handleVaultKV2Delete)
	mux.HandleFunc("GET /v1/{mount}/metadata/{path...}", h.handleVaultKV2Metadata)
	mux.HandleFunc("GET /v1/{mount}/{path...}", h.handleVaultKV1Read)
	mux.HandleFunc("POST /v1/{mount}/{path...}", h.handleVaultKV1Write)
	mux.HandleFunc("DELETE /v1/{mount}/{path...}", h.handleVaultKV1Delete)
	return mux
}

func (h *Handler) handleCreateSecret(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req CreateSecretRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	out, err := h.svc.CreateSecret(r.Context(), req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "create_failed", err.Error(), reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"secret": out, "request_id": reqID})
}

func (h *Handler) handleListSecrets(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	limit := atoi(r.URL.Query().Get("limit"))
	offset := atoi(r.URL.Query().Get("offset"))
	secretType := strings.TrimSpace(r.URL.Query().Get("secret_type"))
	items, err := h.svc.ListSecrets(r.Context(), tenantID, secretType, limit, offset)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleGetSecret(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	secret, err := h.svc.GetSecret(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, errNotFound) {
			status = http.StatusNotFound
		}
		writeErr(w, status, "read_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"secret": secret, "request_id": reqID})
}

func (h *Handler) handleGetSecretValue(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	format := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("format")))
	out, err := h.svc.GetSecretValue(r.Context(), tenantID, r.PathValue("id"), format)
	if err != nil {
		switch {
		case errors.Is(err, errExpired):
			writeErr(w, http.StatusGone, "secret_expired", err.Error(), reqID, tenantID)
		case errors.Is(err, errNotFound):
			writeErr(w, http.StatusNotFound, "not_found", err.Error(), reqID, tenantID)
		default:
			writeErr(w, http.StatusBadRequest, "value_read_failed", err.Error(), reqID, tenantID)
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"value":        out.Value,
		"format":       out.Format,
		"content_type": out.ContentType,
		"request_id":   reqID,
	})
}

func (h *Handler) handleUpdateSecret(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var req UpdateSecretRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	out, err := h.svc.UpdateSecret(r.Context(), tenantID, r.PathValue("id"), req)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errNotFound) {
			status = http.StatusNotFound
		}
		writeErr(w, status, "update_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"secret": out, "request_id": reqID})
}

func (h *Handler) handleDeleteSecret(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	if err := h.svc.DeleteSecret(r.Context(), tenantID, r.PathValue("id")); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, errNotFound) {
			status = http.StatusNotFound
		}
		writeErr(w, status, "delete_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "deleted", "request_id": reqID})
}

func (h *Handler) handleGenerateSSHKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req GenerateSSHKeyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	secret, pub, err := h.svc.GenerateSSHKey(r.Context(), req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "generate_failed", err.Error(), reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"secret":     secret,
		"public_key": pub,
		"request_id": reqID,
	})
}

func (h *Handler) handleVaultSysHealth(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"initialized":                  true,
		"sealed":                       false,
		"standby":                      false,
		"performance_standby":          false,
		"replication_performance_mode": "disabled",
		"replication_dr_mode":          "disabled",
		"server_time_utc":              time.Now().UTC().Unix(),
		"version":                      "openbao-compatible-v1",
		"cluster_name":                 "vecta-kms",
		"cluster_id":                   "vecta-kms-local",
		"request_id":                   reqID,
	})
}

func (h *Handler) handleVaultSealStatus(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"type":          "shamir",
		"initialized":   true,
		"sealed":        false,
		"t":             1,
		"n":             1,
		"progress":      0,
		"nonce":         "",
		"version":       "openbao-compatible-v1",
		"build_date":    time.Now().UTC().Format(time.RFC3339),
		"request_id":    reqID,
		"recovery_seal": false,
	})
}

func (h *Handler) handleVaultTokenLookupSelf(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustVaultTenant(r)
	token := strings.TrimSpace(r.Header.Get("X-Vault-Token"))
	if token == "" {
		authz := strings.TrimSpace(r.Header.Get("Authorization"))
		if strings.HasPrefix(strings.ToLower(authz), "bearer ") {
			token = strings.TrimSpace(authz[7:])
		}
	}
	if token == "" {
		token = "anonymous"
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"request_id": reqID,
		"data": map[string]interface{}{
			"id":            token,
			"display_name":  "token",
			"policies":      []string{"default"},
			"meta":          map[string]interface{}{"tenant_id": tenantID},
			"path":          "auth/token/create",
			"orphan":        true,
			"renewable":     false,
			"ttl":           0,
			"creation_time": time.Now().UTC().Unix(),
			"expire_time":   nil,
		},
	})
}

func (h *Handler) handleVaultKV2Read(w http.ResponseWriter, r *http.Request) {
	h.vaultKVRead(w, r, true)
}

func (h *Handler) handleVaultKV1Read(w http.ResponseWriter, r *http.Request) {
	h.vaultKVRead(w, r, false)
}

func (h *Handler) vaultKVRead(w http.ResponseWriter, r *http.Request, kv2 bool) {
	reqID := requestID(r)
	tenantID := mustVaultTenant(r)
	path := strings.TrimSpace(r.PathValue("path"))
	if tenantID == "" || path == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant and path are required", reqID, tenantID)
		return
	}
	secret, err := h.svc.GetSecretByName(r.Context(), tenantID, path)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, errNotFound) {
			status = http.StatusNotFound
		}
		writeErr(w, status, "read_failed", err.Error(), reqID, tenantID)
		return
	}
	valueOut, err := h.svc.GetSecretValue(r.Context(), tenantID, secret.ID, "raw")
	if err != nil {
		if errors.Is(err, errExpired) {
			writeErr(w, http.StatusGone, "secret_expired", err.Error(), reqID, tenantID)
			return
		}
		writeErr(w, http.StatusBadRequest, "value_read_failed", err.Error(), reqID, tenantID)
		return
	}
	dataMap := parseVaultDataMap(valueOut.Value)
	if kv2 {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"request_id":     reqID,
			"lease_id":       "",
			"renewable":      false,
			"lease_duration": 0,
			"data": map[string]interface{}{
				"data": dataMap,
				"metadata": map[string]interface{}{
					"created_time":  secret.CreatedAt.UTC().Format(time.RFC3339),
					"updated_time":  secret.UpdatedAt.UTC().Format(time.RFC3339),
					"deletion_time": "",
					"destroyed":     false,
					"version":       secret.CurrentVersion,
				},
			},
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"request_id":     reqID,
		"lease_id":       "",
		"renewable":      false,
		"lease_duration": 0,
		"data":           dataMap,
	})
}

func (h *Handler) handleVaultKV2Write(w http.ResponseWriter, r *http.Request) {
	h.vaultKVWrite(w, r, true)
}

func (h *Handler) handleVaultKV1Write(w http.ResponseWriter, r *http.Request) {
	h.vaultKVWrite(w, r, false)
}

func (h *Handler) vaultKVWrite(w http.ResponseWriter, r *http.Request, kv2 bool) {
	reqID := requestID(r)
	tenantID := mustVaultTenant(r)
	path := strings.TrimSpace(r.PathValue("path"))
	if tenantID == "" || path == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant and path are required", reqID, tenantID)
		return
	}
	data, err := decodeVaultWriteData(r, kv2)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	value := encodeVaultDataValue(data)
	secret, err := h.svc.GetSecretByName(r.Context(), tenantID, path)
	if err != nil && !errors.Is(err, errNotFound) {
		writeErr(w, http.StatusInternalServerError, "write_failed", err.Error(), reqID, tenantID)
		return
	}
	if errors.Is(err, errNotFound) {
		_, createErr := h.svc.CreateSecret(r.Context(), CreateSecretRequest{
			TenantID:        tenantID,
			Name:            path,
			SecretType:      "api_key",
			Value:           value,
			Description:     "vault-compatible secret",
			CreatedBy:       vaultCreatedBy(r),
			Metadata:        map[string]interface{}{"vault_compat": true, "mount": strings.TrimSpace(r.PathValue("mount"))},
			LeaseTTLSeconds: 0,
		})
		if createErr != nil {
			writeErr(w, http.StatusBadRequest, "create_failed", createErr.Error(), reqID, tenantID)
			return
		}
	} else {
		_, updateErr := h.svc.UpdateSecret(r.Context(), tenantID, secret.ID, UpdateSecretRequest{
			Value:     ptrString(value),
			UpdatedBy: vaultCreatedBy(r),
		})
		if updateErr != nil {
			writeErr(w, http.StatusBadRequest, "update_failed", updateErr.Error(), reqID, tenantID)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"request_id": reqID,
		"data": map[string]interface{}{
			"created": true,
		},
	})
}

func (h *Handler) handleVaultKV2Delete(w http.ResponseWriter, r *http.Request) {
	h.vaultKVDelete(w, r)
}

func (h *Handler) handleVaultKV1Delete(w http.ResponseWriter, r *http.Request) {
	h.vaultKVDelete(w, r)
}

func (h *Handler) vaultKVDelete(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustVaultTenant(r)
	path := strings.TrimSpace(r.PathValue("path"))
	if tenantID == "" || path == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant and path are required", reqID, tenantID)
		return
	}
	secret, err := h.svc.GetSecretByName(r.Context(), tenantID, path)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, errNotFound) {
			status = http.StatusNotFound
		}
		writeErr(w, status, "delete_failed", err.Error(), reqID, tenantID)
		return
	}
	if err := h.svc.DeleteSecret(r.Context(), tenantID, secret.ID); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, errNotFound) {
			status = http.StatusNotFound
		}
		writeErr(w, status, "delete_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusNoContent, map[string]interface{}{})
}

func (h *Handler) handleVaultKV2Metadata(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustVaultTenant(r)
	path := strings.TrimSpace(r.PathValue("path"))
	if tenantID == "" || path == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant and path are required", reqID, tenantID)
		return
	}
	secret, err := h.svc.GetSecretByName(r.Context(), tenantID, path)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, errNotFound) {
			status = http.StatusNotFound
		}
		writeErr(w, status, "read_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"request_id": reqID,
		"data": map[string]interface{}{
			"created_time":         secret.CreatedAt.UTC().Format(time.RFC3339),
			"updated_time":         secret.UpdatedAt.UTC().Format(time.RFC3339),
			"max_versions":         0,
			"current_version":      secret.CurrentVersion,
			"oldest_version":       1,
			"cas_required":         false,
			"delete_version_after": "0s",
		},
	})
}

func mustVaultTenant(r *http.Request) string {
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if tenantID == "" {
		tenantID = strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	}
	if tenantID == "" {
		tenantID = strings.TrimSpace(r.Header.Get("X-Vault-Namespace"))
	}
	if tenantID == "" {
		tenantID = strings.TrimSpace(r.Header.Get("X-Namespace"))
	}
	if tenantID == "" {
		tenantID = "default"
	}
	return tenantID
}

func vaultCreatedBy(r *http.Request) string {
	token := strings.TrimSpace(r.Header.Get("X-Vault-Token"))
	if token == "" {
		return "vault-client"
	}
	if len(token) > 12 {
		token = token[:12]
	}
	return "vault-token:" + token
}

func decodeVaultWriteData(r *http.Request, kv2 bool) (map[string]interface{}, error) {
	type kv2Body struct {
		Data map[string]interface{} `json:"data"`
	}
	if kv2 {
		var body kv2Body
		if err := decodeJSON(r, &body); err != nil {
			return nil, err
		}
		if len(body.Data) == 0 {
			return nil, errors.New("data is required")
		}
		return body.Data, nil
	}
	var body map[string]interface{}
	if err := decodeJSON(r, &body); err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, errors.New("request body is required")
	}
	return body, nil
}

func parseVaultDataMap(raw string) map[string]interface{} {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return map[string]interface{}{"value": ""}
	}
	var obj map[string]interface{}
	if json.Unmarshal([]byte(trimmed), &obj) == nil && obj != nil {
		return obj
	}
	return map[string]interface{}{"value": raw}
}

func encodeVaultDataValue(data map[string]interface{}) string {
	if len(data) == 1 {
		if v, ok := data["value"]; ok {
			return stringifyVaultValue(v)
		}
	}
	out, err := json.Marshal(data)
	if err != nil {
		return "{}"
	}
	return string(out)
}

func stringifyVaultValue(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case []byte:
		return string(t)
	default:
		raw, err := json.Marshal(v)
		if err != nil {
			return ""
		}
		return string(raw)
	}
}

func ptrString(v string) *string {
	return &v
}

func mustTenant(r *http.Request, reqID string, w http.ResponseWriter) string {
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

func decodeJSON(r *http.Request, out interface{}) error {
	defer r.Body.Close() //nolint:errcheck
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	return d.Decode(out)
}

func requestID(r *http.Request) string {
	v := strings.TrimSpace(r.Header.Get("X-Request-ID"))
	if v != "" {
		return v
	}
	return newID("req")
}

func atoi(v string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(v))
	return n
}

func writeJSON(w http.ResponseWriter, code int, payload map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeErr(w http.ResponseWriter, code int, errCode string, msg string, requestID string, tenantID string) {
	writeJSON(w, code, map[string]interface{}{
		"error": map[string]interface{}{
			"code":       errCode,
			"message":    msg,
			"request_id": requestID,
			"tenant_id":  tenantID,
		},
	})
}
