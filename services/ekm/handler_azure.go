package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

var azureProvider = NewAzureEKMProvider(nil)

func (h *Handler) handleCreateAzureConfig(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req CreateAzureEKMConfigRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	tenantID, _, err := tenantFromRequest(r, req.TenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	req.TenantID = tenantID

	if strings.TrimSpace(req.AzureTenantID) == "" {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", "azure_tenant_id is required"), reqID, tenantID)
		return
	}
	if strings.TrimSpace(req.VaultName) == "" {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", "vault_name is required"), reqID, tenantID)
		return
	}
	if strings.TrimSpace(req.VaultURL) == "" {
		req.VaultURL = fmt.Sprintf("https://%s.vault.azure.net", req.VaultName)
	}
	if req.AuthMode == "" {
		req.AuthMode = "client_secret"
	}

	cfg := AzureEKMConfig{
		ID:             newID("azcfg"),
		TenantID:       tenantID,
		AzureTenantID:  strings.TrimSpace(req.AzureTenantID),
		SubscriptionID: strings.TrimSpace(req.SubscriptionID),
		ResourceGroup:  strings.TrimSpace(req.ResourceGroup),
		VaultName:      strings.TrimSpace(req.VaultName),
		VaultURL:       strings.TrimSpace(req.VaultURL),
		ManagedHSMName: strings.TrimSpace(req.ManagedHSMName),
		ManagedHSMURL:  strings.TrimSpace(req.ManagedHSMURL),
		ClientID:       strings.TrimSpace(req.ClientID),
		ClientSecret:   strings.TrimSpace(req.ClientSecret),
		AuthMode:       req.AuthMode,
		Status:         "active",
		KeyMappings:    0,
	}

	if err := h.svc.store.CreateAzureEKMConfig(r.Context(), cfg); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}

	h.publishAuditEvent(r.Context(), tenantID, "azure_ekm.config.created", cfg.ID)

	// Mask secret in response
	cfg.ClientSecret = maskSecret(cfg.ClientSecret)
	writeJSON(w, http.StatusCreated, map[string]interface{}{"config": cfg, "request_id": reqID})
}

func (h *Handler) handleListAzureConfigs(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, _, err := tenantFromRequest(r, "")
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}
	items, err := h.svc.store.ListAzureEKMConfigs(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	// Mask secrets in response
	for i := range items {
		items[i].ClientSecret = maskSecret(items[i].ClientSecret)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleGetAzureConfig(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, _, err := tenantFromRequest(r, "")
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}
	cfg, err := h.svc.store.GetAzureEKMConfig(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	cfg.ClientSecret = maskSecret(cfg.ClientSecret)
	writeJSON(w, http.StatusOK, map[string]interface{}{"config": cfg, "request_id": reqID})
}

func (h *Handler) handleUpdateAzureConfig(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req CreateAzureEKMConfigRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	tenantID, _, err := tenantFromRequest(r, req.TenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}

	existing, err := h.svc.store.GetAzureEKMConfig(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}

	existing.AzureTenantID = coalesceStr(strings.TrimSpace(req.AzureTenantID), existing.AzureTenantID)
	existing.SubscriptionID = coalesceStr(strings.TrimSpace(req.SubscriptionID), existing.SubscriptionID)
	existing.ResourceGroup = coalesceStr(strings.TrimSpace(req.ResourceGroup), existing.ResourceGroup)
	existing.VaultName = coalesceStr(strings.TrimSpace(req.VaultName), existing.VaultName)
	existing.VaultURL = coalesceStr(strings.TrimSpace(req.VaultURL), existing.VaultURL)
	existing.ManagedHSMName = coalesceStr(strings.TrimSpace(req.ManagedHSMName), existing.ManagedHSMName)
	existing.ManagedHSMURL = coalesceStr(strings.TrimSpace(req.ManagedHSMURL), existing.ManagedHSMURL)
	existing.ClientID = coalesceStr(strings.TrimSpace(req.ClientID), existing.ClientID)
	if strings.TrimSpace(req.ClientSecret) != "" {
		existing.ClientSecret = strings.TrimSpace(req.ClientSecret)
	}
	existing.AuthMode = coalesceStr(req.AuthMode, existing.AuthMode)

	if err := h.svc.store.UpdateAzureEKMConfig(r.Context(), existing); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}

	h.publishAuditEvent(r.Context(), tenantID, "azure_ekm.config.updated", existing.ID)

	existing.ClientSecret = maskSecret(existing.ClientSecret)
	writeJSON(w, http.StatusOK, map[string]interface{}{"config": existing, "request_id": reqID})
}

func (h *Handler) handleDeleteAzureConfig(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, _, err := tenantFromRequest(r, "")
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}
	configID := r.PathValue("id")
	if err := h.svc.store.DeleteAzureEKMConfig(r.Context(), tenantID, configID); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}

	h.publishAuditEvent(r.Context(), tenantID, "azure_ekm.config.deleted", configID)
	writeJSON(w, http.StatusOK, map[string]interface{}{"deleted": true, "config_id": configID, "request_id": reqID})
}

func (h *Handler) handleTestAzureConnection(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, _, err := tenantFromRequest(r, "")
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}

	cfg, err := h.svc.store.GetAzureEKMConfig(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}

	token, authErr := azureProvider.Authenticate(cfg)
	if authErr != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"connected":  false,
			"error":      authErr.Error(),
			"request_id": reqID,
		})
		return
	}

	// Verify vault access by listing keys
	_, listErr := azureProvider.ListKeysInVault(r.Context(), token, cfg.VaultURL)
	if listErr != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"connected":       false,
			"authenticated":   true,
			"error":           listErr.Error(),
			"request_id":      reqID,
		})
		return
	}

	h.publishAuditEvent(r.Context(), tenantID, "azure_ekm.connection.tested", cfg.ID)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"connected":     true,
		"authenticated": true,
		"vault_url":     cfg.VaultURL,
		"request_id":    reqID,
	})
}

func (h *Handler) handleSyncAzureKeys(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, _, err := tenantFromRequest(r, "")
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}

	cfg, err := h.svc.store.GetAzureEKMConfig(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}

	token, authErr := azureProvider.Authenticate(cfg)
	if authErr != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadGateway, "azure_auth_failed", authErr.Error()), reqID, tenantID)
		return
	}

	mappings, err := h.svc.store.ListAzureKeyMappings(r.Context(), tenantID, cfg.ID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}

	results := make([]AzureSyncResult, 0, len(mappings))
	syncedCount := 0
	for _, m := range mappings {
		keyInfo, getErr := azureProvider.GetKeyFromVault(r.Context(), token, cfg.VaultURL, m.AzureKeyName)
		if getErr != nil {
			_ = h.svc.store.UpdateAzureKeyMappingSync(r.Context(), tenantID, m.ID, "", "", "error")
			results = append(results, AzureSyncResult{MappingID: m.ID, Status: "error", Error: getErr.Error()})
			continue
		}

		// Extract kid and version from the response
		azureKeyID := ""
		azureVersion := ""
		if key, ok := keyInfo["key"].(map[string]interface{}); ok {
			if kid, ok := key["kid"].(string); ok {
				azureKeyID = kid
				parts := strings.Split(kid, "/")
				if len(parts) > 0 {
					azureVersion = parts[len(parts)-1]
				}
			}
		}

		_ = h.svc.store.UpdateAzureKeyMappingSync(r.Context(), tenantID, m.ID, azureKeyID, azureVersion, "synced")
		results = append(results, AzureSyncResult{MappingID: m.ID, Status: "synced", AzureKeyID: azureKeyID})
		syncedCount++
	}

	// Update config sync timestamp and mapping count
	cfg.LastSyncAt = time.Now().UTC()
	cfg.KeyMappings = len(mappings)
	_ = h.svc.store.UpdateAzureEKMConfig(r.Context(), cfg)

	h.publishAuditEvent(r.Context(), tenantID, "azure_ekm.keys.synced", cfg.ID)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"results":    results,
		"total":      len(mappings),
		"synced":     syncedCount,
		"request_id": reqID,
	})
}

func (h *Handler) handleCreateAzureMapping(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req CreateAzureKeyMappingRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	tenantID, _, err := tenantFromRequest(r, req.TenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}

	if strings.TrimSpace(req.ConfigID) == "" {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", "config_id is required"), reqID, tenantID)
		return
	}
	if strings.TrimSpace(req.VectaKeyID) == "" {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", "vecta_key_id is required"), reqID, tenantID)
		return
	}
	if strings.TrimSpace(req.AzureKeyName) == "" {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", "azure_key_name is required"), reqID, tenantID)
		return
	}

	// Verify the config exists
	_, err = h.svc.store.GetAzureEKMConfig(r.Context(), tenantID, req.ConfigID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}

	purpose := strings.TrimSpace(req.Purpose)
	if purpose == "" {
		purpose = "tde"
	}

	mapping := AzureKeyMapping{
		ID:           newID("azmap"),
		TenantID:     tenantID,
		ConfigID:     strings.TrimSpace(req.ConfigID),
		VectaKeyID:   strings.TrimSpace(req.VectaKeyID),
		AzureKeyName: strings.TrimSpace(req.AzureKeyName),
		Purpose:      purpose,
		SyncStatus:   "pending",
	}

	if err := h.svc.store.CreateAzureKeyMapping(r.Context(), mapping); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}

	h.publishAuditEvent(r.Context(), tenantID, "azure_ekm.mapping.created", mapping.ID)
	writeJSON(w, http.StatusCreated, map[string]interface{}{"mapping": mapping, "request_id": reqID})
}

func (h *Handler) handleListAzureMappings(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, _, err := tenantFromRequest(r, "")
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}
	configID := strings.TrimSpace(r.URL.Query().Get("config_id"))
	items, err := h.svc.store.ListAzureKeyMappings(r.Context(), tenantID, configID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleDeleteAzureMapping(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, _, err := tenantFromRequest(r, "")
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}
	mappingID := r.PathValue("id")
	if err := h.svc.store.DeleteAzureKeyMapping(r.Context(), tenantID, mappingID); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}

	h.publishAuditEvent(r.Context(), tenantID, "azure_ekm.mapping.deleted", mappingID)
	writeJSON(w, http.StatusOK, map[string]interface{}{"deleted": true, "mapping_id": mappingID, "request_id": reqID})
}

func (h *Handler) handleImportKeyToAzure(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, _, err := tenantFromRequest(r, "")
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}

	mappingID := r.PathValue("id")
	mappings, err := h.svc.store.ListAzureKeyMappings(r.Context(), tenantID, "")
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}

	var mapping *AzureKeyMapping
	for i := range mappings {
		if mappings[i].ID == mappingID {
			mapping = &mappings[i]
			break
		}
	}
	if mapping == nil {
		h.writeServiceError(w, newServiceError(http.StatusNotFound, "not_found", "mapping not found"), reqID, tenantID)
		return
	}

	cfg, err := h.svc.store.GetAzureEKMConfig(r.Context(), tenantID, mapping.ConfigID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}

	token, authErr := azureProvider.Authenticate(cfg)
	if authErr != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadGateway, "azure_auth_failed", authErr.Error()), reqID, tenantID)
		return
	}

	// Create the key in Azure Key Vault (server-side generated)
	var azureKeyID string
	if cfg.ManagedHSMURL != "" {
		azureKeyID, err = azureProvider.ImportKeyToManagedHSM(r.Context(), token, cfg.ManagedHSMURL, mapping.AzureKeyName, nil, "RSA-HSM")
	} else {
		azureKeyID, err = azureProvider.CreateKeyInVault(r.Context(), token, cfg.VaultURL, mapping.AzureKeyName, "RSA", 2048)
	}
	if err != nil {
		_ = h.svc.store.UpdateAzureKeyMappingSync(r.Context(), tenantID, mappingID, "", "", "error")
		h.writeServiceError(w, newServiceError(http.StatusBadGateway, "azure_import_failed", err.Error()), reqID, tenantID)
		return
	}

	// Extract version from key ID
	parts := strings.Split(azureKeyID, "/")
	version := parts[len(parts)-1]

	_ = h.svc.store.UpdateAzureKeyMappingSync(r.Context(), tenantID, mappingID, azureKeyID, version, "synced")

	h.publishAuditEvent(r.Context(), tenantID, "azure_ekm.key.imported", mappingID)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"mapping_id":        mappingID,
		"azure_key_id":      azureKeyID,
		"azure_key_version": version,
		"request_id":        reqID,
	})
}

func (h *Handler) handleRotateAzureKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, _, err := tenantFromRequest(r, "")
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}

	mappingID := r.PathValue("id")
	mapping, cfg, err := h.resolveAzureMapping(r, tenantID, mappingID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}

	token, authErr := azureProvider.Authenticate(cfg)
	if authErr != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadGateway, "azure_auth_failed", authErr.Error()), reqID, tenantID)
		return
	}

	var newVersion string
	if cfg.ManagedHSMURL != "" {
		newVersion, err = azureProvider.RotateKeyInManagedHSM(r.Context(), token, cfg.ManagedHSMURL, mapping.AzureKeyName)
	} else {
		newVersion, err = azureProvider.RotateKeyInVault(r.Context(), token, cfg.VaultURL, mapping.AzureKeyName)
	}
	if err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadGateway, "azure_rotate_failed", err.Error()), reqID, tenantID)
		return
	}

	_ = h.svc.store.UpdateAzureKeyMappingSync(r.Context(), tenantID, mappingID, mapping.AzureKeyID, newVersion, "synced")

	h.publishAuditEvent(r.Context(), tenantID, "azure_ekm.key.rotated", mappingID)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"mapping_id":  mappingID,
		"new_version": newVersion,
		"request_id":  reqID,
	})
}

func (h *Handler) handleAzureWrapKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req AzureWrapUnwrapRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	tenantID, _, err := tenantFromRequest(r, req.TenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}

	mappingID := r.PathValue("id")
	mapping, cfg, err := h.resolveAzureMapping(r, tenantID, mappingID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}

	token, authErr := azureProvider.Authenticate(cfg)
	if authErr != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadGateway, "azure_auth_failed", authErr.Error()), reqID, tenantID)
		return
	}

	plaintext, decErr := base64.StdEncoding.DecodeString(req.ValueB64)
	if decErr != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", "value must be base64 encoded"), reqID, tenantID)
		return
	}

	algorithm := req.Algorithm
	if algorithm == "" {
		algorithm = "RSA-OAEP-256"
	}

	wrapped, err := azureProvider.WrapKey(r.Context(), token, cfg.VaultURL, mapping.AzureKeyName, algorithm, plaintext)
	if err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadGateway, "azure_wrap_failed", err.Error()), reqID, tenantID)
		return
	}

	h.publishAuditEvent(r.Context(), tenantID, "azure_ekm.key.wrap", mappingID)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"wrapped":    base64.StdEncoding.EncodeToString(wrapped),
		"algorithm":  algorithm,
		"mapping_id": mappingID,
		"request_id": reqID,
	})
}

func (h *Handler) handleAzureUnwrapKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req AzureWrapUnwrapRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	tenantID, _, err := tenantFromRequest(r, req.TenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}

	mappingID := r.PathValue("id")
	mapping, cfg, err := h.resolveAzureMapping(r, tenantID, mappingID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}

	token, authErr := azureProvider.Authenticate(cfg)
	if authErr != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadGateway, "azure_auth_failed", authErr.Error()), reqID, tenantID)
		return
	}

	ciphertext, decErr := base64.StdEncoding.DecodeString(req.ValueB64)
	if decErr != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", "value must be base64 encoded"), reqID, tenantID)
		return
	}

	algorithm := req.Algorithm
	if algorithm == "" {
		algorithm = "RSA-OAEP-256"
	}

	unwrapped, err := azureProvider.UnwrapKey(r.Context(), token, cfg.VaultURL, mapping.AzureKeyName, algorithm, ciphertext)
	if err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadGateway, "azure_unwrap_failed", err.Error()), reqID, tenantID)
		return
	}

	h.publishAuditEvent(r.Context(), tenantID, "azure_ekm.key.unwrap", mappingID)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"unwrapped":  base64.StdEncoding.EncodeToString(unwrapped),
		"algorithm":  algorithm,
		"mapping_id": mappingID,
		"request_id": reqID,
	})
}

// resolveAzureMapping finds a mapping and its parent config.
func (h *Handler) resolveAzureMapping(r *http.Request, tenantID, mappingID string) (AzureKeyMapping, AzureEKMConfig, error) {
	mappings, err := h.svc.store.ListAzureKeyMappings(r.Context(), tenantID, "")
	if err != nil {
		return AzureKeyMapping{}, AzureEKMConfig{}, err
	}
	var mapping *AzureKeyMapping
	for i := range mappings {
		if mappings[i].ID == mappingID {
			mapping = &mappings[i]
			break
		}
	}
	if mapping == nil {
		return AzureKeyMapping{}, AzureEKMConfig{}, newServiceError(http.StatusNotFound, "not_found", "mapping not found")
	}

	cfg, err := h.svc.store.GetAzureEKMConfig(r.Context(), tenantID, mapping.ConfigID)
	if err != nil {
		return AzureKeyMapping{}, AzureEKMConfig{}, err
	}
	return *mapping, cfg, nil
}

// publishAuditEvent publishes an audit event via the event system.
func (h *Handler) publishAuditEvent(ctx context.Context, tenantID, subject, resourceID string) {
	if h.svc.events == nil {
		return
	}
	payload, _ := json.Marshal(map[string]string{
		"tenant_id":   tenantID,
		"resource_id": resourceID,
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
	})
	if err := h.svc.events.Publish(ctx, subject, payload); err != nil {
		log.Printf("[azure-ekm] failed to publish audit event %s: %v", subject, err)
	}
}

// maskSecret returns a masked version of a secret string for safe display.
func maskSecret(s string) string {
	if len(s) <= 4 {
		return "****"
	}
	return s[:2] + strings.Repeat("*", len(s)-4) + s[len(s)-2:]
}

// coalesceStr returns the first non-empty string.
func coalesceStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
