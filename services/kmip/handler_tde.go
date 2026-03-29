package main

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// TDE engine allowlist.
var validTDEEngines = map[string]bool{
	"oracle":     true,
	"sqlserver":  true,
	"postgresql": true,
	"mysql":      true,
	"db2":        true,
}

// TDE rotation policy allowlist.
var validTDERotationPolicies = map[string]bool{
	"none":  true,
	"30d":   true,
	"90d":   true,
	"180d":  true,
	"365d":  true,
}

// TDEDatabase represents a database registration for Transparent Data Encryption key management.
type TDEDatabase struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	Name           string    `json:"name"`
	Engine         string    `json:"engine"`          // oracle, sqlserver, postgresql, mysql, db2
	Host           string    `json:"host"`
	Port           int       `json:"port"`
	Database       string    `json:"database"`
	KeyID          string    `json:"key_id"`          // current TDE key ID
	KeyAlgorithm   string    `json:"key_algorithm"`   // AES-256
	Status         string    `json:"status"`          // registered, key_provisioned, error, revoked
	LastRotated    time.Time `json:"last_rotated,omitempty"`
	RotationPolicy string    `json:"rotation_policy"` // none, 30d, 90d, 180d, 365d
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// TDEStatusSummary aggregates TDE state across all registered databases for a tenant.
type TDEStatusSummary struct {
	TotalDatabases     int            `json:"total_databases"`
	ByEngine           map[string]int `json:"by_engine"`
	ByStatus           map[string]int `json:"by_status"`
	KeysProvisionedPct float64        `json:"keys_provisioned_pct"`
	RotationDueSoon    int            `json:"rotation_due_soon"` // within 30 days
}

// registerTDEDatabaseRequest is the JSON body for POST /tde/databases.
type registerTDEDatabaseRequest struct {
	TenantID       string `json:"tenant_id"`
	Name           string `json:"name"`
	Engine         string `json:"engine"`
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Database       string `json:"database"`
	KeyAlgorithm   string `json:"key_algorithm"`
	RotationPolicy string `json:"rotation_policy"`
}

// handleListTDEDatabases handles GET /tde/databases.
func (h *Handler) handleListTDEDatabases(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	items, err := h.store.ListTDEDatabases(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_tde_databases_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

// handleRegisterTDEDatabase handles POST /tde/databases.
func (h *Handler) handleRegisterTDEDatabase(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req registerTDEDatabaseRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.Name = strings.TrimSpace(req.Name)
	req.Engine = strings.ToLower(strings.TrimSpace(req.Engine))
	req.Host = strings.TrimSpace(req.Host)
	req.Database = strings.TrimSpace(req.Database)
	req.KeyAlgorithm = strings.TrimSpace(req.KeyAlgorithm)
	req.RotationPolicy = strings.ToLower(strings.TrimSpace(req.RotationPolicy))

	if req.TenantID == "" || req.Name == "" || req.Engine == "" || req.Host == "" || req.Database == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id, name, engine, host and database are required", reqID, req.TenantID)
		return
	}
	if !validTDEEngines[req.Engine] {
		writeErr(w, http.StatusBadRequest, "bad_request", "engine must be one of: oracle, sqlserver, postgresql, mysql, db2", reqID, req.TenantID)
		return
	}
	if req.Port <= 0 || req.Port > 65535 {
		writeErr(w, http.StatusBadRequest, "bad_request", "port must be between 1 and 65535", reqID, req.TenantID)
		return
	}
	if req.KeyAlgorithm == "" {
		req.KeyAlgorithm = "AES-256"
	}
	if req.RotationPolicy == "" {
		req.RotationPolicy = "none"
	}
	if !validTDERotationPolicies[req.RotationPolicy] {
		writeErr(w, http.StatusBadRequest, "bad_request", "rotation_policy must be one of: none, 30d, 90d, 180d, 365d", reqID, req.TenantID)
		return
	}

	db := TDEDatabase{
		ID:             newID("tde"),
		TenantID:       req.TenantID,
		Name:           req.Name,
		Engine:         req.Engine,
		Host:           req.Host,
		Port:           req.Port,
		Database:       req.Database,
		KeyAlgorithm:   req.KeyAlgorithm,
		Status:         "registered",
		RotationPolicy: req.RotationPolicy,
	}
	created, err := h.store.CreateTDEDatabase(r.Context(), db)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "register_tde_database_failed", err.Error(), reqID, req.TenantID)
		return
	}
	_ = h.publishAudit(r.Context(), "audit.kmip.tde_database_registered", req.TenantID, map[string]interface{}{
		"tde_id":   created.ID,
		"name":     created.Name,
		"engine":   created.Engine,
		"host":     created.Host,
		"database": created.Database,
	})
	writeJSON(w, http.StatusCreated, map[string]interface{}{"database": created, "request_id": reqID})
}

// handleGetTDEDatabase handles GET /tde/databases/{id}.
func (h *Handler) handleGetTDEDatabase(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "database id is required", reqID, tenantID)
		return
	}
	db, err := h.store.GetTDEDatabase(r.Context(), tenantID, id)
	if err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "get_tde_database_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"database": db, "request_id": reqID})
}

// handleProvisionTDEKey handles POST /tde/databases/{id}/provision.
// It creates or rotates the TDE key for the registered database via the keycore service.
func (h *Handler) handleProvisionTDEKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "database id is required", reqID, tenantID)
		return
	}
	db, err := h.store.GetTDEDatabase(r.Context(), tenantID, id)
	if err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "provision_tde_key_failed", err.Error(), reqID, tenantID)
		return
	}
	if db.Status == "revoked" {
		writeErr(w, http.StatusConflict, "tde_database_revoked", "cannot provision a key for a revoked database registration", reqID, tenantID)
		return
	}

	// If a key already exists, rotate it; otherwise create a new one.
	var keyID string
	if strings.TrimSpace(db.KeyID) != "" {
		result, rotErr := h.keycore.RotateKey(r.Context(), tenantID, db.KeyID, "tde-key-rotation")
		if rotErr != nil {
			db.Status = "error"
			_, _ = h.store.UpdateTDEDatabase(r.Context(), db)
			writeErr(w, http.StatusInternalServerError, "provision_tde_key_failed", rotErr.Error(), reqID, tenantID)
			return
		}
		if rotatedKeyID, ok := result["key_id"].(string); ok && strings.TrimSpace(rotatedKeyID) != "" {
			keyID = strings.TrimSpace(rotatedKeyID)
		} else {
			keyID = db.KeyID
		}
	} else {
		created, createErr := h.keycore.CreateKey(r.Context(), tenantID, CreateRequest{
			Name:      fmt.Sprintf("tde-%s-%s", db.Engine, db.ID),
			Algorithm: db.KeyAlgorithm,
			KeyType:   "symmetric",
			Purpose:   "encrypt",
		})
		if createErr != nil {
			db.Status = "error"
			_, _ = h.store.UpdateTDEDatabase(r.Context(), db)
			writeErr(w, http.StatusInternalServerError, "provision_tde_key_failed", createErr.Error(), reqID, tenantID)
			return
		}
		keyID = strings.TrimSpace(created)
	}

	now := time.Now().UTC()
	db.KeyID = keyID
	db.Status = "key_provisioned"
	db.LastRotated = now

	updated, err := h.store.UpdateTDEDatabase(r.Context(), db)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "provision_tde_key_failed", err.Error(), reqID, tenantID)
		return
	}
	_ = h.publishAudit(r.Context(), "audit.kmip.tde_key_provisioned", tenantID, map[string]interface{}{
		"tde_id":   updated.ID,
		"name":     updated.Name,
		"engine":   updated.Engine,
		"key_id":   updated.KeyID,
		"rotated":  now.Format(time.RFC3339),
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{"database": updated, "request_id": reqID})
}

// handleRevokeTDEKey handles POST /tde/databases/{id}/revoke.
func (h *Handler) handleRevokeTDEKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "database id is required", reqID, tenantID)
		return
	}
	db, err := h.store.GetTDEDatabase(r.Context(), tenantID, id)
	if err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "revoke_tde_key_failed", err.Error(), reqID, tenantID)
		return
	}
	if db.Status == "revoked" {
		writeErr(w, http.StatusConflict, "already_revoked", "tde database key is already revoked", reqID, tenantID)
		return
	}

	// Revoke the key in keycore if one has been provisioned.
	if strings.TrimSpace(db.KeyID) != "" {
		if revokeErr := h.keycore.SetKeyStatus(r.Context(), tenantID, db.KeyID, "revoked"); revokeErr != nil {
			writeErr(w, http.StatusInternalServerError, "revoke_tde_key_failed", revokeErr.Error(), reqID, tenantID)
			return
		}
	}

	db.Status = "revoked"
	updated, err := h.store.UpdateTDEDatabase(r.Context(), db)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "revoke_tde_key_failed", err.Error(), reqID, tenantID)
		return
	}
	_ = h.publishAudit(r.Context(), "audit.kmip.tde_key_revoked", tenantID, map[string]interface{}{
		"tde_id": updated.ID,
		"name":   updated.Name,
		"engine": updated.Engine,
		"key_id": updated.KeyID,
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{"database": updated, "request_id": reqID})
}

// handleGetTDEStatus handles GET /tde/status and returns an aggregate summary
// across all TDE-registered databases for the tenant.
func (h *Handler) handleGetTDEStatus(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	items, err := h.store.ListTDEDatabases(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "get_tde_status_failed", err.Error(), reqID, tenantID)
		return
	}

	summary := TDEStatusSummary{
		TotalDatabases: len(items),
		ByEngine:       make(map[string]int),
		ByStatus:       make(map[string]int),
	}

	provisioned := 0
	rotationThreshold := time.Now().UTC().Add(30 * 24 * time.Hour)

	for _, db := range items {
		summary.ByEngine[db.Engine]++
		summary.ByStatus[db.Status]++
		if db.Status == "key_provisioned" {
			provisioned++
		}
		if !db.LastRotated.IsZero() && db.RotationPolicy != "none" {
			dueAt := tdeRotationDueAt(db.LastRotated, db.RotationPolicy)
			if !dueAt.IsZero() && dueAt.Before(rotationThreshold) {
				summary.RotationDueSoon++
			}
		}
	}

	if summary.TotalDatabases > 0 {
		summary.KeysProvisionedPct = float64(provisioned) / float64(summary.TotalDatabases) * 100.0
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"status": summary, "request_id": reqID})
}

// tdeRotationDueAt calculates when the next rotation is due given the last rotation time
// and the policy string (30d, 90d, 180d, 365d).
func tdeRotationDueAt(lastRotated time.Time, policy string) time.Time {
	if lastRotated.IsZero() || policy == "none" || policy == "" {
		return time.Time{}
	}
	days := map[string]int{
		"30d":  30,
		"90d":  90,
		"180d": 180,
		"365d": 365,
	}
	d, ok := days[policy]
	if !ok {
		return time.Time{}
	}
	return lastRotated.UTC().Add(time.Duration(d) * 24 * time.Hour)
}
