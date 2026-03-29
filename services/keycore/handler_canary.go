package main

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// CanaryKey represents a honeypot key that triggers alerts when accessed.
type CanaryKey struct {
	ID          string            `json:"id"`
	TenantID    string            `json:"tenant_id"`
	Name        string            `json:"name"`
	Algorithm   string            `json:"algorithm"`
	Purpose     string            `json:"purpose"`
	TripCount   int               `json:"trip_count"`
	LastTripped *time.Time        `json:"last_tripped,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	Active      bool              `json:"active"`
	NotifyEmail string            `json:"notify_email"`
	Metadata    map[string]string `json:"metadata"`
}

// CanaryTripEvent records each time a canary key is accessed.
type CanaryTripEvent struct {
	ID         string    `json:"id"`
	CanaryID   string    `json:"canary_id"`
	TenantID   string    `json:"tenant_id"`
	ActorID    string    `json:"actor_id"`
	ActorIP    string    `json:"actor_ip"`
	UserAgent  string    `json:"user_agent"`
	TrippedAt  time.Time `json:"tripped_at"`
	Severity   string    `json:"severity"`
	RawRequest string    `json:"raw_request"`
}

// handleListCanaryKeys lists all canary keys for the tenant.
func (h *Handler) handleListCanaryKeys(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	keys, err := h.svc.store.ListCanaryKeys(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_canary_keys_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": keys, "request_id": reqID})
}

// handleCreateCanaryKey creates a new canary key for the tenant.
func (h *Handler) handleCreateCanaryKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req struct {
		TenantID    string            `json:"tenant_id"`
		Name        string            `json:"name"`
		Algorithm   string            `json:"algorithm"`
		Purpose     string            `json:"purpose"`
		NotifyEmail string            `json:"notify_email"`
		Metadata    map[string]string `json:"metadata"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, req.TenantID)
		return
	}
	tenantID := req.TenantID
	if tenantID == "" {
		tenantID = mustTenant(r, reqID, w)
		if tenantID == "" {
			return
		}
	}
	if req.Name == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "name is required", reqID, tenantID)
		return
	}
	algo := req.Algorithm
	if algo == "" {
		algo = "AES-256-GCM"
	}
	purpose := req.Purpose
	if purpose == "" {
		purpose = "detect_exfiltration"
	}
	if req.Metadata == nil {
		req.Metadata = map[string]string{}
	}

	key := CanaryKey{
		ID:          newID("canary"),
		TenantID:    tenantID,
		Name:        req.Name,
		Algorithm:   algo,
		Purpose:     purpose,
		Active:      true,
		NotifyEmail: req.NotifyEmail,
		Metadata:    req.Metadata,
	}

	if err := h.svc.store.CreateCanaryKey(r.Context(), key); err != nil {
		writeErr(w, http.StatusInternalServerError, "create_canary_key_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"data": key, "request_id": reqID})
}

// handleGetCanaryKey returns details for a single canary key.
func (h *Handler) handleGetCanaryKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	canaryID := strings.TrimSpace(r.PathValue("id"))
	if canaryID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "canary id is required", reqID, tenantID)
		return
	}
	key, err := h.svc.store.GetCanaryKey(r.Context(), tenantID, canaryID)
	if err != nil {
		if err == errStoreNotFound {
			writeErr(w, http.StatusNotFound, "not_found", "canary key not found", reqID, tenantID)
			return
		}
		writeErr(w, http.StatusInternalServerError, "get_canary_key_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": key, "request_id": reqID})
}

// handleDeleteCanaryKey deactivates a canary key.
func (h *Handler) handleDeleteCanaryKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	canaryID := strings.TrimSpace(r.PathValue("id"))
	if canaryID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "canary id is required", reqID, tenantID)
		return
	}
	if err := h.svc.store.DeleteCanaryKey(r.Context(), tenantID, canaryID); err != nil {
		if err == errStoreNotFound {
			writeErr(w, http.StatusNotFound, "not_found", "canary key not found", reqID, tenantID)
			return
		}
		writeErr(w, http.StatusInternalServerError, "delete_canary_key_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]string{"status": "deactivated"}, "request_id": reqID})
}

// handleTripCanaryKey manually trips a canary key (for testing).
func (h *Handler) handleTripCanaryKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	canaryID := strings.TrimSpace(r.PathValue("id"))
	if canaryID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "canary id is required", reqID, tenantID)
		return
	}

	// Verify the canary key exists.
	_, err := h.svc.store.GetCanaryKey(r.Context(), tenantID, canaryID)
	if err != nil {
		if err == errStoreNotFound {
			writeErr(w, http.StatusNotFound, "not_found", "canary key not found", reqID, tenantID)
			return
		}
		writeErr(w, http.StatusInternalServerError, "get_canary_key_failed", err.Error(), reqID, tenantID)
		return
	}

	// Derive actor info from request context.
	actor := accessActorFromHTTPRequest(r)
	actorID := actor.SubjectID
	if actorID == "" {
		actorID = "manual_test"
	}
	actorIP := r.Header.Get("X-Forwarded-For")
	if actorIP == "" {
		actorIP = r.RemoteAddr
	}

	event := CanaryTripEvent{
		ID:         newID("ctrip"),
		CanaryID:   canaryID,
		TenantID:   tenantID,
		ActorID:    actorID,
		ActorIP:    actorIP,
		UserAgent:  r.Header.Get("User-Agent"),
		TrippedAt:  time.Now().UTC(),
		Severity:   "critical",
		RawRequest: "POST /canary/" + canaryID + "/trip",
	}

	if err := h.svc.store.RecordCanaryTrip(r.Context(), event); err != nil {
		writeErr(w, http.StatusInternalServerError, "record_canary_trip_failed", err.Error(), reqID, tenantID)
		return
	}

	// Publish audit event for the canary trip.
	if h.svc.events != nil {
		_ = publishAuditEvent(r.Context(), h.svc.events, "audit.keycore.canary_tripped", tenantID, map[string]any{
			"canary_id":  canaryID,
			"actor_id":   actorID,
			"actor_ip":   actorIP,
			"severity":   "critical",
			"request_id": reqID,
			"tripped_at": event.TrippedAt,
		})
	}

	writeJSON(w, http.StatusCreated, map[string]any{"data": event, "request_id": reqID})
}

// handleListCanaryTrips lists trip events for a canary key.
func (h *Handler) handleListCanaryTrips(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	canaryID := strings.TrimSpace(r.PathValue("id"))
	if canaryID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "canary id is required", reqID, tenantID)
		return
	}
	limitStr := r.URL.Query().Get("limit")
	limit := 50
	if limitStr != "" {
		if v, err := strconv.Atoi(limitStr); err == nil && v > 0 {
			limit = v
		}
	}
	trips, err := h.svc.store.ListCanaryTrips(r.Context(), tenantID, canaryID, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_canary_trips_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": trips, "request_id": reqID})
}

// handleGetCanarySummary returns a summary of canary key activity for the tenant.
func (h *Handler) handleGetCanarySummary(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	summary, err := h.svc.store.GetCanarySummary(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "get_canary_summary_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": summary, "request_id": reqID})
}
