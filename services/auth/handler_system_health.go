package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	pkgauth "vecta-kms/pkg/auth"
)

func (h *Handler) handleSystemHealth(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)

	if h.healthChecker == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"summary": map[string]any{
				"total":    0,
				"running":  0,
				"degraded": 0,
				"down":     0,
				"unknown":  0,
				"all_ok":   false,
			},
			"services":   []any{},
			"request_id": reqID,
			"warning":    "system health checker is not configured",
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	snapshot, err := h.healthChecker.Snapshot(ctx)
	payload := map[string]any{
		"summary":      snapshot.Summary,
		"services":     snapshot.Services,
		"collected_at": snapshot.CollectedAt,
		"request_id":   reqID,
	}
	if err != nil {
		payload["warning"] = err.Error()
	}
	writeJSON(w, http.StatusOK, payload)
}

func (h *Handler) handleRestartSystemService(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	claims, _ := pkgauth.ClaimsFromContext(r.Context())

	if h.healthChecker == nil {
		writeErr(w, http.StatusServiceUnavailable, "restart_unavailable", "system health checker is not configured", reqID, claims.TenantID)
		return
	}

	var req struct {
		Service string `json:"service"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, claims.TenantID)
		return
	}
	serviceName := strings.TrimSpace(req.Service)
	if serviceName == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "service is required", reqID, claims.TenantID)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	target, err := h.healthChecker.RestartService(ctx, serviceName)
	if err != nil {
		switch {
		case errors.Is(err, errRestartNotAllowed):
			writeErr(w, http.StatusForbidden, "restart_not_allowed", err.Error(), reqID, claims.TenantID)
		case errors.Is(err, errRestartUnavailable):
			writeErr(w, http.StatusServiceUnavailable, "restart_unavailable", err.Error(), reqID, claims.TenantID)
		default:
			writeErr(w, http.StatusBadGateway, "restart_failed", err.Error(), reqID, claims.TenantID)
		}
		return
	}

	if h.logger != nil {
		h.logger.Printf("system restart requested tenant=%s user=%s service=%s target=%s", claims.TenantID, claims.UserID, serviceName, target)
	}
	_ = h.publishAudit(r.Context(), "audit.auth.service_restart", reqID, claims.TenantID, map[string]any{
		"service": serviceName,
		"target":  target,
		"user_id": claims.UserID,
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "restarting",
		"service":    serviceName,
		"target":     target,
		"request_id": reqID,
	})
}
