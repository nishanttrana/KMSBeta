package main

import (
	"context"
	"net/http"
	"time"
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
