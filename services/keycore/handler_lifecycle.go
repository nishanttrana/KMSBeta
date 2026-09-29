package main

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// handleDueForLifecycle is the controller-pull endpoint the reconciler
// hits every tick. It returns the keys that are due for an automated
// lifecycle action (rotation; see EvaluateLifecycle). The
// reconciler then POSTs back to the corresponding action endpoint to
// trigger the change; concentrating the "what is due" logic here means
// only one component needs to know the lifecycle rules.
//
// GET /keys/due-for-lifecycle?max=200
func (h *Handler) handleDueForLifecycle(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	maxN, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("max")))
	if maxN <= 0 || maxN > 1000 {
		maxN = 200
	}
	items, err := h.svc.dueForLifecycle(r.Context(), maxN)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "due_failed", "lifecycle scan failed", reqID, "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":      items,
		"request_id": reqID,
	})
}

// dueForLifecycle is the Service-level helper that pulls candidate keys
// and tags each with the action EvaluateLifecycle decides: rotate on an
// operator-set expiry, an expired cryptoperiod or 80% of ops_limit.
type dueLifecycleItem struct {
	TenantID string `json:"tenant_id"`
	KeyID    string `json:"key_id"`
	Action   string `json:"action"`
	Reason   string `json:"reason"`
}

func (s *Service) dueForLifecycle(ctx context.Context, maxN int) ([]dueLifecycleItem, error) {
	if s.cryptoperiod == nil {
		return nil, nil
	}
	scanner, ok := s.store.(interface {
		ScanLifecycleCandidates(ctx context.Context, limit int) ([]LifecycleCandidate, error)
	})
	if !ok {
		return nil, nil
	}
	candidates, err := scanner.ScanLifecycleCandidates(ctx, maxN)
	if err != nil {
		return nil, err
	}
	out := make([]dueLifecycleItem, 0, len(candidates))
	now := time.Now().UTC()
	for _, c := range candidates {
		action, reason := EvaluateLifecycle(c, s.cryptoperiod, now)
		if action == "" {
			continue
		}
		out = append(out, dueLifecycleItem{
			TenantID: c.TenantID,
			KeyID:    c.ID,
			Action:   action,
			Reason:   reason,
		})
	}
	return out, nil
}
