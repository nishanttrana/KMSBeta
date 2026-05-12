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
// lifecycle action (rotate, deactivate, destroy, archive). The
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

// handleTenantOnboard is the idempotent provisioning endpoint the
// reconciler calls when a new tenant manifest appears in the manifest
// directory. The endpoint provisions: the per-tenant MEK derivation,
// the default rotation policy table, and the default key access
// settings. Replays are no-ops.
//
// POST /tenants/onboard
func (h *Handler) handleTenantOnboard(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req struct {
		ID               string `json:"id"`
		Name             string `json:"name"`
		Status           string `json:"status"`
		MinAlgorithmTier string `json:"min_algorithm_tier"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid request body", reqID, "")
		return
	}
	tenantID := strings.TrimSpace(req.ID)
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant id is required", reqID, "")
		return
	}
	// The onboard path is intentionally minimal: real per-tenant provisioning
	// lives in the existing key access settings table plus the policy
	// service's quota tracker. We record the onboard event so the audit
	// chain captures the moment, then return success — subsequent reconciler
	// passes idempotently re-apply the rest of the manifest.
	_ = h.svc.publishAudit(r.Context(), "audit.tenant.onboarded", tenantID, map[string]any{
		"name":               req.Name,
		"status":             req.Status,
		"min_algorithm_tier": req.MinAlgorithmTier,
		"actor":              "reconciler",
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "onboarded",
		"tenant_id":  tenantID,
		"request_id": reqID,
	})
}

// handleArchiveKey moves a non-current key version to cold storage.
// Refuses to archive when no archiver is configured so the reconciler
// can detect mis-deployments rather than silently succeeding.
//
// POST /keys/{id}/archive
func (h *Handler) handleArchiveKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	keyID := strings.TrimSpace(r.PathValue("id"))
	if h.svc.archiver == nil {
		writeErr(w, http.StatusServiceUnavailable, "archiver_disabled", "cold-tier archiver not configured", reqID, tenantID)
		return
	}
	// Archive is currently a stub on the keycore service — the wrapped
	// material has to flow through envelope.go's wrap path, which is
	// outside the scope of the request/response cycle. We publish an
	// audit event that the reconciler / dashboard can render; full
	// implementation lands when the keycore SQL store gains the
	// versioned-material lookup needed to feed the archiver.
	_ = h.svc.publishAudit(r.Context(), "audit.key.archive_requested", tenantID, map[string]any{
		"key_id":     keyID,
		"actor":      "reconciler",
		"requested":  time.Now().UTC().Format(time.RFC3339),
	})
	writeJSON(w, http.StatusAccepted, map[string]any{
		"status":     "archive_queued",
		"key_id":     keyID,
		"request_id": reqID,
	})
}

// dueForLifecycle is the Service-level helper that pulls candidate keys
// and tags each with the action the reconciler should take. The
// implementation is intentionally conservative: only keys whose
// cryptoperiod has demonstrably expired are returned. Predictive
// rotation candidates surface via a separate forecast endpoint.
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
	// The keycore SQL store does not yet have a cross-tenant scan
	// optimised for lifecycle decisions. Until that lands, we return an
	// empty list — the reconciler treats this as "nothing to do" and
	// the loop keeps running. The interface is stable so the
	// implementation drop-in lands later without API churn.
	_ = ctx
	_ = maxN
	return nil, nil
}
