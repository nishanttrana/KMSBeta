package main

import (
	"net/http"
	"strings"

	"vecta-kms/pkg/cbom"
)

// handleCBOMInventory returns the cryptographic bill of materials for a
// tenant. The data is derived from the audit log: every key-management
// audit event records the algorithm + parameters, so the inventory is a
// projection over the immutable chain rather than a separate source of
// truth. That makes the report tamper-evident automatically.
//
// GET /audit/cbom/inventory?tenant_id=...&floor=pqc-hybrid
func (h *Handler) handleCBOMInventory(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	floor := cbom.Tier(strings.ToLower(strings.TrimSpace(r.URL.Query().Get("floor"))))
	samples, err := h.store.CBOMSamples(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "cbom_failed", "failed to build inventory", reqID, tenantID)
		return
	}
	entries := make([]cbom.Entry, 0, len(samples))
	for _, s := range samples {
		entries = append(entries, cbom.Entry{
			Algorithm:   s.Algorithm,
			Parameters:  s.Parameters,
			KeyCount:    s.KeyCount,
			FirstSeenAt: s.FirstSeenAt,
			LastUsedAt:  s.LastUsedAt,
		})
	}
	inv := cbom.Build(tenantID, floor, entries)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"inventory":  inv,
		"request_id": reqID,
	})
}

// handleCBOMDiff compares the live inventory against a target tier and
// returns only the entries that fall below the floor. This is the
// "what needs to migrate" view consumed by the migration planner.
//
// GET /audit/cbom/diff?tenant_id=...&target=pqc-hybrid
func (h *Handler) handleCBOMDiff(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	target := cbom.Tier(strings.ToLower(strings.TrimSpace(r.URL.Query().Get("target"))))
	if target == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "target tier is required", reqID, tenantID)
		return
	}
	samples, err := h.store.CBOMSamples(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "cbom_failed", "failed to build diff", reqID, tenantID)
		return
	}
	entries := make([]cbom.Entry, 0, len(samples))
	for _, s := range samples {
		entries = append(entries, cbom.Entry{
			Algorithm:   s.Algorithm,
			Parameters:  s.Parameters,
			KeyCount:    s.KeyCount,
			FirstSeenAt: s.FirstSeenAt,
			LastUsedAt:  s.LastUsedAt,
		})
	}
	inv := cbom.Build(tenantID, target, entries)
	below := make([]cbom.Entry, 0)
	for _, e := range inv.Entries {
		if e.Note != "" || e.Deprecated {
			below = append(below, e)
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"target":        target,
		"total_keys":    inv.TotalKeys,
		"below_floor":   below,
		"ready_percent": inv.ReadinessPercent,
		"request_id":    reqID,
	})
}
