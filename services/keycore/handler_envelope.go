package main

import (
	"net/http"
	"strings"
)

func (h *Handler) handleListKEKs(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	keks, err := h.svc.store.ListKEKs(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_keks_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": keks})
}

func (h *Handler) handleCreateKEK(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req CreateKEKRequest
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
	algorithm := req.Algorithm
	if algorithm == "" {
		algorithm = "AES-256-GCM"
	}
	kek := KEK{
		ID:        newID("kek"),
		TenantID:  tenantID,
		Name:      req.Name,
		Algorithm: algorithm,
		Version:   1,
		Status:    "active",
	}
	created, err := h.svc.store.CreateKEK(r.Context(), kek)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "create_kek_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"data": created})
}

func (h *Handler) handleRotateKEK(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	kekID := strings.TrimPrefix(r.PathValue("id"), "")
	if kekID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "kek id is required", reqID, tenantID)
		return
	}
	kek, err := h.svc.store.RotateKEK(r.Context(), tenantID, kekID)
	if err != nil {
		if err == errStoreNotFound {
			writeErr(w, http.StatusNotFound, "not_found", "KEK not found", reqID, tenantID)
			return
		}
		writeErr(w, http.StatusInternalServerError, "rotate_kek_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": kek})
}

func (h *Handler) handleListDEKs(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	kekID := r.URL.Query().Get("kek_id")
	deks, err := h.svc.store.ListDEKs(r.Context(), tenantID, kekID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_deks_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": deks})
}

func (h *Handler) handleGetHierarchy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	nodes, err := h.svc.store.GetEnvelopeHierarchy(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "hierarchy_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": nodes})
}

func (h *Handler) handleStartRewrap(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req StartRewrapRequest
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
	if req.OldKEKID == "" || req.NewKEKID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "old_kek_id and new_kek_id are required", reqID, tenantID)
		return
	}
	job := RewrapJob{
		ID:       newID("rwrap"),
		TenantID: tenantID,
		OldKEKID: req.OldKEKID,
		NewKEKID: req.NewKEKID,
	}
	created, err := h.svc.store.CreateRewrapJob(r.Context(), job)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "rewrap_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"data": created})
}

func (h *Handler) handleListRewrapJobs(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	jobs, err := h.svc.store.ListRewrapJobs(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_rewrap_jobs_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": jobs})
}
