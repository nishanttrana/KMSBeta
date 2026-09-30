package main

import (
	"errors"
	"log"
	"net/http"
	"strings"

	"vecta-kms/pkg/route"
)

// Handler serves discovery through the route kernel (7.9.0-beta). Until then
// the service verified no token at all: tenantcheck.Enforce skipped every
// request because nothing put claims in the context, and scans and
// classifications took the tenant from the body. Every route now needs a
// verified JWT (pkg/jwtauth in main.go) and discovery.read or
// discovery.write, and emits audit.discovery.<action>, refusals included.
type Handler struct {
	svc    *Service
	router *route.Router
}

func NewHandler(svc *Service, audit route.Emitter, logger *log.Logger) *Handler {
	h := &Handler{svc: svc}
	r := route.New("discovery", audit, logger)
	read := func(action string) route.Spec {
		return route.Spec{Action: action, Permission: "discovery.read", Resource: "discovery"}
	}
	r.Handle("POST /discovery/scan", route.Spec{Action: "scan_start", Permission: "discovery.write", Resource: "discovery_scan"}, h.startScan)
	r.Handle("GET /discovery/scans", read("scans_list"), h.listScans)
	r.Handle("GET /discovery/scans/{id}", route.Spec{Action: "scan_read", Permission: "discovery.read", Resource: "discovery_scan", TargetParam: "id"}, h.getScan)
	r.Handle("GET /discovery/assets", read("assets_list"), h.listAssets)
	// pqc and sbom read the inventory here with their service tokens.
	r.Handle("GET /discovery/crypto/assets", read("assets_list"), h.listAssets)
	r.Handle("GET /discovery/assets/{id}", route.Spec{Action: "asset_read", Permission: "discovery.read", Resource: "crypto_asset", TargetParam: "id"}, h.getAsset)
	r.Handle("PUT /discovery/assets/{id}/classify", route.Spec{Action: "asset_review", Permission: "discovery.write", Resource: "crypto_asset", TargetParam: "id"}, h.reviewAsset)
	r.Handle("GET /discovery/summary", read("summary_read"), h.summary)
	h.router = r
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.router.ServeHTTP(w, r) }

func (h *Handler) startScan(c *route.Call) {
	var req ScanRequest
	if !c.Decode(&req) {
		return
	}
	req.TenantID = c.Tenant
	item, err := h.svc.StartScan(c.R.Context(), req)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.Target(item.ID)
	c.Detail("scan_types", item.ScanType)
	c.Detail("status", item.Status)
	c.JSON(http.StatusAccepted, map[string]interface{}{"scan": item})
}

func (h *Handler) listScans(c *route.Call) {
	items, err := h.svc.ListScans(c.R.Context(), c.Tenant, atoi(c.R.URL.Query().Get("limit")), atoi(c.R.URL.Query().Get("offset")))
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

func (h *Handler) getScan(c *route.Call) {
	item, err := h.svc.GetScan(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"scan": item})
}

func (h *Handler) listAssets(c *route.Call) {
	q := c.R.URL.Query()
	items, err := h.svc.ListAssets(
		c.R.Context(),
		c.Tenant,
		atoi(q.Get("limit")),
		atoi(q.Get("offset")),
		strings.ToLower(strings.TrimSpace(q.Get("source"))),
		strings.ToLower(strings.TrimSpace(q.Get("asset_type"))),
		strings.ToLower(strings.TrimSpace(q.Get("classification"))),
	)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

func (h *Handler) getAsset(c *route.Call) {
	item, err := h.svc.GetAsset(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"asset": item})
}

// reviewAsset records an operator's review (status, notes). The
// classification is a catalogue fact about the algorithm and can't be
// overridden here; a request that tries is refused.
func (h *Handler) reviewAsset(c *route.Call) {
	var req ClassifyRequest
	if !c.Decode(&req) {
		return
	}
	item, err := h.svc.ClassifyAsset(c.R.Context(), c.Tenant, c.R.PathValue("id"), req)
	if errors.Is(err, errClassificationIsCatalogue) {
		c.Refuse(http.StatusConflict, "classification_is_catalogue", err.Error())
		return
	}
	if err != nil {
		h.fail(c, err)
		return
	}
	c.Detail("status", item.Status)
	c.JSON(http.StatusOK, map[string]interface{}{"asset": item})
}

func (h *Handler) summary(c *route.Call) {
	item, err := h.svc.Summary(c.R.Context(), c.Tenant)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"summary": item})
}

func (h *Handler) fail(c *route.Call, err error) {
	var svcErr serviceError
	if errors.As(err, &svcErr) {
		c.Error(svcErr.HTTPStatus, svcErr.Code, svcErr.Message)
		return
	}
	// Don't leak internal error details on 5xx.
	if status := httpStatusForErr(err); status < 500 {
		c.Error(status, "not_found", err.Error())
		return
	}
	c.Error(http.StatusInternalServerError, "internal_error", "internal server error")
}
