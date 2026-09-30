package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"

	"vecta-kms/pkg/route"
	"vecta-kms/pkg/tenantcheck"
)

// Handler serves the SBOM and CBOM APIs. Every route is registered through
// the pkg/route kernel, which authenticates the caller, binds the tenant to
// the verified token, checks the route's permission and emits one
// audit.sbom.<action> event per request, refusals included.
type Handler struct {
	svc    *Service
	router *route.Router
}

// Permissions for the sbom domain.
const (
	permRead  = "sbom.read"
	permWrite = "sbom.write" // generate snapshots
)

// reasonPlatformTenant refuses a platform-wide write (the platform SBOM and
// its advisories are shared by every tenant) from a tenant other than the
// platform tenant.
const reasonPlatformTenant = "platform_tenant_required"

func NewHandler(svc *Service, audit route.Emitter, logger *log.Logger) *Handler {
	h := &Handler{svc: svc, router: route.New("sbom", audit, logger)}
	h.routes()
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.router.ServeHTTP(w, r)
}

func (h *Handler) routes() {
	r := h.router
	// The platform SBOM belongs to no tenant.
	platform := func(action, perm, resource, target string) route.Spec {
		return route.Spec{Action: action, Permission: perm, Resource: resource, TargetParam: target, Tenancy: route.PlatformScoped}
	}
	r.Handle("POST /sbom/generate", platform("sbom_generate_requested", permWrite, "sbom", ""), h.generateSBOM)
	r.Handle("GET /sbom/latest", platform("sbom_latest_read", permRead, "sbom", ""), h.latestSBOM)
	r.Handle("GET /sbom/history", platform("sbom_history_listed", permRead, "sbom", ""), h.sbomHistory)
	r.Handle("GET /sbom/diff", platform("sbom_diff_read", permRead, "sbom", ""), h.sbomDiff)
	r.Handle("GET /sbom/{id}/export", platform("sbom_exported", permRead, "sbom", "id"), h.sbomExport)
	r.Handle("GET /sbom/{id}", platform("sbom_read", permRead, "sbom", "id"), h.sbomByID)

	cbom := func(action, perm, target string) route.Spec {
		return route.Spec{Action: action, Permission: perm, Resource: "cbom", TargetParam: target}
	}
	r.Handle("POST /cbom/generate", cbom("cbom_generate_requested", permWrite, ""), h.generateCBOM)
	r.Handle("GET /cbom/latest", cbom("cbom_latest_read", permRead, ""), h.latestCBOM)
	r.Handle("GET /cbom/history", cbom("cbom_history_listed", permRead, ""), h.cbomHistory)
	r.Handle("GET /cbom/summary", cbom("cbom_summary_read", permRead, ""), h.cbomSummary)
	r.Handle("GET /cbom/pqc-readiness", cbom("cbom_pqc_readiness_read", permRead, ""), h.cbomPQCReadiness)
	r.Handle("GET /cbom/diff", cbom("cbom_diff_read", permRead, ""), h.cbomDiff)
	r.Handle("GET /cbom/{id}/export", cbom("cbom_exported", permRead, "id"), h.cbomExport)
	r.Handle("GET /cbom/{id}", cbom("cbom_read", permRead, "id"), h.cbomByID)
}

// platformWriter refuses a write to platform-wide SBOM state unless the
// caller belongs to the platform tenant (or is a tenant-less root token or an
// internal service principal). Tenant administrators elsewhere hold
// sbom.write too, but must not change what every tenant sees.
func platformWriter(c *route.Call) bool {
	tenant := strings.TrimSpace(c.Claims.TenantID)
	if tenant == "" || tenant == tenantcheck.InternalServiceTenant() || tenantcheck.IsServicePrincipal(c.Claims) {
		return true
	}
	c.Refuse(http.StatusForbidden, reasonPlatformTenant, "the platform SBOM is managed from the platform tenant")
	return false
}

type generateRequest struct {
	Trigger string `json:"trigger"`
}

func (h *Handler) generateSBOM(c *route.Call) {
	if !platformWriter(c) {
		return
	}
	var req generateRequest
	if !decodeOptional(c, &req) {
		return
	}
	item, err := h.svc.GenerateSBOM(c.R.Context(), req.Trigger)
	if err != nil {
		h.serviceError(c, err)
		return
	}
	c.Target(item.ID)
	c.Detail("component_count", len(item.Document.Components))
	c.JSON(http.StatusAccepted, map[string]interface{}{"status": "accepted", "snapshot": item})
}

func (h *Handler) latestSBOM(c *route.Call) {
	item, err := h.svc.GetLatestSBOM(c.R.Context())
	if err != nil {
		h.serviceError(c, err)
		return
	}
	c.Target(item.ID)
	c.JSON(http.StatusOK, map[string]interface{}{"item": item})
}

func (h *Handler) sbomHistory(c *route.Call) {
	items, err := h.svc.ListSBOMHistory(c.R.Context(), atoi(c.R.URL.Query().Get("limit")))
	if err != nil {
		h.serviceError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

func (h *Handler) sbomByID(c *route.Call) {
	item, err := h.svc.GetSBOMByID(c.R.Context(), c.R.PathValue("id"))
	if err != nil {
		h.serviceError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"item": item})
}

func (h *Handler) sbomExport(c *route.Call) {
	format := firstNonEmpty(c.R.URL.Query().Get("format"), "cyclonedx")
	encoding := firstNonEmpty(c.R.URL.Query().Get("encoding"), "json")
	c.Detail("format", format)
	out, err := h.svc.ExportSBOM(c.R.Context(), c.R.PathValue("id"), format, encoding)
	if err != nil {
		h.serviceError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"export": out})
}

func (h *Handler) sbomDiff(c *route.Call) {
	q := c.R.URL.Query()
	diff, err := h.svc.DiffSBOM(c.R.Context(), strings.TrimSpace(q.Get("from")), strings.TrimSpace(q.Get("to")))
	if err != nil {
		h.serviceError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"diff": diff})
}

// generateCBOM builds a CBOM for the caller's own tenant. The tenant comes
// from the kernel (bound to the verified token); a tenant_id in the body is
// checked by the kernel and must match it.
func (h *Handler) generateCBOM(c *route.Call) {
	var req struct {
		TenantID string `json:"tenant_id"` // verified by the kernel; c.Tenant is used
		Trigger  string `json:"trigger"`
	}
	if !decodeOptional(c, &req) {
		return
	}
	item, err := h.svc.GenerateCBOM(c.R.Context(), c.Tenant, req.Trigger)
	if err != nil {
		h.serviceError(c, err)
		return
	}
	c.Target(item.ID)
	c.Detail("asset_count", item.Document.TotalAssetCount)
	c.JSON(http.StatusAccepted, map[string]interface{}{"status": "accepted", "snapshot": item})
}

func (h *Handler) latestCBOM(c *route.Call) {
	item, err := h.svc.GetLatestCBOM(c.R.Context(), c.Tenant)
	if err != nil {
		h.serviceError(c, err)
		return
	}
	c.Target(item.ID)
	c.JSON(http.StatusOK, map[string]interface{}{"item": item})
}

func (h *Handler) cbomHistory(c *route.Call) {
	items, err := h.svc.ListCBOMHistory(c.R.Context(), c.Tenant, atoi(c.R.URL.Query().Get("limit")))
	if err != nil {
		h.serviceError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

func (h *Handler) cbomByID(c *route.Call) {
	item, err := h.svc.GetCBOMByID(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if err != nil {
		h.serviceError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"item": item})
}

func (h *Handler) cbomExport(c *route.Call) {
	format := firstNonEmpty(c.R.URL.Query().Get("format"), "cyclonedx")
	c.Detail("format", format)
	out, err := h.svc.ExportCBOM(c.R.Context(), c.Tenant, c.R.PathValue("id"), format)
	if err != nil {
		h.serviceError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"export": out})
}

func (h *Handler) cbomSummary(c *route.Call) {
	out, err := h.svc.CBOMSummary(c.R.Context(), c.Tenant)
	if err != nil {
		h.serviceError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"summary": out})
}

func (h *Handler) cbomPQCReadiness(c *route.Call) {
	out, err := h.svc.CBOMPQCReadiness(c.R.Context(), c.Tenant)
	if err != nil {
		h.serviceError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"pqc_readiness": out})
}

func (h *Handler) cbomDiff(c *route.Call) {
	q := c.R.URL.Query()
	diff, err := h.svc.DiffCBOM(c.R.Context(), c.Tenant, strings.TrimSpace(q.Get("from")), strings.TrimSpace(q.Get("to")))
	if err != nil {
		h.serviceError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"diff": diff})
}

// serviceError writes a service error; 5xx details stay out of the response.
func (h *Handler) serviceError(c *route.Call, err error) {
	var svcErr serviceError
	if errors.As(err, &svcErr) {
		c.Error(svcErr.HTTPStatus, svcErr.Code, svcErr.Message)
		return
	}
	status := httpStatusForErr(err)
	msg := err.Error()
	if status >= 500 {
		msg = "internal server error"
	}
	c.Error(status, "internal_error", msg)
}

// decodeOptional decodes a JSON body that may be absent, rejecting unknown
// fields. On a malformed body it writes a 400 and returns false.
func decodeOptional(c *route.Call, out interface{}) bool {
	raw, err := io.ReadAll(io.LimitReader(c.R.Body, route.MaxBody))
	if err != nil {
		c.Error(http.StatusBadRequest, "bad_request", "unreadable request body")
		return false
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return true
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		c.Error(http.StatusBadRequest, "bad_request", err.Error())
		return false
	}
	return true
}

func atoi(v string) int {
	n := 0
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return n
		}
		n = n*10 + int(v[i]-'0')
	}
	return n
}

// Public reports whether r reaches a Public route (pkg/jwtauth.MustWrapRouter).
func (h *Handler) Public(r *http.Request) bool { return h.router.Public(r) }

// Routed reports whether r matches a route (pkg/jwtauth.MustWrapRouter).
func (h *Handler) Routed(r *http.Request) bool { return h.router.Routed(r) }
