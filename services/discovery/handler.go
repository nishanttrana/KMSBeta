package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
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
	// TLS endpoints the network scan handshakes with (7.11.0-beta).
	r.Handle("GET /discovery/targets", read("targets_list"), h.listTargets)
	r.Handle("POST /discovery/targets", route.Spec{Action: "target_add", Permission: "discovery.write", Resource: "discovery_target"}, h.addTarget)
	r.Handle("DELETE /discovery/targets/{id}", route.Spec{Action: "target_remove", Permission: "discovery.write", Resource: "discovery_target", TargetParam: "id"}, h.removeTarget)
	// 7.18.0-beta: source status, file uploads, and removing a stale asset.
	r.Handle("GET /discovery/sources", read("sources_read"), h.sources)
	r.Handle("POST /discovery/upload", route.Spec{Action: "upload_scan", Permission: "discovery.write", Resource: "discovery_scan"}, h.upload)
	r.Handle("DELETE /discovery/assets/{id}", route.Spec{Action: "asset_remove", Permission: "discovery.write", Resource: "crypto_asset", TargetParam: "id"}, h.removeAsset)
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
	if errors.Is(err, errScanRunning) {
		c.Detail("running_scan_id", item.ID)
		c.Refuse(http.StatusConflict, "scan_running", err.Error())
		return
	}
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

// listAssets pages the assets matching the query's filters; total is how
// many match in the whole inventory, which is the number the summary shows
// for the same filter.
func (h *Handler) listAssets(c *route.Call) {
	q := c.R.URL.Query()
	lower := func(k string) string { return strings.ToLower(strings.TrimSpace(q.Get(k))) }
	f := AssetFilter{
		Source: lower("source"), AssetType: lower("asset_type"), Query: q.Get("q"),
		PQCReady: lower("pqc_ready") == "true", NotSeen: lower("not_seen") == "true", ExpiringDays: atoi(q.Get("expiring_days")),
	}
	if cls := lower("classification"); cls != "" {
		f.Classes = strings.Split(cls, ",")
	}
	if q.Has("algorithm") {
		alg := q.Get("algorithm")
		f.Algorithm = &alg
	}
	items, total, err := h.svc.FindAssets(c.R.Context(), c.Tenant, atoi(q.Get("limit")), atoi(q.Get("offset")), f)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": items, "total": total})
}

func (h *Handler) getAsset(c *route.Call) {
	item, err := h.svc.GetAsset(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"asset": item})
}

// reviewAsset records an operator's review (status, notes) in the asset's
// metadata, where a rescan keeps it. The classification is a catalogue fact
// about the algorithm and can't be overridden here; a request that tries is
// refused.
func (h *Handler) reviewAsset(c *route.Call) {
	var req ClassifyRequest
	if !c.Decode(&req) {
		return
	}
	item, err := h.svc.ClassifyAsset(c.R.Context(), c.Tenant, c.R.PathValue("id"), req, c.Actor())
	if errors.Is(err, errClassificationIsCatalogue) {
		c.Refuse(http.StatusConflict, "classification_is_catalogue", err.Error())
		return
	}
	if err != nil {
		h.fail(c, err)
		return
	}
	c.Detail("review_status", item.Metadata["review_status"])
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

func (h *Handler) listTargets(c *route.Call) {
	items, err := h.svc.ListTargets(c.R.Context(), c.Tenant)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

// addTarget refuses, with its reason audited, a host that isn't a DNS name,
// IP or range of at most 256 addresses, a reserved address (loopback,
// link-local, metadata), a KMS platform host, a protocol other than tls or
// ssh, a duplicate, and the per-tenant limit.
func (h *Handler) addTarget(c *route.Call) {
	var req struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
	}
	if !c.Decode(&req) {
		return
	}
	c.Detail("host", req.Host)
	c.Detail("port", req.Port)
	c.Detail("protocol", defaultString(req.Protocol, "tls"))
	t, err := h.svc.AddTarget(c.R.Context(), c.Tenant, req.Host, req.Port, req.Protocol, c.Actor())
	switch {
	case errors.Is(err, errInvalidTarget):
		c.Refuse(http.StatusBadRequest, "invalid_target", err.Error())
		return
	case errors.Is(err, errPlatformTarget):
		c.Refuse(http.StatusBadRequest, "platform_target", err.Error())
		return
	case errors.Is(err, errTargetExists):
		c.Refuse(http.StatusConflict, "target_exists", err.Error())
		return
	case errors.Is(err, errTargetLimit):
		c.Refuse(http.StatusConflict, "target_limit", err.Error())
		return
	case err != nil:
		h.fail(c, err)
		return
	}
	c.Target(t.ID)
	c.JSON(http.StatusCreated, map[string]interface{}{"target": t})
}

func (h *Handler) removeTarget(c *route.Call) {
	t, err := h.svc.RemoveTarget(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if err != nil {
		h.fail(c, err)
		return
	}
	c.Detail("host", t.Host)
	c.Detail("port", t.Port)
	c.JSON(http.StatusOK, map[string]interface{}{"removed": t.ID})
}

func (h *Handler) sources(c *route.Call) {
	items, err := h.svc.Sources(c.R.Context(), c.Tenant)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

// maxUploadBody is the JSON body that carries a maxUploadBytes file.
var maxUploadBody = int64(base64.StdEncoding.EncodedLen(maxUploadBytes) + 4096)

// upload inventories one file sent as {"name", "content" (base64)}. The
// file is parsed in memory and never stored or logged; only its name, size
// and finding count go in the audit event. Refused: an empty or undecodable
// file (invalid_upload) and one over 2 MiB (upload_too_large).
func (h *Handler) upload(c *route.Call) {
	body, err := io.ReadAll(io.LimitReader(c.R.Body, maxUploadBody+1))
	if err != nil {
		c.Error(http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	tooLarge := fmt.Sprintf("a file is at most %d MiB", maxUploadBytes>>20)
	if int64(len(body)) > maxUploadBody {
		c.Refuse(http.StatusRequestEntityTooLarge, "upload_too_large", tooLarge)
		return
	}
	c.R.Body = io.NopCloser(bytes.NewReader(body))
	var req struct {
		Name    string `json:"name"`
		Content string `json:"content"`
	}
	if !c.Decode(&req) {
		return
	}
	c.Detail("file", uploadName(req.Name))
	raw, err := base64.StdEncoding.DecodeString(req.Content)
	switch {
	case err != nil || len(raw) == 0:
		c.Refuse(http.StatusBadRequest, "invalid_upload", "content must be the file's bytes, base64-encoded")
		return
	case len(raw) > maxUploadBytes:
		c.Refuse(http.StatusRequestEntityTooLarge, "upload_too_large", tooLarge)
		return
	}
	c.Detail("bytes", len(raw))
	scan, assets, err := h.svc.ScanUpload(c.R.Context(), c.Tenant, req.Name, raw)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.Target(scan.ID)
	c.Detail("assets", len(assets))
	c.JSON(http.StatusOK, map[string]interface{}{"scan": scan, "assets": assets})
}

func (h *Handler) removeAsset(c *route.Call) {
	a, err := h.svc.RemoveAsset(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if err != nil {
		h.fail(c, err)
		return
	}
	c.Detail("asset_type", a.AssetType)
	c.Detail("source", a.Source)
	c.JSON(http.StatusOK, map[string]interface{}{"removed": a.ID})
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

// Public reports whether r reaches a Public route (pkg/jwtauth.MustWrapRouter).
func (h *Handler) Public(r *http.Request) bool { return h.router.Public(r) }

// Routed reports whether r matches a route (pkg/jwtauth.MustWrapRouter).
func (h *Handler) Routed(r *http.Request) bool { return h.router.Routed(r) }
