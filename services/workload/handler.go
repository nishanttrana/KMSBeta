package main

import (
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"

	"vecta-kms/pkg/mek"
	"vecta-kms/pkg/route"
)

// Permissions of the workload-identity routes (docs/API_REFERENCE.md).
const (
	permRead  = "workload.read"
	permWrite = "workload.write" // settings, registrations, federation bundles
	permIssue = "workload.issue" // an SVID, and for X.509 its private key
)

// Handler serves every workload-identity route through the pkg/route kernel:
// the verified token names the tenant, the route's permission is enforced,
// and each request emits audit.workload.<action>, refusals included.
type Handler struct {
	svc    *Service
	router *route.Router
}

func NewHandler(svc *Service, audit route.Emitter, logger *log.Logger) *Handler {
	h := &Handler{svc: svc}
	r := route.New("workload", audit, logger)
	r.Handle("GET /workload-identity/settings", route.Spec{Action: "settings_viewed", Permission: permRead, Resource: "workload_identity_settings"}, h.getSettings)
	r.Handle("PUT /workload-identity/settings", route.Spec{Action: "settings_updated", Permission: permWrite, Resource: "workload_identity_settings", Severity: "warning"}, h.putSettings)
	r.Handle("POST /workload-identity/settings/rotate-signing-keys", route.Spec{Action: "signing_keys_rotated", Permission: permWrite, Resource: "workload_identity_settings", Severity: "warning"}, h.rotateSigningKeys)
	r.Handle("GET /workload-identity/summary", route.Spec{Action: "summary_viewed", Permission: permRead, Resource: "workload_identity_settings"}, h.getSummary)
	r.Handle("GET /workload-identity/registrations", route.Spec{Action: "registrations_viewed", Permission: permRead, Resource: "workload_registration"}, h.listRegistrations)
	r.Handle("POST /workload-identity/registrations", route.Spec{Action: "registration_upserted", Permission: permWrite, Resource: "workload_registration"}, h.upsertRegistration)
	r.Handle("PUT /workload-identity/registrations/{id}", route.Spec{Action: "registration_upserted", Permission: permWrite, Resource: "workload_registration", TargetParam: "id"}, h.upsertRegistration)
	r.Handle("DELETE /workload-identity/registrations/{id}", route.Spec{Action: "registration_deleted", Permission: permWrite, Resource: "workload_registration", TargetParam: "id", Severity: "warning"}, h.deleteRegistration)
	r.Handle("GET /workload-identity/federation", route.Spec{Action: "federation_viewed", Permission: permRead, Resource: "federation_bundle"}, h.listFederation)
	r.Handle("POST /workload-identity/federation", route.Spec{Action: "federation_bundle_upserted", Permission: permWrite, Resource: "federation_bundle", Severity: "warning"}, h.upsertFederation)
	r.Handle("PUT /workload-identity/federation/{id}", route.Spec{Action: "federation_bundle_upserted", Permission: permWrite, Resource: "federation_bundle", TargetParam: "id", Severity: "warning"}, h.upsertFederation)
	r.Handle("DELETE /workload-identity/federation/{id}", route.Spec{Action: "federation_bundle_deleted", Permission: permWrite, Resource: "federation_bundle", TargetParam: "id", Severity: "warning"}, h.deleteFederation)
	r.Handle("POST /workload-identity/issue", route.Spec{Action: "svid_issued", Permission: permIssue, Resource: "workload_registration", Severity: "warning"}, h.issueSVID)
	r.Handle("GET /workload-identity/issuances", route.Spec{Action: "issuance_history_viewed", Permission: permRead, Resource: "svid_issuance"}, h.listIssuances)
	// The one route without a bearer token: the workload's SVID is the
	// credential (docs/DECISIONS.md 2026-09-29).
	r.Handle("POST /workload-identity/token/exchange", route.Spec{Action: "token_exchanged", Public: true, Resource: "workload_registration", Severity: "warning"}, h.exchangeToken)
	r.Handle("GET /workload-identity/graph", route.Spec{Action: "graph_viewed", Permission: permRead, Resource: "workload_registration"}, h.getGraph)
	r.Handle("GET /workload-identity/usage", route.Spec{Action: "key_usage_viewed", Permission: permRead, Resource: "workload_registration"}, h.listUsage)
	h.router = r
	return h
}

// MountKeyring adds the master-key routes (exposure register, backup
// re-wrap) of the sealed signing keys (pkg/mek).
func (h *Handler) MountKeyring(k *mek.Keyring) { k.Routes(h.router, "workload") }

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.router.ServeHTTP(w, r) }

// Public reports whether r reaches the token exchange, which authenticates
// with the SVID instead of a bearer token (pkg/jwtauth.MustWrapRouter).
func (h *Handler) Public(r *http.Request) bool { return h.router.Public(r) }

func (h *Handler) getSettings(c *route.Call) {
	item, err := h.svc.GetSettings(c.R.Context(), c.Tenant)
	if err != nil {
		writeServiceError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"settings": item})
}

func (h *Handler) rotateSigningKeys(c *route.Call) {
	item, err := h.svc.RotateSigningKeys(c.R.Context(), c.Tenant, c.Actor())
	if err != nil {
		writeServiceError(c, err)
		return
	}
	c.Detail("trust_domain", item.TrustDomain)
	c.Detail("jwt_signer_key_id", item.JWTSignerKeyID)
	c.JSON(http.StatusOK, map[string]interface{}{"settings": item})
}

func (h *Handler) putSettings(c *route.Call) {
	var body WorkloadIdentitySettings
	if !c.Decode(&body) {
		return
	}
	body.TenantID = c.Tenant
	body.UpdatedBy = c.Actor()
	item, err := h.svc.UpdateSettings(c.R.Context(), body)
	if err != nil {
		writeServiceError(c, err)
		return
	}
	c.Detail("enabled", item.Enabled)
	c.Detail("trust_domain", item.TrustDomain)
	c.Detail("federation_enabled", item.FederationEnabled)
	c.Detail("token_exchange_enabled", item.TokenExchangeEnabled)
	c.Detail("default_x509_ttl_seconds", item.DefaultX509TTLSeconds)
	c.Detail("default_jwt_ttl_seconds", item.DefaultJWTTTLSeconds)
	c.Detail("allowed_audiences", item.AllowedAudiences)
	c.JSON(http.StatusOK, map[string]interface{}{"settings": item})
}

func (h *Handler) getSummary(c *route.Call) {
	item, err := h.svc.GetSummary(c.R.Context(), c.Tenant)
	if err != nil {
		writeServiceError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"summary": item})
}

func (h *Handler) listRegistrations(c *route.Call) {
	items, err := h.svc.ListRegistrations(c.R.Context(), c.Tenant)
	if err != nil {
		writeServiceError(c, err)
		return
	}
	c.Detail("count", len(items))
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

func (h *Handler) upsertRegistration(c *route.Call) {
	var body WorkloadRegistration
	if !c.Decode(&body) {
		return
	}
	body.TenantID = c.Tenant
	if id := c.R.PathValue("id"); id != "" {
		body.ID = id
	}
	item, err := h.svc.UpsertRegistration(c.R.Context(), body)
	if err != nil {
		writeServiceError(c, err)
		return
	}
	c.Target(item.ID)
	c.Detail("spiffe_id", item.SpiffeID)
	c.Detail("issue_x509_svid", item.IssueX509SVID)
	c.Detail("issue_jwt_svid", item.IssueJWTSVID)
	c.Detail("allowed_interfaces", item.AllowedInterfaces)
	c.Detail("allowed_key_count", len(item.AllowedKeyIDs))
	c.Detail("permissions", item.Permissions)
	c.Detail("enabled", item.Enabled)
	c.JSON(http.StatusOK, map[string]interface{}{"registration": item})
}

func (h *Handler) deleteRegistration(c *route.Call) {
	if err := h.svc.DeleteRegistration(c.R.Context(), c.Tenant, c.R.PathValue("id")); err != nil {
		writeServiceError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"ok": true})
}

func (h *Handler) listFederation(c *route.Call) {
	items, err := h.svc.ListFederationBundles(c.R.Context(), c.Tenant)
	if err != nil {
		writeServiceError(c, err)
		return
	}
	c.Detail("count", len(items))
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

func (h *Handler) upsertFederation(c *route.Call) {
	var body WorkloadFederationBundle
	if !c.Decode(&body) {
		return
	}
	body.TenantID = c.Tenant
	if id := c.R.PathValue("id"); id != "" {
		body.ID = id
	}
	item, err := h.svc.UpsertFederationBundle(c.R.Context(), body)
	if err != nil {
		writeServiceError(c, err)
		return
	}
	c.Target(item.ID)
	c.Detail("trust_domain", item.TrustDomain)
	c.Detail("bundle_endpoint", item.BundleEndpoint)
	c.Detail("has_jwks", item.JWKSJSON != "")
	c.Detail("has_ca_bundle", item.CABundlePEM != "")
	c.Detail("enabled", item.Enabled)
	c.JSON(http.StatusOK, map[string]interface{}{"bundle": item})
}

func (h *Handler) deleteFederation(c *route.Call) {
	if err := h.svc.DeleteFederationBundle(c.R.Context(), c.Tenant, c.R.PathValue("id")); err != nil {
		writeServiceError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"ok": true})
}

func (h *Handler) issueSVID(c *route.Call) {
	var body IssueSVIDRequest
	if !c.Decode(&body) {
		return
	}
	body.TenantID = c.Tenant
	c.Target(body.RegistrationID)
	item, err := h.svc.IssueSVID(c.R.Context(), body)
	if err != nil {
		writeServiceError(c, err)
		return
	}
	c.Target(item.RegistrationID)
	c.Detail("issuance_id", item.IssuanceID)
	c.Detail("spiffe_id", item.SpiffeID)
	c.Detail("svid_type", item.SVIDType)
	c.Detail("serial_or_key_id", item.SerialOrKeyID)
	c.Detail("private_key_returned", item.PrivateKeyPEM != "")
	c.Detail("expires_at", item.ExpiresAt)
	c.JSON(http.StatusOK, map[string]interface{}{"issued": item})
}

func (h *Handler) listIssuances(c *route.Call) {
	items, err := h.svc.ListIssuances(c.R.Context(), c.Tenant, queryLimit(c))
	if err != nil {
		writeServiceError(c, err)
		return
	}
	c.Detail("count", len(items))
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

// exchangeToken trades a verified SVID for a scoped KMS token. It needs no
// bearer token: the SVID is the credential. The tenant named in the request
// only selects whose trust anchors verify it; an SVID that doesn't verify
// against them, or doesn't match the registration, is refused and audited.
func (h *Handler) exchangeToken(c *route.Call) {
	var body TokenExchangeRequest
	if !c.Decode(&body) {
		return
	}
	body.TenantID = c.Tenant
	c.Target(body.RegistrationID)
	c.Detail("interface_name", body.InterfaceName)
	item, verified, err := h.svc.ExchangeToken(c.R.Context(), body)
	if verified.SpiffeID != "" {
		c.Authenticated(verified.SpiffeID, "workload")
		c.Detail("spiffe_id", verified.SpiffeID)
		c.Detail("trust_domain", verified.TrustDomain)
		c.Detail("svid_type", verified.SVIDType)
		c.Detail("document_hash", verified.DocumentHash)
		c.Detail("serial_or_key_id", verified.SerialOrKeyID)
	}
	if err != nil {
		var se serviceError
		if errors.As(err, &se) && se.HTTPStatus >= 400 && se.HTTPStatus < 500 && se.HTTPStatus != http.StatusBadRequest {
			c.Refuse(se.HTTPStatus, se.Code, se.Message)
			return
		}
		writeServiceError(c, err)
		return
	}
	c.Target(item.RegistrationID)
	c.Detail("allowed_permissions", item.AllowedPermissions)
	c.Detail("allowed_key_ids", item.AllowedKeyIDs)
	c.JSON(http.StatusOK, map[string]interface{}{"exchange": item})
}

func (h *Handler) getGraph(c *route.Call) {
	item, err := h.svc.GetGraph(c.R.Context(), c.Tenant)
	if err != nil {
		writeServiceError(c, err)
		return
	}
	c.Detail("node_count", len(item.Nodes))
	c.Detail("edge_count", len(item.Edges))
	c.JSON(http.StatusOK, map[string]interface{}{"graph": item})
}

func (h *Handler) listUsage(c *route.Call) {
	items, err := h.svc.ListUsage(c.R.Context(), c.Tenant, queryLimit(c))
	if err != nil {
		writeServiceError(c, err)
		return
	}
	c.Detail("count", len(items))
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

func queryLimit(c *route.Call) int {
	if parsed, err := strconv.Atoi(strings.TrimSpace(c.R.URL.Query().Get("limit"))); err == nil {
		return parsed
	}
	return 100
}

// writeServiceError maps a service error onto the kernel's error envelope;
// server errors never leak their detail (OWASP A05).
func writeServiceError(c *route.Call, err error) {
	var se serviceError
	switch {
	case errors.As(err, &se):
		c.Error(se.HTTPStatus, se.Code, se.Message)
	case errors.Is(err, errNotFound):
		c.Error(http.StatusNotFound, "not_found", "not found")
	default:
		c.Error(http.StatusInternalServerError, "internal_error", "internal server error")
	}
}
