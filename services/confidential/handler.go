package main

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	pkgaudit "vecta-kms/pkg/audit"
	"vecta-kms/pkg/route"
)

// Permissions of the confidential routes (docs/API_REFERENCE.md).
const (
	permRead     = "confidential.read"
	permWrite    = "confidential.write"    // the tenant attestation policy
	permEvaluate = "confidential.evaluate" // a verdict, recorded; no key leaves keycore
	permRelease  = "confidential.release"  // handler_release.go
)

// Handler serves every confidential route through the pkg/route kernel:
// the verified token names the tenant and the actor, the route's permission
// is enforced, and each request emits audit.confidential.<action>, refusals
// included.
type Handler struct {
	svc    *Service
	router *route.Router
	audit  route.Emitter
}

// SetAuditClient wires the unified audit client used by the kernel.
func (h *Handler) SetAuditClient(a route.Emitter) { h.audit = a }

type kernelEmitter struct{ h *Handler }

func (e kernelEmitter) Emit(ctx context.Context, action string, evt pkgaudit.Event) error {
	if e.h.audit == nil {
		return nil
	}
	return e.h.audit.Emit(ctx, action, evt)
}

func NewHandler(svc *Service) *Handler {
	h := &Handler{svc: svc}
	r := route.New("confidential", kernelEmitter{h}, nil)
	r.Handle("GET /confidential/policy", route.Spec{Action: "policy_viewed", Permission: permRead, Resource: "attestation_policy"}, h.getPolicy)
	r.Handle("PUT /confidential/policy", route.Spec{Action: "policy_updated", Permission: permWrite, Resource: "attestation_policy", Severity: "warning"}, h.setPolicy)
	r.Handle("GET /confidential/summary", route.Spec{Action: "summary_viewed", Permission: permRead, Resource: "attestation_policy"}, h.getSummary)
	r.Handle("POST /confidential/evaluate", route.Spec{Action: "key_release_evaluated", Permission: permEvaluate, Resource: "key"}, h.evaluate)
	r.Handle("GET /confidential/releases", route.Spec{Action: "releases_viewed", Permission: permRead, Resource: "attested_release"}, h.listReleases)
	r.Handle("GET /confidential/releases/{id}", route.Spec{Action: "release_viewed", Permission: permRead, Resource: "attested_release", TargetParam: "id"}, h.getRelease)
	h.handleRelease(r)
	h.router = r
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.router.ServeHTTP(w, r) }

func (h *Handler) getPolicy(c *route.Call) {
	item, err := h.svc.GetAttestationPolicy(c.R.Context(), c.Tenant)
	if err != nil {
		writeServiceError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"policy": item})
}

func (h *Handler) setPolicy(c *route.Call) {
	var req AttestationPolicy
	if !c.Decode(&req) {
		return
	}
	req.TenantID = c.Tenant
	req.UpdatedBy = c.Actor()
	item, err := h.svc.UpdateAttestationPolicy(c.R.Context(), req)
	if err != nil {
		writeServiceError(c, err)
		return
	}
	c.Detail("provider", item.Provider)
	c.Detail("mode", item.Mode)
	c.Detail("enabled", item.Enabled)
	c.Detail("approved_image_count", len(item.ApprovedImages))
	c.Detail("key_scope_count", len(item.KeyScopes))
	c.Detail("cluster_scope", item.ClusterScope)
	c.Detail("fallback_action", item.FallbackAction)
	c.Detail("require_secure_boot", item.RequireSecureBoot)
	c.Detail("require_debug_disabled", item.RequireDebugDisabled)
	c.JSON(http.StatusOK, map[string]interface{}{"policy": item})
}

func (h *Handler) getSummary(c *route.Call) {
	item, err := h.svc.GetAttestationSummary(c.R.Context(), c.Tenant)
	if err != nil {
		writeServiceError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"summary": item})
}

func (h *Handler) evaluate(c *route.Call) {
	var req AttestedReleaseRequest
	if !c.Decode(&req) {
		return
	}
	req.TenantID = c.Tenant
	req.Requester = c.Actor()
	c.Target(req.KeyID)
	item, err := h.svc.EvaluateAttestedRelease(c.R.Context(), req)
	if err != nil {
		writeServiceError(c, err)
		return
	}
	c.Detail("release_id", item.ReleaseID)
	c.Detail("decision", item.Decision)
	c.Detail("allowed", item.Allowed)
	c.Detail("provider", item.Provider)
	c.Detail("measurement_hash", item.MeasurementHash)
	c.Detail("claims_hash", item.ClaimsHash)
	c.Detail("policy_version", item.PolicyVersion)
	c.Detail("cryptographically_verified", item.CryptographicallyVerified)
	c.Detail("verification_mode", item.VerificationMode)
	c.Detail("verification_issuer", item.VerificationIssuer)
	c.Detail("verification_key_id", item.VerificationKeyID)
	c.Detail("attestation_document_hash", item.AttestationDocumentHash)
	c.Detail("attestation_document_format", item.AttestationDocumentFormat)
	c.Detail("key_scope", req.KeyScope)
	c.Detail("cluster_node_id", item.ClusterNodeID)
	c.Detail("workload_identity", req.WorkloadIdentity)
	c.Detail("image_digest", req.ImageDigest)
	c.Detail("image_ref", req.ImageRef)
	c.Detail("attester", req.Attester)
	c.Detail("dry_run", req.DryRun)
	c.JSON(http.StatusOK, map[string]interface{}{"result": item})
}

func (h *Handler) listReleases(c *route.Call) {
	limit := 100
	if parsed, err := strconv.Atoi(c.R.URL.Query().Get("limit")); err == nil {
		limit = parsed
	}
	items, err := h.svc.ListReleaseHistory(c.R.Context(), c.Tenant, limit)
	if err != nil {
		writeServiceError(c, err)
		return
	}
	c.Detail("count", len(items))
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

func (h *Handler) getRelease(c *route.Call) {
	item, err := h.svc.GetReleaseRecord(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if err != nil {
		writeServiceError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"item": item})
}

// writeServiceError maps a service error onto the kernel's error envelope;
// server errors never leak their detail (OWASP A05).
func writeServiceError(c *route.Call, err error) {
	var se serviceError
	if errors.As(err, &se) {
		c.Error(se.HTTPStatus, se.Code, se.Message)
		return
	}
	c.Error(http.StatusInternalServerError, "internal_error", "internal server error")
}

// Public reports whether r reaches a Public route (pkg/jwtauth.MustWrapRouter).
func (h *Handler) Public(r *http.Request) bool { return h.router.Public(r) }

// Routed reports whether r matches a route (pkg/jwtauth.MustWrapRouter).
func (h *Handler) Routed(r *http.Request) bool { return h.router.Routed(r) }
