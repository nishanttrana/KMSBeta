package main

import (
	"errors"
	"net/http"
	"strings"

	"vecta-kms/pkg/route"
	"vecta-kms/pkg/svctls"
)

// Service mTLS routes (docs/SECURITY/INTERNAL_TLS.md). The platform's own
// internal mTLS is no tenant's data: only the root tenant may read or change
// it. Every call is audited by the kernel as audit.certs.<action>, refusals
// with their reason.

const (
	permInternalMTLSRead  = "cert.internal_mtls.read"
	permInternalMTLSWrite = "cert.internal_mtls.write"
)

func (s *Service) RegisterInternalMTLSRoutes(k *route.Router) {
	k.Handle("GET /certs/internal-mtls", route.Spec{
		Action: "internal_mtls_inventory_read", Permission: permInternalMTLSRead, Resource: "internal_mtls_identity",
	}, s.handleMTLSInventory)
	k.Handle("PUT /certs/internal-mtls/{identity}/policy", route.Spec{
		Action: "internal_mtls_policy_updated", Permission: permInternalMTLSWrite, Resource: "internal_mtls_identity",
		TargetParam: "identity", Severity: "warning",
	}, s.handleMTLSPolicy)
	k.Handle("POST /certs/internal-mtls/{identity}/rotate", route.Spec{
		Action: "internal_mtls_rotated", Permission: permInternalMTLSWrite, Resource: "internal_mtls_identity",
		TargetParam: "identity", Severity: "warning",
	}, s.handleMTLSRotate)
	k.Handle("POST /certs/internal-mtls/rotate-all", route.Spec{
		Action: "internal_mtls_rotated_all", Permission: permInternalMTLSWrite, Resource: "internal_mtls_identity",
		Severity: "critical",
	}, s.handleMTLSRotateAll)
}

func rootOnly(c *route.Call) bool {
	if !strings.EqualFold(c.Tenant, "root") {
		c.Refuse(http.StatusForbidden, "not_root_tenant", "internal mTLS is platform administration: root tenant only")
		return false
	}
	return true
}

func (s *Service) handleMTLSInventory(c *route.Call) {
	if !rootOnly(c) {
		return
	}
	items, meta, err := s.MTLSInventory(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "inventory_unavailable", err.Error())
		return
	}
	c.Detail("identities", len(items))
	c.JSON(http.StatusOK, map[string]interface{}{"items": items, "meta": meta})
}

func (s *Service) refuseMTLS(c *route.Call, err error) {
	var r mtlsRefusal
	if errors.As(err, &r) {
		status := http.StatusBadRequest
		if r.reason == "unknown_identity" {
			status = http.StatusNotFound
		}
		if r.reason == "unchanged" {
			status = http.StatusConflict
		}
		c.Refuse(status, r.reason, r.msg)
		return
	}
	c.Error(http.StatusInternalServerError, "internal_mtls_change_failed", err.Error())
}

func (s *Service) handleMTLSPolicy(c *route.Call) {
	if !rootOnly(c) {
		return
	}
	var req struct {
		KeyAlgorithm string `json:"key_algorithm"`
		KXProfile    string `json:"kx_profile"`
		Reason       string `json:"reason"`
	}
	if !c.Decode(&req) {
		return
	}
	identity := c.R.PathValue("identity")
	c.Detail("requested_key_algorithm", req.KeyAlgorithm)
	c.Detail("requested_kx_profile", req.KXProfile)
	c.Detail("reason", req.Reason)
	res, err := s.ApplyMTLSChange(c.R.Context(), c.Tenant, mtlsChange{
		Identity: identity, KeyAlgorithm: strings.TrimSpace(req.KeyAlgorithm), KXProfile: strings.TrimSpace(req.KXProfile),
		RestartMode: svctls.RestartGraceful, Reason: req.Reason, Actor: c.Actor(),
	})
	if err != nil {
		s.refuseMTLS(c, err)
		return
	}
	s.mtlsDetails(c, res)
	c.JSON(http.StatusOK, map[string]interface{}{"identity": identity, "result": res})
}

func (s *Service) handleMTLSRotate(c *route.Call) {
	if !rootOnly(c) {
		return
	}
	var req struct {
		Mode   string `json:"mode"`
		Reason string `json:"reason"`
	}
	if !c.Decode(&req) {
		return
	}
	identity := c.R.PathValue("identity")
	mode := strings.TrimSpace(req.Mode)
	if mode == "" {
		mode = svctls.RestartGraceful
	}
	c.Detail("restart_mode", mode)
	c.Detail("reason", req.Reason)
	res, err := s.ApplyMTLSChange(c.R.Context(), c.Tenant, mtlsChange{
		Identity: identity, Rotate: true, RestartMode: mode, Reason: req.Reason, Actor: c.Actor(),
	})
	if err != nil {
		s.refuseMTLS(c, err)
		return
	}
	s.mtlsDetails(c, res)
	c.JSON(http.StatusOK, map[string]interface{}{"identity": identity, "result": res})
}

func (s *Service) handleMTLSRotateAll(c *route.Call) {
	if !rootOnly(c) {
		return
	}
	var req struct {
		Mode    string `json:"mode"`
		Reason  string `json:"reason"`
		Confirm string `json:"confirm"`
	}
	if !c.Decode(&req) {
		return
	}
	mode := strings.TrimSpace(req.Mode)
	if mode == "" {
		mode = svctls.RestartGraceful
	}
	c.Detail("restart_mode", mode)
	c.Detail("reason", req.Reason)
	if strings.TrimSpace(req.Confirm) != "rotate-all" {
		c.Refuse(http.StatusBadRequest, "confirmation_required", `type "rotate-all" to confirm rotating every internal certificate`)
		return
	}
	items, span, err := s.RotateAllMTLS(c.R.Context(), c.Tenant, mode, req.Reason, c.Actor())
	if err != nil {
		s.refuseMTLS(c, err)
		return
	}
	c.Detail("identities", len(items))
	c.Detail("restart_span_seconds", span.Seconds())
	c.JSON(http.StatusOK, map[string]interface{}{"items": items, "restart_span_seconds": span.Seconds()})
}

func (s *Service) mtlsDetails(c *route.Call, res mtlsChangeResult) {
	c.Detail("kind", res.Kind)
	c.Detail("generation", res.Policy.Generation)
	c.Detail("key_algorithm", res.Policy.KeyAlgorithm)
	c.Detail("kx_profile", res.Policy.KXProfile)
	c.Detail("previous_key_algorithm", res.PrevPolicy.KeyAlgorithm)
	c.Detail("previous_kx_profile", res.PrevPolicy.KXProfile)
	c.Detail("restart_mode", res.Policy.RestartMode)
	c.Detail("certificates_revoked", res.Revoked)
	c.Detail("reissued", res.Reissued)
}
