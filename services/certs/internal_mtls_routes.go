package main

import (
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

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
	// The external listeners' key exchange (edge_tls.go).
	k.Handle("GET /certs/edge-tls", route.Spec{
		Action: "edge_tls_read", Permission: permInternalMTLSRead, Resource: "edge_tls",
	}, s.handleEdgeRead)
	k.Handle("PUT /certs/edge-tls", route.Spec{
		Action: "edge_tls_policy_updated", Permission: permInternalMTLSWrite, Resource: "edge_tls",
		Severity: "warning",
	}, s.handleEdgePolicy)
	// The edge certificate (edge_cert.go). The source is replicated; a CSR
	// and an external certificate belong to the node that serves them
	// (pkg/clusterroute.Local).
	k.Handle("PUT /certs/edge-tls/certificate", route.Spec{
		Action: "edge_tls_certificate_source_updated", Permission: permInternalMTLSWrite, Resource: "edge_tls",
		Severity: "warning",
	}, s.handleEdgeCertSource)
	k.Handle("POST /certs/edge-tls/csr", route.Spec{
		Action: "edge_tls_csr_created", Permission: permInternalMTLSWrite, Resource: "edge_tls",
		Severity: "warning",
	}, s.handleEdgeCSR)
	k.Handle("POST /certs/edge-tls/certificate/install", route.Spec{
		Action: "edge_tls_certificate_installed", Permission: permInternalMTLSWrite, Resource: "edge_tls",
		Severity: "warning",
	}, s.handleEdgeInstall)
	// What the external listeners were measured to accept: public facts any
	// client can observe, read by the pqc inventory with its service token.
	k.Handle("GET /certs/edge-tls/measurement", route.Spec{
		Action: "edge_tls_measurement_read", Permission: route.Authenticated, Resource: "edge_tls",
	}, s.handleEdgeMeasurement)
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

func (s *Service) handleEdgeRead(c *route.Call) {
	if !rootOnly(c) {
		return
	}
	v, err := s.EdgeInventory(c.R.Context())
	if err != nil {
		c.Error(http.StatusInternalServerError, "edge_tls_unavailable", err.Error())
		return
	}
	c.Detail("kx_profile", v.Policy.KXProfile)
	c.Detail("applied", v.Applied)
	c.JSON(http.StatusOK, map[string]interface{}{"edge": v})
}

func (s *Service) handleEdgePolicy(c *route.Call) {
	if !rootOnly(c) {
		return
	}
	var req struct {
		KXProfile string `json:"kx_profile"`
		Reason    string `json:"reason"`
	}
	if !c.Decode(&req) {
		return
	}
	c.Target(svctls.EdgeIdentity)
	c.Detail("requested_kx_profile", req.KXProfile)
	c.Detail("reason", req.Reason)
	res, err := s.SetEdgeKX(c.R.Context(), strings.TrimSpace(req.KXProfile), req.Reason, c.Actor())
	if err != nil {
		s.refuseMTLS(c, err)
		return
	}
	c.Detail("kx_profile", res.Policy.KXProfile)
	c.Detail("previous_kx_profile", res.Previous.KXProfile)
	c.Detail("generation", res.Policy.Generation)
	c.Detail("envoy_groups", svctls.EnvoyCurves(res.Policy.KXProfile))
	c.JSON(http.StatusOK, map[string]interface{}{"result": res})
}

func (s *Service) handleEdgeCertSource(c *route.Call) {
	if !rootOnly(c) {
		return
	}
	var req struct {
		Listener     string `json:"listener"`
		Source       string `json:"source"`
		CAID         string `json:"ca_id"`
		KeyAlgorithm string `json:"key_algorithm"`
		Reason       string `json:"reason"`
	}
	if !c.Decode(&req) {
		return
	}
	c.Target(svctls.EdgeIdentity)
	c.Detail("listener", listenerOrDefault(req.Listener))
	c.Detail("requested_source", req.Source)
	c.Detail("requested_ca_id", req.CAID)
	c.Detail("reason", req.Reason)
	prev, next, err := s.SetEdgeCertificateSource(c.R.Context(), c.Tenant, req.Listener, edgeCertChoice{
		Source: strings.TrimSpace(req.Source), CAID: strings.TrimSpace(req.CAID), KeyAlgorithm: strings.TrimSpace(req.KeyAlgorithm),
		Reason: req.Reason, UpdatedBy: c.Actor(),
	})
	if err != nil {
		s.refuseMTLS(c, err)
		return
	}
	c.Detail("source", next.Source)
	c.Detail("ca_id", next.CAID)
	c.Detail("key_algorithm", next.KeyAlgorithm)
	c.Detail("previous_source", prev.Source)
	c.Detail("previous_ca_id", prev.CAID)
	v := s.edgeCertificateView(c.R.Context(), c.Tenant, listenerOrDefault(req.Listener), "")
	if v.Installed != nil {
		c.Detail("installed_serial", v.Installed.Serial)
	}
	c.JSON(http.StatusOK, map[string]interface{}{"certificate": v})
}

func (s *Service) handleEdgeCSR(c *route.Call) {
	if !rootOnly(c) {
		return
	}
	var req struct {
		Listener     string   `json:"listener"`
		SubjectCN    string   `json:"subject_cn"`
		SANs         []string `json:"sans"`
		KeyAlgorithm string   `json:"key_algorithm"`
	}
	if !c.Decode(&req) {
		return
	}
	c.Target(svctls.EdgeIdentity)
	c.Detail("listener", listenerOrDefault(req.Listener))
	c.Detail("subject_cn", req.SubjectCN)
	c.Detail("sans", req.SANs)
	c.Detail("node", nodeName())
	p, err := s.CreateEdgeCSR(c.R.Context(), req.Listener, req.SubjectCN, req.SANs, strings.TrimSpace(req.KeyAlgorithm), c.Actor())
	if err != nil {
		s.refuseMTLS(c, err)
		return
	}
	c.Detail("key_algorithm", p.KeyAlgorithm)
	c.JSON(http.StatusOK, map[string]interface{}{"csr": p})
}

func (s *Service) handleEdgeInstall(c *route.Call) {
	if !rootOnly(c) {
		return
	}
	var req struct {
		Listener       string `json:"listener"`
		CertificatePEM string `json:"certificate_pem"`
		ChainPEM       string `json:"chain_pem"`
		Reason         string `json:"reason"`
	}
	if !c.Decode(&req) {
		return
	}
	c.Target(svctls.EdgeIdentity)
	c.Detail("node", nodeName())
	c.Detail("listener", listenerOrDefault(req.Listener))
	c.Detail("reason", req.Reason)
	leaf, err := s.InstallEdgeCertificate(c.R.Context(), req.Listener, req.CertificatePEM, req.ChainPEM)
	if err != nil {
		s.refuseMTLS(c, err)
		return
	}
	c.Detail("serial", leaf.SerialNumber.Text(16))
	c.Detail("subject", leaf.Subject.String())
	c.Detail("issuer", leaf.Issuer.String())
	c.Detail("not_after", leaf.NotAfter.UTC())
	c.JSON(http.StatusOK, map[string]interface{}{"certificate": s.edgeCertificateView(c.R.Context(), c.Tenant, listenerOrDefault(req.Listener), "")})
}

// edgeMeasurement is what the pqc inventory reports per external listener.
type edgeMeasurement struct {
	Name           string    `json:"name"`
	AcceptedGroups []string  `json:"accepted_groups"`
	Negotiated     string    `json:"negotiated_group"`
	MeasuredAt     time.Time `json:"measured_at"`
}

func (s *Service) handleEdgeMeasurement(c *route.Call) {
	v, err := s.EdgeInventory(c.R.Context())
	if err != nil {
		c.Error(http.StatusInternalServerError, "edge_tls_unavailable", err.Error())
		return
	}
	out := []edgeMeasurement{}
	for _, l := range v.Listeners {
		if l.Observed == nil {
			continue
		}
		out = append(out, edgeMeasurement{Name: l.Name, AcceptedGroups: l.Observed.ServerGroups,
			Negotiated: l.Observed.LastHandshakeGroup, MeasuredAt: l.Observed.LastHandshakeAt})
	}
	c.Detail("listeners", len(out))
	c.JSON(http.StatusOK, map[string]interface{}{"listeners": out, "configured": len(v.Listeners)})
}

func nodeName() string {
	if h, err := os.Hostname(); err == nil {
		return h
	}
	return ""
}

// listenerOrDefault names the listener a request is for, for audit details.
func listenerOrDefault(l string) string {
	if n, err := normListener(l); err == nil {
		return n
	}
	return strings.TrimSpace(l)
}
