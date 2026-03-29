package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// handleListMeshServices returns all services registered in the mTLS mesh.
func (h *Handler) handleListMeshServices(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	items, err := h.svc.store.ListMeshServices(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_mesh_services_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

// handleRegisterMeshService registers a new service in the mTLS mesh.
func (h *Handler) handleRegisterMeshService(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req RegisterServiceRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	if strings.TrimSpace(req.TenantID) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required", reqID, "")
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "name is required", reqID, req.TenantID)
		return
	}
	if strings.TrimSpace(req.Endpoint) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "endpoint is required", reqID, req.TenantID)
		return
	}
	ns := strings.TrimSpace(req.Namespace)
	if ns == "" {
		ns = "default"
	}
	if req.RenewDaysBefore <= 0 {
		req.RenewDaysBefore = 30
	}
	anchors := req.TrustAnchors
	if anchors == nil {
		anchors = []string{}
	}

	svc := MeshService{
		ID:              meshNewID("msvc"),
		TenantID:        strings.TrimSpace(req.TenantID),
		Name:            strings.TrimSpace(req.Name),
		Namespace:       ns,
		Endpoint:        strings.TrimSpace(req.Endpoint),
		CertStatus:      "missing",
		AutoRenew:       req.AutoRenew,
		RenewDaysBefore: req.RenewDaysBefore,
		TrustAnchors:    anchors,
		MTLSEnabled:     req.MTLSEnabled,
		CreatedAt:       time.Now().UTC(),
	}

	saved, err := h.svc.store.CreateMeshService(r.Context(), svc)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "register_mesh_service_failed", err.Error(), reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"service": saved, "request_id": reqID})
}

// handleRenewServiceCert generates a new EC P-256 self-signed cert for a mesh service.
func (h *Handler) handleRenewServiceCert(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "id is required", reqID, tenantID)
		return
	}

	svcRecord, err := h.svc.store.GetMeshService(r.Context(), tenantID, id)
	if err != nil {
		status := http.StatusInternalServerError
		if err == errStoreNotFound {
			status = http.StatusNotFound
		}
		writeErr(w, status, "get_mesh_service_failed", err.Error(), reqID, tenantID)
		return
	}

	// Generate EC P-256 key pair.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "keygen_failed", err.Error(), reqID, tenantID)
		return
	}

	serialNum, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "serial_gen_failed", err.Error(), reqID, tenantID)
		return
	}

	cn := fmt.Sprintf("%s.%s.mesh.vecta.internal", svcRecord.Name, svcRecord.Namespace)
	notBefore := time.Now().UTC().Add(-time.Minute)
	notAfter := time.Now().UTC().Add(90 * 24 * time.Hour)

	tpl := &x509.Certificate{
		SerialNumber: serialNum,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Vecta KMS Mesh"},
		},
		DNSNames:              []string{cn, svcRecord.Name, svcRecord.Endpoint},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &privKey.PublicKey, privKey)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "cert_create_failed", err.Error(), reqID, tenantID)
		return
	}

	parsedCert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "cert_parse_failed", err.Error(), reqID, tenantID)
		return
	}

	// Compute fingerprint from raw DER.
	fpSum := sha256.Sum256(derBytes)
	fingerprint := hex.EncodeToString(fpSum[:])
	serialHex := fmt.Sprintf("%x", parsedCert.SerialNumber)

	// Encode PEM (stored for reference — not persisted to DB in this minimal store).
	_ = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	certRecord := MeshCertificate{
		ID:           meshNewID("mcert"),
		TenantID:     tenantID,
		ServiceID:    svcRecord.ID,
		ServiceName:  svcRecord.Name,
		CN:           cn,
		SANs:         []string{cn, svcRecord.Name},
		Issuer:       "self-signed (Vecta Mesh)",
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		Serial:       serialHex,
		Fingerprint:  fingerprint,
		KeyAlgorithm: "EC-P256",
		Revoked:      false,
		CreatedAt:    time.Now().UTC(),
	}

	savedCert, err := h.svc.store.CreateMeshCertificate(r.Context(), certRecord)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store_mesh_cert_failed", err.Error(), reqID, tenantID)
		return
	}

	// Update service record to reflect new cert.
	if err := h.svc.store.UpdateMeshServiceCert(r.Context(), tenantID, id, savedCert.ID, cn, notAfter); err != nil {
		writeErr(w, http.StatusInternalServerError, "update_service_cert_failed", err.Error(), reqID, tenantID)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"certificate": savedCert,
		"request_id":  reqID,
	})
}

// handleListMeshCertificates returns all certificates issued to mesh services.
func (h *Handler) handleListMeshCertificates(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	items, err := h.svc.store.ListMeshCertificates(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_mesh_certs_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

// handleListTrustAnchors returns all trust anchors for the mesh.
func (h *Handler) handleListTrustAnchors(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	items, err := h.svc.store.ListTrustAnchors(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_trust_anchors_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

// handleAddTrustAnchor adds a new trust anchor to the mesh.
func (h *Handler) handleAddTrustAnchor(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req AddTrustAnchorRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	if strings.TrimSpace(req.TenantID) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required", reqID, "")
		return
	}
	if strings.TrimSpace(req.Fingerprint) == "" || strings.TrimSpace(req.Subject) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "fingerprint and subject are required", reqID, req.TenantID)
		return
	}

	notBefore := meshParseTime(req.NotBefore)
	notAfter := meshParseTime(req.NotAfter)
	if notBefore.IsZero() {
		notBefore = time.Now().UTC().Add(-24 * time.Hour)
	}
	if notAfter.IsZero() {
		notAfter = time.Now().UTC().Add(365 * 24 * time.Hour)
	}

	ta := TrustAnchor{
		ID:          meshNewID("ta"),
		TenantID:    strings.TrimSpace(req.TenantID),
		Name:        strings.TrimSpace(req.Name),
		Fingerprint: strings.TrimSpace(req.Fingerprint),
		Subject:     strings.TrimSpace(req.Subject),
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		CreatedAt:   time.Now().UTC(),
	}

	saved, err := h.svc.store.CreateTrustAnchor(r.Context(), ta)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "add_trust_anchor_failed", err.Error(), reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"trust_anchor": saved, "request_id": reqID})
}

// handleGetTopology returns the mTLS mesh topology graph.
func (h *Handler) handleGetTopology(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	edges, err := h.svc.store.GetMeshTopology(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "get_topology_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"edges": edges, "request_id": reqID})
}

// --- mesh utility helpers ---

func meshNewID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

func meshParseTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
