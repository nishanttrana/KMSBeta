package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/ovh/kmip-go/ttlv"
)

func (h *Handler) HTTPHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /kmip/capabilities", h.handleCapabilities)
	mux.HandleFunc("GET /kmip/profiles", h.handleListClientProfiles)
	mux.HandleFunc("POST /kmip/profiles", h.handleCreateClientProfile)
	mux.HandleFunc("DELETE /kmip/profiles/{id}", h.handleDeleteClientProfile)
	mux.HandleFunc("GET /kmip/clients", h.handleListClients)
	mux.HandleFunc("GET /kmip/clients/{id}", h.handleGetClient)
	mux.HandleFunc("POST /kmip/clients", h.handleCreateClient)
	mux.HandleFunc("DELETE /kmip/clients/{id}", h.handleDeleteClient)
	mux.HandleFunc("GET /kmip/interop/targets", h.handleListInteropTargets)
	mux.HandleFunc("POST /kmip/interop/targets", h.handleCreateInteropTarget)
	mux.HandleFunc("DELETE /kmip/interop/targets/{id}", h.handleDeleteInteropTarget)
	mux.HandleFunc("POST /kmip/interop/targets/{id}/validate", h.handleValidateInteropTarget)
	return mux
}

func (h *Handler) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	versionsRaw := parseSupportedProtocolVersions()
	versions := make([]string, 0, len(versionsRaw))
	highestVersion := ""
	for _, v := range versionsRaw {
		version := fmt.Sprintf("%d.%d", v.ProtocolVersionMajor, v.ProtocolVersionMinor)
		if highestVersion == "" {
			highestVersion = version
		}
		versions = append(versions, version)
	}
	opsRaw := supportedKMIPOperations()
	ops := make([]string, 0, len(opsRaw))
	for _, op := range opsRaw {
		ops = append(ops, strings.TrimSpace(ttlv.EnumStr(op)))
	}
	missingOps := diffKMIPCapabilities(knownKMIP32Operations(), ops)
	objRaw := supportedKMIPObjectTypes()
	objects := make([]string, 0, len(objRaw))
	for _, objType := range objRaw {
		objects = append(objects, strings.TrimSpace(ttlv.EnumStr(objType)))
	}
	missingObjects := diffKMIPCapabilities(knownKMIP32ObjectTypes(), objects)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"capabilities": map[string]interface{}{
			"library":                    "github.com/ovh/kmip-go",
			"library_version":            kmipLibraryVersion(),
			"protocol":                   "TTLV over TLS",
			"port":                       KMIPPort,
			"highest_supported_version":  highestVersion,
			"supported_versions":         versions,
			"operations":                 ops,
			"implemented_operations":     ops,
			"unimplemented_operations":   missingOps,
			"object_types":               objects,
			"implemented_object_types":   objects,
			"unimplemented_object_types": missingObjects,
			"auth_modes": []string{
				"mTLS client certificate",
			},
			"interoperability_scope": []string{
				"Generic KMIP clients implementing KMIP 1.0-3.2 over TTLV/TLS",
			},
			"integration_targets": knownIntegrationTargets(),
			"integration_note":    "Compatibility is protocol-level (KMIP 1.0-3.2 over TTLV/TLS + mTLS). Product-specific enablement and policy mapping must be validated per vendor deployment profile.",
		},
		"request_id": reqID,
	})
}

func kmipLibraryVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info == nil {
		return "unknown"
	}
	for _, dep := range info.Deps {
		if dep == nil {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(dep.Path), "github.com/ovh/kmip-go") {
			v := strings.TrimSpace(dep.Version)
			if v != "" {
				return v
			}
		}
	}
	return "unknown"
}

func diffKMIPCapabilities(reference []string, implemented []string) []string {
	if len(reference) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(implemented))
	for _, value := range implemented {
		key := strings.ToLower(strings.TrimSpace(value))
		if key == "" {
			continue
		}
		seen[key] = struct{}{}
	}
	out := make([]string, 0)
	for _, value := range reference {
		key := strings.ToLower(strings.TrimSpace(value))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		out = append(out, value)
	}
	return out
}

func knownKMIP32Operations() []string {
	return []string{
		"Create",
		"Register",
		"Get",
		"GetAttributes",
		"Locate",
		"Activate",
		"Revoke",
		"Destroy",
		"ReKey",
		"Encrypt",
		"Decrypt",
		"Sign",
		"SignatureVerify",
		"Query",
		"DiscoverVersions",
		"CreateKeyPair",
		"ModifyAttribute",
		"DeleteAttribute",
		"GetAttributeList",
		"Certify",
		"ReCertify",
		"Check",
		"Import",
		"Export",
		"Archive",
		"Recover",
		"Validate",
		"MAC",
		"MACVerify",
		"Hash",
		"DeriveKey",
		"GetUsageAllocation",
	}
}

func knownKMIP32ObjectTypes() []string {
	return []string{
		"SymmetricKey",
		"PublicKey",
		"PrivateKey",
		"SecretData",
		"Certificate",
		"OpaqueObject",
		"SplitKey",
		"Template",
		"PGPKey",
	}
}

func knownIntegrationTargets() []string {
	return []string{
		"MySQL (KMIP-capable editions)",
		"MongoDB Enterprise",
		"VMware vSphere / ESXi",
		"Scality",
		"NetApp",
		"HPE storage platforms",
		"Dell platforms",
	}
}

func (h *Handler) handleListClientProfiles(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	items, err := h.store.ListClientProfiles(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_profiles_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleCreateClientProfile(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req CreateKMIPClientProfileRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	profile, err := h.createClientProfile(r.Context(), req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "create_profile_failed", err.Error(), reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"profile": profile, "request_id": reqID})
}

func (h *Handler) handleDeleteClientProfile(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	profileID := strings.TrimSpace(r.PathValue("id"))
	if profileID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "profile id is required", reqID, tenantID)
		return
	}
	profile, err := h.store.GetClientProfile(r.Context(), tenantID, profileID)
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, errNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "delete_profile_failed", err.Error(), reqID, tenantID)
		return
	}
	attachedClients, err := h.store.CountClientsByProfile(r.Context(), tenantID, profileID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "delete_profile_failed", err.Error(), reqID, tenantID)
		return
	}
	if attachedClients > 0 {
		writeErr(w, http.StatusConflict, "profile_in_use", "profile is assigned to existing kmip clients; delete those clients first", reqID, tenantID)
		return
	}
	if err := h.store.DeleteClientProfile(r.Context(), tenantID, profileID); err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, errNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "delete_profile_failed", err.Error(), reqID, tenantID)
		return
	}
	_ = h.publishAudit(r.Context(), "audit.kmip.client_profile_deleted", tenantID, map[string]interface{}{
		"profile_id": profileID,
		"name":       profile.Name,
		"role":       profile.Role,
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "deleted", "request_id": reqID})
}

func (h *Handler) handleListClients(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	items, err := h.store.ListClients(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_clients_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleGetClient(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	out, err := h.store.GetClientByID(r.Context(), tenantID, strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, errNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "get_client_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"client": out, "request_id": reqID})
}

func (h *Handler) handleCreateClient(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req CreateKMIPClientRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	out, err := h.createClient(r.Context(), req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "create_client_failed", err.Error(), reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"client":          out.Client,
		"issued_cert_pem": out.IssuedCertPEM,
		"issued_key_pem":  out.IssuedKeyPEM,
		"request_id":      reqID,
	})
}

func (h *Handler) handleDeleteClient(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	clientID := strings.TrimSpace(r.PathValue("id"))
	if clientID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "client id is required", reqID, tenantID)
		return
	}
	client, err := h.store.GetClientByID(r.Context(), tenantID, clientID)
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, errNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "delete_client_failed", err.Error(), reqID, tenantID)
		return
	}
	if err := h.store.DeleteClient(r.Context(), tenantID, clientID); err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, errNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "delete_client_failed", err.Error(), reqID, tenantID)
		return
	}
	_ = h.publishAudit(r.Context(), "audit.kmip.client_deleted", tenantID, map[string]interface{}{
		"client_id":        clientID,
		"name":             client.Name,
		"role":             client.Role,
		"profile_id":       client.ProfileID,
		"cert_fingerprint": client.CertFingerprintSHA256,
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "deleted", "request_id": reqID})
}

func (h *Handler) handleListInteropTargets(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	items, err := h.store.ListInteropTargets(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_interop_targets_failed", err.Error(), reqID, tenantID)
		return
	}
	views := make([]KMIPInteropTargetView, 0, len(items))
	for _, item := range items {
		views = append(views, toInteropTargetView(item))
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": views, "request_id": reqID})
}

func (h *Handler) handleCreateInteropTarget(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req CreateKMIPInteropTargetRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	target, err := h.createInteropTarget(r.Context(), req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "create_interop_target_failed", err.Error(), reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"target":     toInteropTargetView(target),
		"request_id": reqID,
	})
}

func (h *Handler) handleDeleteInteropTarget(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	targetID := strings.TrimSpace(r.PathValue("id"))
	if targetID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "interop target id is required", reqID, tenantID)
		return
	}
	target, err := h.store.GetInteropTarget(r.Context(), tenantID, targetID)
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, errNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "delete_interop_target_failed", err.Error(), reqID, tenantID)
		return
	}
	if err := h.store.DeleteInteropTarget(r.Context(), tenantID, targetID); err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, errNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "delete_interop_target_failed", err.Error(), reqID, tenantID)
		return
	}
	_ = h.publishAudit(r.Context(), "audit.kmip.interop_target_deleted", tenantID, map[string]interface{}{
		"target_id": target.ID,
		"name":      target.Name,
		"vendor":    target.Vendor,
		"endpoint":  target.Endpoint,
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "deleted", "request_id": reqID})
}

func (h *Handler) handleValidateInteropTarget(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	targetID := strings.TrimSpace(r.PathValue("id"))
	if targetID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "interop target id is required", reqID, tenantID)
		return
	}
	target, err := h.store.GetInteropTarget(r.Context(), tenantID, targetID)
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, errNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "validate_interop_target_failed", err.Error(), reqID, tenantID)
		return
	}
	report := h.runInteropValidation(r.Context(), target)
	status := "failed"
	if report.Verified {
		status = "verified"
	}
	if err := h.store.UpdateInteropTargetValidation(r.Context(), tenantID, targetID, status, report.Error, marshalInteropValidationReport(report), report.CheckedAt); err != nil {
		writeErr(w, http.StatusInternalServerError, "validate_interop_target_failed", err.Error(), reqID, tenantID)
		return
	}
	updated, err := h.store.GetInteropTarget(r.Context(), tenantID, targetID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "validate_interop_target_failed", err.Error(), reqID, tenantID)
		return
	}
	_ = h.publishAudit(r.Context(), "audit.kmip.interop_validated", tenantID, map[string]interface{}{
		"target_id":          updated.ID,
		"name":               updated.Name,
		"vendor":             updated.Vendor,
		"endpoint":           updated.Endpoint,
		"status":             status,
		"verified":           report.Verified,
		"discover_ok":        report.DiscoverVersionsOK,
		"query_ok":           report.QueryOK,
		"key_operation_ok":   report.KeyOperationOK,
		"negotiated_version": report.NegotiatedVersion,
		"error":              report.Error,
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"target":     toInteropTargetView(updated),
		"result":     report,
		"request_id": reqID,
	})
}

func (h *Handler) createClientProfile(ctx context.Context, req CreateKMIPClientProfileRequest) (KMIPClientProfile, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.Name = strings.TrimSpace(req.Name)
	req.CAID = strings.TrimSpace(req.CAID)
	req.UsernameLocation = strings.ToLower(strings.TrimSpace(req.UsernameLocation))
	req.SubjectFieldToModify = strings.ToLower(strings.TrimSpace(req.SubjectFieldToModify))
	req.Role = strings.ToLower(strings.TrimSpace(req.Role))
	if req.CertificateDurationDays <= 0 {
		req.CertificateDurationDays = 365
	}
	if req.CertificateDurationDays > 3650 {
		req.CertificateDurationDays = 3650
	}
	if req.UsernameLocation == "" {
		req.UsernameLocation = "cn"
	}
	if req.SubjectFieldToModify == "" {
		req.SubjectFieldToModify = "uid"
	}
	if req.Role == "" {
		req.Role = "kmip-client"
	}
	if req.TenantID == "" || req.Name == "" || req.CAID == "" {
		return KMIPClientProfile{}, errors.New("tenant_id, name and ca_id are required")
	}
	if !isRoleAllowed(req.Role) {
		return KMIPClientProfile{}, errors.New("role must be one of kmip-client, kmip-admin, kmip-service")
	}
	if h.certs == nil {
		return KMIPClientProfile{}, errors.New("certs integration is not configured")
	}
	cas, err := h.certs.ListCAs(ctx, req.TenantID)
	if err != nil {
		return KMIPClientProfile{}, err
	}
	foundCA := false
	for _, ca := range cas {
		if strings.TrimSpace(ca.ID) == req.CAID {
			foundCA = true
			break
		}
	}
	if !foundCA {
		return KMIPClientProfile{}, errors.New("selected CA was not found in Certificates tab")
	}
	profile := KMIPClientProfile{
		ID:                      newID("kpf"),
		TenantID:                req.TenantID,
		Name:                    req.Name,
		CAID:                    req.CAID,
		UsernameLocation:        req.UsernameLocation,
		SubjectFieldToModify:    req.SubjectFieldToModify,
		DoNotModifySubjectDN:    req.DoNotModifySubjectDN,
		CertificateDurationDays: req.CertificateDurationDays,
		Role:                    req.Role,
		MetadataJSON:            validJSONOr(req.MetadataJSON, "{}"),
	}
	if err := h.store.CreateClientProfile(ctx, profile); err != nil {
		return KMIPClientProfile{}, err
	}
	return h.store.GetClientProfile(ctx, req.TenantID, profile.ID)
}

func (h *Handler) createInteropTarget(ctx context.Context, req CreateKMIPInteropTargetRequest) (KMIPInteropTarget, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.Name = strings.TrimSpace(req.Name)
	req.Vendor = normalizeInteropVendor(req.Vendor)
	req.Endpoint = normalizeInteropEndpoint(req.Endpoint)
	req.ServerName = strings.TrimSpace(req.ServerName)
	req.ExpectedMinVersion = strings.TrimSpace(req.ExpectedMinVersion)
	if req.ExpectedMinVersion == "" {
		req.ExpectedMinVersion = "1.0"
	}

	if req.TenantID == "" || req.Name == "" || req.Endpoint == "" {
		return KMIPInteropTarget{}, errors.New("tenant_id, name and endpoint are required")
	}
	if _, _, err := parseVersionParts(req.ExpectedMinVersion); err != nil {
		return KMIPInteropTarget{}, errors.New("expected_min_version must be in MAJOR.MINOR format")
	}
	if strings.TrimSpace(req.CAPEM) == "" {
		return KMIPInteropTarget{}, errors.New("ca_pem is required")
	}
	if strings.TrimSpace(req.ClientCertPEM) == "" || strings.TrimSpace(req.ClientKeyPEM) == "" {
		return KMIPInteropTarget{}, errors.New("client_cert_pem and client_key_pem are required")
	}
	if _, err := tls.X509KeyPair([]byte(req.ClientCertPEM), []byte(req.ClientKeyPEM)); err != nil {
		return KMIPInteropTarget{}, errors.New("invalid client certificate/key pair")
	}
	if _, err := parseAllCertificates(req.CAPEM); err != nil {
		return KMIPInteropTarget{}, errors.New("invalid ca_pem chain")
	}

	target := KMIPInteropTarget{
		ID:                 newID("kmit"),
		TenantID:           req.TenantID,
		Name:               req.Name,
		Vendor:             req.Vendor,
		Endpoint:           req.Endpoint,
		ServerName:         req.ServerName,
		ExpectedMinVersion: req.ExpectedMinVersion,
		TestKeyOperation:   req.TestKeyOperation,
		CAPEM:              strings.TrimSpace(req.CAPEM),
		ClientCertPEM:      strings.TrimSpace(req.ClientCertPEM),
		ClientKeyPEM:       strings.TrimSpace(req.ClientKeyPEM),
		LastStatus:         "unknown",
		LastError:          "",
		LastReportJSON:     "{}",
	}
	if err := h.store.CreateInteropTarget(ctx, target); err != nil {
		return KMIPInteropTarget{}, err
	}
	out, err := h.store.GetInteropTarget(ctx, req.TenantID, target.ID)
	if err != nil {
		return KMIPInteropTarget{}, err
	}
	_ = h.publishAudit(ctx, "audit.kmip.interop_target_created", req.TenantID, map[string]interface{}{
		"target_id":            out.ID,
		"name":                 out.Name,
		"vendor":               out.Vendor,
		"endpoint":             out.Endpoint,
		"server_name":          out.ServerName,
		"expected_min_version": out.ExpectedMinVersion,
		"test_key_operation":   out.TestKeyOperation,
	})
	return out, nil
}

func (h *Handler) createClient(ctx context.Context, req CreateKMIPClientRequest) (CreateKMIPClientResult, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.Name = strings.TrimSpace(req.Name)
	req.ProfileID = strings.TrimSpace(req.ProfileID)
	req.EnrollmentMode = strings.ToLower(strings.TrimSpace(req.EnrollmentMode))
	req.RegistrationToken = strings.TrimSpace(req.RegistrationToken)
	req.Role = strings.ToLower(strings.TrimSpace(req.Role))
	req.CommonName = strings.TrimSpace(req.CommonName)
	if req.TenantID == "" || req.Name == "" {
		return CreateKMIPClientResult{}, errors.New("tenant_id and name are required")
	}
	if req.EnrollmentMode == "" {
		req.EnrollmentMode = "internal"
	}
	if req.EnrollmentMode != "internal" && req.EnrollmentMode != "external" {
		return CreateKMIPClientResult{}, errors.New("enrollment_mode must be internal or external")
	}

	var profile KMIPClientProfile
	if req.ProfileID != "" {
		p, err := h.store.GetClientProfile(ctx, req.TenantID, req.ProfileID)
		if err != nil {
			return CreateKMIPClientResult{}, err
		}
		profile = p
	}
	if req.Role == "" {
		req.Role = strings.ToLower(strings.TrimSpace(profile.Role))
	}
	if req.Role == "" {
		req.Role = "kmip-client"
	}
	if !isRoleAllowed(req.Role) {
		return CreateKMIPClientResult{}, errors.New("role must be one of kmip-client, kmip-admin, kmip-service")
	}
	if req.RegistrationToken == "" {
		req.RegistrationToken = newID("kmipreg")
	}

	var (
		leafCert      *x509.Certificate
		certPEM       string
		certID        string
		issuedKeyPEM  string
		issuedCertPEM string
	)
	switch req.EnrollmentMode {
	case "internal":
		if h.certs == nil {
			return CreateKMIPClientResult{}, errors.New("certs integration is not configured")
		}
		caID := strings.TrimSpace(profile.CAID)
		if caID == "" {
			return CreateKMIPClientResult{}, errors.New("profile must include a CA for internal enrollment")
		}
		subjectCN := req.CommonName
		if subjectCN == "" {
			subjectCN = fmt.Sprintf("%s:%s", req.TenantID, req.Role)
		}
		issueReq := CertsIssueCertificateRequest{
			TenantID:     req.TenantID,
			CAID:         caID,
			ProfileID:    "",
			CertType:     "mtls-client",
			Protocol:     "kmip",
			SubjectCN:    subjectCN,
			CSRPem:       strings.TrimSpace(req.CSRPEM),
			ServerKeygen: true,
			ValidityDays: int64(profile.CertificateDurationDays),
			MetadataJSON: validJSONOr(req.MetadataJSON, "{}"),
		}
		if issueReq.ValidityDays <= 0 {
			issueReq.ValidityDays = 365
		}
		issued, err := h.certs.IssueCertificate(ctx, issueReq)
		if err != nil {
			return CreateKMIPClientResult{}, err
		}
		certID = strings.TrimSpace(issued.ID)
		certPEM = strings.TrimSpace(issued.CertPEM)
		issuedCertPEM = certPEM
		issuedKeyPEM = strings.TrimSpace(issued.KeyPEM)
		leaf, err := parseLeafCertificate(certPEM)
		if err != nil {
			return CreateKMIPClientResult{}, err
		}
		leafCert = leaf
	case "external":
		certPEM = strings.TrimSpace(req.CertificatePEM)
		if certPEM == "" {
			return CreateKMIPClientResult{}, errors.New("certificate_pem is required for external enrollment")
		}
		leaf, err := parseLeafCertificate(certPEM)
		if err != nil {
			return CreateKMIPClientResult{}, err
		}
		if err := h.verifyExternalCertificate(ctx, req.TenantID, leaf, req.CABundlePEM); err != nil {
			return CreateKMIPClientResult{}, err
		}
		if strings.TrimSpace(req.PrivateKeyPEM) != "" {
			if err := validatePrivateKeyMatchesCertificate(leaf, req.PrivateKeyPEM); err != nil {
				return CreateKMIPClientResult{}, err
			}
		}
		leafCert = leaf
	}

	if leafCert == nil {
		return CreateKMIPClientResult{}, errors.New("client certificate is required")
	}
	fingerprint := clientFingerprintSHA256(leafCert)
	if _, err := h.store.GetClientByFingerprint(ctx, fingerprint); err == nil {
		return CreateKMIPClientResult{}, errors.New("a kmip client with this certificate already exists")
	} else if !errors.Is(err, errNotFound) {
		return CreateKMIPClientResult{}, err
	}

	client := KMIPClient{
		ID:                    newID("kmipc"),
		TenantID:              req.TenantID,
		ProfileID:             req.ProfileID,
		Name:                  req.Name,
		Role:                  req.Role,
		Status:                "active",
		EnrollmentMode:        req.EnrollmentMode,
		RegistrationToken:     req.RegistrationToken,
		CertID:                certID,
		CertSubject:           leafCert.Subject.String(),
		CertIssuer:            leafCert.Issuer.String(),
		CertSerial:            leafCert.SerialNumber.Text(16),
		CertFingerprintSHA256: fingerprint,
		CertNotBefore:         leafCert.NotBefore.UTC(),
		CertNotAfter:          leafCert.NotAfter.UTC(),
		CertificatePEM:        certPEM,
		CABundlePEM:           strings.TrimSpace(req.CABundlePEM),
		MetadataJSON:          validJSONOr(req.MetadataJSON, "{}"),
	}
	if err := h.store.CreateClient(ctx, client); err != nil {
		return CreateKMIPClientResult{}, err
	}
	out, err := h.store.GetClientByID(ctx, req.TenantID, client.ID)
	if err != nil {
		return CreateKMIPClientResult{}, err
	}
	_ = h.publishAudit(ctx, "audit.kmip.client_registered", req.TenantID, map[string]interface{}{
		"client_id":          out.ID,
		"name":               out.Name,
		"role":               out.Role,
		"enrollment_mode":    out.EnrollmentMode,
		"cert_fingerprint":   out.CertFingerprintSHA256,
		"cert_not_after":     out.CertNotAfter.Format(time.RFC3339),
		"profile_id":         out.ProfileID,
		"registration_token": out.RegistrationToken,
	})
	return CreateKMIPClientResult{
		Client:        out,
		IssuedCertPEM: issuedCertPEM,
		IssuedKeyPEM:  issuedKeyPEM,
	}, nil
}

func (h *Handler) verifyExternalCertificate(ctx context.Context, tenantID string, leaf *x509.Certificate, caBundlePEM string) error {
	if leaf == nil {
		return errors.New("invalid certificate")
	}
	if h.certs == nil {
		return errors.New("certs integration is not configured")
	}
	cas, err := h.certs.ListCAs(ctx, tenantID)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	addedRoots := 0
	for _, ca := range cas {
		pemText := strings.TrimSpace(ca.CertPEM)
		if pemText == "" {
			continue
		}
		cert, parseErr := parseLeafCertificate(pemText)
		if parseErr != nil {
			continue
		}
		roots.AddCert(cert)
		addedRoots++
	}
	if addedRoots == 0 {
		return errors.New("no CA configured in Certificates tab; create/upload CA first")
	}
	intermediates := x509.NewCertPool()
	bundleCerts, _ := parseAllCertificates(caBundlePEM)
	for _, cert := range bundleCerts {
		if cert != nil {
			intermediates.AddCert(cert)
		}
	}
	verify := func(keyUsage []x509.ExtKeyUsage) error {
		_, verifyErr := leaf.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			KeyUsages:     keyUsage,
			CurrentTime:   time.Now().UTC(),
		})
		return verifyErr
	}
	if err := verify([]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}); err != nil {
		if errAny := verify([]x509.ExtKeyUsage{x509.ExtKeyUsageAny}); errAny != nil {
			return errors.New("external certificate is not trusted by uploaded CA in Certificates tab")
		}
	}
	return nil
}

func validatePrivateKeyMatchesCertificate(cert *x509.Certificate, privateKeyPEM string) error {
	key, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		return err
	}
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok || rsaKey.PublicKey.N.Cmp(pub.N) != 0 || rsaKey.PublicKey.E != pub.E {
			return errors.New("private key does not match certificate public key")
		}
	case *ecdsa.PublicKey:
		ecdsaKey, ok := key.(*ecdsa.PrivateKey)
		if !ok || ecdsaKey.PublicKey.X.Cmp(pub.X) != 0 || ecdsaKey.PublicKey.Y.Cmp(pub.Y) != 0 {
			return errors.New("private key does not match certificate public key")
		}
	case ed25519.PublicKey:
		edKey, ok := key.(ed25519.PrivateKey)
		if !ok {
			return errors.New("private key does not match certificate public key")
		}
		pubFromKey := edKey.Public().(ed25519.PublicKey)
		if !ed25519.PublicKey(pubFromKey).Equal(pub) {
			return errors.New("private key does not match certificate public key")
		}
	default:
		return errors.New("certificate key type is not supported for private key validation")
	}
	return nil
}

func parsePrivateKey(rawPEM string) (interface{}, error) {
	rest := []byte(strings.TrimSpace(rawPEM))
	for len(rest) > 0 {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = next
		switch strings.TrimSpace(block.Type) {
		case "PRIVATE KEY":
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err == nil {
				return key, nil
			}
		case "RSA PRIVATE KEY":
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err == nil {
				return key, nil
			}
		case "EC PRIVATE KEY":
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err == nil {
				return key, nil
			}
		}
	}
	return nil, errors.New("invalid private key PEM")
}

func parseLeafCertificate(rawPEM string) (*x509.Certificate, error) {
	certs, err := parseAllCertificates(rawPEM)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, errors.New("certificate PEM is required")
	}
	for _, cert := range certs {
		if cert != nil && !cert.IsCA {
			return cert, nil
		}
	}
	return certs[0], nil
}

func parseAllCertificates(rawPEM string) ([]*x509.Certificate, error) {
	rest := []byte(strings.TrimSpace(rawPEM))
	if len(rest) == 0 {
		return nil, errors.New("certificate PEM is required")
	}
	out := make([]*x509.Certificate, 0)
	for len(rest) > 0 {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = next
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.New("invalid certificate PEM")
		}
		out = append(out, cert)
	}
	if len(out) == 0 {
		return nil, errors.New("invalid certificate PEM")
	}
	return out, nil
}

func decodeJSON(r *http.Request, out interface{}) error {
	defer r.Body.Close() //nolint:errcheck
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}

func mustTenant(r *http.Request, w http.ResponseWriter, requestID string) string {
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if tenantID == "" {
		tenantID = strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	}
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required (query or X-Tenant-ID)", requestID, "")
		return ""
	}
	return tenantID
}

func requestID(r *http.Request) string {
	id := strings.TrimSpace(r.Header.Get("X-Request-ID"))
	if id != "" {
		return id
	}
	return newID("req")
}

func writeJSON(w http.ResponseWriter, code int, payload map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeErr(w http.ResponseWriter, code int, errCode string, msg string, requestID string, tenantID string) {
	writeJSON(w, code, map[string]interface{}{
		"error": map[string]interface{}{
			"code":       errCode,
			"message":    msg,
			"request_id": requestID,
			"tenant_id":  tenantID,
		},
	})
}
