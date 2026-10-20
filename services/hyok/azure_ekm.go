package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"vecta-kms/pkg/clientip"
	pkgcrypto "vecta-kms/pkg/crypto"
)

// Azure Managed HSM external key management: the EKM Proxy API
// (0.1-preview). Managed HSM calls this service over mTLS to wrap and unwrap
// data keys under a key that stays in the KMS; nothing is created in Azure.
// The listener is the service's own (AZURE_EKM_PORT, azure_ekm_listener.go),
// not Envoy's edge: the Managed HSM client certificate is the credential,
// and this service verifies it against the CA and subject CN the tenant set
// on its endpoint (docs/CLOUD_INTEGRATION.md, "Azure EKM").
//
// A tenant's endpoint is found by the path prefix Managed HSM puts before
// every call, unique across tenants. Each external key name the tenant
// gives Managed HSM maps to one Vecta key: AES-256 (A256KW, A256KWP) or RSA
// 2048/3072/4096 (RSA-OAEP-256, RSA-OAEP). Wrap and unwrap go through
// ProcessCrypto, so policy, key access justifications, the request log and
// audit apply as to every HYOK call; governance approval does not, since
// Managed HSM waits 250 ms for an answer.

const azureEKMAPIVersion = "0.1-preview"

var (
	azurePrefixRe  = regexp.MustCompile(`^[A-Za-z0-9-]+(/[A-Za-z0-9-]+)*$`)
	azureKeyNameRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
)

// AzureEKMMetadata is the azure endpoint's metadata_json.
type AzureEKMMetadata struct {
	PathPrefix      string `json:"path_prefix"`
	ClientCAPEM     string `json:"client_ca_pem"`
	ClientSubjectCN string `json:"client_subject_cn"`
	// Keys maps the external key name Managed HSM uses to a Vecta key ID.
	Keys map[string]string `json:"keys"`
}

func parseAzureEKMMetadata(raw string) (AzureEKMMetadata, error) {
	var m AzureEKMMetadata
	d := json.NewDecoder(strings.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&m); err != nil {
		return m, fmt.Errorf("metadata: %w", err)
	}
	m.PathPrefix = strings.Trim(strings.TrimSpace(m.PathPrefix), "/")
	m.ClientSubjectCN = strings.TrimSpace(m.ClientSubjectCN)
	if len(m.PathPrefix) > 64 || !azurePrefixRe.MatchString(m.PathPrefix) {
		return m, errors.New("path_prefix is required: up to 64 letters, digits, hyphens and slashes")
	}
	if m.ClientSubjectCN == "" {
		return m, errors.New("client_subject_cn is required: the subject CN of Managed HSM's client certificate")
	}
	if _, err := m.clientRoots(); err != nil {
		return m, err
	}
	for name, keyID := range m.Keys {
		if !azureKeyNameRe.MatchString(name) {
			return m, fmt.Errorf("key name %q: up to 64 letters, digits and hyphens", name)
		}
		if strings.TrimSpace(keyID) == "" {
			return m, fmt.Errorf("key name %q maps to no key", name)
		}
	}
	return m, nil
}

// clientRoots is the CA set Managed HSM's client certificate must chain to.
func (m AzureEKMMetadata) clientRoots() (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	rest, n := []byte(m.ClientCAPEM), 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("client_ca_pem: %w", err)
		}
		if !cert.IsCA {
			return nil, fmt.Errorf("client_ca_pem: %q is not a CA certificate", cert.Subject.CommonName)
		}
		pool.AddCert(cert)
		n++
	}
	if n == 0 {
		return nil, errors.New("client_ca_pem is required: the CA that issues Managed HSM's client certificate, in PEM")
	}
	return pool, nil
}

// validateAzureEndpoint checks an azure endpoint before it is stored.
func (s *Service) validateAzureEndpoint(ctx context.Context, cfg *EndpointConfig) error {
	bad := func(code, msg string) error { return newServiceError(http.StatusBadRequest, code, msg) }
	cfg.AuthMode = AuthModeMTLS
	if cfg.GovernanceRequired {
		return bad("governance_unavailable", "Managed HSM waits 250 ms for an answer, so an Azure EKM call can't wait for an approval")
	}
	meta, err := parseAzureEKMMetadata(cfg.MetadataJSON)
	if err != nil {
		return bad("bad_metadata", err.Error())
	}
	others, err := s.store.ListEndpointsByProtocol(ctx, ProtocolAzureEKM)
	if err != nil {
		return err
	}
	for _, o := range others {
		if o.TenantID == cfg.TenantID {
			continue
		}
		if om, err := parseAzureEKMMetadata(o.MetadataJSON); err == nil && strings.EqualFold(om.PathPrefix, meta.PathPrefix) {
			return newServiceError(http.StatusConflict, "path_prefix_taken", "another tenant uses this path prefix")
		}
	}
	for name, keyID := range meta.Keys {
		key, err := s.keycore.GetKey(ctx, cfg.TenantID, keyID)
		if err != nil {
			return bad("key_unavailable", fmt.Sprintf("key name %q: %v", name, err))
		}
		if _, ok := azureKeyShape(firstString(key["algorithm"])); !ok {
			return bad("key_unsupported", fmt.Sprintf("key name %q: Azure EKM takes an AES-256 or an RSA 2048/3072/4096 key, not %s", name, firstString(key["algorithm"])))
		}
	}
	normalized, _ := json.Marshal(meta)
	cfg.MetadataJSON = string(normalized)
	return nil
}

// azureKeyShape is the key_type and key_size Managed HSM is told.
func azureKeyShape(algorithm string) (struct {
	Type string
	Size int
}, bool) {
	a := strings.ToUpper(strings.TrimSpace(algorithm))
	out := struct {
		Type string
		Size int
	}{}
	switch {
	case strings.HasPrefix(a, "AES-256"):
		out.Type, out.Size = "oct", 256
	case a == "RSA-2048" || strings.HasPrefix(a, "RSA-2048-"):
		out.Type, out.Size = "RSA", 2048
	case a == "RSA-3072" || strings.HasPrefix(a, "RSA-3072-"):
		out.Type, out.Size = "RSA", 3072
	case a == "RSA-4096" || strings.HasPrefix(a, "RSA-4096-"):
		out.Type, out.Size = "RSA", 4096
	default:
		return out, false
	}
	return out, true
}

// azureProbes is when Managed HSM last reached each tenant's endpoint
// (POST info, about three times a minute). Node-local, shown in Health.
type azureProbes struct {
	mu   sync.Mutex
	last map[string]time.Time
}

func (p *azureProbes) note(tenantID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.last == nil {
		p.last = map[string]time.Time{}
	}
	p.last[tenantID] = time.Now().UTC()
}

func (p *azureProbes) get(tenantID string) time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.last[tenantID]
}

type azureRequestContext struct {
	RequestID     string `json:"request_id"`
	CorrelationID string `json:"correlation_id"`
	PoolName      string `json:"pool_name"`
}

type azureRequest struct {
	RequestContext azureRequestContext `json:"request_context"`
	Alg            string              `json:"alg"`
	Value          string              `json:"value"`
}

// AzureEKMHandler serves the EKM Proxy API on the Azure listener.
type AzureEKMHandler struct {
	svc     *Service
	version string
}

func NewAzureEKMHandler(svc *Service, version string) *AzureEKMHandler {
	return &AzureEKMHandler{svc: svc, version: version}
}

func writeProxyError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]interface{}{"code": code, "message": message})
}

// refuse answers a ProxyError and audits it.
func (h *AzureEKMHandler) refuse(w http.ResponseWriter, r *http.Request, tenantID string, rc azureRequestContext, status int, code, reason string) {
	writeProxyError(w, status, code, reason)
	result := "refused"
	if status >= 500 {
		result = "failed"
	}
	_ = h.svc.publishAudit(r.Context(), "audit.hyok.azure_ekm_refused", tenantID, map[string]interface{}{
		"route": r.Method + " " + r.URL.Path, "code": code, "reason": reason, "result": result, "severity": "warning",
		"status": status, "correlation_id": rc.CorrelationID, "pool_name": rc.PoolName, "remote_ip": remoteHost(r),
	})
}

// remoteHost is the peer's address. No proxy stands in front of this
// listener, so a forwarded-address header is the caller's own words: it is
// dropped (ServeHTTP) and clientip falls back to the connection.
func remoteHost(r *http.Request) string {
	return clientip.From(r)
}

// azurePath splits /<prefix>/info and /<prefix>/<key>/<op>.
func azurePath(p string) (prefix, key, op string, ok bool) {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	n := len(parts)
	if n < 2 {
		return "", "", "", false
	}
	op = parts[n-1]
	switch op {
	case "info":
		return strings.Join(parts[:n-1], "/"), "", op, true
	case "metadata", "wrapkey", "unwrapkey":
		if n < 3 {
			return "", "", "", false
		}
		return strings.Join(parts[:n-2], "/"), parts[n-2], op, true
	}
	return "", "", "", false
}

func (h *AzureEKMHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Header.Del(clientip.Header)
	ctx := r.Context()
	var body azureRequest
	if r.Method != http.MethodPost {
		h.refuse(w, r, "", body.RequestContext, http.StatusMethodNotAllowed, "MethodNotAllowed", "only POST is served")
		return
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&body); err != nil {
		h.refuse(w, r, "", body.RequestContext, http.StatusBadRequest, "InvalidRequest", "the body is not JSON")
		return
	}
	prefix, keyName, op, ok := azurePath(r.URL.Path)
	if !ok {
		h.refuse(w, r, "", body.RequestContext, http.StatusNotFound, "NotFound", "no such EKM Proxy API path")
		return
	}
	if v := r.URL.Query().Get("api-version"); v != azureEKMAPIVersion {
		h.refuse(w, r, "", body.RequestContext, http.StatusBadRequest, "UnsupportedApiVersion", "api-version must be "+azureEKMAPIVersion)
		return
	}
	tenantID, meta, err := h.svc.azureEndpointForPrefix(ctx, prefix)
	if err != nil {
		h.refuse(w, r, "", body.RequestContext, http.StatusNotFound, "NotFound", "no enabled Azure EKM endpoint has this path prefix")
		return
	}
	identity, reason := verifyAzureClient(r, meta)
	if reason != "" {
		h.refuse(w, r, tenantID, body.RequestContext, http.StatusUnauthorized, "Unauthorized", reason)
		return
	}
	identity.TenantID = tenantID

	if op == "info" {
		h.svc.azure.note(tenantID)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"api_version":  azureEKMAPIVersion,
			"proxy_vendor": "Vecta",
			"proxy_name":   "Vecta KMS HYOK " + h.version,
			"ekm_vendor":   "Vecta",
			"ekm_product":  "Vecta KMS " + h.version,
		})
		return
	}
	keyID, mapped := meta.Keys[keyName]
	if !mapped {
		h.refuse(w, r, tenantID, body.RequestContext, http.StatusNotFound, "KeyNotFound", "no key is mapped to this name")
		return
	}
	key, err := h.svc.keycore.GetKey(ctx, tenantID, keyID)
	if err != nil {
		h.refuse(w, r, tenantID, body.RequestContext, http.StatusNotFound, "KeyNotFound", "the mapped key is not available")
		return
	}
	if st := strings.ToLower(firstString(key["status"])); st != "" && st != "active" {
		h.refuse(w, r, tenantID, body.RequestContext, http.StatusForbidden, "KeyDisabled", "the mapped key is "+st)
		return
	}
	shape, ok := azureKeyShape(firstString(key["algorithm"]))
	if !ok {
		h.refuse(w, r, tenantID, body.RequestContext, http.StatusForbidden, "KeyTypeNotSupported", "the mapped key is not AES-256 or RSA")
		return
	}
	if op == "metadata" {
		h.metadata(w, r, tenantID, keyID, keyName, shape.Type, shape.Size, body.RequestContext)
		return
	}
	h.wrap(w, r, tenantID, keyID, keyName, shape.Type, op, identity, body)
}

func (h *AzureEKMHandler) metadata(w http.ResponseWriter, r *http.Request, tenantID, keyID, keyName, keyType string, size int, rc azureRequestContext) {
	out := map[string]interface{}{"key_type": keyType, "key_size": size, "key_ops": []string{"wrapKey", "unwrapKey"}}
	if keyType == "RSA" {
		pubMeta, err := h.svc.keycore.PublicKey(r.Context(), tenantID, keyID)
		if err != nil {
			h.refuse(w, r, tenantID, rc, http.StatusInternalServerError, "PublicKeyUnavailable", "the key's public part could not be read")
			return
		}
		pub, err := pkgcrypto.ParseRSAPublicKeyAny(firstString(pubMeta["public_key_pem"]))
		if err != nil {
			h.refuse(w, r, tenantID, rc, http.StatusInternalServerError, "PublicKeyUnavailable", "the key's public part is not RSA")
			return
		}
		n, e, err := pkgcrypto.RSAPublicKeyJWK(pub)
		if err != nil {
			h.refuse(w, r, tenantID, rc, http.StatusInternalServerError, "PublicKeyUnavailable", err.Error())
			return
		}
		out["n"], out["e"] = n, e
	}
	_ = h.svc.publishAudit(r.Context(), "audit.hyok.azure_ekm_metadata", tenantID, map[string]interface{}{
		"key_id": keyID, "key_name": keyName, "result": "success", "correlation_id": rc.CorrelationID, "pool_name": rc.PoolName,
	})
	writeJSON(w, http.StatusOK, out)
}

func (h *AzureEKMHandler) wrap(w http.ResponseWriter, r *http.Request, tenantID, keyID, keyName, keyType, op string, identity AuthIdentity, body azureRequest) {
	rc := body.RequestContext
	alg := strings.TrimSpace(body.Alg)
	if (keyType == "oct" && !pkgcrypto.JWAIsAES(alg)) || (keyType == "RSA" && !pkgcrypto.JWAIsRSA(alg)) {
		h.refuse(w, r, tenantID, rc, http.StatusBadRequest, "UnsupportedAlgorithm", fmt.Sprintf("alg %q does not apply to a %s key", alg, keyType))
		return
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(strings.TrimSpace(body.Value), "="))
	if err != nil || len(raw) == 0 {
		h.refuse(w, r, tenantID, rc, http.StatusBadRequest, "InvalidRequest", "value must be base64url")
		return
	}
	defer pkgcrypto.Zeroize(raw)
	req := ProxyCryptoRequest{WrapAlgorithm: alg, ReferenceID: rc.CorrelationID, RequesterID: identity.Subject}
	operation := "wrap"
	if op == "wrapkey" {
		req.PlaintextB64 = base64.StdEncoding.EncodeToString(raw)
	} else {
		operation = "unwrap"
		req.CiphertextB64 = base64.StdEncoding.EncodeToString(raw)
	}
	out, err := h.svc.ProcessCrypto(r.Context(), tenantID, ProtocolAzureEKM, operation, keyID, r.URL.Path, identity, req)
	if err != nil {
		status, code := azureErrorFor(err)
		h.refuse(w, r, tenantID, rc, status, code, err.Error())
		return
	}
	if out.Status == "pending_approval" {
		h.refuse(w, r, tenantID, rc, http.StatusForbidden, "ApprovalRequired", "the key's access rules hold this call for approval, which Managed HSM can't wait for")
		return
	}
	result := out.CiphertextB64
	if operation == "unwrap" {
		result = out.PlaintextB64
	}
	bytesOut, err := base64.StdEncoding.DecodeString(result)
	if err != nil || len(bytesOut) == 0 {
		h.refuse(w, r, tenantID, rc, http.StatusInternalServerError, "InternalError", "keycore returned no result")
		return
	}
	defer pkgcrypto.Zeroize(bytesOut)
	writeJSON(w, http.StatusOK, map[string]interface{}{"value": base64.RawURLEncoding.EncodeToString(bytesOut)})
}

// azureErrorFor maps a HYOK refusal to the EKM Proxy API's status and code.
func azureErrorFor(err error) (int, string) {
	var svcErr serviceError
	if !errors.As(err, &svcErr) {
		return http.StatusInternalServerError, "InternalError"
	}
	switch {
	case svcErr.HTTPStatus == http.StatusTooManyRequests:
		return http.StatusTooManyRequests, "TooManyRequests"
	case svcErr.HTTPStatus == http.StatusNotFound:
		return http.StatusNotFound, "KeyNotFound"
	case svcErr.HTTPStatus == http.StatusBadRequest:
		return http.StatusBadRequest, "InvalidRequest"
	case svcErr.HTTPStatus == http.StatusUnauthorized:
		return http.StatusUnauthorized, "Unauthorized"
	case svcErr.HTTPStatus >= 400 && svcErr.HTTPStatus < 500:
		return http.StatusForbidden, "Forbidden"
	}
	return http.StatusInternalServerError, "InternalError"
}

// azureEndpointForPrefix finds the enabled azure endpoint with prefix.
func (s *Service) azureEndpointForPrefix(ctx context.Context, prefix string) (string, AzureEKMMetadata, error) {
	all, err := s.store.ListEnabledEndpointsByProtocol(ctx, ProtocolAzureEKM)
	if err != nil {
		return "", AzureEKMMetadata{}, err
	}
	for _, cfg := range all {
		meta, err := parseAzureEKMMetadata(cfg.MetadataJSON)
		if err == nil && strings.EqualFold(meta.PathPrefix, strings.Trim(prefix, "/")) {
			return cfg.TenantID, meta, nil
		}
	}
	return "", AzureEKMMetadata{}, errNotFound
}

// verifyAzureClient checks the TLS client certificate against the endpoint's
// CA and subject CN; reason is empty when it passes.
func verifyAzureClient(r *http.Request, meta AzureEKMMetadata) (AuthIdentity, string) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return AuthIdentity{}, "no client certificate"
	}
	roots, err := meta.clientRoots()
	if err != nil {
		return AuthIdentity{}, "the endpoint's client CA does not load"
	}
	leaf := r.TLS.PeerCertificates[0]
	inter := x509.NewCertPool()
	for _, c := range r.TLS.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return AuthIdentity{}, "the client certificate does not chain to the endpoint's client CA"
	}
	if leaf.Subject.CommonName != meta.ClientSubjectCN {
		return AuthIdentity{}, "the client certificate's subject CN is not the endpoint's"
	}
	return AuthIdentity{
		Mode:     AuthModeMTLS,
		Subject:  "azure-managed-hsm:" + leaf.Subject.CommonName,
		ClientCN: leaf.Subject.CommonName,
		Issuer:   leaf.Issuer.CommonName,
		RemoteIP: remoteHost(r),
	}, ""
}
