package main

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/credstore"
	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/sigv4"
	"vecta-kms/pkg/tenantcheck"
)

// AWS KMS external key store (XKS proxy API v1). AWS KMS calls the KMS to
// encrypt and decrypt with an AES-256 key that stays here (HYOK). Calls come
// through the HTTPS edge at <edge>/svc/hyok/xks/<path prefix>/kms/xks/v1/...
// and are signed with SigV4 (service kms-xks-proxy) using an aws_xks
// credential from Playbooks → Credentials; up to two may be attached so the
// customer can rotate. AES-GCM output carries the key version in
// ciphertextMetadata, so rotating the Vecta key never strands data, and the
// AAD given to keycore binds that metadata as the spec prescribes:
// u16 len(aad) || aad || u8 len(metadata) || metadata. Encrypt answers a
// ciphertextDataIntegrityValue (Appendix C) only after decrypting its own
// output. (docs/CLOUD_INTEGRATION.md, "AWS XKS".)

const (
	xksService   = "kms-xks-proxy"
	xksAPIPrefix = "/kms/xks/v1/"
	// xksMetaV1 marks ciphertextMetadata = 0x01 || u32 key version.
	xksMetaV1      = 0x01
	xksMaxPlain    = 4300
	xksMaxAAD      = 8192
	xksCredCache   = 15 * time.Second
	xksCredMaxKeys = 2
)

var (
	xksPrefixRe = regexp.MustCompile(`^[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*$`)
	xksKeyIDRe  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
)

// AWSXKSMetadata is the aws_xks endpoint's metadata_json.
type AWSXKSMetadata struct {
	PathPrefix    string            `json:"path_prefix"`
	CredentialIDs []string          `json:"credential_ids"`
	Keys          map[string]string `json:"keys"`
}

func parseAWSXKSMetadata(raw string) (AWSXKSMetadata, error) {
	var m AWSXKSMetadata
	d := json.NewDecoder(strings.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&m); err != nil {
		return m, fmt.Errorf("metadata: %w", err)
	}
	m.PathPrefix = strings.Trim(strings.TrimSpace(m.PathPrefix), "/")
	if len(m.PathPrefix) > 64 || !xksPrefixRe.MatchString(m.PathPrefix) {
		return m, errors.New("path_prefix is required: up to 64 letters, digits, hyphens, underscores and slashes")
	}
	if n := len(m.CredentialIDs); n == 0 || n > xksCredMaxKeys || (n == 2 && m.CredentialIDs[0] == m.CredentialIDs[1]) {
		return m, errors.New("credential_ids: one or two different aws_xks credentials")
	}
	for name, keyID := range m.Keys {
		if !xksKeyIDRe.MatchString(name) {
			return m, fmt.Errorf("external key id %q: up to 128 letters, digits, '.', '-' and '_'", name)
		}
		if strings.TrimSpace(keyID) == "" {
			return m, fmt.Errorf("external key id %q maps to no key", name)
		}
	}
	return m, nil
}

// xksExternalPrefix is the edge path in front of this service (Envoy routes
// /svc/hyok/ here and rewrites it to /); AWS signs the path it called.
func xksExternalPrefix() string {
	if v := strings.TrimRight(strings.TrimSpace(os.Getenv("XKS_EXTERNAL_PATH_PREFIX")), "/"); v != "" {
		return v
	}
	return "/svc/hyok"
}

func isAES256(algorithm string) bool {
	a := strings.ToUpper(strings.TrimSpace(algorithm))
	return a == "AES-256" || a == "AES-256-GCM"
}

// validateAWSXKSEndpoint checks an aws_xks endpoint before it is stored.
// claims are the caller's: attaching a credential needs
// compliance.connection.use.
func (s *Service) validateAWSXKSEndpoint(ctx context.Context, cfg *EndpointConfig, claims *pkgauth.Claims) error {
	bad := func(code, msg string) error { return newServiceError(http.StatusBadRequest, code, msg) }
	cfg.AuthMode = AuthModeSigV4
	if cfg.GovernanceRequired {
		return bad("governance_unavailable", "AWS KMS waits 250 ms for an answer, so an XKS call can't wait for an approval")
	}
	meta, err := parseAWSXKSMetadata(cfg.MetadataJSON)
	if err != nil {
		return bad("bad_metadata", err.Error())
	}
	if !route.Allowed(claims, credstore.PermissionUse) {
		return newServiceError(http.StatusForbidden, "credential_use_not_permitted", "attaching a credential needs "+credstore.PermissionUse)
	}
	for _, id := range meta.CredentialIDs {
		c, err := s.creds.Resolve(ctx, cfg.TenantID, id)
		if err != nil {
			return bad("credential_unavailable", fmt.Sprintf("credential %s: %v", id, err))
		}
		if c.Type != "aws_xks" {
			return bad("credential_wrong_type", fmt.Sprintf("credential %s is %s, not aws_xks", id, c.Type))
		}
	}
	others, err := s.store.ListEndpointsByProtocol(ctx, ProtocolAWSXKS)
	if err != nil {
		return err
	}
	for _, o := range others {
		if o.TenantID == cfg.TenantID {
			continue
		}
		if om, err := parseAWSXKSMetadata(o.MetadataJSON); err == nil && strings.EqualFold(om.PathPrefix, meta.PathPrefix) {
			return newServiceError(http.StatusConflict, "path_prefix_taken", "another tenant uses this path prefix")
		}
	}
	for name, keyID := range meta.Keys {
		key, err := s.keycore.GetKey(ctx, cfg.TenantID, keyID)
		if err != nil {
			return bad("key_unavailable", fmt.Sprintf("external key id %q: %v", name, err))
		}
		if !isAES256(firstString(key["algorithm"])) {
			return bad("key_unsupported", fmt.Sprintf("external key id %q: XKS takes an AES-256 key, not %s", name, firstString(key["algorithm"])))
		}
	}
	normalized, _ := json.Marshal(meta)
	cfg.MetadataJSON = string(normalized)
	return nil
}

// xksCreds caches opened credentials briefly: AWS calls about 30 times a
// second at peak and answers in 250 ms.
type xksCreds struct {
	mu   sync.Mutex
	byID map[string]xksCredEntry
}

type xksCredEntry struct {
	keyID, secret string
	until         time.Time
}

func (s *Service) xksSecrets(ctx context.Context, tenantID string, ids []string) (map[string]string, error) {
	out := map[string]string{}
	now := time.Now()
	for _, id := range ids {
		cacheKey := tenantID + "/" + id
		s.xks.mu.Lock()
		e, ok := s.xks.byID[cacheKey]
		s.xks.mu.Unlock()
		if !ok || now.After(e.until) {
			c, err := s.creds.Resolve(ctx, tenantID, id)
			if err != nil {
				return nil, err
			}
			if c.Type != "aws_xks" {
				return nil, fmt.Errorf("credential %s is not aws_xks", id)
			}
			e = xksCredEntry{keyID: c.Fields["access_key_id"], secret: c.Fields["secret_access_key"], until: now.Add(xksCredCache)}
			s.xks.mu.Lock()
			if s.xks.byID == nil {
				s.xks.byID = map[string]xksCredEntry{}
			}
			s.xks.byID[cacheKey] = e
			s.xks.mu.Unlock()
		}
		out[e.keyID] = e.secret
	}
	return out, nil
}

func (s *Service) xksEndpointForPrefix(ctx context.Context, prefix string) (EndpointConfig, AWSXKSMetadata, error) {
	all, err := s.store.ListEnabledEndpointsByProtocol(ctx, ProtocolAWSXKS)
	if err != nil {
		return EndpointConfig{}, AWSXKSMetadata{}, err
	}
	for _, cfg := range all {
		if meta, err := parseAWSXKSMetadata(cfg.MetadataJSON); err == nil && strings.EqualFold(meta.PathPrefix, prefix) {
			return cfg, meta, nil
		}
	}
	return EndpointConfig{}, AWSXKSMetadata{}, errNotFound
}

// xksAAD is the AAD keycore authenticates: the request's AAD and the
// ciphertext metadata, each with its length.
func xksAAD(aad, meta []byte) []byte {
	out := make([]byte, 0, 3+len(aad)+len(meta))
	out = binary.BigEndian.AppendUint16(out, uint16(len(aad)))
	out = append(out, aad...)
	out = append(out, byte(len(meta)))
	return append(out, meta...)
}

func xksMeta(version int) []byte {
	return binary.BigEndian.AppendUint32([]byte{xksMetaV1}, uint32(version))
}

func xksMetaVersion(meta []byte) (int, bool) {
	if len(meta) != 5 || meta[0] != xksMetaV1 {
		return 0, false
	}
	v := binary.BigEndian.Uint32(meta[1:])
	return int(v), v > 0
}

// xksCDIV is Appendix C: SHA-256 over aad || metadata || iv || ciphertext || tag.
func xksCDIV(aad, meta, iv, ct, tag []byte) []byte {
	buf := make([]byte, 0, len(aad)+len(meta)+len(iv)+len(ct)+len(tag))
	for _, p := range [][]byte{aad, meta, iv, ct, tag} {
		buf = append(buf, p...)
	}
	return pkgcrypto.SHA256(buf)
}

type xksRequest struct {
	RequestMetadata struct {
		AWSPrincipalArn string `json:"awsPrincipalArn"`
		KMSOperation    string `json:"kmsOperation"`
		KMSRequestID    string `json:"kmsRequestId"`
		KMSKeyArn       string `json:"kmsKeyArn"`
		KMSViaService   string `json:"kmsViaService"`
		AWSSourceVpc    string `json:"awsSourceVpc"`
		AWSSourceVpce   string `json:"awsSourceVpce"`
	} `json:"requestMetadata"`
	Plaintext           string `json:"plaintext"`
	Ciphertext          string `json:"ciphertext"`
	CiphertextMetadata  string `json:"ciphertextMetadata"`
	EncryptionAlgorithm string `json:"encryptionAlgorithm"`
	AAD                 string `json:"additionalAuthenticatedData"`
	IV                  string `json:"initializationVector"`
	AuthenticationTag   string `json:"authenticationTag"`
	CDIVAlgorithm       string `json:"ciphertextDataIntegrityValueAlgorithm"`
}

// xksError answers in the XKS shape and records the event's outcome.
func xksError(c *route.Call, status int, name, msg string) {
	result := route.ResultRefused
	if status >= 500 {
		result = route.ResultFailure
	}
	c.Detail("error_name", name)
	if len(msg) > 500 {
		msg = msg[:500]
	}
	c.Protocol(status, map[string]string{"errorName": name, "errorMessage": msg}, result, name)
}

func b64(v string) ([]byte, error) {
	if v == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(v)
}

// handleXKS serves POST /xks/{rest...}.
func (h *Handler) handleXKS(c *route.Call) {
	ctx := c.R.Context()
	body, err := io.ReadAll(io.LimitReader(c.R.Body, 64<<10))
	if err != nil {
		xksError(c, http.StatusBadRequest, "ValidationException", "the body could not be read")
		return
	}
	rest := "/" + c.R.PathValue("rest")
	i := strings.Index(rest, xksAPIPrefix)
	if i < 0 {
		xksError(c, http.StatusNotFound, "InvalidUriPathException", "not an XKS proxy API path")
		return
	}
	prefix, tail := strings.Trim(rest[:i], "/"), rest[i+len(xksAPIPrefix):]
	cfg, meta, err := h.svc.xksEndpointForPrefix(ctx, prefix)
	if err != nil {
		xksError(c, http.StatusNotFound, "InvalidUriPathException", "no enabled XKS endpoint has this path prefix")
		return
	}
	c.Tenant = cfg.TenantID
	secrets, err := h.svc.xksSecrets(ctx, cfg.TenantID, meta.CredentialIDs)
	if err != nil {
		xksError(c, http.StatusInternalServerError, "InternalException", "the endpoint's credential could not be opened")
		return
	}
	verified, err := sigv4.Verify(c.R, body, xksExternalPrefix()+c.R.URL.EscapedPath(), xksService, func(id string) (string, bool) {
		s, ok := secrets[id]
		return s, ok
	}, time.Now())
	if err != nil {
		c.Detail("reason_detail", err.Error())
		xksError(c, http.StatusUnauthorized, "AuthenticationFailedException", "the request signature does not verify")
		return
	}
	c.Authenticated(verified.AccessKeyID, "aws_xks_credential")
	var req xksRequest
	if err := json.Unmarshal(body, &req); err != nil {
		xksError(c, http.StatusBadRequest, "ValidationException", "the body is not JSON")
		return
	}
	c.Detail("kms_request_id", req.RequestMetadata.KMSRequestID)
	c.Detail("kms_operation", req.RequestMetadata.KMSOperation)
	if req.RequestMetadata.AWSPrincipalArn != "" {
		c.Detail("aws_principal_arn", req.RequestMetadata.AWSPrincipalArn)
	}
	identity := AuthIdentity{Mode: AuthModeSigV4, Subject: "aws-xks:" + verified.AccessKeyID, TenantID: cfg.TenantID, RemoteIP: remoteHost(c.R)}

	if tail == "health" {
		h.xksHealth(c, cfg.TenantID, meta)
		return
	}
	parts := strings.Split(tail, "/")
	if len(parts) != 3 || parts[0] != "keys" {
		xksError(c, http.StatusNotFound, "InvalidUriPathException", "not an XKS proxy API path")
		return
	}
	extID, op := parts[1], parts[2]
	keyID, ok := meta.Keys[extID]
	if !ok {
		xksError(c, http.StatusNotFound, "KeyNotFoundException", "no key is mapped to this external key id")
		return
	}
	c.Target(keyID)
	key, err := h.svc.keycore.GetKey(ctx, cfg.TenantID, keyID)
	if err != nil {
		xksError(c, http.StatusNotFound, "KeyNotFoundException", "the mapped key is not available")
		return
	}
	enabled := strings.EqualFold(firstString(key["status"]), "active")
	switch op {
	case "metadata":
		status := "DISABLED"
		if enabled {
			status = "ENABLED"
		}
		c.Protocol(http.StatusOK, map[string]interface{}{"keySpec": "AES_256", "keyUsage": []string{"ENCRYPT", "DECRYPT"}, "keyStatus": status}, "", "")
	case "encrypt", "decrypt":
		if req.EncryptionAlgorithm != "AES_GCM" {
			xksError(c, http.StatusBadRequest, "ValidationException", "encryptionAlgorithm must be AES_GCM")
			return
		}
		if !enabled {
			xksError(c, http.StatusBadRequest, "InvalidStateException", "the mapped key is not enabled")
			return
		}
		if op == "encrypt" {
			h.xksEncrypt(c, cfg.TenantID, keyID, extractInt(key["current_version"]), identity, req)
		} else {
			h.xksDecrypt(c, cfg.TenantID, keyID, identity, req)
		}
	default:
		xksError(c, http.StatusNotFound, "InvalidUriPathException", "not an XKS proxy API path")
	}
}

func (h *Handler) xksHealth(c *route.Call, tenantID string, meta AWSXKSMetadata) {
	// A deep check: keycore must answer for a mapped key.
	status := "ACTIVE"
	for _, keyID := range meta.Keys {
		if _, err := h.svc.keycore.GetKey(c.R.Context(), tenantID, keyID); err != nil {
			status = "UNAVAILABLE"
		}
		break
	}
	h.svc.azure.note("xks:" + tenantID)
	c.Protocol(http.StatusOK, map[string]interface{}{
		"xksProxyFleetSize": 1,
		"xksProxyVendor":    "Vecta",
		"xksProxyModel":     "Vecta KMS HYOK " + h.version,
		"ekmVendor":         "Vecta",
		"ekmFleetDetails":   []map[string]string{{"id": "vecta-kms", "model": "Vecta KMS " + h.version, "healthStatus": status}},
	}, "", "")
}

// xksFault maps a HYOK refusal to the XKS error.
func xksFault(c *route.Call, op string, err error) {
	var svcErr serviceError
	if !errors.As(err, &svcErr) {
		xksError(c, http.StatusInternalServerError, "InternalException", "internal error")
		return
	}
	switch s := svcErr.HTTPStatus; {
	case s == http.StatusTooManyRequests:
		xksError(c, s, "ThrottlingException", svcErr.Message)
	case s == http.StatusNotFound:
		xksError(c, s, "KeyNotFoundException", svcErr.Message)
	case s == http.StatusBadRequest && op == "decrypt":
		xksError(c, s, "InvalidCiphertextException", "the ciphertext does not decrypt with this key")
	case s == http.StatusBadRequest:
		xksError(c, s, "ValidationException", svcErr.Message)
	case s >= 400 && s < 500 && s != http.StatusFailedDependency:
		xksError(c, http.StatusForbidden, "AccessDeniedException", svcErr.Message)
	case s == http.StatusFailedDependency || s == http.StatusBadGateway:
		xksError(c, http.StatusServiceUnavailable, "DependencyTimeoutException", "a service the key depends on did not answer")
	default:
		xksError(c, http.StatusInternalServerError, "InternalException", "internal error")
	}
}

func (h *Handler) xksEncrypt(c *route.Call, tenantID, keyID string, version int, identity AuthIdentity, req xksRequest) {
	plain, err1 := b64(req.Plaintext)
	aad, err2 := b64(req.AAD)
	if err1 != nil || err2 != nil || len(plain) == 0 || len(plain) > xksMaxPlain || len(aad) > xksMaxAAD {
		xksError(c, http.StatusBadRequest, "ValidationException", "plaintext (1 to 4300 bytes) and additionalAuthenticatedData (up to 8192) must be base64")
		return
	}
	defer pkgcrypto.Zeroize(plain)
	if req.CDIVAlgorithm != "" && req.CDIVAlgorithm != "SHA_256" {
		xksError(c, http.StatusBadRequest, "ValidationException", "ciphertextDataIntegrityValueAlgorithm must be SHA_256")
		return
	}
	if version <= 0 {
		xksError(c, http.StatusInternalServerError, "InternalException", "the key has no current version")
		return
	}
	meta := xksMeta(version)
	out, err := h.svc.ProcessCrypto(c.R.Context(), tenantID, ProtocolAWSXKS, "encrypt", keyID, c.R.URL.Path, identity, ProxyCryptoRequest{
		PlaintextB64: base64.StdEncoding.EncodeToString(plain), AADB64: base64.StdEncoding.EncodeToString(xksAAD(aad, meta)),
		ReferenceID: req.RequestMetadata.KMSRequestID, RequesterID: identity.Subject,
	})
	if err != nil {
		xksFault(c, "encrypt", err)
		return
	}
	if out.Status == "pending_approval" {
		xksError(c, http.StatusForbidden, "AccessDeniedException", "the key's access rules hold this call for approval, which AWS KMS can't wait for")
		return
	}
	if out.Version != version {
		// The key rotated between reading it and encrypting: the metadata
		// would name the wrong version. AWS retries.
		xksError(c, http.StatusServiceUnavailable, "DependencyTimeoutException", "the key rotated during the call")
		return
	}
	blob, err1 := base64.StdEncoding.DecodeString(out.CiphertextB64)
	iv, err2 := base64.StdEncoding.DecodeString(out.IVB64)
	if err1 != nil || err2 != nil || len(blob) != len(plain)+16 || len(iv) != 12 {
		xksError(c, http.StatusInternalServerError, "InternalException", "keycore returned an unexpected AES-GCM output")
		return
	}
	ct, tag := blob[:len(plain)], blob[len(plain):]
	resp := map[string]interface{}{
		"ciphertext":           base64.StdEncoding.EncodeToString(ct),
		"ciphertextMetadata":   base64.StdEncoding.EncodeToString(meta),
		"initializationVector": base64.StdEncoding.EncodeToString(iv),
		"authenticationTag":    base64.StdEncoding.EncodeToString(tag),
	}
	if req.CDIVAlgorithm == "SHA_256" {
		// Appendix C: compute the value, then prove the output decrypts.
		cdiv := xksCDIV(aad, meta, iv, ct, tag)
		back, err := h.svc.keycore.DecryptAAD(c.R.Context(), tenantID, keyID, out.CiphertextB64, out.IVB64, base64.StdEncoding.EncodeToString(xksAAD(aad, meta)), version)
		got, _ := base64.StdEncoding.DecodeString(firstString(back["plaintext"]))
		if err != nil || subtle.ConstantTimeCompare(got, plain) != 1 {
			pkgcrypto.Zeroize(got)
			xksError(c, http.StatusInternalServerError, "InternalException", "the encrypt output did not decrypt; nothing was returned")
			return
		}
		pkgcrypto.Zeroize(got)
		resp["ciphertextDataIntegrityValue"] = base64.StdEncoding.EncodeToString(cdiv)
	}
	c.Protocol(http.StatusOK, resp, "", "")
}

func (h *Handler) xksDecrypt(c *route.Call, tenantID, keyID string, identity AuthIdentity, req xksRequest) {
	ct, e1 := b64(req.Ciphertext)
	meta, e2 := b64(req.CiphertextMetadata)
	aad, e3 := b64(req.AAD)
	iv, e4 := b64(req.IV)
	tag, e5 := b64(req.AuthenticationTag)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || len(tag) != 16 || len(aad) > xksMaxAAD {
		xksError(c, http.StatusBadRequest, "ValidationException", "fields must be base64; authenticationTag is 16 bytes")
		return
	}
	version, ok := xksMetaVersion(meta)
	if !ok || len(iv) != 12 {
		xksError(c, http.StatusBadRequest, "InvalidCiphertextException", "this ciphertext was not produced by this key store")
		return
	}
	out, err := h.svc.ProcessCrypto(c.R.Context(), tenantID, ProtocolAWSXKS, "decrypt", keyID, c.R.URL.Path, identity, ProxyCryptoRequest{
		CiphertextB64: base64.StdEncoding.EncodeToString(append(append([]byte{}, ct...), tag...)), IVB64: base64.StdEncoding.EncodeToString(iv),
		AADB64: base64.StdEncoding.EncodeToString(xksAAD(aad, meta)), Version: version,
		ReferenceID: req.RequestMetadata.KMSRequestID, RequesterID: identity.Subject,
	})
	if err != nil {
		xksFault(c, "decrypt", err)
		return
	}
	if out.Status == "pending_approval" {
		xksError(c, http.StatusForbidden, "AccessDeniedException", "the key's access rules hold this call for approval, which AWS KMS can't wait for")
		return
	}
	c.Protocol(http.StatusOK, map[string]interface{}{"plaintext": out.PlaintextB64}, "", "")
}

// credentialUsage names the XKS and OCI endpoints using each credential,
// for the credential store's "used by" and its delete guard. Only
// compliance asks.
func (h *Handler) credentialUsage(c *route.Call) {
	if !tenantcheck.IsServicePrincipal(c.Claims) || c.Claims.ClientID != "kms-compliance" {
		c.Refuse(http.StatusForbidden, "caller_not_allowed", "only the credential store may call this")
		return
	}
	items := []map[string]string{}
	for _, protocol := range []string{ProtocolAWSXKS, ProtocolOCIEKM} {
		cfg, err := h.svc.store.GetEndpoint(c.R.Context(), c.Tenant, protocol)
		if errors.Is(err, errNotFound) {
			continue
		}
		if err != nil {
			c.Error(http.StatusInternalServerError, "internal_error", "endpoint lookup failed")
			return
		}
		if meta, err := parseAWSXKSMetadata(cfg.MetadataJSON); protocol == ProtocolAWSXKS && err == nil {
			for _, id := range meta.CredentialIDs {
				items = append(items, map[string]string{"connection_id": id, "label": "AWS XKS endpoint " + meta.PathPrefix})
			}
		}
		if meta, err := parseOCIEKMMetadata(cfg.MetadataJSON); protocol == ProtocolOCIEKM && err == nil && meta.JWKSCredentialID != "" {
			items = append(items, map[string]string{"connection_id": meta.JWKSCredentialID, "label": "OCI External KMS endpoint " + meta.PathPrefix})
		}
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

// kernelRoutes are the hyok routes on the route kernel.
func (h *Handler) kernelRoutes(rt *route.Router) {
	rt.Handle("POST /xks/{rest...}", route.Spec{Action: "xks_request", Public: true, Tenancy: route.PlatformScoped, Resource: "key", OpaqueBody: true}, h.handleXKS)
	rt.Handle("GET /oci/{rest...}", route.Spec{Action: "oci_ekm_request", Public: true, Tenancy: route.PlatformScoped, Resource: "key"}, h.handleOCI)
	rt.Handle("POST /oci/{rest...}", route.Spec{Action: "oci_ekm_request", Public: true, Tenancy: route.PlatformScoped, Resource: "key", OpaqueBody: true}, h.handleOCI)
	rt.Handle("GET /hyok/credential-usage", route.Spec{Action: "credential_usage_read", Permission: route.Authenticated, Resource: "credential"}, h.credentialUsage)
}

// kernelAuth puts a verified Vecta bearer token's claims in the context for
// the kernel. Any other Authorization (an XKS SigV4 header) is left for the
// route that verifies it, as is the OCI identity domain token on /oci/.
func (h *Handler) kernelAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authz := strings.TrimSpace(r.Header.Get("Authorization"))
		ctx := r.Context()
		if strings.HasPrefix(strings.ToLower(authz), "bearer ") && !strings.HasPrefix(r.URL.Path, "/oci/") {
			if claims, err := h.jwtParser(strings.TrimSpace(authz[7:])); err == nil && claims != nil {
				ctx = pkgauth.ContextWithClaims(ctx, claims)
			} else {
				ctx = route.WithInvalidToken(ctx)
			}
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
