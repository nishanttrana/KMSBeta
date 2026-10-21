package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/credstore"
	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/oidc"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/ssrfguard"
)

// OCI External Key Management (External KMS vendor API v1). An OCI vault of
// type "external" calls the KMS to encrypt and decrypt with an AES key that
// stays here (HYOK). Calls come through the HTTPS edge at
// <edge>/svc/hyok/oci/<path prefix>/ekm/v1/vaults/{vaultId}/... and carry an
// OAuth2 access token from the customer's OCI identity domain (client
// credentials, scope oci_ekms). The token is verified against the domain's
// JWKS: issuer, audience (the resource app's primary audience), expiry,
// scope and an allow-list of client IDs. If the domain's signing keys are
// not public, an oci_identity_domain credential from Playbooks →
// Credentials fetches them. keyVersionId is the Vecta key version number;
// the AAD given to keycore is "oci-ekm/v1" || u16 len(aad) || aad, so
// decrypt always names the version and OCI ciphertext can't be replayed
// through another HYOK protocol. (docs/CLOUD_INTEGRATION.md, "OCI External
// KMS".)

const (
	ociAPIPrefix     = "/ekm/v1/"
	ociScope         = "oci_ekms"
	ociDefaultIssuer = "https://identity.oraclecloud.com/"
	ociMaxPlain      = 4096
	ociMaxAADChars   = 4096
	ociMaxClients    = 10
	ociVendor        = "Vecta KMS"
	// ociJWKSScope is the identity domain scope a confidential app's token
	// needs to read the domain's signing certificate.
	ociJWKSScope = "urn:opc:idm:__myscopes__"
)

var (
	ociVaultIDRe  = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,255}$`)
	ociClientIDRe = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	ociAADDomain  = []byte("oci-ekm/v1")
	// newOCIVerifier builds the JWKS verifier for one endpoint; tests
	// replace it to reach an identity domain double.
	newOCIVerifier = func() *oidc.Verifier {
		return &oidc.Verifier{HTTP: ssrfguard.NewHTTPSClient(10 * time.Second), CheckURL: ssrfguard.ValidateWebhookURL}
	}
)

// OCIEKMMetadata is the oci_ekm endpoint's metadata_json. issuer and
// jwks_url are copied from <identity domain>/.well-known/idcs-configuration.
type OCIEKMMetadata struct {
	PathPrefix       string            `json:"path_prefix"`
	VaultID          string            `json:"vault_id"`
	Issuer           string            `json:"issuer"`
	JWKSURL          string            `json:"jwks_url"`
	Audience         string            `json:"audience"`
	ClientIDs        []string          `json:"client_ids"`
	JWKSCredentialID string            `json:"jwks_credential_id,omitempty"`
	Keys             map[string]string `json:"keys"`
}

func parseOCIEKMMetadata(raw string) (OCIEKMMetadata, error) {
	var m OCIEKMMetadata
	d := json.NewDecoder(strings.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&m); err != nil {
		return m, fmt.Errorf("metadata: %w", err)
	}
	m.PathPrefix = strings.Trim(strings.TrimSpace(m.PathPrefix), "/")
	if len(m.PathPrefix) > 64 || !xksPrefixRe.MatchString(m.PathPrefix) {
		return m, errors.New("path_prefix is required: up to 64 letters, digits, hyphens, underscores and slashes")
	}
	m.VaultID = strings.TrimSpace(m.VaultID)
	if !ociVaultIDRe.MatchString(m.VaultID) {
		return m, errors.New("vault_id is required: up to 255 letters, digits, '.', ':', '-' and '_'")
	}
	m.Issuer = strings.TrimSpace(m.Issuer)
	if m.Issuer == "" {
		m.Issuer = ociDefaultIssuer
	}
	if u, err := url.Parse(m.Issuer); err != nil || u.Scheme != "https" || u.Host == "" {
		return m, errors.New("issuer must be an https URL")
	}
	m.JWKSURL = strings.TrimSpace(m.JWKSURL)
	if u, err := url.Parse(m.JWKSURL); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return m, errors.New("jwks_url must be the identity domain's https JWKS URL")
	}
	m.Audience = strings.TrimSpace(m.Audience)
	if m.Audience == "" {
		return m, errors.New("audience is required: the resource app's primary audience")
	}
	if n := len(m.ClientIDs); n == 0 || n > ociMaxClients {
		return m, fmt.Errorf("client_ids: one to %d confidential app client IDs", ociMaxClients)
	}
	seen := map[string]bool{}
	for i, id := range m.ClientIDs {
		id = strings.TrimSpace(id)
		if !ociClientIDRe.MatchString(id) || seen[id] {
			return m, fmt.Errorf("client_ids: %q is not a distinct client ID", id)
		}
		seen[id], m.ClientIDs[i] = true, id
	}
	m.JWKSCredentialID = strings.TrimSpace(m.JWKSCredentialID)
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

// ociKeyBytes is an AES key's length in bytes, or 0 for any other key.
func ociKeyBytes(algorithm string) int {
	switch strings.ToUpper(strings.TrimSpace(algorithm)) {
	case "AES-128", "AES-128-GCM":
		return 16
	case "AES-192", "AES-192-GCM":
		return 24
	case "AES-256", "AES-256-GCM":
		return 32
	}
	return 0
}

// validateOCIEKMEndpoint checks an oci_ekm endpoint before it is stored.
// Attaching a JWKS credential needs compliance.connection.use.
func (s *Service) validateOCIEKMEndpoint(ctx context.Context, cfg *EndpointConfig, claims *pkgauth.Claims) error {
	bad := func(code, msg string) error { return newServiceError(http.StatusBadRequest, code, msg) }
	cfg.AuthMode = AuthModeOCIJWT
	if cfg.GovernanceRequired {
		return bad("governance_unavailable", "OCI KMS waits seconds for an answer, so an External KMS call can't wait for an approval")
	}
	meta, err := parseOCIEKMMetadata(cfg.MetadataJSON)
	if err != nil {
		return bad("bad_metadata", err.Error())
	}
	if id := meta.JWKSCredentialID; id != "" {
		if !route.Allowed(claims, credstore.PermissionUse) {
			return newServiceError(http.StatusForbidden, "credential_use_not_permitted", "attaching a credential needs "+credstore.PermissionUse)
		}
		c, err := s.creds.Resolve(ctx, cfg.TenantID, id)
		if err != nil {
			return bad("credential_unavailable", fmt.Sprintf("credential %s: %v", id, err))
		}
		if c.Type != "oci_identity_domain" {
			return bad("credential_wrong_type", fmt.Sprintf("credential %s is %s, not oci_identity_domain", id, c.Type))
		}
	}
	others, err := s.store.ListEndpointsByProtocol(ctx, ProtocolOCIEKM)
	if err != nil {
		return err
	}
	for _, o := range others {
		if o.TenantID == cfg.TenantID {
			continue
		}
		if om, err := parseOCIEKMMetadata(o.MetadataJSON); err == nil && strings.EqualFold(om.PathPrefix, meta.PathPrefix) {
			return newServiceError(http.StatusConflict, "path_prefix_taken", "another tenant uses this path prefix")
		}
	}
	for name, keyID := range meta.Keys {
		key, err := s.keycore.GetKey(ctx, cfg.TenantID, keyID)
		if err != nil {
			return bad("key_unavailable", fmt.Sprintf("external key id %q: %v", name, err))
		}
		if ociKeyBytes(firstString(key["algorithm"])) == 0 {
			return bad("key_unsupported", fmt.Sprintf("external key id %q: OCI External KMS takes an AES key, not %s", name, firstString(key["algorithm"])))
		}
	}
	normalized, _ := json.Marshal(meta)
	cfg.MetadataJSON = string(normalized)
	return nil
}

// ociVerifiers keeps one JWKS verifier per endpoint so its key cache
// survives between calls; a changed setting builds a new one.
type ociVerifiers struct {
	mu   sync.Mutex
	byID map[string]ociVerifierEntry
}

type ociVerifierEntry struct {
	fingerprint string
	v           *oidc.Verifier
}

func (s *Service) ociVerifier(tenantID string, meta OCIEKMMetadata) *oidc.Verifier {
	raw, _ := json.Marshal(meta)
	sum := sha256.Sum256(raw)
	fp := hex.EncodeToString(sum[:])
	s.oci.mu.Lock()
	defer s.oci.mu.Unlock()
	if e, ok := s.oci.byID[tenantID]; ok && e.fingerprint == fp {
		return e.v
	}
	v := newOCIVerifier()
	if meta.JWKSCredentialID != "" {
		v.Authorize = (&ociJWKSToken{svc: s, tenantID: tenantID, credID: meta.JWKSCredentialID, jwksURL: meta.JWKSURL, client: v.HTTP, check: v.CheckURL}).authorize
	}
	if s.oci.byID == nil {
		s.oci.byID = map[string]ociVerifierEntry{}
	}
	s.oci.byID[tenantID] = ociVerifierEntry{fingerprint: fp, v: v}
	return v
}

// ociJWKSToken gets an access token for reading a protected JWKS with the
// identity domain app's client credentials, and reuses it until shortly
// before it expires.
type ociJWKSToken struct {
	svc              *Service
	tenantID, credID string
	jwksURL          string
	client           *http.Client
	check            func(string) error
	mu               sync.Mutex
	token            string
	until            time.Time
}

func (t *ociJWKSToken) authorize(ctx context.Context, req *http.Request) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.token == "" || time.Now().After(t.until) {
		if err := t.fetch(ctx); err != nil {
			return fmt.Errorf("identity domain token: %w", err)
		}
	}
	req.Header.Set("Authorization", "Bearer "+t.token)
	return nil
}

func (t *ociJWKSToken) fetch(ctx context.Context) error {
	c, err := t.svc.creds.Resolve(ctx, t.tenantID, t.credID)
	if err != nil {
		return err
	}
	if c.Type != "oci_identity_domain" {
		return fmt.Errorf("credential %s is not oci_identity_domain", t.credID)
	}
	u, err := url.Parse(t.jwksURL)
	if err != nil {
		return err
	}
	tokenURL := u.Scheme + "://" + u.Host + "/oauth2/v1/token"
	if t.check != nil {
		if err := t.check(tokenURL); err != nil {
			return err
		}
	}
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {ociJWKSScope}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(c.Fields["client_id"], c.Fields["client_secret"])
	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token endpoint answered %d", resp.StatusCode)
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out); err != nil || out.AccessToken == "" {
		return errors.New("token endpoint gave no access token")
	}
	life := time.Duration(out.ExpiresIn) * time.Second
	if life <= 2*time.Minute {
		life = 2 * time.Minute
	}
	t.token, t.until = out.AccessToken, time.Now().Add(life-time.Minute)
	return nil
}

func (s *Service) ociEndpointForPrefix(ctx context.Context, prefix string) (EndpointConfig, OCIEKMMetadata, error) {
	all, err := s.store.ListEnabledEndpointsByProtocol(ctx, ProtocolOCIEKM)
	if err != nil {
		return EndpointConfig{}, OCIEKMMetadata{}, err
	}
	for _, cfg := range all {
		if meta, err := parseOCIEKMMetadata(cfg.MetadataJSON); err == nil && strings.EqualFold(meta.PathPrefix, prefix) {
			return cfg, meta, nil
		}
	}
	return EndpointConfig{}, OCIEKMMetadata{}, errNotFound
}

// ociVerify checks the bearer token and returns the calling client ID.
func (s *Service) ociVerify(ctx context.Context, r *http.Request, tenantID string, meta OCIEKMMetadata) (string, error) {
	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(authz) < 8 || !strings.EqualFold(authz[:7], "bearer ") {
		return "", errors.New("no bearer token")
	}
	claims, err := s.ociVerifier(tenantID, meta).VerifyJWT(ctx, strings.TrimSpace(authz[7:]), meta.JWKSURL, meta.Issuer, meta.Audience, time.Now())
	if err != nil {
		return "", err
	}
	if !ociHasScope(claims, ociScope) {
		return "", errors.New("token lacks the oci_ekms scope")
	}
	clientID, _ := claims["client_id"].(string)
	for _, allowed := range meta.ClientIDs {
		if clientID != "" && clientID == allowed {
			return clientID, nil
		}
	}
	return "", fmt.Errorf("client %q is not allowed on this endpoint", clientID)
}

func ociHasScope(claims jwt.MapClaims, want string) bool {
	switch v := claims["scope"].(type) {
	case string:
		for _, s := range strings.Fields(v) {
			if s == want {
				return true
			}
		}
	case []interface{}:
		for _, s := range v {
			if s == want {
				return true
			}
		}
	}
	return false
}

// ociAAD is the AAD keycore authenticates for OCI: a domain label and the
// request's AAD with its length.
func ociAAD(aad []byte) []byte {
	out := append([]byte{}, ociAADDomain...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(aad)))
	return append(out, aad...)
}

// ociError answers in the External KMS shape ({"code": "<status>",
// "message"}) and records the event's outcome.
func ociError(c *route.Call, status int, reason, msg string) {
	result := route.ResultRefused
	if status >= 500 {
		result = route.ResultFailure
	}
	if len(msg) > 500 {
		msg = msg[:500]
	}
	c.Protocol(status, map[string]string{"code": strconv.Itoa(status), "message": msg}, result, reason)
}

type ociCryptoRequest struct {
	Plaintext    string `json:"plaintext"`
	Ciphertext   string `json:"ciphertext"`
	AAD          string `json:"aad"`
	IV           string `json:"iv"`
	Mode         string `json:"mode"`
	Pad          string `json:"pad"`
	Tag          string `json:"tag"`
	TagLen       int    `json:"tagLen"`
	KeyVersionID string `json:"keyVersionId"`
	Length       int    `json:"length"`
}

// handleOCI serves GET and POST /oci/{rest...}.
func (h *Handler) handleOCI(c *route.Call) {
	ctx := c.R.Context()
	reqID := strings.TrimSpace(c.R.Header.Get("opc-request-id"))
	if reqID == "" || len(reqID) > 98 {
		reqID = newID("ocireq")
	}
	c.W.Header().Set("opc-request-id", reqID)
	c.Detail("opc_request_id", reqID)
	body, err := io.ReadAll(io.LimitReader(c.R.Body, 64<<10))
	if err != nil {
		ociError(c, http.StatusBadRequest, "bad_request", "Bad Request: the body could not be read")
		return
	}
	rest := "/" + c.R.PathValue("rest")
	i := strings.Index(rest, ociAPIPrefix)
	if i < 0 {
		ociError(c, http.StatusNotFound, "not_found", "not an External KMS vendor API path")
		return
	}
	prefix, tail := strings.Trim(rest[:i], "/"), strings.Split(rest[i+len(ociAPIPrefix):], "/")
	cfg, meta, err := h.svc.ociEndpointForPrefix(ctx, prefix)
	if err != nil {
		ociError(c, http.StatusNotFound, "not_found", "no enabled OCI External KMS endpoint has this path prefix")
		return
	}
	c.Tenant = cfg.TenantID
	clientID, err := h.svc.ociVerify(ctx, c.R, cfg.TenantID, meta)
	if err != nil {
		c.Detail("reason_detail", err.Error())
		ociError(c, http.StatusUnauthorized, route.ReasonInvalidToken, "the access token does not verify")
		return
	}
	c.Authenticated(clientID, "oci_identity_domain_client")
	identity := AuthIdentity{Mode: AuthModeOCIJWT, Subject: "oci-ekm:" + clientID, TenantID: cfg.TenantID, RemoteIP: remoteHost(c.R)}
	if len(tail) < 2 || tail[0] != "vaults" || tail[1] != meta.VaultID {
		ociError(c, http.StatusNotFound, "vault_not_found", "Error in getting OCI vault")
		return
	}
	var req ociCryptoRequest
	if c.R.Method == http.MethodPost {
		if err := json.Unmarshal(body, &req); err != nil {
			ociError(c, http.StatusBadRequest, "bad_request", "Bad Request: the body is not JSON")
			return
		}
	}
	op := strings.Join(tail[2:], "/")
	switch {
	case c.R.Method == http.MethodGet && op == "metadata":
		c.Protocol(http.StatusOK, map[string]string{"state": "ACTIVE", "vendor": ociVendor}, "", "")
		return
	case c.R.Method == http.MethodPost && op == "generateRandomBytes":
		h.ociRandom(c, req)
		return
	}
	if len(tail) < 5 || tail[2] != "keys" {
		ociError(c, http.StatusNotFound, "not_found", "not an External KMS vendor API path")
		return
	}
	extID := tail[3]
	keyID, ok := meta.Keys[extID]
	if !ok {
		ociError(c, http.StatusNotFound, "key_not_found", "Invalid key details provided")
		return
	}
	c.Target(keyID)
	key, err := h.svc.keycore.GetKey(ctx, cfg.TenantID, keyID)
	if err != nil {
		ociError(c, http.StatusNotFound, "key_not_found", "Invalid key details provided")
		return
	}
	if !strings.EqualFold(firstString(key["status"]), "active") {
		ociError(c, http.StatusForbidden, "key_disabled", "OCI key is not in Active state to perform the operation.")
		return
	}
	current := extractInt(key["current_version"])
	switch keyOp := strings.Join(tail[4:], "/"); {
	case c.R.Method == http.MethodGet && keyOp == "metadata":
		c.Protocol(http.StatusOK, map[string]interface{}{
			"keyId": extID, "currentKeyVersionId": strconv.Itoa(current), "state": "ACTIVE",
			"keyShape": map[string]interface{}{"algorithm": "AES", "length": ociKeyBytes(firstString(key["algorithm"]))},
			"keyOps":   []string{"ENCRYPT", "DECRYPT"},
		}, "", "")
	case c.R.Method == http.MethodGet && len(tail) == 7 && tail[4] == "keyVersions" && tail[6] == "metadata":
		h.ociVersionMetadata(c, cfg.TenantID, keyID, extID, tail[5], current)
	case c.R.Method == http.MethodPost && keyOp == "encrypt":
		h.ociEncrypt(c, cfg.TenantID, keyID, extID, current, identity, req)
	case c.R.Method == http.MethodPost && keyOp == "decrypt":
		h.ociDecrypt(c, cfg.TenantID, keyID, extID, identity, req)
	default:
		ociError(c, http.StatusNotFound, "not_found", "not an External KMS vendor API path")
	}
}

func (h *Handler) ociVersionMetadata(c *route.Call, tenantID, keyID, extID, versionID string, current int) {
	n, err := strconv.Atoi(versionID)
	if err != nil || n < 1 || strconv.Itoa(n) != versionID {
		ociError(c, http.StatusNotFound, "version_not_found", "Invalid Key details")
		return
	}
	versions, err := h.svc.keycore.KeyVersions(c.R.Context(), tenantID, keyID)
	if err != nil {
		ociError(c, http.StatusServiceUnavailable, "keycore_unavailable", "the key's versions could not be read")
		return
	}
	for _, v := range versions {
		if extractInt(v["version"]) != n {
			continue
		}
		state, ops := "DISABLED", []string{}
		if strings.EqualFold(firstString(v["status"]), "active") {
			state, ops = "ACTIVE", []string{"DECRYPT"}
			if n == current {
				ops = []string{"ENCRYPT", "DECRYPT"}
			}
		}
		c.Protocol(http.StatusOK, map[string]interface{}{"keyId": extID, "keyVersionId": versionID, "state": state, "keyVersionOps": ops}, "", "")
		return
	}
	ociError(c, http.StatusNotFound, "version_not_found", "Invalid Key details")
}

// ociGCM checks the fields every AES-GCM call shares.
func ociGCM(c *route.Call, req ociCryptoRequest) ([]byte, bool) {
	if req.Mode != "" && req.Mode != "AES_GCM" {
		ociError(c, http.StatusBadRequest, "mode_unsupported", "Bad Request: mode must be AES_GCM")
		return nil, false
	}
	if req.Pad != "" && req.Pad != "NONE" && req.Pad != "PKCS7" {
		ociError(c, http.StatusBadRequest, "bad_request", "Bad Request: pad must be NONE or PKCS7")
		return nil, false
	}
	if len(req.AAD) >= ociMaxAADChars {
		ociError(c, http.StatusBadRequest, "bad_request", "Bad Request: aad must be fewer than 4096 characters")
		return nil, false
	}
	aad, err := b64(req.AAD)
	if err != nil {
		ociError(c, http.StatusBadRequest, "bad_request", "Bad Request: aad is not base64")
		return nil, false
	}
	return aad, true
}

// ociFault maps a HYOK refusal to the External KMS error.
func ociFault(c *route.Call, op string, err error) {
	var svcErr serviceError
	if !errors.As(err, &svcErr) {
		ociError(c, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}
	switch s := svcErr.HTTPStatus; {
	case s == http.StatusTooManyRequests:
		ociError(c, s, "throttled", svcErr.Message)
	case s == http.StatusNotFound:
		ociError(c, s, "key_not_found", "Invalid key details provided")
	case s == http.StatusBadRequest && op == "decrypt":
		ociError(c, s, "decrypt_failed", "Error in decryption: the ciphertext, IV, tag or AAD does not authenticate with this key version")
	case s == http.StatusBadRequest:
		ociError(c, s, "bad_request", "Bad Request: "+svcErr.Message)
	case s >= 400 && s < 500 && s != http.StatusFailedDependency:
		ociError(c, http.StatusForbidden, firstNonEmpty(svcErr.Code, "access_denied"), svcErr.Message)
	case s == http.StatusFailedDependency || s == http.StatusBadGateway:
		ociError(c, http.StatusServiceUnavailable, "dependency_unavailable", "a service the key depends on did not answer")
	default:
		ociError(c, http.StatusInternalServerError, "internal_error", "internal error")
	}
}

func (h *Handler) ociEncrypt(c *route.Call, tenantID, keyID, extID string, current int, identity AuthIdentity, req ociCryptoRequest) {
	aad, ok := ociGCM(c, req)
	if !ok {
		return
	}
	if req.TagLen != 0 && req.TagLen != 16 {
		ociError(c, http.StatusBadRequest, "bad_request", "Bad Request: tagLen must be 16")
		return
	}
	plain, err := b64(req.Plaintext)
	if err != nil || len(plain) == 0 || len(plain) > ociMaxPlain {
		pkgcrypto.Zeroize(plain)
		ociError(c, http.StatusBadRequest, "bad_request", "Bad Request: plaintext must be base64, 1 to 4096 bytes")
		return
	}
	defer pkgcrypto.Zeroize(plain)
	if current <= 0 {
		ociError(c, http.StatusInternalServerError, "internal_error", "the key has no current version")
		return
	}
	if req.KeyVersionID != "" && req.KeyVersionID != strconv.Itoa(current) {
		ociError(c, http.StatusBadRequest, "version_not_current", "Bad Request: only the current key version "+strconv.Itoa(current)+" encrypts")
		return
	}
	if req.IV != "" {
		// keycore draws every GCM nonce itself; the answer carries it.
		c.Detail("caller_iv_replaced", "true")
	}
	out, err := h.svc.ProcessCrypto(c.R.Context(), tenantID, ProtocolOCIEKM, "encrypt", keyID, c.R.URL.Path, identity, ProxyCryptoRequest{
		PlaintextB64: base64.StdEncoding.EncodeToString(plain), AADB64: base64.StdEncoding.EncodeToString(ociAAD(aad)),
		ReferenceID: c.W.Header().Get("opc-request-id"), RequesterID: identity.Subject,
	})
	if err != nil {
		ociFault(c, "encrypt", err)
		return
	}
	if out.Status == "pending_approval" {
		ociError(c, http.StatusForbidden, "approval_required", "the key's access rules hold this call for approval, which OCI KMS can't wait for")
		return
	}
	blob, err1 := base64.StdEncoding.DecodeString(out.CiphertextB64)
	iv, err2 := base64.StdEncoding.DecodeString(out.IVB64)
	if err1 != nil || err2 != nil || len(blob) != len(plain)+16 || len(iv) != 12 || out.Version <= 0 {
		ociError(c, http.StatusInternalServerError, "internal_error", "keycore returned an unexpected AES-GCM output")
		return
	}
	c.Protocol(http.StatusOK, map[string]interface{}{
		"ciphertext": base64.StdEncoding.EncodeToString(blob[:len(plain)]), "tag": base64.StdEncoding.EncodeToString(blob[len(plain):]),
		"iv": base64.StdEncoding.EncodeToString(iv), "aad": req.AAD, "keyId": extID, "keyVersionId": strconv.Itoa(out.Version),
		"mode": "AES_GCM", "pad": "NONE",
	}, "", "")
}

func (h *Handler) ociDecrypt(c *route.Call, tenantID, keyID, extID string, identity AuthIdentity, req ociCryptoRequest) {
	aad, ok := ociGCM(c, req)
	if !ok {
		return
	}
	ct, e1 := b64(req.Ciphertext)
	iv, e2 := b64(req.IV)
	tag, e3 := b64(req.Tag)
	if e1 != nil || e2 != nil || e3 != nil || len(ct) == 0 {
		ociError(c, http.StatusBadRequest, "bad_request", "Bad Request: ciphertext, iv and tag must be base64")
		return
	}
	version, err := strconv.Atoi(req.KeyVersionID)
	if err != nil || version < 1 {
		ociError(c, http.StatusBadRequest, "bad_request", "Bad Request: keyVersionId is required")
		return
	}
	if len(iv) != 12 || len(tag) != 16 {
		ociError(c, http.StatusBadRequest, "decrypt_failed", "Error in decryption: iv is 12 bytes and tag 16")
		return
	}
	out, err := h.svc.ProcessCrypto(c.R.Context(), tenantID, ProtocolOCIEKM, "decrypt", keyID, c.R.URL.Path, identity, ProxyCryptoRequest{
		CiphertextB64: base64.StdEncoding.EncodeToString(append(append([]byte{}, ct...), tag...)), IVB64: base64.StdEncoding.EncodeToString(iv),
		AADB64: base64.StdEncoding.EncodeToString(ociAAD(aad)), Version: version,
		ReferenceID: c.W.Header().Get("opc-request-id"), RequesterID: identity.Subject,
	})
	if err != nil {
		ociFault(c, "decrypt", err)
		return
	}
	if out.Status == "pending_approval" {
		ociError(c, http.StatusForbidden, "approval_required", "the key's access rules hold this call for approval, which OCI KMS can't wait for")
		return
	}
	c.Protocol(http.StatusOK, map[string]interface{}{
		"plaintext": out.PlaintextB64, "keyId": extID, "keyVersionId": req.KeyVersionID,
		"aad": req.AAD, "iv": req.IV, "tag": req.Tag, "mode": "AES_GCM", "pad": "NONE",
	}, "", "")
}

func (h *Handler) ociRandom(c *route.Call, req ociCryptoRequest) {
	if req.Length != 16 && req.Length != 24 && req.Length != 32 {
		ociError(c, http.StatusBadRequest, "bad_request", "Bad Request: length must be 16, 24 or 32")
		return
	}
	b, err := pkgcrypto.RandomBytes(req.Length)
	if err != nil {
		ociError(c, http.StatusInternalServerError, "internal_error", "the random source failed")
		return
	}
	defer pkgcrypto.Zeroize(b)
	c.Detail("length", strconv.Itoa(req.Length))
	c.Protocol(http.StatusCreated, map[string]interface{}{"randomBytes": base64.StdEncoding.EncodeToString(b), "length": req.Length}, "", "")
}
