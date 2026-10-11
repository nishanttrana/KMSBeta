// Package hsmconnector is the hsm-connector service's core: it loads a
// tenant's PKCS#11 library and performs key operations in the HSM
// (docs/SECURITY/HSM_INTEGRATION.md). services/hsm-connector boots it; it
// needs cgo. Tests of other packages start it against SoftHSM2 through
// pkg/hsmconnector/softhsmtest.
package hsmconnector

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/miekg/pkcs11"

	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/hsm"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/tenantcheck"
)

// Handler serves the connector API. Every route goes through the kernel
// (authenticated, tenant-checked, audited as audit.hsm.<action>). Crypto
// routes also require one of the platform identities that use the HSM;
// status is open to the tenant's own administrators.
type Handler struct {
	router  *route.Router
	configs ConfigSource
	// connections resolves an HSM credential named by ?connection_id=; nil
	// refuses such requests (connections.go).
	connections ConnectionSource
	p11         *Provider
}

// SetConnections wires the HSM credential store.
func (h *Handler) SetConnections(src ConnectionSource) { h.connections = src }

// config is the session configuration for the request: the HSM credential
// it names, or else the tenant's profile.
func (h *Handler) config(c *route.Call) (TenantConfig, error) {
	id := strings.TrimSpace(c.R.URL.Query().Get("connection_id"))
	if id == "" {
		return h.configs.Load(c.R.Context(), c.Tenant)
	}
	c.Detail("connection_id", id)
	if h.connections == nil {
		return TenantConfig{}, errConnectionsUnavailable
	}
	return h.connections.LoadConnection(c.R.Context(), c.Tenant, id)
}

// Only these services may use keys: keycore (tenant keys and HSM-resident
// keys) and governance (backup keys under the tenant key).
var (
	keyUsers   = []string{"kms-keycore", "kms-governance"}
	keyManager = []string{"kms-keycore"}
)

func NewHandler(configs ConfigSource, p11 *Provider, audit route.Emitter, logger *log.Logger) *Handler {
	h := &Handler{router: route.New("hsm", audit, logger), configs: configs, p11: p11}
	r := h.router
	r.Handle("POST /hsm/keys", route.Spec{Action: "key_generated", Permission: "hsm.key.create", Resource: "hsm_key"}, h.generate)
	r.Handle("POST /hsm/keys/wrap-for-import", route.Spec{Action: "key_wrapped_for_cloud", Permission: "hsm.key.use", Resource: "hsm_key", Severity: "warning"}, h.wrapForImport)
	r.Handle("POST /hsm/keys/import", route.Spec{Action: "key_imported", Permission: "hsm.key.create", Resource: "hsm_key", Severity: "warning"}, h.importKey)
	r.Handle("POST /hsm/tenant-key", route.Spec{Action: "tenant_key_ensured", Permission: "hsm.key.create", Resource: "hsm_key"}, h.tenantKey)
	r.Handle("POST /hsm/encrypt", route.Spec{Action: "encrypt", Permission: "hsm.key.use", Resource: "hsm_key"}, h.encrypt)
	r.Handle("POST /hsm/decrypt", route.Spec{Action: "decrypt", Permission: "hsm.key.use", Resource: "hsm_key"}, h.decrypt)
	r.Handle("POST /hsm/sign", route.Spec{Action: "sign", Permission: "hsm.key.use", Resource: "hsm_key"}, h.sign)
	r.Handle("POST /hsm/verify", route.Spec{Action: "verify", Permission: "hsm.key.use", Resource: "hsm_key"}, h.verify)
	r.Handle("POST /hsm/random", route.Spec{Action: "random_generated", Permission: "hsm.key.use", Resource: "hsm"}, h.random)
	r.Handle("POST /hsm/keys/destroy", route.Spec{Action: "key_destroyed", Permission: "hsm.key.delete", Resource: "hsm_key", Severity: "warning"}, h.destroy)
	r.Handle("POST /hsm/keys/inspect", route.Spec{Action: "key_inspected", Permission: "hsm.key.read", Resource: "hsm_key"}, h.inspect)
	r.Handle("GET /hsm/objects", route.Spec{Action: "objects_listed", Permission: "hsm.read", Resource: "hsm"}, h.objects)
	r.Handle("GET /hsm/status", route.Spec{Action: "status_read", Permission: "hsm.read", Resource: "hsm"}, h.status)
	r.Handle("GET /healthz", route.Spec{Action: "health", Public: true, Tenancy: route.PlatformScoped}, func(c *route.Call) {
		c.JSON(http.StatusOK, map[string]interface{}{"status": "ok"})
	})
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.router.ServeHTTP(w, r) }

// Router exposes the kernel router (routetest).
func (h *Handler) Router() *route.Router { return h.router }

// callerIs admits only the named platform service identities.
func callerIs(c *route.Call, ids []string) bool {
	if tenantcheck.IsServicePrincipal(c.Claims) {
		for _, id := range ids {
			if strings.TrimSpace(c.Claims.ClientID) == id {
				return true
			}
		}
	}
	c.Refuse(http.StatusForbidden, "caller_not_allowed", "only "+strings.Join(ids, ", ")+" may use HSM keys")
	return false
}

type opRequest struct {
	TenantID      string `json:"tenant_id"`
	Label         string `json:"label"`
	Algorithm     string `json:"algorithm"`
	Hash          string `json:"hash"`
	PlaintextB64  string `json:"plaintext_b64"`
	CiphertextB64 string `json:"ciphertext_b64"`
	IVB64         string `json:"iv_b64"`
	AADB64        string `json:"aad_b64"`
	DigestB64     string `json:"digest_b64"`
	SignatureB64  string `json:"signature_b64"`
	Length        int    `json:"length"`
	MaterialB64   string `json:"material_b64"`
	// ImportMethod: for AES material, create_object or unwrap to use only
	// that way of placing it; empty tries the first, then the second.
	ImportMethod string `json:"import_method"`
	// Extractable: generate a key that can be wrapped for a cloud import
	// (BYOK). It stays sensitive: its value can leave only wrapped.
	Extractable bool `json:"extractable"`
	// WrappingKeyB64 (a cloud's RSA import key, DER), Scheme (a pkg/crypto
	// cloud wrapping scheme) and Digest ("sha256" or empty) are for
	// wrap-for-import (byok.go).
	WrappingKeyB64 string `json:"wrapping_key_b64"`
	Scheme         string `json:"scheme"`
	Digest         string `json:"digest"`
}

// begin decodes the request, checks the caller and label, and opens a
// session on the tenant's HSM. It writes the response on any failure.
func (h *Handler) begin(c *route.Call, ids []string, needLabel bool) (*opRequest, *pkcs11.Ctx, pkcs11.SessionHandle, func(), bool) {
	if !callerIs(c, ids) {
		return nil, nil, 0, nil, false
	}
	var in opRequest
	if !c.Decode(&in) {
		return nil, nil, 0, nil, false
	}
	if needLabel {
		c.Target(in.Label)
		if err := hsm.CheckLabel(c.Tenant, in.Label); err != nil {
			c.Detail("label", in.Label)
			c.Refuse(http.StatusForbidden, "foreign_label", err.Error())
			return nil, nil, 0, nil, false
		}
	}
	ctx, sh, release, ok := h.open(c)
	return &in, ctx, sh, release, ok
}

func (h *Handler) open(c *route.Call) (*pkcs11.Ctx, pkcs11.SessionHandle, func(), bool) {
	cfg, err := h.config(c)
	if err != nil {
		h.fail(c, err)
		return nil, 0, nil, false
	}
	c.Detail("provider", cfg.Provider)
	ctx, sh, release, err := h.p11.session(cfg)
	if err != nil {
		h.fail(c, err)
		return nil, 0, nil, false
	}
	return ctx, sh, release, true
}

// fail maps an error to its response; refusals are audited as such.
func (h *Handler) fail(c *route.Call, err error) {
	switch {
	case errors.Is(err, ErrNotConfigured):
		c.Refuse(http.StatusConflict, "hsm_not_configured", err.Error())
	case errors.Is(err, errLibraryRefused):
		c.Refuse(http.StatusConflict, "library_not_allowed", err.Error())
	case errors.Is(err, errPINMissing):
		c.Refuse(http.StatusConflict, "pin_not_provided", err.Error())
	case errors.Is(err, ErrConnectionNotFound):
		c.Refuse(http.StatusConflict, "hsm_connection_not_found", err.Error())
	case errors.Is(err, errPINMismatch):
		c.Refuse(http.StatusConflict, "pin_mismatch", err.Error())
	case errors.Is(err, errConnectionsUnavailable):
		c.Error(http.StatusServiceUnavailable, "hsm_connections_unavailable", err.Error())
	case errors.Is(err, errImportRefused):
		c.Refuse(http.StatusConflict, "hsm_import_refused", err.Error())
	case errors.Is(err, hsm.ErrNotFound):
		c.Error(http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, errExists):
		c.Error(http.StatusConflict, "exists", err.Error())
	case errors.Is(err, errAuthFailed):
		c.Refuse(http.StatusUnprocessableEntity, "integrity_check_failed", err.Error())
	default:
		c.Error(http.StatusBadGateway, "hsm_error", err.Error())
	}
}

func decode(c *route.Call, field, v string) ([]byte, bool) {
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		c.Error(http.StatusBadRequest, "bad_request", field+" must be base64")
		return nil, false
	}
	return b, true
}

func (h *Handler) generate(c *route.Call) {
	in, ctx, sh, release, ok := h.begin(c, keyManager, true)
	if !ok {
		return
	}
	defer release()
	alg := hsm.NormalizeAlgorithm(in.Algorithm)
	c.Detail("algorithm", alg)
	if alg == "" {
		c.Refuse(http.StatusBadRequest, "algorithm_not_supported", "algorithm "+in.Algorithm+" can't be HSM-resident")
		return
	}
	c.Detail("extractable", in.Extractable)
	res, err := generate(ctx, sh, in.Label, alg, in.Extractable)
	if err != nil {
		h.fail(c, err)
		return
	}
	id := h.identity(c)
	c.Detail("hsm_serial", id.SerialNumber)
	c.Detail("hsm_token", id.TokenLabel)
	c.JSON(http.StatusCreated, map[string]interface{}{
		"label": res.Label, "public_key_b64": base64.StdEncoding.EncodeToString(res.PublicKey),
		"kcv_b64": base64.StdEncoding.EncodeToString(res.KCV), "hsm": id,
	})
}

// importKey places existing key material in the HSM as a sensitive, never
// extractable token object: AES material, or an RSA or ECDSA private key
// (PKCS#8, PKCS#1 or SEC 1 DER). The HSM reports it honestly afterwards:
// CKA_LOCAL is false, because it was not generated there.
func (h *Handler) importKey(c *route.Call) {
	in, ctx, sh, release, ok := h.begin(c, keyManager, true)
	if !ok {
		return
	}
	defer release()
	alg := hsm.NormalizeAlgorithm(in.Algorithm)
	c.Detail("algorithm", alg)
	if alg == "" {
		c.Refuse(http.StatusBadRequest, "algorithm_not_supported", "AES-128/192/256 material and RSA-2048/3072/4096 or ECDSA P-256/P-384 private keys can be imported into the HSM")
		return
	}
	material, ok := decode(c, "material_b64", in.MaterialB64)
	if !ok {
		return
	}
	defer pkgcrypto.Zeroize(material)
	var (
		res    hsm.GenerateResult
		method = importCreateObject
		err    error
	)
	if strings.HasPrefix(alg, "AES-") {
		if want := map[string]int{"AES-128": 16, "AES-192": 24, "AES-256": 32}[alg]; len(material) != want {
			c.Error(http.StatusBadRequest, "bad_request", fmt.Sprintf("%s material must be %d bytes", alg, want))
			return
		}
		if in.ImportMethod != "" && in.ImportMethod != importCreateObject && in.ImportMethod != importUnwrap {
			c.Error(http.StatusBadRequest, "bad_request", "import_method is create_object or unwrap")
			return
		}
		res, method, err = importAES(ctx, sh, in.Label, material, in.ImportMethod)
	} else {
		key, perr := pkgcrypto.HSMPrivateKeyFromDER(material)
		if perr != nil {
			c.Error(http.StatusBadRequest, "bad_request", perr.Error())
			return
		}
		defer key.Zeroize()
		if key.Algorithm != alg {
			c.Error(http.StatusBadRequest, "bad_request", fmt.Sprintf("the material is a %s key, not %s", key.Algorithm, alg))
			return
		}
		res, err = importPrivate(ctx, sh, in.Label, key)
	}
	if err != nil {
		h.fail(c, err)
		return
	}
	id := h.identity(c)
	c.Detail("hsm_serial", id.SerialNumber)
	c.Detail("hsm_token", id.TokenLabel)
	c.Detail("import_method", method)
	c.JSON(http.StatusCreated, map[string]interface{}{
		"label": res.Label, "kcv_b64": base64.StdEncoding.EncodeToString(res.KCV),
		"public_key_b64": base64.StdEncoding.EncodeToString(res.PublicKey), "import_method": method, "hsm": id,
	})
}

func (h *Handler) tenantKey(c *route.Call) {
	if c.R.URL.Query().Get("connection_id") != "" {
		// The tenant key is the KMS's root of trust: it lives on the
		// tenant's HSM profile (HSM tab), never on a key-holding credential.
		c.Refuse(http.StatusConflict, "root_of_trust_is_the_profile", "the tenant key is created on the tenant's HSM profile, not on an HSM credential")
		return
	}
	_, ctx, sh, release, ok := h.begin(c, keyUsers, false)
	if !ok {
		return
	}
	defer release()
	label := hsm.TenantKeyLabel(c.Tenant)
	c.Target(label)
	created := false
	if _, err := findOne(ctx, sh, pkcs11.CKO_SECRET_KEY, label); errors.Is(err, hsm.ErrNotFound) {
		if _, err := generate(ctx, sh, label, "AES-256", false); err != nil {
			h.fail(c, err)
			return
		}
		created = true
	} else if err != nil {
		h.fail(c, err)
		return
	}
	c.Detail("created", created)
	c.JSON(http.StatusOK, map[string]interface{}{"label": label, "created": created})
}

func (h *Handler) encrypt(c *route.Call) {
	in, ctx, sh, release, ok := h.begin(c, keyUsers, true)
	if !ok {
		return
	}
	defer release()
	pt, ok1 := decode(c, "plaintext_b64", in.PlaintextB64)
	aad, ok2 := decode(c, "aad_b64", in.AADB64)
	if !ok1 || !ok2 {
		return
	}
	iv, ct, err := encrypt(ctx, sh, in.Label, pt, aad)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.Detail("mechanism", "CKM_AES_GCM")
	c.JSON(http.StatusOK, map[string]interface{}{
		"iv_b64": base64.StdEncoding.EncodeToString(iv), "ciphertext_b64": base64.StdEncoding.EncodeToString(ct),
	})
}

func (h *Handler) decrypt(c *route.Call) {
	in, ctx, sh, release, ok := h.begin(c, keyUsers, true)
	if !ok {
		return
	}
	defer release()
	iv, ok1 := decode(c, "iv_b64", in.IVB64)
	ct, ok2 := decode(c, "ciphertext_b64", in.CiphertextB64)
	aad, ok3 := decode(c, "aad_b64", in.AADB64)
	if !ok1 || !ok2 || !ok3 {
		return
	}
	pt, err := decrypt(ctx, sh, in.Label, iv, ct, aad)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.Detail("mechanism", "CKM_AES_GCM")
	c.JSON(http.StatusOK, map[string]interface{}{"plaintext_b64": base64.StdEncoding.EncodeToString(pt)})
}

func (h *Handler) sign(c *route.Call) {
	in, ctx, sh, release, ok := h.begin(c, keyManager, true)
	if !ok {
		return
	}
	defer release()
	digest, ok := decode(c, "digest_b64", in.DigestB64)
	if !ok {
		return
	}
	c.Detail("hash", in.Hash)
	sig, err := sign(ctx, sh, in.Label, in.Hash, digest)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"signature_b64": base64.StdEncoding.EncodeToString(sig)})
}

func (h *Handler) verify(c *route.Call) {
	in, ctx, sh, release, ok := h.begin(c, keyManager, true)
	if !ok {
		return
	}
	defer release()
	digest, ok1 := decode(c, "digest_b64", in.DigestB64)
	sig, ok2 := decode(c, "signature_b64", in.SignatureB64)
	if !ok1 || !ok2 {
		return
	}
	valid, err := verify(ctx, sh, in.Label, in.Hash, digest, sig)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.Detail("verified", valid)
	c.JSON(http.StatusOK, map[string]interface{}{"verified": valid})
}

func (h *Handler) destroy(c *route.Call) {
	in, ctx, sh, release, ok := h.begin(c, keyManager, true)
	if !ok {
		return
	}
	defer release()
	if in.Label == hsm.TenantKeyLabel(c.Tenant) {
		// Destroying the tenant key would make every key version it wraps
		// unreadable: that is a tenant crypto-shred, not a key operation.
		c.Refuse(http.StatusConflict, "tenant_key_protected", "the tenant key can't be destroyed through the key API")
		return
	}
	n, err := destroy(ctx, sh, in.Label)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.Detail("objects_destroyed", n)
	c.JSON(http.StatusOK, map[string]interface{}{"destroyed": n})
}

// identity names the token the tenant's profile points at.
func (h *Handler) identity(c *route.Call) hsm.Identity {
	cfg, err := h.config(c)
	if err != nil {
		return hsm.Identity{}
	}
	return h.p11.identity(cfg)
}

// inspect reads a key's attributes back from the HSM: proof it was
// generated there (CKA_LOCAL), is sensitive and was never extractable.
func (h *Handler) inspect(c *route.Call) {
	in, ctx, sh, release, ok := h.begin(c, keyManager, true)
	if !ok {
		return
	}
	defer release()
	objs, err := inspect(ctx, sh, in.Label)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.Detail("objects", len(objs))
	c.JSON(http.StatusOK, map[string]interface{}{"objects": objs, "hsm": h.identity(c)})
}

// objects lists the keys and certificates in the tenant's partition.
func (h *Handler) objects(c *route.Call) {
	if !callerIs(c, keyManager) {
		return
	}
	ctx, sh, release, ok := h.open(c)
	if !ok {
		return
	}
	defer release()
	objs, truncated, err := listObjects(ctx, sh, c.Tenant)
	if err != nil {
		h.fail(c, err)
		return
	}
	managed := 0
	for _, o := range objs {
		if o.Managed {
			managed++
		}
	}
	c.Detail("objects", len(objs))
	c.Detail("managed", managed)
	c.JSON(http.StatusOK, map[string]interface{}{"objects": objs, "truncated": truncated, "hsm": h.identity(c)})
}

// maxRandomBytes bounds one C_GenerateRandom draw.
const maxRandomBytes = 4096

// random draws bytes from the tenant HSM's generator (C_GenerateRandom).
func (h *Handler) random(c *route.Call) {
	in, ctx, sh, release, ok := h.begin(c, keyUsers, false)
	if !ok {
		return
	}
	defer release()
	c.Detail("length", in.Length)
	if in.Length <= 0 || in.Length > maxRandomBytes {
		c.Error(http.StatusBadRequest, "bad_request", "length must be 1..4096")
		return
	}
	out, err := ctx.GenerateRandom(sh, in.Length)
	if err != nil {
		h.fail(c, fmt.Errorf("C_GenerateRandom: %w", err))
		return
	}
	id := h.identity(c)
	c.Detail("hsm_serial", id.SerialNumber)
	c.JSON(http.StatusOK, map[string]interface{}{"bytes_b64": base64.StdEncoding.EncodeToString(out), "hsm": id})
}

func (h *Handler) status(c *route.Call) {
	cfg, err := h.config(c)
	if errors.Is(err, ErrNotConfigured) {
		c.JSON(http.StatusOK, map[string]interface{}{"status": hsm.Status{}})
		return
	}
	if err != nil {
		c.JSON(http.StatusOK, map[string]interface{}{"status": hsm.Status{Configured: true, Error: err.Error()}})
		return
	}
	st, err := h.p11.status(cfg)
	if err != nil {
		st.Error = err.Error()
	}
	c.Detail("connected", st.Connected)
	c.JSON(http.StatusOK, map[string]interface{}{"status": st})
}
