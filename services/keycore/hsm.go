package main

import (
	"context"
	stdcrypto "crypto"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"vecta-kms/pkg/crypto"
	"vecta-kms/pkg/hsm"
	"vecta-kms/pkg/route"
)

// HSM integration (docs/SECURITY/HSM_INTEGRATION.md). keycore reaches the
// customer's HSM only through the hsm-connector (pkg/hsm), which loads the
// tenant's PKCS#11 library. Two per-tenant switches:
//
//   - tenant key: new key versions have their data key encrypted by the
//     tenant's own AES-256 key in its HSM. Versions created before keep
//     keycore's master key (the owner chose "new keys only").
//   - HSM keys: a key created with hsm=true is generated in the HSM, never
//     leaves it, and its encrypt, decrypt, sign and verify run there.
//     Anything that needs its material (export, wrap, derive, MAC, KEM) is
//     refused and audited.

const (
	protectionMEK         = "mek"
	protectionTenantHSM   = "tenant_hsm"
	protectionHSMResident = "hsm_resident"

	// labelHSM marks an HSM-resident key (its versions are hsm.KeyLabel(...)).
	labelHSM         = "hsm"
	labelHSMResident = "resident"
)

// HSMBackend is the connector client (pkg/hsm.Client).
type HSMBackend interface {
	Generate(ctx context.Context, tenant, label, algorithm string) (hsm.GenerateResult, error)
	EnsureTenantKey(ctx context.Context, tenant string) (string, error)
	Encrypt(ctx context.Context, tenant, label string, plaintext, aad []byte) ([]byte, []byte, error)
	Decrypt(ctx context.Context, tenant, label string, iv, ciphertext, aad []byte) ([]byte, error)
	Sign(ctx context.Context, tenant, label, hash string, digest []byte) ([]byte, error)
	Verify(ctx context.Context, tenant, label, hash string, digest, signature []byte) (bool, error)
	Destroy(ctx context.Context, tenant, label string) error
	Status(ctx context.Context, tenant string) (hsm.Status, error)
}

// SetHSMBackend wires the connector client.
func (s *Service) SetHSMBackend(b HSMBackend) { s.hsm = b }

// HSMSettings are a tenant's two HSM switches.
type HSMSettings struct {
	TenantID         string    `json:"tenant_id"`
	TenantKeyEnabled bool      `json:"tenant_key_enabled"`
	HSMKeysEnabled   bool      `json:"hsm_keys_enabled"`
	TenantKeyLabel   string    `json:"tenant_key_label,omitempty"`
	UpdatedBy        string    `json:"updated_by,omitempty"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// hsmRefusal is an HSM operation keycore refuses; it's audited as
// audit.key.hsm_refused and answered with Status and Reason.
type hsmRefusal struct {
	Status int
	Reason string
	msg    string
}

func (e *hsmRefusal) Error() string { return e.msg }

func (s *Service) refuseHSM(ctx context.Context, tenantID, keyID, operation string, status int, reason, msg string) error {
	_ = s.publishAudit(ctx, "audit.key.hsm_refused", tenantID, map[string]any{
		"key_id": keyID, "operation": operation, "reason": reason, "result": "refused", "severity": "warning", "description": msg,
	})
	return &hsmRefusal{Status: status, Reason: reason, msg: msg}
}

// hsmFailure turns a connector error into a refusal where it's one.
func (s *Service) hsmFailure(ctx context.Context, tenantID, keyID, operation string, err error) error {
	switch {
	case errors.Is(err, hsm.ErrNotConfigured):
		return s.refuseHSM(ctx, tenantID, keyID, operation, http.StatusConflict, "hsm_not_configured",
			"no enabled HSM profile for this tenant: configure it in the HSM tab")
	case errors.Is(err, hsm.ErrUnavailable):
		return s.refuseHSM(ctx, tenantID, keyID, operation, http.StatusServiceUnavailable, "hsm_unavailable", err.Error())
	}
	return err
}

func (s *SQLStore) GetHSMSettings(ctx context.Context, tenantID string) (HSMSettings, error) {
	out := HSMSettings{TenantID: tenantID}
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_key_enabled, hsm_keys_enabled, tenant_key_label, updated_by, updated_at
FROM keycore_hsm_settings WHERE tenant_id=$1`, tenantID).Scan(&out.TenantKeyEnabled, &out.HSMKeysEnabled, &out.TenantKeyLabel, &out.UpdatedBy, &out.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	return out, err
}

func (s *SQLStore) UpsertHSMSettings(ctx context.Context, in HSMSettings) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO keycore_hsm_settings (tenant_id, tenant_key_enabled, hsm_keys_enabled, tenant_key_label, updated_by, updated_at)
VALUES ($1,$2,$3,$4,$5,CURRENT_TIMESTAMP)
ON CONFLICT (tenant_id) DO UPDATE SET tenant_key_enabled=EXCLUDED.tenant_key_enabled, hsm_keys_enabled=EXCLUDED.hsm_keys_enabled,
    tenant_key_label=EXCLUDED.tenant_key_label, updated_by=EXCLUDED.updated_by, updated_at=CURRENT_TIMESTAMP`,
		in.TenantID, in.TenantKeyEnabled, in.HSMKeysEnabled, in.TenantKeyLabel, in.UpdatedBy)
	return err
}

// UpdateHSMSettings turns a tenant's switches on or off. Turning either on
// needs a working HSM; the tenant key is generated in it the first time.
func (s *Service) UpdateHSMSettings(ctx context.Context, in HSMSettings) (HSMSettings, error) {
	cur, err := s.store.GetHSMSettings(ctx, in.TenantID)
	if err != nil {
		return HSMSettings{}, err
	}
	next := HSMSettings{TenantID: in.TenantID, TenantKeyEnabled: in.TenantKeyEnabled, HSMKeysEnabled: in.HSMKeysEnabled,
		TenantKeyLabel: cur.TenantKeyLabel, UpdatedBy: in.UpdatedBy}
	if in.TenantKeyEnabled || in.HSMKeysEnabled {
		if s.hsm == nil {
			return HSMSettings{}, s.refuseHSM(ctx, in.TenantID, "", "hsm.settings", http.StatusServiceUnavailable, "hsm_unavailable", "the HSM connector is not enabled on this platform")
		}
		st, err := s.hsm.Status(ctx, in.TenantID)
		if err != nil {
			return HSMSettings{}, s.hsmFailure(ctx, in.TenantID, "", "hsm.settings", err)
		}
		if !st.Configured {
			return HSMSettings{}, s.refuseHSM(ctx, in.TenantID, "", "hsm.settings", http.StatusConflict, "hsm_not_configured", "no enabled HSM profile for this tenant: configure it in the HSM tab")
		}
		if !st.Connected {
			return HSMSettings{}, s.refuseHSM(ctx, in.TenantID, "", "hsm.settings", http.StatusConflict, "hsm_not_connected", "the HSM is configured but not reachable: "+st.Error)
		}
	}
	if in.TenantKeyEnabled && next.TenantKeyLabel == "" {
		label, err := s.hsm.EnsureTenantKey(ctx, in.TenantID)
		if err != nil {
			return HSMSettings{}, s.hsmFailure(ctx, in.TenantID, "", "hsm.settings", err)
		}
		next.TenantKeyLabel = label
	}
	if err := s.store.UpsertHSMSettings(ctx, next); err != nil {
		return HSMSettings{}, err
	}
	_ = s.publishAudit(ctx, "audit.key.hsm_settings_updated", in.TenantID, map[string]any{
		"tenant_key_enabled": next.TenantKeyEnabled, "hsm_keys_enabled": next.HSMKeysEnabled,
		"tenant_key_label": next.TenantKeyLabel, "updated_by": next.UpdatedBy,
		"previous": map[string]any{"tenant_key_enabled": cur.TenantKeyEnabled, "hsm_keys_enabled": cur.HSMKeysEnabled},
		"severity": "warning",
	})
	return s.store.GetHSMSettings(ctx, in.TenantID)
}

// HSMStatus is the connector's view of the tenant's HSM plus its switches.
func (s *Service) HSMStatus(ctx context.Context, tenantID string) (map[string]any, error) {
	settings, err := s.store.GetHSMSettings(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"settings": settings, "connector": s.hsm != nil}
	if s.hsm != nil {
		st, err := s.hsm.Status(ctx, tenantID)
		if err != nil {
			st.Error = err.Error()
		}
		out["hsm"] = st
	}
	return out, nil
}

func materialAAD(ver KeyVersion) []byte {
	return []byte("vecta-kms/key-material|" + ver.TenantID + "|" + ver.KeyID + "|" + ver.ID)
}

// protectMaterial encrypts new key material for ver: under the tenant's HSM
// key when the tenant turned it on, else under keycore's master key.
func (s *Service) protectMaterial(ctx context.Context, ver *KeyVersion, raw []byte) error {
	settings, err := s.store.GetHSMSettings(ctx, ver.TenantID)
	if err != nil {
		return err
	}
	if !settings.TenantKeyEnabled {
		env, err := crypto.EncryptEnvelope(s.mek, raw)
		if err != nil {
			return err
		}
		ver.EncryptedMaterial, ver.MaterialIV = env.Ciphertext, env.DataIV
		ver.WrappedDEK = packWrappedDEK(env.WrappedDEKIV, env.WrappedDEK)
		ver.Protection = protectionMEK
		return nil
	}
	if s.hsm == nil {
		return s.refuseHSM(ctx, ver.TenantID, ver.KeyID, "key.create", http.StatusServiceUnavailable, "hsm_unavailable",
			"the tenant key is in the HSM, and the HSM connector is not enabled on this platform")
	}
	dek, err := crypto.RandomBytes(32)
	if err != nil {
		return err
	}
	defer crypto.Zeroize(dek)
	aad := materialAAD(*ver)
	iv, ct, err := crypto.SealDetached(dek, raw, aad)
	if err != nil {
		return err
	}
	wrapIV, wrapped, err := s.hsm.Encrypt(ctx, ver.TenantID, settings.TenantKeyLabel, dek, aad)
	if err != nil {
		return s.hsmFailure(ctx, ver.TenantID, ver.KeyID, "key.create", err)
	}
	ver.EncryptedMaterial, ver.MaterialIV = ct, iv
	ver.WrappedDEK = append(append([]byte{}, wrapIV...), wrapped...)
	ver.Protection, ver.HSMLabel = protectionTenantHSM, settings.TenantKeyLabel
	return nil
}

var errMaterialInHSM = errors.New("this operation needs the key material, which never leaves the HSM")

// openTenantHSMMaterial decrypts a tenant_hsm version: the HSM decrypts the
// data key, keycore the material.
func (s *Service) openTenantHSMMaterial(ver KeyVersion) ([]byte, error) {
	if s.hsm == nil {
		return nil, errors.New("key material is under the tenant's HSM key, and the HSM connector is not enabled")
	}
	if len(ver.WrappedDEK) <= crypto.GCMNonceSize {
		return nil, errors.New("invalid HSM-wrapped data key")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	aad := materialAAD(ver)
	dek, err := s.hsm.Decrypt(ctx, ver.TenantID, ver.HSMLabel, ver.WrappedDEK[:crypto.GCMNonceSize], ver.WrappedDEK[crypto.GCMNonceSize:], aad)
	if err != nil {
		return nil, fmt.Errorf("tenant HSM key: %w", err)
	}
	defer crypto.Zeroize(dek)
	return crypto.OpenDetached(dek, ver.MaterialIV, ver.EncryptedMaterial, aad)
}

// createHSMKey generates a key in the tenant's HSM.
func (s *Service) createHSMKey(ctx context.Context, req CreateKeyRequest) (Key, error) {
	if req.TenantID == "" || req.Name == "" || req.Algorithm == "" {
		return Key{}, errors.New("tenant_id, name, algorithm are required")
	}
	settings, err := s.store.GetHSMSettings(ctx, req.TenantID)
	if err != nil {
		return Key{}, err
	}
	if !settings.HSMKeysEnabled {
		return Key{}, s.refuseHSM(ctx, req.TenantID, "", "key.create", http.StatusConflict, "hsm_keys_disabled",
			"HSM keys are off for this tenant: turn them on in the HSM tab")
	}
	if s.hsm == nil {
		return Key{}, s.refuseHSM(ctx, req.TenantID, "", "key.create", http.StatusServiceUnavailable, "hsm_unavailable", "the HSM connector is not enabled on this platform")
	}
	alg := hsm.NormalizeAlgorithm(req.Algorithm)
	if alg == "" || isPublicKeyType(req.KeyType) {
		return Key{}, s.refuseHSM(ctx, req.TenantID, "", "key.create", http.StatusBadRequest, "algorithm_not_supported",
			"HSM keys are AES-128/192/256 (GCM), RSA-2048/3072/4096 (PSS signing) or ECDSA P-256/P-384 (signing)")
	}
	if err := s.enforceFIPSKeyAlgorithm(ctx, req.TenantID, req.Algorithm, "key.create"); err != nil {
		return Key{}, err
	}
	if req.KeyType == "" {
		req.KeyType = inferKeyTypeFromAlgorithm(req.Algorithm)
	}
	if req.CreatedBy == "" {
		req.CreatedBy = "system"
	}
	req.IVMode = "internal" // the HSM generates every IV
	req.Tags = normalizeTags(req.Tags)
	_ = s.store.EnsureDefaultTags(ctx, req.TenantID)
	initialStatus, activationAt, err := resolveActivation(req.ActivationMode, req.ActivationDate)
	if err != nil {
		return Key{}, err
	}
	if err := s.checkPolicy(ctx, PolicyEvaluateRequest{
		TenantID: req.TenantID, Operation: "key.create", Algorithm: req.Algorithm, Purpose: req.Purpose,
		IVMode: req.IVMode, OpsLimit: req.OpsLimit, KeyStatus: initialStatus,
	}); err != nil {
		return Key{}, err
	}
	keyID := newID("key")
	label := hsm.KeyLabel(req.TenantID, keyID, 1)
	gen, err := s.hsm.Generate(ctx, req.TenantID, label, alg)
	if err != nil {
		return Key{}, s.hsmFailure(ctx, req.TenantID, keyID, "key.create", err)
	}
	kcv, kcvMethod := hsmKCV(gen)
	labels := KeyLabels{}
	for k, v := range req.Labels {
		labels[k] = v
	}
	labels[labelHSM] = labelHSMResident
	key := Key{
		ID: keyID, TenantID: req.TenantID, Name: req.Name, Algorithm: req.Algorithm, KeyType: req.KeyType,
		Purpose: req.Purpose, Status: initialStatus, ActivationDate: activationAt, CurrentVersion: 1,
		KCV: kcv, KCVAlgorithm: kcvMethod, IVMode: req.IVMode, Owner: req.Owner, Cloud: req.Cloud, Region: req.Region,
		Compliance: req.Compliance, Tags: req.Tags, Labels: map[string]string(labels),
		ExportAllowed: false, // the key never leaves the HSM
		OpsLimit:      req.OpsLimit, OpsLimitWindow: req.OpsLimitWindow,
		ApprovalRequired: req.ApprovalRequired, ApprovalPolicyID: req.ApprovalPolicyID, CreatedBy: req.CreatedBy,
	}
	ver := KeyVersion{
		ID: newID("kv"), TenantID: req.TenantID, KeyID: keyID, Version: 1,
		EncryptedMaterial: []byte{}, MaterialIV: []byte{}, WrappedDEK: []byte{},
		PublicKey: gen.PublicKey, KCV: kcv, Status: initialStatus,
		Protection: protectionHSMResident, HSMLabel: label,
	}
	if err := s.store.CreateKeyWithVersion(ctx, key, ver); err != nil {
		_ = s.hsm.Destroy(ctx, req.TenantID, label) // don't leave an orphan in the HSM
		return Key{}, err
	}
	s.exists.AddString(existsToken(req.TenantID, keyID))
	_ = s.cache.Set(ctx, key)
	_ = s.publishAudit(ctx, "audit.key.create", req.TenantID, map[string]any{
		"key_id": keyID, "kcv": strings.ToUpper(fmt.Sprintf("%X", kcv)), "hsm": true, "hsm_label": label, "algorithm": alg,
	})
	return key, nil
}

// hsmKCV: an AES key's KCV is computed in the HSM; an asymmetric key's is the
// first 3 bytes of SHA-256 over its public key.
func hsmKCV(gen hsm.GenerateResult) ([]byte, string) {
	if len(gen.KCV) > 0 {
		return gen.KCV, "aes-ecb-zero-hsm"
	}
	if len(gen.PublicKey) > 0 {
		sum := sha256.Sum256(gen.PublicKey)
		return sum[:3], "sha256-spki"
	}
	return nil, ""
}

// rotateHSMKey generates the next version of an HSM-resident key.
func (s *Service) rotateHSMKey(ctx context.Context, key Key) (KeyVersion, error) {
	if s.hsm == nil {
		return KeyVersion{}, s.refuseHSM(ctx, key.TenantID, key.ID, "key.rotate", http.StatusServiceUnavailable, "hsm_unavailable", "the HSM connector is not enabled on this platform")
	}
	next := key.CurrentVersion + 1
	label := hsm.KeyLabel(key.TenantID, key.ID, next)
	gen, err := s.hsm.Generate(ctx, key.TenantID, label, hsm.NormalizeAlgorithm(key.Algorithm))
	if err != nil {
		return KeyVersion{}, s.hsmFailure(ctx, key.TenantID, key.ID, "key.rotate", err)
	}
	kcv, _ := hsmKCV(gen)
	return KeyVersion{
		ID: newID("kv"), TenantID: key.TenantID, KeyID: key.ID, Version: next,
		EncryptedMaterial: []byte{}, MaterialIV: []byte{}, WrappedDEK: []byte{},
		PublicKey: gen.PublicKey, KCV: kcv, RotatedFrom: key.CurrentVersion, Status: "active",
		Protection: protectionHSMResident, HSMLabel: label,
	}, nil
}

// destroyHSMObjects removes a destroyed key's versions from the HSM. The
// key is already destroyed in keycore; an HSM failure is audited so the
// object can be removed by hand.
func (s *Service) destroyHSMObjects(ctx context.Context, tenantID string, deleted KeyDeletionRecord) {
	if deleted.Labels[labelHSM] != labelHSMResident || s.hsm == nil {
		return
	}
	var failed []string
	for v := 1; v <= deleted.CurrentVersion; v++ {
		label := hsm.KeyLabel(tenantID, deleted.KeyID, v)
		if err := s.hsm.Destroy(ctx, tenantID, label); err != nil && !errors.Is(err, hsm.ErrNotFound) {
			failed = append(failed, label)
		}
	}
	subject, details := "audit.key.hsm_objects_destroyed", map[string]any{"key_id": deleted.KeyID, "versions": deleted.CurrentVersion}
	if len(failed) > 0 {
		subject = "audit.key.hsm_destroy_failed"
		details["labels"], details["severity"], details["result"], details["reason"] = failed, "critical", "failure", "hsm_unreachable"
		details["description"] = "the key is destroyed in the KMS, but these HSM objects remain: remove them in the HSM"
	}
	_ = s.publishAudit(ctx, subject, tenantID, details)
}

// hsmDigest hashes data for an HSM signature the way software keys do:
// the requested hash, else SHA-384 for P-384 and SHA-256 otherwise.
func hsmDigest(key Key, hint string, data []byte) ([]byte, string, error) {
	fallback := stdcrypto.SHA256
	if hsm.NormalizeAlgorithm(key.Algorithm) == "ECDSA-P384" {
		fallback = stdcrypto.SHA384
	}
	h := resolveSigningHash(hint, fallback)
	name := map[stdcrypto.Hash]string{stdcrypto.SHA256: "SHA-256", stdcrypto.SHA384: "SHA-384", stdcrypto.SHA512: "SHA-512"}[h]
	if name == "" {
		return nil, "", errors.New("HSM keys sign with SHA-256, SHA-384 or SHA-512")
	}
	digest, err := digestForSigning(data, h)
	return digest, name, err
}

// HTTP ---------------------------------------------------------------------

// hsmRouter serves the tenant's HSM switches and status through the kernel;
// the legacy mux mounts it.
func (h *Handler) hsmRouter(audit route.Emitter) *route.Router {
	r := route.New("key", audit, nil)
	r.Handle("GET /hsm/settings", route.Spec{Action: "hsm_status_read", Permission: "key.hsm.read", Resource: "hsm"}, h.getHSM)
	r.Handle("PUT /hsm/settings", route.Spec{Action: "hsm_settings_update", Permission: "key.hsm.write", Resource: "hsm", Severity: "warning"}, h.putHSM)
	return r
}

func (h *Handler) getHSM(c *route.Call) {
	out, err := h.svc.HSMStatus(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "hsm_status_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, out)
}

func (h *Handler) putHSM(c *route.Call) {
	var in struct {
		TenantID         string `json:"tenant_id"`
		TenantKeyEnabled bool   `json:"tenant_key_enabled"`
		HSMKeysEnabled   bool   `json:"hsm_keys_enabled"`
	}
	if !c.Decode(&in) {
		return
	}
	c.Detail("tenant_key_enabled", in.TenantKeyEnabled)
	c.Detail("hsm_keys_enabled", in.HSMKeysEnabled)
	out, err := h.svc.UpdateHSMSettings(c.R.Context(), HSMSettings{
		TenantID: c.Tenant, TenantKeyEnabled: in.TenantKeyEnabled, HSMKeysEnabled: in.HSMKeysEnabled, UpdatedBy: c.Actor(),
	})
	var refused *hsmRefusal
	switch {
	case errors.As(err, &refused):
		c.Refuse(refused.Status, refused.Reason, refused.Error())
		return
	case err != nil:
		c.Error(http.StatusBadRequest, "hsm_settings_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]any{"settings": out})
}

// writeHSMError answers an HSM refusal with its own status and reason.
func writeHSMError(w http.ResponseWriter, err error, reqID, tenantID string) bool {
	var refused *hsmRefusal
	if !errors.As(err, &refused) {
		return false
	}
	writeErr(w, refused.Status, refused.Reason, refused.Error(), reqID, tenantID)
	return true
}
