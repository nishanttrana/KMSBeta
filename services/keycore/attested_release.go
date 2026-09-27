package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"

	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/tenantcheck"
)

// Attested key release: the confidential service, after verifying an
// enclave's attestation and that it commits to a recipient public key, asks
// keycore to release the key's current material sealed to that recipient
// (pkg/crypto.SealToRecipient). Only the enclave holding the private key can
// open it; keycore never sees that key and returns no plaintext.

// attestedReleaseCaller is the only identity that may request a release.
const attestedReleaseCaller = "kms-confidential"

var (
	errReleaseCaller      = errors.New("attested release may only be requested by the confidential service")
	errReleaseNotAllowed  = errors.New("attested release is an export: the key's export policy does not allow it")
	errReleaseKeyInactive = errors.New("only an active key can be released")
)

type AttestedKeyReleaseRequest struct {
	TenantID           string `json:"tenant_id"`
	RecipientPublicKey string `json:"recipient_public_key"` // base64 DER SubjectPublicKeyInfo (RSA 2048-8192)
	ReleaseID          string `json:"release_id"`
	AttestationHash    string `json:"attestation_document_hash"`
	Provider           string `json:"provider"`
}

type AttestedKeyReleaseResult struct {
	KeyID         string `json:"key_id"`
	Version       int    `json:"version"`
	Algorithm     string `json:"algorithm"`
	KeyType       string `json:"key_type"`
	KCV           string `json:"kcv"`
	SealAlgorithm string `json:"seal_algorithm"`
	WrappedKey    string `json:"wrapped_key"`
	Nonce         string `json:"nonce"`
	Ciphertext    string `json:"ciphertext"`
	AAD           string `json:"aad"`
}

// attestedReleaseAAD binds the sealed material to the tenant, key, version
// and release, so a sealed blob cannot be presented as another release.
func attestedReleaseAAD(tenantID, keyID string, version int, releaseID string) string {
	return fmt.Sprintf("vecta-attested-release|%s|%s|%d|%s", tenantID, keyID, version, releaseID)
}

// AttestedRelease seals the key's current material to the recipient key.
func (s *Service) AttestedRelease(ctx context.Context, keyID string, req AttestedKeyReleaseRequest) (AttestedKeyReleaseResult, error) {
	tenantID := strings.TrimSpace(req.TenantID)
	releaseID := strings.TrimSpace(req.ReleaseID)
	if tenantID == "" || releaseID == "" || strings.TrimSpace(req.AttestationHash) == "" {
		return AttestedKeyReleaseResult{}, errors.New("tenant_id, release_id and attestation_document_hash are required")
	}
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.RecipientPublicKey))
	if err != nil {
		return AttestedKeyReleaseResult{}, errors.New("recipient_public_key must be base64 DER")
	}
	recipient, err := pkgcrypto.ParseRecipientPublicKey(der)
	if err != nil {
		return AttestedKeyReleaseResult{}, err
	}
	key, err := s.GetKey(ctx, tenantID, keyID)
	if err != nil {
		return AttestedKeyReleaseResult{}, err
	}
	if normalizeLifecycleStatus(key.Status) != "active" {
		return AttestedKeyReleaseResult{}, errReleaseKeyInactive
	}
	if !key.ExportAllowed {
		return AttestedKeyReleaseResult{}, errReleaseNotAllowed
	}
	if err := s.enforceFIPSKeyAlgorithm(ctx, tenantID, key.Algorithm, "key.attested_release"); err != nil {
		return AttestedKeyReleaseResult{}, err
	}
	if err := s.checkPolicy(ctx, PolicyEvaluateRequest{
		TenantID:          tenantID,
		Operation:         "key.attested_release",
		KeyID:             keyID,
		Algorithm:         key.Algorithm,
		Purpose:           key.Purpose,
		IVMode:            key.IVMode,
		OpsTotal:          key.OpsTotal,
		OpsLimit:          key.OpsLimit,
		KeyStatus:         key.Status,
		DaysSinceRotation: daysSince(key.UpdatedAt),
	}); err != nil {
		return AttestedKeyReleaseResult{}, err
	}
	ver, err := s.GetVersion(ctx, tenantID, keyID, 0)
	if err != nil {
		return AttestedKeyReleaseResult{}, err
	}
	raw, err := s.decryptMaterial(ver)
	if err != nil {
		return AttestedKeyReleaseResult{}, err
	}
	defer pkgcrypto.Zeroize(raw)
	aad := attestedReleaseAAD(tenantID, keyID, ver.Version, releaseID)
	wrapped, nonce, ct, err := pkgcrypto.SealToRecipient(recipient, raw, []byte(aad))
	if err != nil {
		return AttestedKeyReleaseResult{}, err
	}
	s.recordKeyUsage(ctx, tenantID, keyID, "attested_release")
	return AttestedKeyReleaseResult{
		KeyID:         keyID,
		Version:       ver.Version,
		Algorithm:     key.Algorithm,
		KeyType:       key.KeyType,
		KCV:           strings.ToUpper(hex.EncodeToString(ver.KCV)),
		SealAlgorithm: pkgcrypto.RecipientSealAlgorithm,
		WrappedKey:    base64.StdEncoding.EncodeToString(wrapped),
		Nonce:         base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:    base64.StdEncoding.EncodeToString(ct),
		AAD:           aad,
	}, nil
}

// attestedReleaseRouter serves the release through the pkg/route kernel,
// which audits it as audit.key.attested_release (refusals included) and
// meters it: the key is sealed to the recipient here.
func (h *Handler) attestedReleaseRouter(audit route.Emitter) *route.Router {
	r := route.New("key", audit, nil)
	r.Handle("POST /keys/{id}/attested-release", route.Spec{
		Action: "attested_release", Permission: "key.attested_release", Resource: "key", TargetParam: "id", Severity: "warning",
		Metered: "attested_release",
	}, h.attestedRelease)
	return r
}

func (h *Handler) attestedRelease(c *route.Call) {
	if !tenantcheck.IsServicePrincipal(c.Claims) || strings.TrimSpace(c.Claims.ClientID) != attestedReleaseCaller {
		c.Refuse(http.StatusForbidden, "caller_not_confidential_service", errReleaseCaller.Error())
		return
	}
	var req AttestedKeyReleaseRequest
	if !c.Decode(&req) {
		return
	}
	req.TenantID = c.Tenant
	c.Detail("release_id", req.ReleaseID)
	c.Detail("provider", req.Provider)
	c.Detail("attestation_document_hash", req.AttestationHash)
	if der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.RecipientPublicKey)); err == nil {
		c.Detail("recipient_key_binding", pkgcrypto.RecipientKeyBinding(der))
	}
	out, err := h.svc.AttestedRelease(c.R.Context(), c.R.PathValue("id"), req)
	switch {
	case errors.Is(err, errReleaseNotAllowed):
		c.Refuse(http.StatusForbidden, "export_not_allowed", err.Error())
		return
	case errors.Is(err, errReleaseKeyInactive):
		c.Refuse(http.StatusConflict, "key_not_active", err.Error())
		return
	case err != nil:
		refuseKeyOp(c, err, "attested_release_failed")
		return
	}
	c.Detail("version", out.Version)
	c.Detail("seal_algorithm", out.SealAlgorithm)
	c.JSON(http.StatusOK, map[string]interface{}{
		"key_id": out.KeyID, "version": out.Version, "algorithm": out.Algorithm, "key_type": out.KeyType,
		"kcv": out.KCV, "seal_algorithm": out.SealAlgorithm, "wrapped_key": out.WrappedKey,
		"nonce": out.Nonce, "ciphertext": out.Ciphertext, "aad": out.AAD,
	})
}
