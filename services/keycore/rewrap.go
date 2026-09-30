package main

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"vecta-kms/pkg/crypto"
	"vecta-kms/pkg/route"
)

// Crypto agility under a stable key ID (NIST CSWP 39): a rotation may change
// the key's algorithm (RotateKeyTo), older versions keep their own algorithm
// for decrypt and verify, and rewrap moves ciphertext onto the current
// version inside keycore, so the caller never handles the plaintext.

// enforceVersionAlgorithm applies the FIPS mode and the tenant's policy to an
// older version whose algorithm differs from the key's current one; the
// checks before the transaction saw only the current algorithm.
func (s *Service) enforceVersionAlgorithm(ctx context.Context, tenantID string, key, k Key, op string) error {
	if k.Algorithm == key.Algorithm {
		return nil
	}
	if err := s.enforceFIPSKeyAlgorithm(ctx, tenantID, k.Algorithm, op); err != nil {
		return err
	}
	return s.checkPolicy(ctx, PolicyEvaluateRequest{
		TenantID: tenantID, Operation: op, KeyID: key.ID, Algorithm: k.Algorithm, Purpose: key.Purpose,
		IVMode: key.IVMode, OpsTotal: key.OpsTotal, OpsLimit: key.OpsLimit, KeyStatus: key.Status,
		DaysSinceRotation: daysSince(key.UpdatedAt),
	})
}

type RewrapRequest struct {
	TenantID      string `json:"tenant_id"`
	CiphertextB64 string `json:"ciphertext"`
	IVB64         string `json:"iv"`
	AADB64        string `json:"aad"`
	Version       int    `json:"version"` // version that produced the ciphertext
	ReferenceID   string `json:"reference_id"`
}

type RewrapResponse struct {
	KeyID       string `json:"key_id"`
	FromVersion int    `json:"from_version"`
	Version     int    `json:"version"`
	CipherB64   string `json:"ciphertext"`
	IVB64       string `json:"iv"`
}

// Rewrap decrypts under the stated version and encrypts under the current
// one, with every check decrypt and encrypt make (access, policy, approval,
// FIPS) and their audit events.
func (s *Service) Rewrap(ctx context.Context, keyID string, req RewrapRequest) (RewrapResponse, error) {
	dec, err := s.Decrypt(ctx, keyID, DecryptRequest{
		TenantID: req.TenantID, CiphertextB64: req.CiphertextB64, IVB64: req.IVB64, AADB64: req.AADB64,
		Version: req.Version, Operation: "decrypt",
	})
	if err != nil {
		return RewrapResponse{}, err
	}
	enc, err := s.Encrypt(ctx, keyID, EncryptRequest{
		TenantID: req.TenantID, PlaintextB64: dec.PlainB64, AADB64: req.AADB64, ReferenceID: req.ReferenceID, Operation: "encrypt",
	})
	if raw, e := base64.StdEncoding.DecodeString(dec.PlainB64); e == nil {
		crypto.Zeroize(raw)
	}
	if err != nil {
		return RewrapResponse{}, err
	}
	return RewrapResponse{KeyID: keyID, FromVersion: dec.Version, Version: enc.Version, CipherB64: enc.CipherB64, IVB64: enc.IVB64}, nil
}

func (h *Handler) rewrapRouter(audit route.Emitter) *route.Router {
	r := route.New("key", audit, nil)
	r.Handle("POST /keys/{id}/rewrap", route.Spec{Action: "ciphertext_rewrapped", Permission: "key.rewrap", Resource: "key", TargetParam: "id"}, h.rewrap)
	return r
}

func (h *Handler) rewrap(c *route.Call) {
	var req RewrapRequest
	if !c.Decode(&req) {
		return
	}
	if strings.TrimSpace(req.CiphertextB64) == "" {
		c.Error(http.StatusBadRequest, "bad_request", "ciphertext is required")
		return
	}
	req.TenantID = c.Tenant
	out, err := h.svc.Rewrap(c.R.Context(), c.R.PathValue("id"), req)
	var denied policyDeniedError
	var fipsDenied fipsModeViolationError
	switch {
	case err == nil:
	case errors.Is(err, errStoreNotFound):
		c.Error(http.StatusNotFound, "not_found", "key or key version not found")
		return
	case errors.As(err, &denied):
		c.Refuse(http.StatusForbidden, "policy_denied", denied.Error())
		return
	case errors.As(err, &fipsDenied):
		c.Refuse(http.StatusForbidden, "fips_mode_violation", fipsDenied.Error())
		return
	case errors.As(err, new(*accessRefusal)):
		c.Refuse(http.StatusForbidden, "access_denied", err.Error())
		return
	case errors.Is(err, errVersionRefused):
		c.Refuse(http.StatusConflict, "version_refused", err.Error())
		return
	default:
		c.Error(http.StatusBadRequest, "rewrap_failed", err.Error())
		return
	}
	c.Detail("from_version", out.FromVersion)
	c.Detail("version", out.Version)
	c.JSON(http.StatusOK, map[string]interface{}{"data": out})
}
