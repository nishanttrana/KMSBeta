package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"

	"vecta-kms/pkg/crypto"
	"vecta-kms/pkg/route"
)

// Public key read (6.18.0-beta): GET /keys/{id}/public-key returns the
// current version's public key as PEM SubjectPublicKeyInfo. A public key is
// not secret, so the decision is the per-key read (visibility,
// KEY_ACCESS_MODEL.md section 8): whoever may see the key may read its public
// half. A service acting for a user (pkg/delegation, usage "read") gets the
// user's view.
//
// Where it comes from: an HSM key pair's version holds its PKIX DER public
// key; a software key pair holds only its PKCS#8 private key (encrypted), so
// the public key is derived from it and the private material zeroized; an
// imported public component is its own material. A key with no public half,
// or whose public key has no SubjectPublicKeyInfo encoding here (ML-KEM,
// ML-DSA, SLH-DSA are held as raw bytes), is refused, never re-labelled.

var (
	errNoPublicKey     = errors.New("the key has no public key: it is not an asymmetric key")
	errSPKIUnavailable = errors.New("the key's public key has no SubjectPublicKeyInfo encoding in this release")
)

func (h *Handler) publicKeyRouter(audit route.Emitter) *route.Router {
	r := route.New("key", audit, nil)
	// Per-key read: any verified identity, and the key must be visible
	// (KEY_ACCESS_MODEL.md section 9).
	r.Handle("GET /keys/{id}/public-key", route.Spec{
		Action: "public_key_read", Permission: route.Authenticated, Resource: "key", TargetParam: "id",
	}, h.getPublicKey)
	return r
}

func (h *Handler) getPublicKey(c *route.Call) {
	if !h.visibleKey(c) {
		return
	}
	ctx := c.R.Context()
	key, err := h.svc.store.GetKey(ctx, c.Tenant, strings.TrimSpace(c.R.PathValue("id")))
	if err != nil {
		refuseKeyOp(c, err, "public_key_failed")
		return
	}
	c.Detail("algorithm", key.Algorithm)
	if isDeletedLike(key.Status) {
		c.Refuse(http.StatusConflict, "key_deleted", "the key is deleted; it has no public key to read")
		return
	}
	der, ver, err := h.svc.CurrentPublicKey(ctx, key)
	switch {
	case errors.Is(err, errNoPublicKey):
		c.Refuse(http.StatusConflict, "not_asymmetric", err.Error())
		return
	case errors.Is(err, errSPKIUnavailable):
		c.Refuse(http.StatusConflict, "spki_unavailable", err.Error()+" ("+key.Algorithm+")")
		return
	case err != nil:
		refuseKeyOp(c, err, "public_key_failed")
		return
	}
	c.Detail("version", ver.Version)
	c.JSON(http.StatusOK, map[string]any{
		"key_id":         key.ID,
		"version":        ver.Version,
		"algorithm":      key.Algorithm,
		"format":         "spki-pem",
		"public_key_pem": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
	})
}

// CurrentPublicKey returns the DER SubjectPublicKeyInfo of key's current
// version. The caller has already decided the key is visible.
func (s *Service) CurrentPublicKey(ctx context.Context, key Key) ([]byte, KeyVersion, error) {
	ver, err := s.store.GetVersion(ctx, key.TenantID, key.ID, key.CurrentVersion)
	if err != nil {
		return nil, KeyVersion{}, err
	}
	var der []byte
	switch {
	case len(ver.PublicKey) > 0:
		der = append([]byte{}, ver.PublicKey...)
	case isPublicComponentKey(key):
		if der, err = s.decryptMaterial(ver); err != nil {
			return nil, KeyVersion{}, err
		}
		if pub, perr := x509.ParsePKCS1PublicKey(der); perr == nil {
			if der, err = x509.MarshalPKIXPublicKey(pub); err != nil {
				return nil, KeyVersion{}, err
			}
		}
	case key.Labels[labelHSM] == labelHSMResident || inferKeyTypeFromAlgorithm(key.Algorithm) != "asymmetric":
		// An HSM key with no public key recorded is a symmetric HSM key.
		return nil, KeyVersion{}, errNoPublicKey
	default:
		raw, derr := s.decryptMaterial(ver)
		if derr != nil {
			return nil, KeyVersion{}, derr
		}
		der, err = derivePublicFromPrivateMaterial(key.Algorithm, raw)
		crypto.Zeroize(raw)
		if err != nil {
			return nil, KeyVersion{}, err
		}
	}
	if _, err := x509.ParsePKIXPublicKey(der); err != nil {
		return nil, KeyVersion{}, errSPKIUnavailable
	}
	return der, ver, nil
}
