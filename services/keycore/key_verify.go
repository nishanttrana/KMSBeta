package main

import (
	"context"
	"time"

	"vecta-kms/pkg/crypto"
)

// KeyIntegrityResult is the outcome of a real key-integrity check.
type KeyIntegrityResult struct {
	KeyID            string    `json:"key_id"`
	Version          int       `json:"version"`
	Algorithm        string    `json:"algorithm"`
	Status           string    `json:"status"`
	MaterialDecrypts bool      `json:"material_decrypts"`
	KCVAlgorithm     string    `json:"kcv_algorithm,omitempty"`
	KCVChecked       bool      `json:"kcv_checked"`
	KCVMatch         bool      `json:"kcv_match"`
	Verified         bool      `json:"verified"`
	Detail           string    `json:"detail"`
	CheckedAt        time.Time `json:"checked_at"`
}

// VerifyKeyIntegrity proves the integrity of a key's current version. It
// decrypts the stored material under the master key — an AES-GCM auth-tag
// failure here means corruption, tampering, or a wrong/rotated MEK — and for
// keys that carry a KCV it recomputes the KCV from the live material and
// compares it (constant time) to the value recorded at creation. Unlike the
// previous placeholder, this can and does fail; it is a genuine assurance
// check that operates on the real stored key.
func (s *Service) VerifyKeyIntegrity(ctx context.Context, tenantID, keyID string) (KeyIntegrityResult, error) {
	key, err := s.GetKey(ctx, tenantID, keyID)
	if err != nil {
		return KeyIntegrityResult{}, err
	}
	res := KeyIntegrityResult{
		KeyID:        keyID,
		Version:      key.CurrentVersion,
		Algorithm:    key.Algorithm,
		Status:       key.Status,
		KCVAlgorithm: key.KCVAlgorithm,
		CheckedAt:    time.Now().UTC(),
	}

	ver, err := s.store.GetVersion(ctx, tenantID, keyID, key.CurrentVersion)
	if err != nil {
		res.Detail = "current key version not found"
		s.auditIntegrity(ctx, tenantID, res)
		return res, nil
	}

	raw, err := s.decryptMaterial(ver)
	if err != nil {
		res.Detail = "key material failed to decrypt/authenticate under the master key — corruption, tampering, or wrong MEK"
		s.auditIntegrity(ctx, tenantID, res)
		return res, nil
	}
	defer crypto.Zeroize(raw)
	res.MaterialDecrypts = true

	// The authoritative KCV is recorded per version; the key row only carries a
	// denormalised copy updated on rotation. Prefer the version's value.
	expectedKCV := ver.KCV
	if len(expectedKCV) == 0 {
		expectedKCV = key.KCV
	}

	if len(expectedKCV) > 0 {
		recomputed, _, kerr := computeKCVStrict(key.Algorithm, raw)
		if kerr != nil {
			res.Detail = "could not recompute KCV: " + kerr.Error()
			s.auditIntegrity(ctx, tenantID, res)
			return res, nil
		}
		res.KCVChecked = true
		res.KCVMatch = crypto.ConstantTimeEqual(recomputed, expectedKCV)
		res.Verified = res.KCVMatch
		if res.KCVMatch {
			res.Detail = "material decrypts and the recomputed KCV matches the value recorded at creation"
		} else {
			res.Detail = "KCV MISMATCH — stored material does not match its recorded check value"
		}
	} else {
		// Asymmetric / no-KCV keys: the authenticated envelope decrypt above is
		// itself the integrity proof (the GCM tag would otherwise fail).
		res.Verified = true
		res.Detail = "material decrypts and authenticates under the master key (no KCV for this key type)"
	}

	s.auditIntegrity(ctx, tenantID, res)
	return res, nil
}

func (s *Service) auditIntegrity(ctx context.Context, tenantID string, r KeyIntegrityResult) {
	_ = s.publishAudit(ctx, "audit.key.integrity_verified", tenantID, map[string]any{
		"key_id":            r.KeyID,
		"version":           r.Version,
		"verified":          r.Verified,
		"kcv_checked":       r.KCVChecked,
		"kcv_match":         r.KCVMatch,
		"material_decrypts": r.MaterialDecrypts,
	})
}
