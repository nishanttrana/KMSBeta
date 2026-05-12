package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"hash"
	"sync"
	"time"
)

func sha256New() hash.Hash { return sha256.New() }


// WakeSelfTestRegistry tracks which restored keys have already passed
// their post-wake KAT so the test only runs once per restoration. The
// registry is intentionally in-memory; a restart re-runs the test on
// next use, which is safer (and cheap).
type WakeSelfTestRegistry struct {
	mu       sync.Mutex
	verified map[string]time.Time
}

// NewWakeSelfTestRegistry constructs an empty registry.
func NewWakeSelfTestRegistry() *WakeSelfTestRegistry {
	return &WakeSelfTestRegistry{verified: make(map[string]time.Time)}
}

// Verified reports whether a key has passed its wake KAT.
func (r *WakeSelfTestRegistry) Verified(tenantID, keyID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.verified[tenantID+"|"+keyID]
	return ok
}

// MarkVerified records a successful KAT result.
func (r *WakeSelfTestRegistry) MarkVerified(tenantID, keyID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.verified[tenantID+"|"+keyID] = time.Now().UTC()
}

// Reset clears the verified-set for a tenant or key (called on destroy
// or rotation so a recycled identifier doesn't carry stale state).
func (r *WakeSelfTestRegistry) Reset(tenantID, keyID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.verified, tenantID+"|"+keyID)
}

// WakeKAT is the per-key known-answer test run on a destroyed-and-
// restored key. The fingerprint check confirms that the bits coming out
// of the archive store match the bits that went in; the encrypt/decrypt
// round-trip confirms the material is operable. Either failure quarantines
// the key.
//
// The function is deliberately conservative: any error short-circuits to
// a failed verdict so callers can route to the alert pipeline.
func WakeKAT(ctx context.Context, material []byte, expectedFingerprint []byte, encryptor func([]byte) ([]byte, error), decryptor func([]byte) ([]byte, error)) error {
	if len(material) == 0 {
		return errors.New("wake KAT: material is empty")
	}
	if encryptor == nil || decryptor == nil {
		return errors.New("wake KAT: encryptor/decryptor not supplied")
	}
	if len(expectedFingerprint) > 0 {
		if !constantTimeEqual(expectedFingerprint, fingerprintOf(material)) {
			return errors.New("wake KAT: material fingerprint mismatch")
		}
	}
	pt := []byte("wake-self-test-vector")
	ct, err := encryptor(pt)
	if err != nil {
		return errors.New("wake KAT: encrypt failed: " + err.Error())
	}
	got, err := decryptor(ct)
	if err != nil {
		return errors.New("wake KAT: decrypt failed: " + err.Error())
	}
	if !constantTimeEqual(got, pt) {
		return errors.New("wake KAT: round-trip mismatch")
	}
	return nil
}

func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var r byte
	for i := 0; i < len(a); i++ {
		r |= a[i] ^ b[i]
	}
	return r == 0
}

// fingerprintOf returns a non-reversible 32-byte tag over the key
// material. SHA-256 is FIPS-approved and the value is recorded at key
// creation so a future wake KAT has a comparison target.
func fingerprintOf(material []byte) []byte {
	h := sha256New()
	h.Write(material) //nolint:errcheck
	return h.Sum(nil)
}
