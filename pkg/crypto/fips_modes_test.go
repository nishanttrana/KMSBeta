package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/fips140"
	"errors"
	"testing"

	"vecta-kms/pkg/fips/fipstest"
)

// Module-generated-IV AES-GCM must work in every FIPS runtime mode.
func TestGCMWorksInEveryMode(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	blob, err := Seal(key, []byte("pt"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := Open(key, blob, []byte("aad")); err != nil || string(pt) != "pt" {
		t.Fatalf("Open: %q %v", pt, err)
	}
	nonce, ct, err := SealDetached(key, []byte("pt"), nil)
	if err != nil || len(nonce) != GCMNonceSize {
		t.Fatalf("SealDetached: nonce=%d err=%v", len(nonce), err)
	}
	if pt, err := OpenDetached(key, nonce, ct, nil); err != nil || string(pt) != "pt" {
		t.Fatalf("OpenDetached: %q %v", pt, err)
	}
	env, err := EncryptEnvelope(key, []byte("material"))
	if err != nil || len(env.DataIV) != storedEnvelopeIVSize || len(env.WrappedDEKIV) != storedEnvelopeIVSize {
		t.Fatalf("EncryptEnvelope: %+v %v", env, err)
	}
	if pt, err := DecryptEnvelope(key, env); err != nil || string(pt) != "material" {
		t.Fatalf("DecryptEnvelope: %q %v", pt, err)
	}
}

// Envelopes written before the FIPS module switch (16-byte IV, first 12
// bytes used by cipher.NewGCM) must still decrypt, in every mode.
func TestLegacyEnvelopeStillDecrypts(t *testing.T) {
	mek := []byte("0123456789abcdef0123456789abcdef")
	dek := []byte("fedcba9876543210fedcba9876543210")
	legacySeal := func(key, iv, pt []byte) []byte {
		var out []byte
		fips140.WithoutEnforcement(func() {
			blk, _ := aes.NewCipher(key)
			gcm, err := cipher.NewGCM(blk)
			if err != nil {
				t.Fatal(err)
			}
			out = gcm.Seal(nil, iv[:12], pt, nil)
		})
		return out
	}
	dataIV := []byte("0123456789ABCDEF")
	wrapIV := []byte("FEDCBA9876543210")
	env := &EnvelopeCiphertext{
		Ciphertext:   legacySeal(dek, dataIV, []byte("legacy")),
		DataIV:       dataIV,
		WrappedDEK:   legacySeal(mek, wrapIV, dek),
		WrappedDEKIV: wrapIV,
	}
	if pt, err := DecryptEnvelope(mek, env); err != nil || string(pt) != "legacy" {
		t.Fatalf("legacy envelope: %q %v", pt, err)
	}
}

// Strict mode refuses caller-chosen GCM IVs and SHA-1 with clean errors.
func TestStrictModeRefusals(t *testing.T) {
	fipstest.StrictOnly(t)
	key := []byte("0123456789abcdef0123456789abcdef")
	if _, err := SealGCMWithNonce(key, make([]byte, GCMNonceSize), []byte("pt"), nil); !errors.Is(err, ErrCallerNonceStrict) {
		t.Fatalf("SealGCMWithNonce: got %v, want ErrCallerNonceStrict", err)
	}
	if _, _, err := FieldEncrypt(key, "AES-GCM", []byte("pt"), nil, true); !errors.Is(err, ErrCallerNonceStrict) {
		t.Fatalf("deterministic field encryption: got %v, want ErrCallerNonceStrict", err)
	}
	if _, err := HMACSHA1Interop(key, []byte("x")); !errors.Is(err, ErrSHA1Strict) {
		t.Fatalf("HMACSHA1Interop: got %v, want ErrSHA1Strict", err)
	}
}
