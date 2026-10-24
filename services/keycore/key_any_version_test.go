package main

import (
	"crypto/fips140"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// A ciphertext from any version decrypts with any_version: the caller (a
// PKCS#11 application) keeps only ciphertext and IV, and the key rotates
// underneath it (13.58.0-beta).
func TestDecryptAnyVersionFindsTheVersion(t *testing.T) {
	_, svc, rec := newActorTestHandler(t)
	ctx := adminCtx()
	key := ownedKey(t, svc)
	// A PKCS#11 caller supplies the IV, except in FIPS strict mode, which
	// refuses a caller's AES-GCM IV (SP 800-38D): there keycore makes it.
	iv, mode := b64([]byte("0123456789ab")), "external"
	if fips140.Enforced() {
		if _, err := svc.Encrypt(ctx, key.ID, EncryptRequest{TenantID: "t1", PlaintextB64: b64([]byte("x")), IVB64: iv, IVMode: mode}); err == nil {
			t.Fatal("FIPS strict mode took a caller's IV")
		}
		iv, mode = "", ""
	}
	enc := func(plain string) CryptoResponse {
		t.Helper()
		out, err := svc.Encrypt(ctx, key.ID, EncryptRequest{TenantID: "t1", PlaintextB64: b64([]byte(plain)), IVB64: iv, IVMode: mode, AADB64: b64([]byte("row-1"))})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	v1 := enc("from version 1")
	if _, err := svc.RotateKey(ctx, "t1", key.ID, "scheduled", ""); err != nil {
		t.Fatal(err)
	}
	v2 := enc("from version 2")
	if (iv != "" && v1.IVB64 != iv) || v2.Version != 2 {
		t.Fatalf("external IV not used, or no rotation: %+v %+v", v1, v2)
	}
	dec := func(ct CryptoResponse, any bool, aad string) (CryptoResponse, error) {
		return svc.Decrypt(ctx, key.ID, DecryptRequest{TenantID: "t1", CiphertextB64: ct.CipherB64, IVB64: ct.IVB64, AADB64: b64([]byte(aad)), AnyVersion: any})
	}
	for want, ct := range map[string]CryptoResponse{"from version 1": v1, "from version 2": v2} {
		out, err := dec(ct, true, "row-1")
		plain, _ := base64.StdEncoding.DecodeString(out.PlainB64)
		if err != nil || string(plain) != want || out.Version != ct.Version {
			t.Fatalf("any version: %q v%d %v, want %q v%d", plain, out.Version, err, want, ct.Version)
		}
	}
	// The audit event says the version was searched for.
	rec.mu.Lock()
	var found bool
	for _, ev := range rec.events {
		if ev["_subject"] == "audit.key.decrypt" && strings.Contains(fmt.Sprint(ev), "any_version:true") {
			found = true
		}
	}
	rec.mu.Unlock()
	if !found {
		t.Fatal("no audit.key.decrypt event carries any_version")
	}
	// Without it, version 0 is the current version only, as before.
	if _, err := dec(v1, false, "row-1"); err == nil {
		t.Fatal("version 1's ciphertext opened under the current version")
	}
	// Other additional data opens under no version.
	if _, err := dec(v1, true, "row-2"); !errors.Is(err, errDecryptMismatch) {
		t.Fatalf("other aad: %v, want errDecryptMismatch", err)
	}
}

// A digest the caller computed signs with a software RSA or ECDSA key, as
// with an HSM key; the signature is the one signing the message would make
// (13.58.0-beta).
func TestPrehashedSigningWithSoftwareKeys(t *testing.T) {
	_, svc, _ := newActorTestHandler(t)
	ctx := adminCtx()
	msg := []byte("tbs certificate")
	d256, d384 := sha256.Sum256(msg), sha512.Sum384(msg)
	for _, tc := range []struct {
		alg, hash string
		digest    []byte
	}{
		{"ECDSA-P256", "SHA-256", d256[:]},
		{"ECDSA-P384", "SHA-384", d384[:]},
		{"RSA-2048", "SHA-256", d256[:]},
	} {
		t.Run(tc.alg, func(t *testing.T) {
			key, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t1", Name: "signer-" + tc.alg, Algorithm: tc.alg, KeyType: "asymmetric", Purpose: "sign", CreatedBy: "owner-1"})
			if err != nil {
				t.Fatal(err)
			}
			sig, err := svc.Sign(ctx, key.ID, SignRequest{TenantID: "t1", DataB64: b64(tc.digest), Algorithm: tc.hash, Prehashed: true})
			if err != nil {
				t.Fatal(err)
			}
			ok, err := svc.Verify(ctx, key.ID, VerifyRequest{TenantID: "t1", DataB64: b64(msg), SignatureB64: sig.SignatureB64, Algorithm: tc.hash})
			if err != nil || !ok.Verified {
				t.Fatalf("the prehashed signature doesn't verify over the message: %v", err)
			}
			// And over the digest (13.59.0-beta); another digest fails.
			ok, err = svc.Verify(ctx, key.ID, VerifyRequest{TenantID: "t1", DataB64: b64(tc.digest), SignatureB64: sig.SignatureB64, Algorithm: tc.hash, Prehashed: true})
			if err != nil || !ok.Verified {
				t.Fatalf("prehashed verify: %v", err)
			}
			other := append([]byte{}, tc.digest...)
			other[0] ^= 1
			if ok, err := svc.Verify(ctx, key.ID, VerifyRequest{TenantID: "t1", DataB64: b64(other), SignatureB64: sig.SignatureB64, Algorithm: tc.hash, Prehashed: true}); err != nil || ok.Verified {
				t.Fatalf("another digest verified: %v", err)
			}
			if _, err := svc.Sign(ctx, key.ID, SignRequest{TenantID: "t1", DataB64: b64(tc.digest[:20]), Algorithm: tc.hash, Prehashed: true}); err == nil {
				t.Fatal("a short digest was signed")
			}
		})
	}
	if fips140.Enforced() {
		return // no Ed25519 key in FIPS strict mode
	}
	ed, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t1", Name: "ed", Algorithm: "Ed25519", KeyType: "asymmetric", Purpose: "sign", CreatedBy: "owner-1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Sign(ctx, ed.ID, SignRequest{TenantID: "t1", DataB64: b64(d256[:]), Algorithm: "SHA-256", Prehashed: true}); err == nil {
		t.Fatal("Ed25519 signed a digest as if prehashed")
	}
}
