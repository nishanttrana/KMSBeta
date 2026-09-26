package main

import (
	"context"
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	pkgcache "vecta-kms/pkg/cache"
	"vecta-kms/pkg/crypto"
	"vecta-kms/pkg/hsm"
	"vecta-kms/pkg/hsmconnector/softhsmtest"
	"vecta-kms/pkg/metering"
	"vecta-kms/pkg/route/routetest"
)

// These tests run keycore against a real hsm-connector on SoftHSM2 (a real
// PKCS#11 library), through the same HTTP client production uses.

func newHSMService(t *testing.T, tenants ...string) (*Service, *eventRecorder, *hsm.Client) {
	t.Helper()
	srv := softhsmtest.Start(t, "kms-keycore", tenants...)
	rec := &eventRecorder{}
	svc := NewService(newStoreForTest(t), NewKeyCache(pkgcache.NewMemory(5*time.Minute), 5*time.Minute), rec,
		metering.NewMeter(0, time.Hour), []byte("0123456789ABCDEF0123456789ABCDEF"), nil, false)
	client := hsm.New(srv.URL)
	svc.SetHSMBackend(client)
	return svc, rec, client
}

func hsmRefusalReason(err error) string {
	var r *hsmRefusal
	if errors.As(err, &r) {
		return r.Reason
	}
	return ""
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func TestHSMResidentKeyLifecycle(t *testing.T) {
	svc, rec, client := newHSMService(t, "t1")
	ctx := adminCtx()
	create := CreateKeyRequest{TenantID: "t1", Name: "in-hsm", Algorithm: "AES-256", Purpose: "encrypt", Owner: "ops", HSM: true}

	// Off until the tenant turns HSM keys on; the refusal is audited.
	if _, err := svc.CreateKey(ctx, create); hsmRefusalReason(err) != "hsm_keys_disabled" {
		t.Fatalf("create with HSM keys off: %v", err)
	}
	if d := refusalDetails(t, rec, "audit.key.hsm_refused"); d["reason"] != "hsm_keys_disabled" {
		t.Fatalf("refusal: %+v", d)
	}
	if _, err := svc.UpdateHSMSettings(ctx, HSMSettings{TenantID: "t1", HSMKeysEnabled: true, UpdatedBy: "tester"}); err != nil {
		t.Fatal(err)
	}
	if rec.find("audit.key.hsm_settings_updated") == nil {
		t.Fatal("settings change not audited")
	}

	key, err := svc.CreateKey(ctx, create)
	if err != nil {
		t.Fatal(err)
	}
	if key.Labels[labelHSM] != labelHSMResident || key.ExportAllowed || len(key.KCV) != 3 {
		t.Fatalf("key: labels %v export %v kcv %x", key.Labels, key.ExportAllowed, key.KCV)
	}
	ver, err := svc.store.GetVersion(context.Background(), "t1", key.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if ver.Protection != protectionHSMResident || ver.HSMLabel != hsm.KeyLabel("t1", key.ID, 1) || len(ver.EncryptedMaterial) != 0 || len(ver.WrappedDEK) != 0 {
		t.Fatalf("keycore holds material for an HSM key: %+v", ver)
	}

	enc, err := svc.Encrypt(ctx, key.ID, EncryptRequest{TenantID: "t1", PlaintextB64: b64([]byte("card data")), AADB64: b64([]byte("order-7"))})
	if err != nil {
		t.Fatal(err)
	}
	dec, err := svc.Decrypt(ctx, key.ID, DecryptRequest{TenantID: "t1", CiphertextB64: enc.CipherB64, IVB64: enc.IVB64, AADB64: b64([]byte("order-7"))})
	if err != nil || dec.PlainB64 != b64([]byte("card data")) {
		t.Fatalf("decrypt: %v %+v", err, dec)
	}
	if _, err := svc.Decrypt(ctx, key.ID, DecryptRequest{TenantID: "t1", CiphertextB64: enc.CipherB64, IVB64: enc.IVB64, AADB64: b64([]byte("order-8"))}); err == nil {
		t.Fatal("the HSM accepted the wrong AAD")
	}
	// A caller-chosen IV can't be used: the HSM generates every IV.
	if _, err := svc.Encrypt(ctx, key.ID, EncryptRequest{TenantID: "t1", PlaintextB64: b64([]byte("x")), IVMode: "external", IVB64: b64(make([]byte, 12))}); hsmRefusalReason(err) != "iv_mode_not_supported" {
		t.Fatalf("external IV: %v", err)
	}

	// Anything that needs the material is refused and audited.
	if _, err := svc.ExportCurrentVersionWrapped(ctx, "t1", key.ID, ""); err == nil {
		t.Fatal("an HSM key was exported")
	}
	if _, err := svc.decryptMaterial(ver); hsmRefusalReason(err) != "hsm_operation_unsupported" {
		t.Fatalf("material read: %v", err)
	}
	if d := refusalDetails(t, rec, "audit.key.hsm_refused"); d["reason"] != "material_in_hsm" {
		t.Fatalf("material refusal: %+v", d)
	}

	// Rotation makes a new key in the HSM; the new version encrypts.
	v2, err := svc.RotateKey(ctx, "t1", key.ID, "scheduled", "deactivate")
	if err != nil {
		t.Fatal(err)
	}
	if v2.Protection != protectionHSMResident || v2.HSMLabel != hsm.KeyLabel("t1", key.ID, 2) {
		t.Fatalf("rotated version: %+v", v2)
	}
	if _, err := svc.Encrypt(ctx, key.ID, EncryptRequest{TenantID: "t1", PlaintextB64: b64([]byte("after rotation"))}); err != nil {
		t.Fatalf("encrypt with v2: %v", err)
	}

	// Destroying the key destroys every version in the HSM.
	if err := svc.DestroyKeyImmediately(ctx, "t1", key.ID, "test cleanup of HSM key", "tester", "", ""); err != nil {
		t.Fatal(err)
	}
	for v := 1; v <= 2; v++ {
		if _, _, err := client.Encrypt(context.Background(), "t1", hsm.KeyLabel("t1", key.ID, v), []byte("x"), nil); !errors.Is(err, hsm.ErrNotFound) {
			t.Fatalf("v%d still in the HSM: %v", v, err)
		}
	}
	if ev := rec.find("audit.key.hsm_objects_destroyed"); ev == nil {
		t.Fatal("HSM destruction not audited")
	}
}

// Signatures made in the HSM verify with standard software against the
// public key keycore stores.
func TestHSMResidentSigningKeys(t *testing.T) {
	svc, _, _ := newHSMService(t, "t1")
	ctx := adminCtx()
	if _, err := svc.UpdateHSMSettings(ctx, HSMSettings{TenantID: "t1", HSMKeysEnabled: true}); err != nil {
		t.Fatal(err)
	}
	data := []byte("release manifest")
	for _, alg := range []string{"ECDSA-P256", "ECDSA-P384", "RSA-3072"} {
		key, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t1", Name: alg, Algorithm: alg, Purpose: "sign", Owner: "ops", HSM: true})
		if err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		sig, err := svc.Sign(ctx, key.ID, SignRequest{TenantID: "t1", DataB64: b64(data)})
		if err != nil {
			t.Fatalf("%s sign: %v", alg, err)
		}
		raw, _ := base64.StdEncoding.DecodeString(sig.SignatureB64)
		ver, _ := svc.store.GetVersion(context.Background(), "t1", key.ID, 1)
		pub, err := x509.ParsePKIXPublicKey(ver.PublicKey)
		if err != nil {
			t.Fatalf("%s public key: %v", alg, err)
		}
		switch k := pub.(type) {
		case *ecdsa.PublicKey:
			h := stdcrypto.SHA256
			if strings.HasSuffix(alg, "384") {
				h = stdcrypto.SHA384
			}
			hh := h.New()
			hh.Write(data)
			if !ecdsa.VerifyASN1(k, hh.Sum(nil), raw) {
				t.Fatalf("%s: HSM signature doesn't verify in software", alg)
			}
		case *rsa.PublicKey:
			sum := sha256.Sum256(data)
			if err := rsa.VerifyPSS(k, stdcrypto.SHA256, sum[:], raw, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
				t.Fatalf("%s: %v", alg, err)
			}
		}
		// The public half can be exported (for verifiers outside the KMS).
		if exp, err := svc.ExportPublicComponentPlaintext(ctx, "t1", key.ID); err != nil || exp.PublicKeyPlaintext != b64(ver.PublicKey) {
			t.Fatalf("%s public export: %v", alg, err)
		}
		for name, d := range map[string][]byte{"valid": data, "tampered": []byte("release manifesT")} {
			res, err := svc.Verify(ctx, key.ID, VerifyRequest{TenantID: "t1", DataB64: b64(d), SignatureB64: sig.SignatureB64})
			if err != nil || res.Verified != (name == "valid") {
				t.Fatalf("%s verify %s: %v %+v", alg, name, err, res)
			}
		}
	}
	// Algorithms the HSM integration doesn't cover are refused at creation.
	if _, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t1", Name: "ed", Algorithm: "Ed25519", Owner: "ops", HSM: true}); hsmRefusalReason(err) != "algorithm_not_supported" {
		t.Fatalf("Ed25519 in HSM: %v", err)
	}
}

// With the tenant key on, new key versions have their data key encrypted by
// the tenant's key in the HSM. Keys created before keep the master key.
func TestTenantHSMKeyProtectsNewKeys(t *testing.T) {
	svc, rec, _ := newHSMService(t, "t2")
	ctx := adminCtx()
	mk := func(name string) Key {
		k, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t2", Name: name, Algorithm: "AES-256", Purpose: "encrypt", Owner: "ops"})
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	roundTrip := func(k Key) {
		t.Helper()
		enc, err := svc.Encrypt(ctx, k.ID, EncryptRequest{TenantID: "t2", PlaintextB64: b64([]byte("payload"))})
		if err != nil {
			t.Fatalf("%s encrypt: %v", k.Name, err)
		}
		dec, err := svc.Decrypt(ctx, k.ID, DecryptRequest{TenantID: "t2", CiphertextB64: enc.CipherB64, IVB64: enc.IVB64})
		if err != nil || dec.PlainB64 != b64([]byte("payload")) {
			t.Fatalf("%s decrypt: %v", k.Name, err)
		}
	}
	protection := func(k Key) KeyVersion {
		v, err := svc.store.GetVersion(context.Background(), "t2", k.ID, k.CurrentVersion)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}

	before := mk("before")
	st, err := svc.UpdateHSMSettings(ctx, HSMSettings{TenantID: "t2", TenantKeyEnabled: true, UpdatedBy: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	if st.TenantKeyLabel != hsm.TenantKeyLabel("t2") {
		t.Fatalf("tenant key label: %q", st.TenantKeyLabel)
	}
	after := mk("after")
	if v := protection(before); v.Protection != protectionMEK {
		t.Fatalf("existing key changed protection: %q", v.Protection)
	}
	v := protection(after)
	if v.Protection != protectionTenantHSM || v.HSMLabel != st.TenantKeyLabel {
		t.Fatalf("new key: %q %q", v.Protection, v.HSMLabel)
	}
	// keycore's master key alone can't open the new key's material.
	wiv, wrapped, _ := unpackWrappedDEK(v.WrappedDEK)
	if _, err := crypto.DecryptEnvelope(svc.mek, &crypto.EnvelopeCiphertext{WrappedDEK: wrapped, WrappedDEKIV: wiv, Ciphertext: v.EncryptedMaterial, DataIV: v.MaterialIV}); err == nil {
		t.Fatal("the master key opened material protected by the tenant's HSM key")
	}
	roundTrip(before)
	roundTrip(after)
	// Rotation keeps the tenant key.
	if nv, err := svc.RotateKey(ctx, "t2", after.ID, "manual", "keep-active"); err != nil || nv.Protection != protectionTenantHSM {
		t.Fatalf("rotate: %v %q", err, nv.Protection)
	}

	// Off again: new keys go back to the master key; the HSM-protected one
	// still works.
	if _, err := svc.UpdateHSMSettings(ctx, HSMSettings{TenantID: "t2", TenantKeyEnabled: false}); err != nil {
		t.Fatal(err)
	}
	if v := protection(mk("later")); v.Protection != protectionMEK {
		t.Fatalf("after turning off: %q", v.Protection)
	}
	after, _ = svc.GetKey(ctx, "t2", after.ID)
	roundTrip(after)

	// The HSM unreachable: HSM-protected keys stop working, and turning the
	// tenant key on is refused, audited.
	down := httptest.NewServer(http.NotFoundHandler())
	down.Close()
	svc.SetHSMBackend(hsm.New(down.URL))
	if _, err := svc.Encrypt(ctx, after.ID, EncryptRequest{TenantID: "t2", PlaintextB64: b64([]byte("x"))}); err == nil {
		t.Fatal("HSM-protected key worked without the HSM")
	}
	if _, err := svc.UpdateHSMSettings(ctx, HSMSettings{TenantID: "t2", TenantKeyEnabled: true}); hsmRefusalReason(err) != "hsm_unavailable" {
		t.Fatalf("enable with HSM down: %v", err)
	}
	if d := refusalDetails(t, rec, "audit.key.hsm_refused"); d["reason"] != "hsm_unavailable" {
		t.Fatalf("refusal: %+v", d)
	}
}

// A tenant without an HSM profile can't turn the switches on.
func TestHSMSettingsNeedAConfiguredHSM(t *testing.T) {
	svc, _, _ := newHSMService(t, "t1")
	if _, err := svc.UpdateHSMSettings(adminCtx(), HSMSettings{TenantID: "t9", HSMKeysEnabled: true}); hsmRefusalReason(err) != "hsm_not_configured" {
		t.Fatalf("unconfigured tenant: %v", err)
	}
}

func TestHSMRoutesRefusalsAudited(t *testing.T) {
	h, _, _ := newActorTestHandler(t)
	rec := &routetest.Recorder{}
	routetest.RefusalsAudited(t, h.hsmRouter(rec), rec)
}
