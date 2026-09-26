package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	pkgcrypto "vecta-kms/pkg/crypto"
)

const testWrapSecret = "3f1c9a7be2d04c6f8a1b5e9d2c7f4a0b6e8d1c3f5a7b9e0d2c4f6a8b0e1d3c5f"

var testBinding = backupHSMBinding{Enabled: true, ProviderName: "hsm", SlotID: "0", Fingerprint: "hsm|0|||abc", FingerprintHash: "fp"}

// A software-mode key is only in the file handed to the operator. The
// stored package carries its fingerprint and says it isn't retained.
func TestSoftwareBackupKeyIsNotStored(t *testing.T) {
	key, _ := pkgcrypto.RandomBytes(32)
	file, stored, err := buildBackupKeyPackage(key, false, backupHSMBinding{}, "root", "", backupCoverageSummary{})
	if err != nil {
		t.Fatal(err)
	}
	if file["backup_key_b64"] != base64.StdEncoding.EncodeToString(key) {
		t.Fatal("key file does not carry the key")
	}
	raw, _ := json.Marshal(stored)
	if _, ok := stored["backup_key_b64"]; ok || strings.Contains(string(raw), base64.StdEncoding.EncodeToString(key)) {
		t.Fatalf("stored package holds the key: %s", raw)
	}
	if stored["key_retained"] != false || stored["backup_key_sha256"] != sha256Hex(string(key)) {
		t.Fatalf("stored package: %s", raw)
	}
	var reparsed map[string]interface{}
	_ = json.Unmarshal(raw, &reparsed)
	if backupKeyRetained(reparsed) {
		t.Fatal("a software package counts as retained")
	}
}

// HSM-bound keys are wrapped under HKDF-SHA256(secret, binding, tenants),
// round-trip, and are bound to the binding and the tenants.
func TestHSMBoundBackupKeyUsesHKDF(t *testing.T) {
	t.Setenv("BACKUP_HSM_WRAP_SECRET", testWrapSecret)
	key, _ := pkgcrypto.RandomBytes(32)
	file, stored, err := buildBackupKeyPackage(key, true, testBinding, "root", "t1", backupCoverageSummary{})
	if err != nil {
		t.Fatal(err)
	}
	if file["key_derivation"] != backupKeyDerivationHKDF || stored["key_derivation"] != backupKeyDerivationHKDF {
		t.Fatalf("key_derivation = %v", file["key_derivation"])
	}
	if _, ok := file["backup_key_b64"]; ok {
		t.Fatal("hsm_bound package carries the plaintext key")
	}
	pkg := roundTripJSON(t, stored)
	if !backupKeyRetained(pkg) {
		t.Fatal("v2 hsm_bound package not retained")
	}
	got, err := unwrapHSMBoundKey(pkg, testBinding)
	if err != nil || string(got) != string(key) {
		t.Fatalf("unwrap: %v", err)
	}

	// The wrap key is the HKDF output, not a raw hash of the same input.
	wrapKey, _ := backupWrapKey(testWrapSecret, testBinding, "root", "t1")
	want, _ := pkgcrypto.HKDFSHA256([]byte(testWrapSecret), nil, []byte(backupWrapInfoLabel+"|"+testBinding.Fingerprint+"|root|t1"), 32)
	raw, _ := pkgcrypto.Hash("SHA-256", []byte(testWrapSecret+"|"+testBinding.Fingerprint+"|root|t1"))
	if string(wrapKey) != string(want) || string(wrapKey) == string(raw) {
		t.Fatal("wrap key is not HKDF-SHA256")
	}

	other := testBinding
	other.Fingerprint = "hsm|1|||abc"
	if _, err := unwrapHSMBoundKey(pkg, other); err == nil {
		t.Fatal("another HSM binding opened the key")
	}
	moved := roundTripJSON(t, stored)
	moved["target_tenant_id"] = "t2"
	if _, err := unwrapHSMBoundKey(moved, testBinding); err == nil {
		t.Fatal("a package rebound to another tenant opened")
	}
	t.Setenv("BACKUP_HSM_WRAP_SECRET", strings.Repeat("9", 64))
	if _, err := unwrapHSMBoundKey(pkg, testBinding); err == nil {
		t.Fatal("another wrap secret opened the key")
	}
}

// Packages from the raw SHA-256 derivation ("v1") are refused, even with the
// right secret and binding.
func TestHSMBoundV1PackageIsRefused(t *testing.T) {
	t.Setenv("BACKUP_HSM_WRAP_SECRET", testWrapSecret)
	key, _ := pkgcrypto.RandomBytes(32)
	derived, _ := pkgcrypto.Hash("SHA-256", []byte(testWrapSecret+"|"+testBinding.Fingerprint+"|root|"))
	aad := []byte("vecta-kms:backup:hsm-binding:" + testBinding.FingerprintHash)
	wrapped, nonce, err := encryptAESGCM(key, derived[:], aad)
	if err != nil {
		t.Fatal(err)
	}
	v1 := map[string]interface{}{
		"mode": "hsm_bound", "key_derivation": "v1", "request_tenant_id": "root", "target_tenant_id": "",
		"wrapped_key_b64": base64.StdEncoding.EncodeToString(wrapped),
		"wrap_nonce_b64":  base64.StdEncoding.EncodeToString(nonce),
		"wrap_aad_b64":    base64.StdEncoding.EncodeToString(aad),
	}
	if _, err := unwrapHSMBoundKey(v1, testBinding); err == nil || !strings.Contains(err.Error(), "retired") {
		t.Fatalf("v1 package: %v, want refusal", err)
	}
	if backupKeyRetained(v1) {
		t.Fatal("a v1 package counts as retained")
	}
}

// A missing or short wrap secret refuses both creating and opening.
func TestBackupWrapSecretStrength(t *testing.T) {
	key, _ := pkgcrypto.RandomBytes(32)
	for name, secret := range map[string]string{"missing": "", "short": "changeit-backup-secret"} {
		t.Setenv("BACKUP_HSM_WRAP_SECRET", secret)
		if _, _, err := buildBackupKeyPackage(key, true, testBinding, "root", "", backupCoverageSummary{}); err == nil {
			t.Fatalf("%s secret: backup created", name)
		}
		if _, err := backupWrapSecret(); err == nil {
			t.Fatalf("%s secret accepted", name)
		}
	}
}

func roundTripJSON(t *testing.T, v map[string]interface{}) map[string]interface{} {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
