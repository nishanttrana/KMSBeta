package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/hsm"
	"vecta-kms/pkg/hsmconnector/softhsmtest"
)

// A software-mode key is only in the file handed to the operator. The
// stored package carries its fingerprint and says it isn't retained.
func TestSoftwareBackupKeyIsNotStored(t *testing.T) {
	key, _ := pkgcrypto.RandomBytes(32)
	file, stored, err := (&Service{}).buildBackupKeyPackage(context.Background(), key, false, backupHSMBinding{}, "root", "root", "", backupCoverageSummary{})
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
	if backupKeyRetained(roundTripJSON(t, stored)) {
		t.Fatal("a software package counts as retained")
	}
}

// An HSM-bound backup key is wrapped inside the tenant's HSM under its
// tenant key (a real PKCS#11 library, SoftHSM2), and only that key opens it.
func TestHSMBoundBackupKeyWrappedByHSM(t *testing.T) {
	srv := softhsmtest.Start(t, "kms-governance", "root", "t1")
	svc := &Service{hsm: hsm.New(srv.URL)}
	ctx := context.Background()
	key, _ := pkgcrypto.RandomBytes(32)
	file, stored, err := svc.buildBackupKeyPackage(ctx, key, true, backupHSMBinding{ProviderName: "softhsm2"}, "t1", "root", "t1", backupCoverageSummary{})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(stored)
	if _, ok := file["backup_key_b64"]; ok || strings.Contains(string(raw), base64.StdEncoding.EncodeToString(key)) {
		t.Fatal("hsm_bound package carries the plaintext key")
	}
	pkg := roundTripJSON(t, stored)
	if pkg["key_wrap"] != backupKeyWrapHSM || pkg["hsm_key_label"] != hsm.TenantKeyLabel("t1") || !backupKeyRetained(pkg) {
		t.Fatalf("package: %s", raw)
	}
	got, err := svc.unwrapHSMBoundKey(ctx, pkg)
	if err != nil || string(got) != string(key) {
		t.Fatalf("unwrap: %v", err)
	}

	// Pointed at another tenant's HSM key, moved to another tenant pair, or
	// tampered with, it doesn't open.
	cases := map[string]func(map[string]interface{}){
		"other tenant key": func(p map[string]interface{}) {
			p["hsm_tenant_id"], p["hsm_key_label"] = "root", hsm.TenantKeyLabel("root")
		},
		"label outside tenant": func(p map[string]interface{}) { p["hsm_key_label"] = hsm.TenantKeyLabel("root") },
		"rebound target":       func(p map[string]interface{}) { p["target_tenant_id"] = "t2" },
		"tampered": func(p map[string]interface{}) {
			w, _ := base64.StdEncoding.DecodeString(p["wrapped_key_b64"].(string))
			w[0] ^= 1
			p["wrapped_key_b64"] = base64.StdEncoding.EncodeToString(w)
		},
	}
	if _, err := svc.backupHSM().EnsureTenantKey(ctx, "root"); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range cases {
		p := roundTripJSON(t, stored)
		mutate(p)
		if _, err := svc.unwrapHSMBoundKey(ctx, p); err == nil {
			t.Fatalf("%s: opened", name)
		}
	}
}

// Packages from the secret-derived wraps (raw SHA-256 "v1", HKDF "v2") are
// refused: the HSM never held their key.
func TestRetiredHSMBoundFormatsAreRefused(t *testing.T) {
	svc := &Service{}
	for _, kd := range []string{"v1", "v2"} {
		pkg := map[string]interface{}{"mode": "hsm_bound", "key_derivation": kd, "wrapped_key_b64": "AAAA", "wrap_nonce_b64": "AAAA"}
		if _, err := svc.unwrapHSMBoundKey(context.Background(), pkg); err == nil || !strings.Contains(err.Error(), "retired") {
			t.Fatalf("%s package: %v", kd, err)
		}
		if backupKeyRetained(pkg) {
			t.Fatalf("a %s package counts as retained", kd)
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
