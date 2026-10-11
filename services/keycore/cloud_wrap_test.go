package main

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/fips/fipstest"
	"vecta-kms/pkg/route/routetest"
)

func cloudKey(t *testing.T, bits int) (*rsa.PrivateKey, string) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return k, base64.StdEncoding.EncodeToString(der)
}

// asService is a platform service's verified token, as servicetoken mints it.
func asService(id string) *pkgauth.Claims {
	c := serviceClaims(id)
	c.Subject = id
	return c
}

func cloudWrapAs(h *Handler, claims *pkgauth.Claims, keyID string, body map[string]any) (*httptest.ResponseRecorder, CloudWrapResponse) {
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/keys/"+keyID+"/cloud-wrap?tenant_id=t1", bytes.NewReader(raw))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r.WithContext(pkgauth.ContextWithClaims(r.Context(), claims)))
	var out struct {
		Data CloudWrapResponse `json:"data"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr, out.Data
}

// A KMS key is wrapped to the cloud's import key; the cloud's unwrap yields
// exactly the version asked for. Only the cloud service may ask, only for an
// exportable key, and every refusal is audited.
func TestCloudWrapKMSKey(t *testing.T) {
	h, svc := newHandlerForTest(t)
	rec := &routetest.Recorder{}
	h.kernelAudit = rec
	ctx := adminCtx()
	key, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t1", Name: "byok", Algorithm: "AES-256", KeyType: "symmetric",
		Purpose: "encrypt", Owner: "ops", CreatedBy: "tester", ExportAllowed: true})
	if err != nil {
		t.Fatal(err)
	}
	cloud, pubB64 := cloudKey(t, 3072)
	v1, _ := svc.GetVersion(ctx, "t1", key.ID, 1)
	want1, _ := svc.decryptMaterial(v1)

	rr, out := cloudWrapAs(h, asService("kms-cloud"), key.ID, map[string]any{"wrapping_key_b64": pubB64, "scheme": pkgcrypto.CloudWrapRSAOAEPSHA256, "digest": true})
	if rr.Code != http.StatusOK {
		t.Fatalf("cloud wrap: %d %s", rr.Code, rr.Body)
	}
	wrapped, _ := base64.StdEncoding.DecodeString(out.WrappedB64)
	got, err := pkgcrypto.UnwrapCloudImport(cloud, wrapped, pkgcrypto.CloudWrapRSAOAEPSHA256)
	if err != nil || !bytes.Equal(got, want1) || out.Source != "kms" || out.Version != 1 {
		t.Fatalf("cloud unwrap: %v source=%s version=%d", err, out.Source, out.Version)
	}
	if sum, _ := base64.StdEncoding.DecodeString(out.MaterialSHA256B64); !bytes.Equal(sum, pkgcrypto.SHA256(want1)) {
		t.Fatal("material digest differs")
	}
	if e := rec.Last(t); e.Action != "cloud_wrapped" || e.Event.Result != "success" || e.Event.Details["source"] != "kms" ||
		e.Event.Details["version"] != 1 || e.Event.Details["kcv"] != out.KCV || e.Event.Details["wrapping_key_sha256"] != out.WrappingKeySHA256 {
		t.Fatalf("success event %+v", e.Event)
	}

	// After a rotation, version 1 can still be wrapped again (reimport,
	// restore) and the current one is the new material.
	if _, err := svc.RotateKey(ctx, "t1", key.ID, "byok", ""); err != nil {
		t.Fatal(err)
	}
	_, again := cloudWrapAs(h, asService("kms-cloud"), key.ID, map[string]any{"wrapping_key_b64": pubB64, "scheme": pkgcrypto.CloudWrapRSAOAEPSHA256, "version": 1})
	w, _ := base64.StdEncoding.DecodeString(again.WrappedB64)
	if got, _ := pkgcrypto.UnwrapCloudImport(cloud, w, pkgcrypto.CloudWrapRSAOAEPSHA256); !bytes.Equal(got, want1) {
		t.Fatal("version 1 rewrap is not version 1's material")
	}
	_, cur := cloudWrapAs(h, asService("kms-cloud"), key.ID, map[string]any{"wrapping_key_b64": pubB64, "scheme": pkgcrypto.CloudWrapRSAOAEPSHA256})
	w, _ = base64.StdEncoding.DecodeString(cur.WrappedB64)
	if got, _ := pkgcrypto.UnwrapCloudImport(cloud, w, pkgcrypto.CloudWrapRSAOAEPSHA256); cur.Version != 2 || bytes.Equal(got, want1) {
		t.Fatalf("current version %d wrapped version 1's material", cur.Version)
	}

	refused := func(name string, claims *pkgauth.Claims, keyID string, body map[string]any, status int, reason string) {
		t.Helper()
		rr, _ := cloudWrapAs(h, claims, keyID, body)
		if rr.Code != status {
			t.Fatalf("%s: %d %s", name, rr.Code, rr.Body)
		}
		if e := rec.Last(t); e.Event.Result != "refused" || e.Event.Details["reason"] != reason {
			t.Fatalf("%s: refusal event %+v", name, e.Event)
		}
	}
	good := map[string]any{"wrapping_key_b64": pubB64, "scheme": pkgcrypto.CloudWrapRSAOAEPSHA256}
	admin := &pkgauth.Claims{UserID: "u1", TenantID: "t1", Role: "admin", Permissions: []string{"*"}}
	admin.Subject = "u1"
	refused("a user, not the cloud service", admin, key.ID, good, http.StatusForbidden, "caller_not_allowed")
	refused("another service", asService("kms-dataprotect"), key.ID, good, http.StatusForbidden, "caller_not_allowed")
	refused("unknown scheme", asService("kms-cloud"), key.ID, map[string]any{"wrapping_key_b64": pubB64, "scheme": "rsa-pkcs1"}, http.StatusBadRequest, "scheme_not_supported")
	if small, err := rsa.GenerateKey(rand.Reader, 1024); err == nil {
		der, _ := x509.MarshalPKIXPublicKey(&small.PublicKey)
		refused("1024-bit cloud key", asService("kms-cloud"), key.ID, map[string]any{"wrapping_key_b64": base64.StdEncoding.EncodeToString(der), "scheme": pkgcrypto.CloudWrapRSAOAEPSHA256}, http.StatusBadRequest, "bad_wrapping_key")
	}
	fixed, _ := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t1", Name: "fixed", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt", Owner: "ops", CreatedBy: "tester"})
	refused("export not allowed", asService("kms-cloud"), fixed.ID, good, http.StatusForbidden, "export_not_allowed")
}

// Strict FIPS mode refuses the schemes that run outside the module when the
// KMS wraps; rsa-oaep-sha256 still works.
func TestCloudWrapStrictModeRefusesNonModuleSchemes(t *testing.T) {
	fipstest.StrictOnly(t)
	h, svc := newHandlerForTest(t)
	rec := &routetest.Recorder{}
	h.kernelAudit = rec
	key, err := svc.CreateKey(adminCtx(), CreateKeyRequest{TenantID: "t1", Name: "byok", Algorithm: "AES-256", KeyType: "symmetric",
		Purpose: "encrypt", Owner: "ops", CreatedBy: "tester", ExportAllowed: true})
	if err != nil {
		t.Fatal(err)
	}
	_, pubB64 := cloudKey(t, 3072)
	for _, scheme := range []string{pkgcrypto.CloudWrapRSAOAEPSHA1, pkgcrypto.CloudWrapRSAAESKWP256, pkgcrypto.CloudWrapRSAAESKWPSHA1} {
		rr, _ := cloudWrapAs(h, asService("kms-cloud"), key.ID, map[string]any{"wrapping_key_b64": pubB64, "scheme": scheme})
		if rr.Code != http.StatusForbidden {
			t.Fatalf("%s: %d %s", scheme, rr.Code, rr.Body)
		}
		if e := rec.Last(t); e.Event.Details["reason"] != "fips_mode_violation" {
			t.Fatalf("%s: %+v", scheme, e.Event)
		}
	}
	if rr, _ := cloudWrapAs(h, asService("kms-cloud"), key.ID, map[string]any{"wrapping_key_b64": pubB64, "scheme": pkgcrypto.CloudWrapRSAOAEPSHA256}); rr.Code != http.StatusOK {
		t.Fatalf("rsa-oaep-sha256 in strict mode: %d %s", rr.Code, rr.Body)
	}
}

func TestCloudWrapRouteRefusalsAudited(t *testing.T) {
	h, _ := newHandlerForTest(t)
	rec := &routetest.Recorder{}
	routetest.RefusalsAudited(t, h.cloudWrapRouter(rec), rec)
}

// An HSM key created with cloud import allowed is wrapped inside the HSM,
// and so is each rotated version. A key created without it can't be made
// to leave by switching its export policy afterwards: the HSM refuses.
func TestCloudWrapHSMKey(t *testing.T) {
	svc, _, _ := newHSMService(t, "t1")
	ctx := adminCtx()
	if _, err := svc.UpdateHSMSettings(ctx, HSMSettings{TenantID: "t1", HSMKeysEnabled: true, UpdatedBy: "tester"}); err != nil {
		t.Fatal(err)
	}
	key, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t1", Name: "byok-hsm", Algorithm: "AES-256", Purpose: "encrypt", Owner: "ops", HSM: true, ExportAllowed: true})
	if err != nil {
		t.Fatal(err)
	}
	if key.Labels[labelHSMCloudImport] != "allowed" || !key.ExportAllowed {
		t.Fatalf("cloud import key: %v export=%v", key.Labels, key.ExportAllowed)
	}
	cloud, pubB64 := cloudKey(t, 3072)
	check := func(version int, kcv []byte) {
		t.Helper()
		out, err := svc.CloudWrap(ctx, key.ID, CloudWrapRequest{TenantID: "t1", WrappingKeyB64: pubB64, Scheme: pkgcrypto.CloudWrapRSAOAEPSHA256, Version: version})
		if err != nil || out.Source != "hsm" {
			t.Fatalf("hsm wrap v%d: %v %+v", version, err, out)
		}
		w, _ := base64.StdEncoding.DecodeString(out.WrappedB64)
		material, err := pkgcrypto.UnwrapCloudImport(cloud, w, pkgcrypto.CloudWrapRSAOAEPSHA256)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := aes.NewCipher(material)
		e := make([]byte, 16)
		block.Encrypt(e, make([]byte, 16))
		if !bytes.Equal(e[:3], kcv) {
			t.Fatalf("v%d: the cloud got a different key than the HSM holds", version)
		}
	}
	check(1, key.KCV)
	v2, err := svc.RotateKey(ctx, "t1", key.ID, "byok", "")
	if err != nil {
		t.Fatal(err)
	}
	check(2, v2.KCV)

	plain, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t1", Name: "stays", Algorithm: "AES-256", Purpose: "encrypt", Owner: "ops", HSM: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SetExportAllowed(ctx, "t1", plain.ID, true); err != nil {
		t.Fatal(err)
	}
	_, err = svc.CloudWrap(ctx, plain.ID, CloudWrapRequest{TenantID: "t1", WrappingKeyB64: pubB64, Scheme: pkgcrypto.CloudWrapRSAOAEPSHA256})
	var refusal *cloudWrapRefusal
	if !errors.As(err, &refusal) || refusal.reason != "key_not_extractable" {
		t.Fatalf("non-extractable HSM key wrapped: %v", err)
	}
}
