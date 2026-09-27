package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/route/routetest"
)

func releaseAs(h *Handler, claims *pkgauth.Claims, keyID string, body map[string]any) (*httptest.ResponseRecorder, map[string]any) {
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/keys/"+keyID+"/attested-release", bytes.NewReader(raw))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims)))
	out := map[string]any{}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr, out
}

func serviceClaims(clientID string) *pkgauth.Claims {
	return &pkgauth.Claims{ClientID: clientID, TenantID: "root", Role: "client-service", Permissions: []string{"service.internal"}}
}

// A release returns the key's material sealed to the enclave's public key:
// only that private key opens it, bound to tenant, key, version and release.
// Only the confidential service may ask, and only for an active exportable
// key; every outcome is audited as audit.key.attested_release.
func TestAttestedReleaseSealsToRecipientOnlyForConfidentialService(t *testing.T) {
	h, svc := newHandlerForTest(t)
	rec := &routetest.Recorder{}
	h.kernelAudit = rec
	ctx := context.Background()
	key, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t1", Name: "enclave-key", Algorithm: "AES-256", KeyType: "symmetric",
		Purpose: "encrypt", Owner: "ops", CreatedBy: "tester", ExportAllowed: true})
	if err != nil {
		t.Fatal(err)
	}
	enclave, _ := rsa.GenerateKey(rand.Reader, 3072)
	der, _ := x509.MarshalPKIXPublicKey(&enclave.PublicKey)
	body := map[string]any{"tenant_id": "t1", "recipient_public_key": base64.StdEncoding.EncodeToString(der),
		"release_id": "rel_1", "attestation_document_hash": "sha256:abc", "provider": "aws_nitro_enclaves"}

	rr, out := releaseAs(h, serviceClaims("kms-confidential"), key.ID, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("release: %d %s", rr.Code, rr.Body)
	}
	dec := func(k string) []byte { b, _ := base64.StdEncoding.DecodeString(out[k].(string)); return b }
	material, err := pkgcrypto.OpenFromRecipient(enclave, dec("wrapped_key"), dec("nonce"), dec("ciphertext"), []byte(out["aad"].(string)))
	if err != nil {
		t.Fatalf("enclave could not open the release: %v", err)
	}
	ver, _ := svc.GetVersion(ctx, "t1", key.ID, 0)
	want, _ := svc.decryptMaterial(ver)
	if !bytes.Equal(material, want) || out["aad"] != attestedReleaseAAD("t1", key.ID, 1, "rel_1") {
		t.Fatal("released material or binding differs from the key")
	}
	if e := rec.Last(t); e.Action != "attested_release" || e.Event.Result != "success" || e.Event.TargetID != key.ID {
		t.Fatalf("success event %+v", e)
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := pkgcrypto.OpenFromRecipient(other, dec("wrapped_key"), dec("nonce"), dec("ciphertext"), []byte(out["aad"].(string))); err == nil {
		t.Fatal("a different private key opened the release")
	}

	admin := &pkgauth.Claims{UserID: "u1", TenantID: "t1", Role: "admin", Permissions: []string{"*"}}
	for name, claims := range map[string]*pkgauth.Claims{"admin user": admin, "other service": serviceClaims("kms-dataprotect")} {
		if rr, _ := releaseAs(h, claims, key.ID, body); rr.Code != http.StatusForbidden {
			t.Fatalf("%s released a key: %d", name, rr.Code)
		}
		if e := rec.Last(t); e.Event.Result != "refused" {
			t.Fatalf("%s refusal not audited: %+v", name, e)
		}
	}

	noExport, _ := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t1", Name: "locked", Algorithm: "AES-256", KeyType: "symmetric",
		Purpose: "encrypt", Owner: "ops", CreatedBy: "tester"})
	if rr, _ := releaseAs(h, serviceClaims("kms-confidential"), noExport.ID, body); rr.Code != http.StatusForbidden {
		t.Fatalf("non-exportable key released: %d", rr.Code)
	}
	weak := map[string]any{}
	for k, v := range body {
		weak[k] = v
	}
	weak["recipient_public_key"] = base64.StdEncoding.EncodeToString([]byte("not a key"))
	if rr, _ := releaseAs(h, serviceClaims("kms-confidential"), key.ID, weak); rr.Code == http.StatusOK {
		t.Fatal("released to an invalid recipient key")
	}
	if rr, _ := releaseAs(h, serviceClaims("kms-confidential"), key.ID, map[string]any{"tenant_id": "t1", "recipient_public_key": body["recipient_public_key"]}); rr.Code == http.StatusOK {
		t.Fatal("released without a release id and attestation hash")
	}
}
