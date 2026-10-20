package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"vecta-kms/pkg/crypto"
	"vecta-kms/pkg/fips/fipstest"
)

func jwaCall(t *testing.T, h *Handler, keyID, op string, body map[string]any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	rr := httptest.NewRecorder()
	serveAsAdmin(h, rr, httptest.NewRequest(http.MethodPost, "/keys/"+keyID+"/"+op, bytes.NewReader(raw)))
	out := map[string]any{}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out
}

// A256KW output is RFC 3394 under the key's own material, with no IV beside
// it, and unwraps without a version after the key rotates: the version that
// wrapped it is found by its integrity check.
func TestWrapAlgorithmA256KWSurvivesRotation(t *testing.T) {
	fipstest.SkipIfStrict(t, "AES key wrap outside the module")
	h, svc := newHandlerForTest(t)
	ctx := adminCtx()
	key, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t1", Name: "azure-kek", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "wrap", Owner: "ops", CreatedBy: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	dek := bytes.Repeat([]byte{0x5a}, 32)
	dekB64 := base64.StdEncoding.EncodeToString(dek)
	for _, alg := range []string{crypto.JWAA256KW, crypto.JWAA256KWP} {
		code, out := jwaCall(t, h, key.ID, "wrap", map[string]any{"tenant_id": "t1", "plaintext": dekB64, "wrap_algorithm": alg})
		if code != http.StatusOK {
			t.Fatalf("%s wrap: %d %v", alg, code, out)
		}
		wrapped, _ := base64.StdEncoding.DecodeString(out["ciphertext"].(string))
		if iv, _ := out["iv"].(string); iv != "" {
			t.Fatalf("%s wrap returned an IV: %q", alg, iv)
		}
		if alg == crypto.JWAA256KW && len(wrapped) != 40 {
			t.Fatalf("A256KW of 32 bytes is %d bytes, want 40", len(wrapped))
		}
		if _, err := svc.RotateKey(ctx, "t1", key.ID, "test", ""); err != nil {
			t.Fatal(err)
		}
		code, out = jwaCall(t, h, key.ID, "unwrap", map[string]any{"tenant_id": "t1", "ciphertext": out["ciphertext"], "wrap_algorithm": alg})
		if code != http.StatusOK || out["plaintext"] != dekB64 {
			t.Fatalf("%s unwrap after rotation: %d %v", alg, code, out)
		}
		// The version reported is the one that wrapped it, not the current.
		if v, _ := out["version"].(float64); int(v) >= int(currentKey(t, svc, key.ID).CurrentVersion) {
			t.Fatalf("%s unwrap reported version %v", alg, out["version"])
		}
		wrapped[len(wrapped)-1] ^= 1
		code, out = jwaCall(t, h, key.ID, "unwrap", map[string]any{"tenant_id": "t1", "ciphertext": base64.StdEncoding.EncodeToString(wrapped), "wrap_algorithm": alg})
		if code == http.StatusOK {
			t.Fatalf("%s: a tampered blob unwrapped: %v", alg, out)
		}
	}
}

func currentKey(t *testing.T, svc *Service, id string) Key {
	t.Helper()
	k, err := svc.GetKey(adminCtx(), "t1", id)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestWrapAlgorithmRSAOAEP256RoundTrips(t *testing.T) {
	h, svc := newHandlerForTest(t)
	key, err := svc.CreateKey(context.Background(), CreateKeyRequest{TenantID: "t1", Name: "azure-rsa", Algorithm: "RSA-3072", KeyType: "asymmetric", Purpose: "wrap", Owner: "ops", CreatedBy: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	dekB64 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	code, out := jwaCall(t, h, key.ID, "wrap", map[string]any{"tenant_id": "t1", "plaintext": dekB64, "wrap_algorithm": crypto.JWARSAOAEP256})
	if code != http.StatusOK {
		t.Fatalf("wrap: %d %v", code, out)
	}
	if w, _ := base64.StdEncoding.DecodeString(out["ciphertext"].(string)); len(w) != 384 {
		t.Fatalf("RSA-3072 OAEP output is %d bytes", len(w))
	}
	code, out = jwaCall(t, h, key.ID, "unwrap", map[string]any{"tenant_id": "t1", "ciphertext": out["ciphertext"], "wrap_algorithm": crypto.JWARSAOAEP256})
	if code != http.StatusOK || out["plaintext"] != dekB64 {
		t.Fatalf("unwrap: %d %v", code, out)
	}
	// An AES algorithm on an RSA key is refused.
	if code, _ := jwaCall(t, h, key.ID, "wrap", map[string]any{"tenant_id": "t1", "plaintext": dekB64, "wrap_algorithm": crypto.JWAA256KW}); code == http.StatusOK {
		t.Fatal("A256KW accepted on an RSA key")
	}
}

func TestWrapAlgorithmRefusals(t *testing.T) {
	h, svc := newHandlerForTest(t)
	key, err := svc.CreateKey(context.Background(), CreateKeyRequest{TenantID: "t1", Name: "k", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt", Owner: "ops", CreatedBy: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	dekB64 := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if code, _ := jwaCall(t, h, key.ID, "wrap", map[string]any{"tenant_id": "t1", "plaintext": dekB64, "wrap_algorithm": "A128GCMKW"}); code != http.StatusBadRequest {
		t.Fatalf("unknown wrap_algorithm: %d", code)
	}
	if code, _ := jwaCall(t, h, key.ID, "encrypt", map[string]any{"tenant_id": "t1", "plaintext": dekB64, "wrap_algorithm": crypto.JWARSAOAEP256}); code != http.StatusBadRequest {
		t.Fatalf("wrap_algorithm on encrypt: %d", code)
	}
}

func TestWrapAlgorithmStrictModeRefusesNonModule(t *testing.T) {
	fipstest.StrictOnly(t)
	for _, alg := range []string{crypto.JWAA256KW, crypto.JWAA256KWP, crypto.JWARSAOAEP} {
		var fipsErr fipsModeViolationError
		if err := checkWrapAlgorithm("wrap", alg); !errors.As(err, &fipsErr) {
			t.Fatalf("%s in strict mode: %v", alg, err)
		}
	}
	if err := checkWrapAlgorithm("wrap", crypto.JWARSAOAEP256); err != nil {
		t.Fatalf("RSA-OAEP-256 in strict mode: %v", err)
	}
}

// The two calls the hyok service makes for AWS XKS, against the real
// handler: AES-GCM with AAD and an internal IV, and a decrypt naming the
// version after the key rotated (services/hyok/keycore_client.go).
func TestEncryptWithAADDecryptsByVersionAfterRotation(t *testing.T) {
	h, svc := newHandlerForTest(t)
	ctx := adminCtx()
	key, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t1", Name: "xks", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt", Owner: "ops", CreatedBy: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	plain := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	aad := base64.StdEncoding.EncodeToString([]byte{0, 3, 'a', 'b', 'c', 5, 1, 0, 0, 0, 1})
	code, enc := jwaCall(t, h, key.ID, "encrypt", map[string]any{"tenant_id": "t1", "plaintext": plain, "aad": aad, "iv_mode": "internal", "reference_id": "kms-req-1"})
	if code != http.StatusOK {
		t.Fatalf("encrypt: %d %v", code, enc)
	}
	ct, _ := base64.StdEncoding.DecodeString(enc["ciphertext"].(string))
	iv, _ := base64.StdEncoding.DecodeString(enc["iv"].(string))
	if len(ct) != 32+16 || len(iv) != 12 || enc["version"].(float64) != 1 {
		t.Fatalf("ciphertext %d bytes, iv %d bytes, version %v", len(ct), len(iv), enc["version"])
	}
	if _, err := svc.RotateKey(ctx, "t1", key.ID, "test", ""); err != nil {
		t.Fatal(err)
	}
	code, out := jwaCall(t, h, key.ID, "decrypt", map[string]any{"tenant_id": "t1", "ciphertext": enc["ciphertext"], "iv": enc["iv"], "aad": aad, "version": 1})
	if code != http.StatusOK || out["plaintext"] != plain {
		t.Fatalf("decrypt of version 1 after rotation: %d %v", code, out)
	}
	code, _ = jwaCall(t, h, key.ID, "decrypt", map[string]any{"tenant_id": "t1", "ciphertext": enc["ciphertext"], "iv": enc["iv"], "aad": base64.StdEncoding.EncodeToString([]byte("other")), "version": 1})
	if code == http.StatusOK {
		t.Fatal("decrypted with another AAD")
	}
}
