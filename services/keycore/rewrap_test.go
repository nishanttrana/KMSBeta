package main

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"vecta-kms/pkg/route/routetest"
)

// A rotation moves the key to a new algorithm under the same key ID; the old
// version still decrypts its ciphertext, rewrap moves that ciphertext onto the
// new version, and every refusal is audited.
func TestRotationChangesAlgorithmUnderSameKeyID(t *testing.T) {
	h, svc := newHandlerForTest(t)
	pub := &captureKeycorePublisher{}
	svc.events = pub
	rec := &routetest.Recorder{}
	h.kernelAudit = rec
	ctx := adminCtx()
	key, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t1", Name: "k", Algorithm: "AES-128", KeyType: "symmetric", Purpose: "encrypt", Owner: "ops", CreatedBy: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	secret := base64.StdEncoding.EncodeToString([]byte("secret"))
	old, err := svc.Encrypt(ctx, key.ID, EncryptRequest{TenantID: "t1", PlaintextB64: secret})
	if err != nil || old.Version != 1 {
		t.Fatalf("encrypt v1: %v %+v", err, old)
	}

	// Refused: a target that can't do what the key does, audited.
	if _, err := svc.RotateKeyTo(ctx, "t1", key.ID, "pqc", "", "ML-DSA-65"); !errors.Is(err, errAlgorithmChangeRefused) {
		t.Fatalf("encrypt key rotated onto a signature algorithm: %v", err)
	}
	if d := pub.details(t, "audit.key.algorithm_change_refused"); d["result"] != "refused" || d["to_algorithm"] != "ML-DSA-65" {
		t.Fatalf("refusal event %v", d)
	}

	ver, err := svc.RotateKeyTo(ctx, "t1", key.ID, "agility", "", "AES-256")
	if err != nil || ver.Version != 2 || ver.Algorithm != "AES-256" {
		t.Fatalf("rotate to AES-256: %v %+v", err, ver)
	}
	if d := pub.details(t, "audit.key.algorithm_changed"); d["from_algorithm"] != "AES-128" || d["to_algorithm"] != "AES-256" || d["result"] != "success" {
		t.Fatalf("change event %v", d)
	}
	if k, _ := svc.GetKey(ctx, "t1", key.ID); k.Algorithm != "AES-256" || k.ID != key.ID {
		t.Fatalf("key after rotation %+v", k)
	}
	if v1, _ := svc.store.GetVersion(ctx, "t1", key.ID, 1); v1.Algorithm != "AES-128" || v1.Status != "deactivated" {
		t.Fatalf("version 1 not pinned to its algorithm: %+v", v1)
	}

	// The deactivated old version still decrypts what it protected; the
	// current one does not, and an old version never encrypts.
	dec, err := svc.Decrypt(ctx, key.ID, DecryptRequest{TenantID: "t1", CiphertextB64: old.CipherB64, IVB64: old.IVB64, Version: 1})
	if err != nil || dec.PlainB64 != secret || dec.Version != 1 {
		t.Fatalf("decrypt v1: %v %+v", err, dec)
	}
	if _, err := svc.Decrypt(ctx, key.ID, DecryptRequest{TenantID: "t1", CiphertextB64: old.CipherB64, IVB64: old.IVB64}); err == nil {
		t.Fatal("v1 ciphertext decrypted under v2")
	}
	if _, err := svc.store.RunCryptoTxAt(ctx, "t1", key.ID, "encrypt", 1, func(Key, KeyVersion) (CryptoTxResult, error) { return CryptoTxResult{}, nil }); !errors.Is(err, errVersionRefused) {
		t.Fatalf("old version served encrypt: %v", err)
	}

	// Rewrap over HTTP: v1 ciphertext comes back under v2, audited.
	body := `{"ciphertext":"` + old.CipherB64 + `","iv":"` + old.IVB64 + `","version":1}`
	rr := httptest.NewRecorder()
	serveAsAdmin(h, rr, httptest.NewRequest(http.MethodPost, "/keys/"+key.ID+"/rewrap", strings.NewReader(body)))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"from_version":1`) || !strings.Contains(rr.Body.String(), `"version":2`) {
		t.Fatalf("rewrap: %d %s", rr.Code, rr.Body)
	}
	if e := rec.Last(t); e.Action != "ciphertext_rewrapped" || e.Event.Result != "success" {
		t.Fatalf("rewrap event %+v", e)
	}

	// Refused: a version the key doesn't have yet.
	rr = httptest.NewRecorder()
	serveAsAdmin(h, rr, httptest.NewRequest(http.MethodPost, "/keys/"+key.ID+"/rewrap",
		strings.NewReader(`{"ciphertext":"`+old.CipherB64+`","iv":"`+old.IVB64+`","version":`+strconv.Itoa(9)+`}`)))
	if rr.Code != http.StatusConflict {
		t.Fatalf("future version accepted: %d %s", rr.Code, rr.Body)
	}
	if e := rec.Last(t); e.Action != "ciphertext_rewrapped" || e.Event.Result != "refused" || e.Event.Details["reason"] != "version_refused" {
		t.Fatalf("rewrap refusal event %+v", e)
	}
}
