package hsmconnector

import (
	"bytes"
	"crypto/aes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/fips/fipstest"
	"vecta-kms/pkg/hsm"
)

func callAny(t *testing.T, h *Handler, claims *pkgauth.Claims, path string, body map[string]interface{}) (int, map[string]interface{}) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var out map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// A key generated for cloud import is wrapped inside the HSM to a cloud's
// RSA key; unwrapping with that key's private half (what the cloud does)
// yields the HSM key, proven by its check value computed in the HSM.
func TestBYOKWrapInsideHSM(t *testing.T) {
	h, rec := newTestHandler(t)
	keycore := service("kms-keycore")
	cloud, err := rsa.GenerateKey(pkgcrypto.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&cloud.PublicKey)
	label := hsm.KeyLabel("t1", "key_byok", 1)
	code, out := callAny(t, h, keycore, "/hsm/keys", map[string]interface{}{"tenant_id": "t1", "label": label, "algorithm": "AES-256", "extractable": true})
	if code != http.StatusCreated {
		t.Fatalf("generate: %d %v", code, out)
	}
	kcv := field(t, out, "kcv_b64")

	schemes := []string{pkgcrypto.CloudWrapRSAOAEPSHA256, pkgcrypto.CloudWrapRSAAESKWP256, pkgcrypto.CloudWrapRSAOAEPSHA1, pkgcrypto.CloudWrapRSAAESKWPSHA1}
	for _, scheme := range schemes {
		code, out := callAny(t, h, keycore, "/hsm/keys/wrap-for-import", map[string]interface{}{
			"tenant_id": "t1", "label": label, "wrapping_key_b64": b64s(der), "scheme": scheme, "digest": "sha256",
		})
		if code != http.StatusOK {
			t.Fatalf("%s: %d %v", scheme, code, out)
		}
		if ev := rec.Last(t); ev.Action != "key_wrapped_for_cloud" || ev.Event.Result != "success" || ev.Event.Details["scheme"] != scheme {
			t.Fatalf("%s audit: %+v", scheme, ev.Event)
		}
		if pkgcrypto.CloudWrapNeedsModuleOutside(scheme) {
			// The HSM did the wrapping; reading it back here needs KWP or
			// SHA-1 OAEP, which strict mode refuses in this process.
			fipstest.SkipIfStrict(t, "verifying a "+scheme+" blob outside the HSM")
		}
		material, err := pkgcrypto.UnwrapCloudImport(cloud, field(t, out, "wrapped_b64"), scheme)
		if err != nil {
			t.Fatalf("%s: the cloud can't unwrap: %v", scheme, err)
		}
		block, _ := aes.NewCipher(material)
		got := make([]byte, 16)
		block.Encrypt(got, make([]byte, 16))
		if !bytes.Equal(got[:3], kcv) {
			t.Fatalf("%s: unwrapped key's KCV %x, HSM key's %x", scheme, got[:3], kcv)
		}
		sum := sha256.Sum256(material)
		if !bytes.Equal(field(t, out, "material_sha256_b64"), sum[:]) {
			t.Fatalf("%s: C_DigestKey does not match the key", scheme)
		}
	}
}

// Every other platform key is never extractable: the HSM refuses to wrap
// it, and the refusal is audited. Only keycore may ask.
func TestBYOKWrapRefusals(t *testing.T) {
	h, rec := newTestHandler(t)
	keycore := service("kms-keycore")
	cloud, _ := rsa.GenerateKey(pkgcrypto.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&cloud.PublicKey)
	label := hsm.KeyLabel("t1", "key_fixed", 1)
	if code, out := callAny(t, h, keycore, "/hsm/keys", map[string]interface{}{"tenant_id": "t1", "label": label, "algorithm": "AES-256"}); code != http.StatusCreated {
		t.Fatalf("generate: %d %v", code, out)
	}
	body := map[string]interface{}{"tenant_id": "t1", "label": label, "wrapping_key_b64": b64s(der), "scheme": pkgcrypto.CloudWrapRSAOAEPSHA256}
	if code, out := callAny(t, h, keycore, "/hsm/keys/wrap-for-import", body); code != http.StatusConflict {
		t.Fatalf("non-extractable key wrapped: %d %v", code, out)
	}
	if ev := rec.Last(t); ev.Event.Result != "refused" || ev.Event.Details["reason"] != "key_not_extractable" {
		t.Fatalf("refusal audit: %+v", ev.Event)
	}
	if code, _ := callAny(t, h, service("kms-cloud"), "/hsm/keys/wrap-for-import", body); code != http.StatusForbidden {
		t.Fatalf("a service other than keycore asked to wrap: %d", code)
	}
	if ev := rec.Last(t); ev.Event.Result != "refused" || ev.Event.Details["reason"] != "caller_not_allowed" {
		t.Fatalf("caller refusal audit: %+v", ev.Event)
	}
}
