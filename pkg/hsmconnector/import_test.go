package hsmconnector

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"net/http"
	"strings"
	"testing"

	"vecta-kms/pkg/hsm"
)

// An RSA or ECDSA private key made elsewhere is placed in the HSM as a
// generated one would be: a token object, sensitive, never extractable,
// that the HSM says it did not generate. It signs there, and the signature
// verifies in software under the public key of the key that was sent.
func TestImportedPrivateKeySignsInHSM(t *testing.T) {
	h, rec := newTestHandler(t)
	keycore := service("kms-keycore")
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	pkcs8 := func(k any) []byte {
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	sec1, _ := x509.MarshalECPrivateKey(p384)
	digest := sha256.Sum256([]byte("release-2.0.0.tar.gz"))
	for alg, c := range map[string]struct {
		der []byte
		pub any
	}{
		"RSA-2048":   {x509.MarshalPKCS1PrivateKey(rsaKey), &rsaKey.PublicKey},
		"ECDSA-P256": {pkcs8(p256), &p256.PublicKey},
		"ECDSA-P384": {sec1, &p384.PublicKey},
	} {
		label := hsm.KeyLabel("t1", "imp_"+strings.ToLower(alg), 1)
		code, out := call(t, h, keycore, http.MethodPost, "/hsm/keys/import", map[string]string{"tenant_id": "t1", "label": label, "algorithm": alg, "material_b64": b64s(c.der)})
		if code != http.StatusCreated {
			t.Fatalf("%s import: %d %v", alg, code, out)
		}
		if ev := rec.Last(t); ev.Action != "key_imported" || ev.Event.Result != "success" || ev.Event.Details["algorithm"] != alg {
			t.Fatalf("%s audit: %+v", alg, ev.Event)
		}
		want, _ := x509.MarshalPKIXPublicKey(c.pub)
		if got := field(t, out, "public_key_b64"); !bytes.Equal(got, want) {
			t.Fatalf("%s: the HSM answered with another public key", alg)
		}
		code, out = call(t, h, keycore, http.MethodPost, "/hsm/keys/inspect", map[string]string{"tenant_id": "t1", "label": label})
		objs, _ := objectsFrom(t, out)
		if code != http.StatusOK || len(objs) != 2 {
			t.Fatalf("%s inspect: %d %v", alg, code, out)
		}
		private := 0
		for _, o := range objs {
			if o.Class != "private_key" {
				continue
			}
			private++
			if !isTrue(o.Sensitive) || !isFalse(o.Extractable) || !isFalse(o.Local) {
				t.Fatalf("%s private key attributes: sensitive=%v extractable=%v local=%v", alg, o.Sensitive, o.Extractable, o.Local)
			}
		}
		if private != 1 {
			t.Fatalf("%s: %d private key objects: %+v", alg, private, objs)
		}
		code, out = call(t, h, keycore, http.MethodPost, "/hsm/sign", map[string]string{"tenant_id": "t1", "label": label, "hash": "SHA-256", "digest_b64": b64s(digest[:])})
		if code != http.StatusOK {
			t.Fatalf("%s sign: %d %v", alg, code, out)
		}
		if err := verifySoftware(c.pub, digest[:], field(t, out, "signature_b64")); err != nil {
			t.Fatalf("%s: the HSM's signature does not verify under the imported key's public key: %v", alg, err)
		}
		// The label is taken: a second import is refused and changes nothing.
		if code, _ := call(t, h, keycore, http.MethodPost, "/hsm/keys/import", map[string]string{"tenant_id": "t1", "label": label, "algorithm": alg, "material_b64": b64s(c.der)}); code != http.StatusConflict {
			t.Fatalf("%s: a second import under the same label: %d", alg, code)
		}
		call(t, h, keycore, http.MethodPost, "/hsm/keys/destroy", map[string]string{"tenant_id": "t1", "label": label})
	}

	// What is not such a key is refused, and leaves nothing in the HSM.
	p224, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	pubOnly, _ := x509.MarshalPKIXPublicKey(&p256.PublicKey)
	refused := map[string]map[string]string{
		"another algorithm than named":  {"algorithm": "RSA-2048", "material_b64": b64s(pkcs8(p256))},
		"a curve the platform excludes": {"algorithm": "ECDSA-P256", "material_b64": b64s(pkcs8(p224))},
		"a public key":                  {"algorithm": "ECDSA-P256", "material_b64": b64s(pubOnly)},
		"not a key":                     {"algorithm": "RSA-2048", "material_b64": b64s([]byte("0123456789abcdef0123456789abcdef"))},
		"an algorithm with no HSM form": {"algorithm": "ED25519", "material_b64": b64s(pkcs8(p256))},
	}
	// A 1024-bit key can only be made for the test outside strict FIPS
	// mode, where the module itself refuses to generate one.
	if small, err := rsa.GenerateKey(rand.Reader, 1024); err == nil {
		refused["a size the HSM path excludes"] = map[string]string{"algorithm": "RSA-2048", "material_b64": b64s(x509.MarshalPKCS1PrivateKey(small))}
	}
	for name, body := range refused {
		label := hsm.KeyLabel("t1", "imp_refused", 1)
		body["tenant_id"], body["label"] = "t1", label
		if code, out := call(t, h, keycore, http.MethodPost, "/hsm/keys/import", body); code != http.StatusBadRequest {
			t.Fatalf("%s: %d %v", name, code, out)
		}
		if code, out := call(t, h, keycore, http.MethodPost, "/hsm/keys/inspect", map[string]string{"tenant_id": "t1", "label": label}); code == http.StatusOK {
			if objs, _ := objectsFrom(t, out); len(objs) != 0 {
				t.Fatalf("%s left %d objects in the HSM", name, len(objs))
			}
		}
	}
}

// AES material can be brought into an HSM that refuses to create a secret
// key from a value: the HSM makes a session RSA key pair, the material is
// wrapped to it (RSA-OAEP, SHA-256) and unwrapped inside the HSM. The key
// is the one that was sent (same check value as the same material placed
// directly), never extractable, and the session pair is gone afterwards.
func TestAESImportByUnwrapInTheHSM(t *testing.T) {
	h, rec := newTestHandler(t)
	keycore := service("kms-keycore")
	material := []byte("fedcba9876543210fedcba9876543210")
	direct := hsm.KeyLabel("t1", "imp_direct", 1)
	code, out := call(t, h, keycore, http.MethodPost, "/hsm/keys/import", map[string]string{"tenant_id": "t1", "label": direct, "algorithm": "AES-256", "material_b64": b64s(material), "import_method": "create_object"})
	if code != http.StatusCreated || out["import_method"] != "create_object" {
		t.Fatalf("direct import: %d %v", code, out)
	}
	wantKCV := field(t, out, "kcv_b64")

	label := hsm.KeyLabel("t1", "imp_unwrap", 1)
	code, out = call(t, h, keycore, http.MethodPost, "/hsm/keys/import", map[string]string{"tenant_id": "t1", "label": label, "algorithm": "AES-256", "material_b64": b64s(material), "import_method": "unwrap"})
	if code == http.StatusConflict && strings.Contains(strings.ToUpper(errorMessage(out)), "C_UNWRAPKEY") &&
		(strings.Contains(errorMessage(out), "CKR_ARGUMENTS_BAD") || strings.Contains(errorMessage(out), "CKR_MECHANISM_PARAM_INVALID") || strings.Contains(errorMessage(out), "CKR_MECHANISM_INVALID")) {
		// The refusal itself is real behaviour worth keeping: audited, and
		// nothing left behind.
		if ev := rec.Last(t); ev.Event.Result != "refused" {
			t.Fatalf("refusal audit: %+v", ev.Event)
		}
		t.Skipf("this PKCS#11 library does not unwrap with RSA-OAEP and SHA-256 (SoftHSM2 before 2.7 supports SHA-1 only): %s", errorMessage(out))
	}
	if code != http.StatusCreated || out["import_method"] != "unwrap" {
		t.Fatalf("unwrap import: %d %v", code, out)
	}
	if ev := rec.Last(t); ev.Action != "key_imported" || ev.Event.Details["import_method"] != "unwrap" {
		t.Fatalf("audit: %+v", ev.Event)
	}
	if got := field(t, out, "kcv_b64"); len(got) != 3 || !bytes.Equal(got, wantKCV) {
		t.Fatalf("the unwrapped key is not the material sent: kcv %x, want %x", got, wantKCV)
	}
	code, out = call(t, h, keycore, http.MethodPost, "/hsm/keys/inspect", map[string]string{"tenant_id": "t1", "label": label})
	objs, _ := objectsFrom(t, out)
	// Its length is proven by the check value above; SoftHSM2 does not set
	// CKA_VALUE_LEN on a key it unwrapped, so the size it reports is not
	// asserted here.
	if code != http.StatusOK || len(objs) != 1 || !isTrue(objs[0].Sensitive) || !isFalse(objs[0].Extractable) || !isFalse(objs[0].Local) {
		t.Fatalf("unwrapped key: %d %+v", code, objs)
	}
	// It decrypts what the directly placed copy of the same key encrypted.
	code, out = call(t, h, keycore, http.MethodPost, "/hsm/encrypt", map[string]string{"tenant_id": "t1", "label": direct, "plaintext_b64": b64s([]byte("payload")), "aad_b64": ""})
	if code != http.StatusOK {
		t.Fatalf("encrypt: %d %v", code, out)
	}
	code, dec := call(t, h, keycore, http.MethodPost, "/hsm/decrypt", map[string]string{"tenant_id": "t1", "label": label, "ciphertext_b64": b64s(field(t, out, "ciphertext_b64")), "iv_b64": b64s(field(t, out, "iv_b64")), "aad_b64": ""})
	if code != http.StatusOK || string(field(t, dec, "plaintext_b64")) != "payload" {
		t.Fatalf("decrypt with the unwrapped key: %d %v", code, dec)
	}
	for _, l := range []string{direct, label} {
		call(t, h, keycore, http.MethodPost, "/hsm/keys/destroy", map[string]string{"tenant_id": "t1", "label": l})
	}
	if code, _ := call(t, h, keycore, http.MethodPost, "/hsm/keys/import", map[string]string{"tenant_id": "t1", "label": label, "algorithm": "AES-256", "material_b64": b64s(material), "import_method": "telepathy"}); code != http.StatusBadRequest {
		t.Fatalf("an unknown import method: %d", code)
	}
}

func errorMessage(out map[string]interface{}) string {
	e, _ := out["error"].(map[string]interface{})
	msg, _ := e["message"].(string)
	return msg
}
