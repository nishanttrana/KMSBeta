package hsmconnector

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/miekg/pkcs11"

	"vecta-kms/pkg/hsm"
)

func isTrue(b *bool) bool  { return b != nil && *b }
func isFalse(b *bool) bool { return b != nil && !*b }

func objectsFrom(t *testing.T, out map[string]interface{}) ([]hsm.ObjectInfo, hsm.Identity) {
	t.Helper()
	raw, _ := json.Marshal(out)
	var v struct {
		Objects []hsm.ObjectInfo `json:"objects"`
		HSM     hsm.Identity     `json:"hsm"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v.Objects, v.HSM
}

// Keys the KMS generates are read back from the HSM with the label, ID and
// attributes asked for: made on the token (CKA_LOCAL), sensitive and never
// extractable, with only the intended usages.
func TestGeneratedKeysHaveHSMAttributes(t *testing.T) {
	h, rec := newTestHandler(t)
	keycore := service("kms-keycore")
	cases := []struct {
		alg     string
		objects int
		keyType string
		bits    int
	}{
		{"AES-256", 1, "AES", 256},
		{"RSA-2048", 2, "RSA", 2048},
		{"ECDSA-P384", 2, "EC", 384},
	}
	for _, tc := range cases {
		label := hsm.KeyLabel("t1", "key_attr_"+tc.keyType, 1)
		code, out := call(t, h, keycore, http.MethodPost, "/hsm/keys", map[string]string{"tenant_id": "t1", "label": label, "algorithm": tc.alg})
		if code != http.StatusCreated {
			t.Fatalf("%s: %d %v", tc.alg, code, out)
		}
		_, id := objectsFrom(t, out)
		if id.TokenLabel != "vecta-a" || id.SerialNumber == "" || id.Manufacturer == "" {
			t.Fatalf("%s: generate didn't report the HSM: %+v", tc.alg, id)
		}
		code, out = call(t, h, keycore, http.MethodPost, "/hsm/keys/inspect", map[string]string{"tenant_id": "t1", "label": label})
		if code != http.StatusOK {
			t.Fatalf("%s inspect: %d %v", tc.alg, code, out)
		}
		if ev := rec.Last(t); ev.Action != "key_inspected" || ev.Event.Result != "success" {
			t.Fatalf("inspect audit: %+v", ev)
		}
		objs, _ := objectsFrom(t, out)
		if len(objs) != tc.objects {
			t.Fatalf("%s: %d objects, want %d", tc.alg, len(objs), tc.objects)
		}
		for _, o := range objs {
			if o.Label != label || o.IDHex != hex.EncodeToString([]byte(label)) || o.KeyType != tc.keyType || o.SizeBits != tc.bits {
				t.Fatalf("%s %s: label/id/type/size %+v", tc.alg, o.Class, o)
			}
			if !isTrue(o.Token) || !isTrue(o.Local) || !o.Managed {
				t.Fatalf("%s %s: not a token object generated on the HSM: %+v", tc.alg, o.Class, o)
			}
			switch o.Class {
			case "secret_key", "private_key":
				if !isTrue(o.Private) || !isTrue(o.Sensitive) || !isFalse(o.Extractable) || !isTrue(o.AlwaysSensitive) || !isTrue(o.NeverExtractable) {
					t.Fatalf("%s %s: key protection attributes: %+v", tc.alg, o.Class, o)
				}
			}
			switch o.Class {
			case "secret_key":
				if !isTrue(o.Encrypt) || !isTrue(o.Decrypt) || !isFalse(o.Wrap) || !isFalse(o.Unwrap) {
					t.Fatalf("AES usages: %+v", o)
				}
			case "private_key":
				if !isTrue(o.Sign) {
					t.Fatalf("%s private key can't sign: %+v", tc.alg, o)
				}
			case "public_key":
				if !isTrue(o.Verify) {
					t.Fatalf("%s public key can't verify: %+v", tc.alg, o)
				}
			default:
				t.Fatalf("%s: unexpected class %s", tc.alg, o.Class)
			}
		}
	}
	// Another tenant can't inspect t1's key.
	if code, _ := call(t, h, keycore, http.MethodPost, "/hsm/keys/inspect", map[string]string{"tenant_id": "t2", "label": hsm.KeyLabel("t1", "key_attr_AES", 1)}); code != http.StatusForbidden {
		t.Fatalf("cross-tenant inspect: %d", code)
	}
}

// A partition that already holds keys and certificates: they're listed for
// the tenant (as not managed by the KMS), with the certificate's details;
// another tenant's KMS objects on the same partition are not.
func TestPartitionListing(t *testing.T) {
	h, rec := newTestHandler(t)
	keycore := service("kms-keycore")
	cfg, _ := staticConfigs{}.Load(context.Background(), "t1")
	ctx, sh, release, err := sharedProvider.session(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	// What another application left in the partition.
	if _, err := ctx.GenerateKey(sh, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)}, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY), pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 16), pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "legacy-app-key"), pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
	}); err != nil {
		t.Fatal(err)
	}
	certKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(4242), Subject: pkix.Name{CommonName: "legacy.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &certKey.PublicKey, certKey)
	if _, err := ctx.CreateObject(sh, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE), pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true), pkcs11.NewAttribute(pkcs11.CKA_LABEL, "legacy-cert"),
		pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, tpl.RawSubject), pkcs11.NewAttribute(pkcs11.CKA_VALUE, der),
	}); err != nil {
		t.Fatal(err)
	}
	mine, theirs := hsm.KeyLabel("t1", "key_list", 1), hsm.KeyLabel("t2", "key_list", 1)
	for tenant, label := range map[string]string{"t1": mine, "t2": theirs} {
		if code, out := call(t, h, keycore, http.MethodPost, "/hsm/keys", map[string]string{"tenant_id": tenant, "label": label, "algorithm": "AES-128"}); code != http.StatusCreated {
			t.Fatalf("generate %s: %d %v", label, code, out)
		}
	}

	req := map[string]string{}
	code, out := call(t, h, keycore, http.MethodGet, "/hsm/objects?tenant_id=t1", req)
	if code != http.StatusOK {
		t.Fatalf("list: %d %v", code, out)
	}
	if ev := rec.Last(t); ev.Action != "objects_listed" {
		t.Fatalf("list audit: %+v", ev)
	}
	objs, id := objectsFrom(t, out)
	if id.TokenLabel != "vecta-a" {
		t.Fatalf("identity: %+v", id)
	}
	byLabel := map[string]hsm.ObjectInfo{}
	for _, o := range objs {
		byLabel[o.Label] = o
	}
	if o, ok := byLabel["legacy-app-key"]; !ok || o.Managed || o.KeyType != "AES" || o.SizeBits != 128 || !isTrue(o.Extractable) {
		t.Fatalf("existing key: %+v (listed %v)", o, ok)
	}
	c, ok := byLabel["legacy-cert"]
	if !ok || c.Class != "certificate" || c.Certificate == nil || c.Certificate.Subject != "CN=legacy.example.com" || c.Certificate.Serial != "1092" {
		t.Fatalf("existing certificate: %+v", c)
	}
	if o, ok := byLabel[mine]; !ok || !o.Managed {
		t.Fatalf("own KMS key: %+v", o)
	}
	if _, ok := byLabel[theirs]; ok {
		t.Fatal("another tenant's KMS key was listed")
	}
	// Only the platform's key manager may list.
	if code, _ := call(t, h, service("kms-governance"), http.MethodGet, "/hsm/objects?tenant_id=t1", req); code != http.StatusForbidden {
		t.Fatalf("governance listing: %d", code)
	}
}
