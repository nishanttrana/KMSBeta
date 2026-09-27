package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	pkgcache "vecta-kms/pkg/cache"
	"vecta-kms/pkg/clusterstate"
	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/fips/fipstest"
	"vecta-kms/pkg/metering"
)

func newCaptureService(t *testing.T) (*Service, *captureKeycorePublisher) {
	t.Helper()
	pub := &captureKeycorePublisher{}
	svc := NewService(newStoreForTest(t), NewKeyCache(pkgcache.NewMemory(5*time.Minute), 5*time.Minute), pub, metering.NewMeter(0, time.Hour), []byte("0123456789ABCDEF0123456789ABCDEF"), nil, false)
	return svc, pub
}

func countSubject(subjects []string, want string) int {
	n := 0
	for _, s := range subjects {
		if s == want {
			n++
		}
	}
	return n
}

// Each of these used to be stored as 32 random bytes or a substitute key
// under the requested name.
func TestCreateKeyRefusesAlgorithmsItCannotGenerate(t *testing.T) {
	svc, pub := newCaptureService(t)
	refused := []string{
		"XMSS-SHA256-H10", "HSS-LMS-SHA256-H10", "DSA-3072", "DH-2048", "Camellia-256",
		"ECDSA-Brainpool-P256r1", "ECDSA-SECP256K1", "RSA-1024", "ML-DSA-44",
		"ECDSA-P384 + ML-DSA-65", "SLH-DSA-512x", "Ed448",
	}
	for i, alg := range refused {
		_, err := svc.CreateKey(context.Background(), CreateKeyRequest{TenantID: "t1", Name: "k", Algorithm: alg, KeyType: "asymmetric-private", Purpose: "sign-verify", Owner: "ops", CreatedBy: "tester"})
		if err == nil {
			t.Fatalf("%s: created", alg)
		}
		if alg != "Ed448" && !errors.Is(err, errKeyAlgorithmUnsupported) {
			t.Fatalf("%s: %v", alg, err)
		}
		if alg != "Ed448" && countSubject(pub.subjects, "audit.key.create_refused") != i+1 {
			t.Fatalf("%s: create_refused not audited", alg)
		}
	}
	if countSubject(pub.subjects, "audit.key.create") != 0 {
		t.Fatal("a refused key was audited as created")
	}
	if _, _, err := svc.FormKey(context.Background(), FormKeyRequest{TenantID: "t1", Name: "c", Algorithm: "RSA-2048", ComponentMode: "clear-generated", Components: []FormKeyComponent{{}, {}}}); err == nil {
		t.Fatal("XOR components formed an RSA key")
	}
}

// The generated key is the one the name asks for.
func TestGeneratedKeyMatchesItsName(t *testing.T) {
	raw, err := generateMaterialForCreate("RSA-3072", "asymmetric-private")
	if err != nil {
		t.Fatal(err)
	}
	k, err := x509.ParsePKCS8PrivateKey(raw)
	if err != nil || k.(*rsa.PrivateKey).N.BitLen() != 3072 {
		t.Fatalf("RSA-3072: %v", err)
	}
	raw, _ = generateMaterialForCreate("ECDSA-P384", "asymmetric-private")
	k, err = x509.ParsePKCS8PrivateKey(raw)
	if err != nil || k.(*ecdsa.PrivateKey).Curve != elliptic.P384() {
		t.Fatalf("ECDSA-P384: %v", err)
	}
	for alg, n := range map[string]int{"AES-128": 16, "AES-256-GCM": 32, "3DES": 24, "HMAC-SHA256": 32} {
		raw, err := generateMaterialForCreate(alg, "symmetric")
		if err != nil || len(raw) != n {
			t.Fatalf("%s: %d bytes, %v", alg, len(raw), err)
		}
	}
}

// Every SLH-DSA set generates its own parameters, and a stored key signs and
// verifies (parsing used to panic: the parameter set was never supplied).
func TestSLHDSAParameterSetsSignAndVerify(t *testing.T) {
	fipstest.SkipIfStrict(t, "SLH-DSA (outside the certified module)")
	for alg, want := range map[string]string{
		"SLH-DSA-SHA2-128s": "SLH-DSA-SHA2-128s", "SLH-DSA-128f": "SLH-DSA-SHAKE-128f", "slh_dsa_shake_256f": "SLH-DSA-SHAKE-256f",
	} {
		id, ok := slhdsaParams(alg)
		if !ok || id.String() != want {
			t.Fatalf("%s -> %v", alg, id)
		}
		priv, err := generateMaterialForCreate(alg, "asymmetric-private")
		if err != nil {
			t.Fatal(err)
		}
		sig, err := signWithKeyAlgorithm(alg, "asymmetric-private", priv, []byte("msg"), "")
		if err != nil {
			t.Fatalf("%s sign: %v", alg, err)
		}
		if ok, err := verifyWithKeyAlgorithm(alg, "asymmetric-private", priv, []byte("msg"), sig, ""); err != nil || !ok {
			t.Fatalf("%s verify: %v %v", alg, ok, err)
		}
	}
}

func TestCorrectKeyAlgorithmLabels(t *testing.T) {
	fipstest.SkipIfStrict(t, "fixtures store non-approved algorithm names")
	svc, pub := newCaptureService(t)
	ctx := context.Background()
	fixture := func(alg string, material []byte) string {
		k, err := svc.createKeyFromMaterial(ctx, CreateKeyRequest{TenantID: "t1", Name: alg, Algorithm: alg, KeyType: "asymmetric-private", Purpose: "sign-verify", Owner: "ops", CreatedBy: "tester"}, material, "", "key.create", "audit.key.create")
		if err != nil {
			t.Fatalf("fixture %s: %v", alg, err)
		}
		return k.ID
	}
	random32, _ := pkgcrypto.RandomBytes(32)
	p256, _ := generateMaterialForCreate("ECDSA-P256", "asymmetric-private")
	rsa2048, _ := generateMaterialForCreate("RSA-2048", "asymmetric-private")
	want := map[string]string{
		fixture("XMSS-SHA256-H10", random32):    invalidKeyMaterial,
		fixture("SLH-DSA-128s", random32):       invalidKeyMaterial,
		fixture("ECDSA-Brainpool-P256r1", p256): "ECDSA-P256",
		fixture("RSA-1024", rsa2048):            "RSA-2048",
		fixture("RSA-2048", rsa2048):            "RSA-2048",
	}

	clusterstate.SetDefault(clusterstate.Static(clusterstate.State{NodeID: "node-2", Role: clusterstate.RoleFollower, PrimaryNodeID: "node-1", PrimaryURL: "https://primary:8210", ForwardCredential: "cred"}))
	if n, err := svc.CorrectKeyAlgorithmLabels(ctx); err != nil || n != 0 {
		clusterstate.SetDefault(nil)
		t.Fatalf("member corrected %d (%v); only the primary writes the keys table", n, err)
	}
	clusterstate.SetDefault(nil)

	n, err := svc.CorrectKeyAlgorithmLabels(ctx)
	if err != nil || n != 4 {
		for id, alg := range want {
			k, _ := svc.GetKey(ctx, "t1", id)
			t.Logf("%s: now %q want %q", k.Name, k.Algorithm, alg)
		}
		t.Fatalf("corrected %d, %v; want 4", n, err)
	}
	for id, alg := range want {
		k, err := svc.GetKey(ctx, "t1", id)
		if err != nil || k.Algorithm != alg {
			t.Fatalf("key %s: %q, want %q (%v)", id, k.Algorithm, alg, err)
		}
	}
	if countSubject(pub.subjects, "audit.key.algorithm_label_corrected") != 4 {
		t.Fatal("corrections not audited")
	}
	if n, _ := svc.CorrectKeyAlgorithmLabels(ctx); n != 0 {
		t.Fatalf("second run corrected %d; must be idempotent", n)
	}
}
