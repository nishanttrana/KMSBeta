package main

import (
	"encoding/base64"
	"errors"
	"testing"

	"vecta-kms/pkg/fips/fipstest"
)

// A composite key signs with both algorithms; the signature verifies only
// when both halves do, so stripping or corrupting either one fails.
func TestCompositeSignatureKey(t *testing.T) {
	fipstest.SkipIfStrict(t, "ML-DSA half of a composite signature key")
	_, svc := newHandlerForTest(t)
	ctx := adminCtx()
	for _, alg := range []string{"ML-DSA-65+ECDSA-P256", "ML-DSA-87+ECDSA-P384"} {
		key, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t1", Name: alg, Algorithm: alg,
			KeyType: "asymmetric", Purpose: "sign", Owner: "ops", CreatedBy: "tester"})
		if err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		data := base64.StdEncoding.EncodeToString([]byte("release-1.0.tar.gz digest"))
		sig, err := svc.Sign(ctx, key.ID, SignRequest{TenantID: "t1", DataB64: data})
		if err != nil {
			t.Fatalf("%s sign: %v", alg, err)
		}
		verify := func(sigB64 string) bool {
			res, err := svc.Verify(ctx, key.ID, VerifyRequest{TenantID: "t1", DataB64: data, SignatureB64: sigB64})
			return err == nil && res.Verified
		}
		if !verify(sig.SignatureB64) {
			t.Fatalf("%s: valid composite signature did not verify", alg)
		}
		raw, _ := base64.StdEncoding.DecodeString(sig.SignatureB64)
		pq, cl, err := splitComposite(raw)
		if err != nil {
			t.Fatal(err)
		}
		for name, bad := range map[string][]byte{
			"classical half only":    cl,
			"post-quantum half only": joinComposite(pq, nil),
			"corrupted classical":    append(joinComposite(pq, cl)[:len(raw)-1], raw[len(raw)-1]^1),
			"corrupted post-quantum": func() []byte { b := append([]byte(nil), raw...); b[10] ^= 1; return b }(),
		} {
			if verify(base64.StdEncoding.EncodeToString(bad)) {
				t.Fatalf("%s: %s verified", alg, name)
			}
		}
	}
}

// Strict mode refuses a composite key cleanly (its ML-DSA half is outside the
// certified module).
func TestStrictModeRefusesCompositeSignatureKey(t *testing.T) {
	fipstest.StrictOnly(t)
	_, svc := newHandlerForTest(t)
	_, err := svc.CreateKey(adminCtx(), CreateKeyRequest{TenantID: "t1", Name: "c", Algorithm: "ML-DSA-65+ECDSA-P256",
		KeyType: "asymmetric", Purpose: "sign", Owner: "ops", CreatedBy: "tester"})
	var v fipsModeViolationError
	if !errors.As(err, &v) {
		t.Fatalf("composite key in strict mode: %v", err)
	}
}
