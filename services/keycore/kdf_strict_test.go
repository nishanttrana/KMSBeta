package main

import (
	"context"
	"encoding/base64"
	"testing"

	"vecta-kms/pkg/fips/fipstest"
)

// Under VECTA_FIPS_MODE=only a non-approved KDF is refused and audited.
func TestKDFStrictRefusalAudited(t *testing.T) {
	fipstest.StrictOnly(t)
	svc, pub := newCaptureService(t)
	b := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	for _, alg := range []string{"scrypt", "argon2id"} {
		if _, err := svc.DeriveEnterpriseKDF(context.Background(), KDFDeriveRequest{TenantID: "t1", Algorithm: alg, SecretBase64: b, SaltBase64: b}); err == nil {
			t.Fatalf("%s derived in strict mode", alg)
		}
	}
	if countSubject(pub.subjects, "audit.key.kdf_refused") != 2 {
		t.Fatalf("refusals not audited: %v", pub.subjects)
	}
}
