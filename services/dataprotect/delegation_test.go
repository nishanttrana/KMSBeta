package main

import (
	"context"
	"testing"
)

// Each dataprotect operation meters in keycore with the usage it performs,
// before it derives a working key, so keycore decides with the grants of the
// user behind the request. The operation's own outcome doesn't matter here
// (in FIPS strict mode the test key's legacy derivation is refused after the
// meter call).
func TestDataprotectNamesItsUsage(t *testing.T) {
	svc, _, _ := newDataProtectService(t)
	fake := svc.keycore.(*fakeDataProtectKeyCore)
	ctx := context.Background()
	_, _ = svc.FPEEncrypt(ctx, FPERequest{TenantID: "t1", KeyID: "key-1", Algorithm: "FF1", Plaintext: "1234567890"})
	_, _ = svc.FPEDecrypt(ctx, FPERequest{TenantID: "t1", KeyID: "key-1", Algorithm: "FF1", Ciphertext: "1234567890"})
	if len(fake.usages) != 2 || fake.usages[0] != "fpe-encrypt" || fake.usages[1] != "fpe-decrypt" {
		t.Fatalf("usages sent to keycore: %v", fake.usages)
	}
}
