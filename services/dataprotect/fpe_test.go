package main

import (
	"context"
	"testing"

	"vecta-kms/pkg/fips/fipstest"
)

// legacyEncryptForTest reproduces the pre-1.26.0 additive transform, only to
// produce ciphertext the decrypt-only migration path must still read.
func legacyEncryptForTest(key []byte, tweak, plaintext string, radix int, ff3 bool) string {
	x, runes, _ := fpeNumerals(plaintext, radix)
	rounds := 10
	if ff3 {
		rounds, tweak = 8, "ff3:"+tweak
	}
	for round := 0; round < rounds; round++ {
		material := hmacSHA256(key, "ff1", tweak, strconvI(round), strconvI(len(x)), strconvI(radix))
		for i := range x {
			x[i] = uint16((int(x[i]) + int(material[i%len(material)])%radix) % radix)
		}
	}
	return fpeString(x, runes)
}

func TestFF1CasePreservingRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	ct, err := ff1Encrypt(key, "tenant-a", "AbCd9876zz", 36)
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) != 10 || ct == "AbCd9876zz" {
		t.Fatalf("ciphertext %q", ct)
	}
	for i, r := range ct {
		if isUpper(r) != isUpper(rune("AbCd9876zz"[i])) {
			t.Fatalf("case not preserved at %d: %q", i, ct)
		}
	}
	pt, err := ff1Decrypt(key, "tenant-a", ct, 36)
	if err != nil || pt != "AbCd9876zz" {
		t.Fatalf("decrypt = %q, %v", pt, err)
	}
	if _, err := ff1Encrypt(key, "", "12345", 10); err == nil {
		t.Fatal("accepted a domain below the SP 800-38G minimum")
	}
}

func TestFPERefusalsAudited(t *testing.T) {
	svc, _, pub := newDataProtectService(t)
	ctx := context.Background()
	cases := []struct {
		name string
		call func() error
	}{
		{"ff3-1 encrypt", func() error {
			_, err := svc.FPEEncrypt(ctx, FPERequest{TenantID: "t1", KeyID: "key-1", Algorithm: "FF3-1", Plaintext: "1234567890"})
			return err
		}},
		{"ff3-1 decrypt", func() error {
			_, err := svc.FPEDecrypt(ctx, FPERequest{TenantID: "t1", KeyID: "key-1", Algorithm: "FF3", Ciphertext: "1234567890"})
			return err
		}},
		{"legacy encrypt", func() error {
			_, err := svc.FPEEncrypt(ctx, FPERequest{TenantID: "t1", KeyID: "key-1", Algorithm: "LEGACY-FF1", Plaintext: "1234567890"})
			return err
		}},
	}
	for i, tc := range cases {
		if err := tc.call(); err == nil {
			t.Fatalf("%s: accepted", tc.name)
		}
		if got := pub.Count("audit.dataprotect.fpe_refused"); got != i+1 {
			t.Fatalf("%s: fpe_refused events = %d, want %d", tc.name, got, i+1)
		}
	}
	if pub.Count("audit.dataprotect.fpe_encrypted") != 0 {
		t.Fatal("a refused request was audited as encrypted")
	}
}

func TestFPELegacyDecryptMigrationPath(t *testing.T) {
	fipstest.SkipIfStrict(t, "identifier-derived working keys (test keycore has no material)")
	svc, _, pub := newDataProtectService(t)
	ctx := context.Background()
	key, err := svc.resolveWorkingKey(ctx, "t1", "key-1", "fpe")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		algo string
		ff3  bool
	}{{"LEGACY-FF1", false}, {"LEGACY-FF3-1", true}} {
		old := legacyEncryptForTest(key, "tw", "4111111111111111", 10, tc.ff3)
		out, err := svc.FPEDecrypt(ctx, FPERequest{TenantID: "t1", KeyID: "key-1", Algorithm: tc.algo, Tweak: "tw", Ciphertext: old})
		if err != nil {
			t.Fatalf("%s: %v", tc.algo, err)
		}
		if out["plaintext"] != "4111111111111111" {
			t.Fatalf("%s: plaintext %v", tc.algo, out["plaintext"])
		}
	}
	if pub.Count("audit.dataprotect.fpe_legacy_decrypted") != 2 {
		t.Fatalf("legacy decrypts audited %d times, want 2", pub.Count("audit.dataprotect.fpe_legacy_decrypted"))
	}
	enc, err := svc.FPEEncrypt(ctx, FPERequest{TenantID: "t1", KeyID: "key-1", Plaintext: "4111111111111111"})
	if err != nil {
		t.Fatal(err)
	}
	want, _ := ff1Encrypt(key, "", "4111111111111111", 10)
	if enc["ciphertext"] != want {
		t.Fatalf("default algorithm is not FF1: %v vs %s", enc["ciphertext"], want)
	}
}

// Non-consistent shuffle used j = i, so every swap was a no-op and the value
// came back unmasked.
func TestShuffleMaskActuallyShuffles(t *testing.T) {
	const in = "abcdefghijklmnop"
	for run := 0; run < 5; run++ {
		out := maskString(in, "shuffle", false, nil)
		if out == in {
			t.Fatalf("run %d: shuffle returned the value unmasked", run)
		}
		if len(out) != len(in) || sortedRunes(out) != sortedRunes(in) {
			t.Fatalf("run %d: %q is not a permutation of %q", run, out, in)
		}
	}
	seed := []byte{7, 3, 9, 1, 250, 12, 44, 90}
	a, b := maskString(in, "shuffle", true, seed), maskString(in, "shuffle", true, seed)
	if a != b || a == in {
		t.Fatalf("consistent shuffle: %q, %q", a, b)
	}
}

func sortedRunes(s string) string {
	r := []rune(s)
	for i := 1; i < len(r); i++ {
		for j := i; j > 0 && r[j] < r[j-1]; j-- {
			r[j], r[j-1] = r[j-1], r[j]
		}
	}
	return string(r)
}
