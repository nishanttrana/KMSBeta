package crypto

import (
	"bytes"
	"crypto/fips140"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"testing"

	"vecta-kms/pkg/fips/fipstest"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 5649 section 6 test vectors.
func TestKWPRFC5649Vectors(t *testing.T) {
	fipstest.SkipIfStrict(t, "AES key wrap with padding outside the module")
	kek := unhex(t, "5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8")
	for _, v := range []struct{ plain, wrapped string }{
		{"c37b7e6492584340bed12207808941155068f738", "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a"},
		{"466f7250617369", "afbeb0f07dfbf5419200f2ccb50bb24f"},
	} {
		got, err := wrapKWP(kek, unhex(t, v.plain))
		if err != nil || hex.EncodeToString(got) != v.wrapped {
			t.Fatalf("wrap %s = %x, %v; want %s", v.plain, got, err, v.wrapped)
		}
		back, err := unwrapKWP(kek, got)
		if err != nil || hex.EncodeToString(back) != v.plain {
			t.Fatalf("unwrap = %x, %v", back, err)
		}
	}
}

func TestKWPRejectsTamper(t *testing.T) {
	fipstest.SkipIfStrict(t, "AES key wrap with padding outside the module")
	kek := unhex(t, "5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8")
	w, _ := wrapKWP(kek, unhex(t, "c37b7e6492584340bed12207808941155068f738"))
	w[len(w)-1] ^= 1
	if _, err := unwrapKWP(kek, w); err == nil {
		t.Fatal("a tampered KWP blob unwrapped")
	}
}

func TestWrapForCloudImportRoundTrips(t *testing.T) {
	priv, err := rsa.GenerateKey(Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	material := make([]byte, 32)
	_, _ = Reader.Read(material)
	for _, scheme := range CloudWrapSchemes {
		if CloudWrapNeedsModuleOutside(scheme) && fips140.Enforced() {
			continue
		}
		w, err := WrapForCloudImport(&priv.PublicKey, material, scheme)
		if err != nil {
			t.Fatalf("%s: %v", scheme, err)
		}
		back, err := UnwrapCloudImport(priv, w, scheme)
		if err != nil || !bytes.Equal(back, material) {
			t.Fatalf("%s: round trip failed: %v", scheme, err)
		}
	}
}

func TestWrapForCloudImportRefusesWeakKeysAndUnknownSchemes(t *testing.T) {
	// Strict mode won't generate a 1024-bit key; the size check is the same.
	if small, err := rsa.GenerateKey(Reader, 1024); err == nil {
		if _, err := WrapForCloudImport(&small.PublicKey, []byte("0123456789abcdef"), CloudWrapRSAOAEPSHA256); err == nil {
			t.Fatal("a 1024-bit wrapping key was accepted")
		}
	}
	big, _ := rsa.GenerateKey(Reader, 2048)
	if _, err := WrapForCloudImport(&big.PublicKey, []byte("x"), "rsa-pkcs1"); err == nil {
		t.Fatal("an unknown scheme was accepted")
	}
}

func TestCloudWrapRefusedInStrictMode(t *testing.T) {
	fipstest.StrictOnly(t)
	priv, _ := rsa.GenerateKey(Reader, 2048)
	for _, scheme := range []string{CloudWrapRSAOAEPSHA1, CloudWrapRSAAESKWP256, CloudWrapRSAAESKWPSHA1} {
		if _, err := WrapForCloudImport(&priv.PublicKey, make([]byte, 32), scheme); !errors.Is(err, ErrCloudWrapStrict) {
			t.Fatalf("%s in strict mode: %v", scheme, err)
		}
	}
	if _, err := WrapForCloudImport(&priv.PublicKey, make([]byte, 32), CloudWrapRSAOAEPSHA256); err != nil {
		t.Fatalf("rsa-oaep-sha256 in strict mode: %v", err)
	}
}
