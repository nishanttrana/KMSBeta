package crypto

import (
	"bytes"
	"crypto/rsa"
	"errors"
	"testing"

	"vecta-kms/pkg/fips/fipstest"
)

// RFC 3394 section 4.3 and 4.6: a 256-bit KEK wrapping 128 and 256 bits.
func TestA256KWRFC3394Vectors(t *testing.T) {
	fipstest.SkipIfStrict(t, "AES key wrap outside the module")
	kek := unhex(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	for _, v := range []struct{ plain, wrapped string }{
		{"00112233445566778899AABBCCDDEEFF", "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7"},
		{"00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F", "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"},
	} {
		got, err := JWAWrapAES(JWAA256KW, kek, unhex(t, v.plain))
		if err != nil || !bytes.Equal(got, unhex(t, v.wrapped)) {
			t.Fatalf("wrap %s = %X, %v; want %s", v.plain, got, err, v.wrapped)
		}
		back, err := JWAUnwrapAES(JWAA256KW, kek, got)
		if err != nil || !bytes.Equal(back, unhex(t, v.plain)) {
			t.Fatalf("unwrap = %X, %v", back, err)
		}
	}
}

func TestA256KWRejectsTamperAndTheWrongKey(t *testing.T) {
	fipstest.SkipIfStrict(t, "AES key wrap outside the module")
	kek, other := make([]byte, 32), make([]byte, 32)
	_, _ = Reader.Read(kek)
	_, _ = Reader.Read(other)
	dek := make([]byte, 32)
	_, _ = Reader.Read(dek)
	for _, alg := range []string{JWAA256KW, JWAA256KWP} {
		w, err := JWAWrapAES(alg, kek, dek)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := JWAUnwrapAES(alg, other, w); err == nil {
			t.Fatalf("%s: unwrapped under another key", alg)
		}
		w[len(w)-1] ^= 1
		if _, err := JWAUnwrapAES(alg, kek, w); err == nil {
			t.Fatalf("%s: a tampered blob unwrapped", alg)
		}
	}
}

func TestJWARefusesAKeyThatDoesNotFit(t *testing.T) {
	fipstest.SkipIfStrict(t, "AES key wrap outside the module")
	if _, err := JWAWrapAES(JWAA256KW, make([]byte, 16), make([]byte, 32)); !errors.Is(err, ErrJWAUnsupported) {
		t.Fatalf("A256KW under a 128-bit key: %v", err)
	}
	if _, err := JWAWrapAES("A128GCMKW", make([]byte, 32), make([]byte, 32)); !errors.Is(err, ErrJWAUnsupported) {
		t.Fatalf("unknown algorithm: %v", err)
	}
	priv, _ := rsa.GenerateKey(Reader, 2048)
	if _, err := JWAWrapRSA(JWAA256KW, &priv.PublicKey, make([]byte, 32)); !errors.Is(err, ErrJWAUnsupported) {
		t.Fatalf("an AES algorithm on an RSA key: %v", err)
	}
}

func TestJWARSARoundTrips(t *testing.T) {
	priv, err := rsa.GenerateKey(Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	dek := make([]byte, 32)
	_, _ = Reader.Read(dek)
	algs := []string{JWARSAOAEP256}
	if !fipstest.Strict() {
		algs = append(algs, JWARSAOAEP)
	}
	for _, alg := range algs {
		w, err := JWAWrapRSA(alg, &priv.PublicKey, dek)
		if err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		back, err := JWAUnwrapRSA(alg, priv, w)
		if err != nil || !bytes.Equal(back, dek) {
			t.Fatalf("%s: round trip failed: %v", alg, err)
		}
	}
	// The two OAEP hashes are not interchangeable.
	if !fipstest.Strict() {
		w, _ := JWAWrapRSA(JWARSAOAEP256, &priv.PublicKey, dek)
		if _, err := JWAUnwrapRSA(JWARSAOAEP, priv, w); err == nil {
			t.Fatal("RSA-OAEP-256 output unwrapped as RSA-OAEP")
		}
	}
}

func TestJWARefusedInStrictMode(t *testing.T) {
	fipstest.StrictOnly(t)
	for _, alg := range []string{JWAA256KW, JWAA256KWP} {
		if _, err := JWAWrapAES(alg, make([]byte, 32), make([]byte, 32)); !errors.Is(err, ErrJWAStrict) {
			t.Fatalf("%s in strict mode: %v", alg, err)
		}
	}
	priv, _ := rsa.GenerateKey(Reader, 2048)
	if _, err := JWAWrapRSA(JWARSAOAEP, &priv.PublicKey, make([]byte, 32)); !errors.Is(err, ErrJWAStrict) {
		t.Fatalf("RSA-OAEP in strict mode: %v", err)
	}
	if _, err := JWAWrapRSA(JWARSAOAEP256, &priv.PublicKey, make([]byte, 32)); err != nil {
		t.Fatalf("RSA-OAEP-256 in strict mode: %v", err)
	}
}
