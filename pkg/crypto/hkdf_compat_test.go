package crypto

import (
	"bytes"
	"crypto/sha256"
	"io"
	"testing"

	xhkdf "golang.org/x/crypto/hkdf"
)

// HKDFSHA256 moved from x/crypto/hkdf to the FIPS-module crypto/hkdf; derived
// keys must be byte-identical so nothing derived earlier changes.
func TestHKDFSHA256MatchesPreviousImplementation(t *testing.T) {
	secret, salt, info := []byte("0123456789abcdef0123456789abcdef"), []byte("salt"), []byte("info")
	got, err := HKDFSHA256(secret, salt, info, 32)
	if err != nil {
		t.Fatal(err)
	}
	want := make([]byte, 32)
	if _, err := io.ReadFull(xhkdf.New(sha256.New, secret, salt, info), want); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("HKDFSHA256 output changed")
	}
}
