package crypto

import (
	"bytes"
	"testing"
)

func TestEnvelopeRoundTrip(t *testing.T) {
	mek := []byte("0123456789ABCDEF0123456789ABCDEF")
	pt := []byte("top-secret-data")
	env, err := EncryptEnvelope(mek, pt)
	if err != nil {
		t.Fatal(err)
	}
	out, err := DecryptEnvelope(mek, env)
	if err != nil {
		t.Fatal(err)
	}
	if !ConstantTimeEqual(out, pt) {
		t.Fatal("decrypted plaintext mismatch")
	}
}

func TestRewrapEnvelopeMovesOnlyTheDEK(t *testing.T) {
	oldMEK, _ := RandomBytes(32)
	newMEK, _ := RandomBytes(32)
	env, err := EncryptEnvelope(oldMEK, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if !EnvelopeWrappedUnder(oldMEK, env) || EnvelopeWrappedUnder(newMEK, env) {
		t.Fatal("EnvelopeWrappedUnder does not identify the wrapping key")
	}
	out, err := RewrapEnvelope(oldMEK, newMEK, env)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Ciphertext, env.Ciphertext) || !bytes.Equal(out.DataIV, env.DataIV) {
		t.Fatal("rewrap changed the data ciphertext")
	}
	if bytes.Equal(out.WrappedDEKIV, env.WrappedDEKIV) {
		t.Fatal("rewrap reused the wrap IV")
	}
	if EnvelopeWrappedUnder(oldMEK, out) {
		t.Fatal("old MEK still opens the rewrapped DEK")
	}
	pt, err := DecryptEnvelope(newMEK, out)
	if err != nil || string(pt) != "payload" {
		t.Fatalf("decrypt after rewrap: %q %v", pt, err)
	}
	if _, err := RewrapEnvelope(newMEK, oldMEK, env); err == nil {
		t.Fatal("rewrap with the wrong old MEK succeeded")
	}
}
