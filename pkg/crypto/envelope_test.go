package crypto

import "testing"

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
