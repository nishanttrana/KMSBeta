package crypto

import (
	"bytes"
	"testing"
)

func TestKEMSealRoundTripAndBinding(t *testing.T) {
	r, err := NewKEMRecipient()
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("0123456789abcdef0123456789abcdef")
	aad := []byte("join|tok_1|node-2")
	sealed, err := KEMSeal(r.EncapsulationKey(), secret, aad, "keycore-mek")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, secret) {
		t.Fatal("sealed output must not contain the secret")
	}
	got, err := r.Open(sealed, aad, "keycore-mek")
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("round trip: %v", err)
	}
	if _, err := r.Open(sealed, aad, "certs-crwk"); err == nil {
		t.Fatal("a different purpose label must not open the secret")
	}
	if _, err := r.Open(sealed, []byte("join|tok_2|node-2"), "keycore-mek"); err == nil {
		t.Fatal("a different transfer context must not open the secret")
	}
	other, _ := NewKEMRecipient()
	if _, err := other.Open(sealed, aad, "keycore-mek"); err == nil {
		t.Fatal("another recipient must not open the secret")
	}
	if _, err := KEMSeal([]byte("short"), secret, aad, "x"); err == nil {
		t.Fatal("an invalid encapsulation key must be rejected")
	}
}

// A recipient restored from its seed opens what was sealed to the original.
func TestKEMRecipientSeedRoundTrip(t *testing.T) {
	r, err := NewKEMRecipient()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := KEMSeal(r.EncapsulationKey(), []byte("lease"), []byte("aad"), "test")
	if err != nil {
		t.Fatal(err)
	}
	again, err := KEMRecipientFromSeed(r.Seed())
	if err != nil {
		t.Fatal(err)
	}
	if out, err := again.Open(sealed, []byte("aad"), "test"); err != nil || string(out) != "lease" {
		t.Fatalf("restored recipient: %q %v", out, err)
	}
	if _, err := KEMRecipientFromSeed(make([]byte, 10)); err == nil {
		t.Fatal("a short seed was accepted")
	}
}
