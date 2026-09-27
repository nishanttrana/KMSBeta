package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
)

func TestSealToRecipientRoundTripAndBinding(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParseRecipientPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("0123456789abcdef0123456789abcdef")
	aad := []byte("tenant|key|1|rel_1")
	wrapped, nonce, ct, err := SealToRecipient(pub, secret, aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, secret) {
		t.Fatal("plaintext visible in ciphertext")
	}
	got, err := OpenFromRecipient(priv, wrapped, nonce, ct, aad)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("round trip failed: %v", err)
	}
	if _, err := OpenFromRecipient(priv, wrapped, nonce, ct, []byte("other aad")); err == nil {
		t.Fatal("opened under different aad")
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := OpenFromRecipient(other, wrapped, nonce, ct, aad); err == nil {
		t.Fatal("opened by a different private key")
	}
	if RecipientKeyBinding(der) == "" || RecipientKeyBinding(der) == RecipientKeyBinding(append([]byte{0}, der...)) {
		t.Fatal("binding does not identify the key")
	}
}

func TestParseRecipientPublicKeyRefusesWeakOrNonRSA(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecDER, _ := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	if _, err := ParseRecipientPublicKey(ecDER); err == nil {
		t.Fatal("EC recipient accepted")
	}
	if _, err := ParseRecipientPublicKey([]byte("not der")); err == nil {
		t.Fatal("garbage accepted")
	}
}
