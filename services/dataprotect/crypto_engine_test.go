package main

import (
	"encoding/base64"
	"testing"
)

func TestAlgorithmCiphertextBehavior(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	plaintext := []byte("alice@example.com")
	aad := []byte("ctx")

	gcmIV1, gcmCT1, err := encryptWithAlgorithm(key, "AES-GCM", plaintext, aad, false)
	if err != nil {
		t.Fatalf("aes-gcm encrypt #1: %v", err)
	}
	gcmIV2, gcmCT2, err := encryptWithAlgorithm(key, "AES-GCM", plaintext, aad, false)
	if err != nil {
		t.Fatalf("aes-gcm encrypt #2: %v", err)
	}
	if base64.StdEncoding.EncodeToString(gcmIV1)+"."+base64.StdEncoding.EncodeToString(gcmCT1) ==
		base64.StdEncoding.EncodeToString(gcmIV2)+"."+base64.StdEncoding.EncodeToString(gcmCT2) {
		t.Fatalf("expected AES-GCM ciphertext to differ across runs due to random nonce")
	}

	chIV, chCT, err := encryptWithAlgorithm(key, "CHACHA20-POLY1305", plaintext, aad, false)
	if err != nil {
		t.Fatalf("chacha20-poly1305 encrypt: %v", err)
	}
	if base64.StdEncoding.EncodeToString(gcmCT1) == base64.StdEncoding.EncodeToString(chCT) &&
		base64.StdEncoding.EncodeToString(gcmIV1) == base64.StdEncoding.EncodeToString(chIV) {
		t.Fatalf("expected ChaCha20-Poly1305 output to differ from AES-GCM")
	}

	_, sivCT1, err := encryptWithAlgorithm(key, "AES-SIV", plaintext, aad, true)
	if err != nil {
		t.Fatalf("aes-siv encrypt #1: %v", err)
	}
	_, sivCT2, err := encryptWithAlgorithm(key, "AES-SIV", plaintext, aad, true)
	if err != nil {
		t.Fatalf("aes-siv encrypt #2: %v", err)
	}
	if base64.StdEncoding.EncodeToString(sivCT1) != base64.StdEncoding.EncodeToString(sivCT2) {
		t.Fatalf("expected AES-SIV ciphertext to be deterministic for same key/plaintext/aad")
	}
}
