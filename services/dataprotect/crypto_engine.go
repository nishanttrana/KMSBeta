package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

func encryptWithAlgorithm(key []byte, algorithm string, plaintext []byte, aad []byte, deterministic bool) ([]byte, []byte, error) {
	algorithm = normalizeFieldAlgorithm(algorithm, deterministic)
	switch algorithm {
	case "AES-GCM":
		return encryptAESGCM(key, plaintext, aad, deterministic)
	case "CHACHA20-POLY1305":
		return encryptChaCha(key, plaintext, aad, deterministic)
	case "AES-SIV":
		ct, err := encryptAESSIVLike(key, plaintext, aad)
		return []byte{}, ct, err
	default:
		return nil, nil, errors.New("unsupported algorithm")
	}
}

func decryptWithAlgorithm(key []byte, algorithm string, iv []byte, ciphertext []byte, aad []byte, deterministic bool) ([]byte, error) {
	algorithm = normalizeFieldAlgorithm(algorithm, deterministic)
	switch algorithm {
	case "AES-GCM":
		return decryptAESGCM(key, iv, ciphertext, aad)
	case "CHACHA20-POLY1305":
		return decryptChaCha(key, iv, ciphertext, aad)
	case "AES-SIV":
		return decryptAESSIVLike(key, ciphertext, aad)
	default:
		return nil, errors.New("unsupported algorithm")
	}
}

func encryptAESGCM(key []byte, plaintext []byte, aad []byte, deterministic bool) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	var nonce []byte
	if deterministic {
		tag := hmacSHA256(key, string(aad), string(plaintext))
		nonce = make([]byte, gcm.NonceSize())
		copy(nonce, tag[:gcm.NonceSize()])
		zeroizeAll(tag)
	} else {
		nonce = randBytes(gcm.NonceSize())
	}
	ct := gcm.Seal(nil, nonce, plaintext, aad)
	return nonce, ct, nil
}

func decryptAESGCM(key []byte, nonce []byte, ciphertext []byte, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("invalid nonce")
	}
	return gcm.Open(nil, nonce, ciphertext, aad)
}

func encryptChaCha(key []byte, plaintext []byte, aad []byte, deterministic bool) ([]byte, []byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, err
	}
	var nonce []byte
	if deterministic {
		tag := hmacSHA256(key, string(aad), string(plaintext), "xchacha")
		nonce = make([]byte, chacha20poly1305.NonceSizeX)
		copy(nonce, tag[:chacha20poly1305.NonceSizeX])
		zeroizeAll(tag)
	} else {
		nonce = randBytes(chacha20poly1305.NonceSizeX)
	}
	ct := aead.Seal(nil, nonce, plaintext, aad)
	return nonce, ct, nil
}

func decryptChaCha(key []byte, nonce []byte, ciphertext []byte, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, errors.New("invalid nonce")
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}

// This is a deterministic AEAD-like construction compatible with searchable equality.
// It is not a full RFC 5297 implementation but offers synthetic-IV deterministic semantics.
func encryptAESSIVLike(key []byte, plaintext []byte, aad []byte) ([]byte, error) {
	siv := hmacSHA256(key, "siv", string(aad), string(plaintext))
	iv := make([]byte, 16)
	copy(iv, siv[:16])
	ctrKeyHash := hmacSHA256(key, "ctr-key")
	ctrKey := make([]byte, 32)
	copy(ctrKey, ctrKeyHash[:32])
	defer zeroizeAll(siv, ctrKeyHash, ctrKey)

	block, err := aes.NewCipher(ctrKey)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, iv)
	ct := make([]byte, len(plaintext))
	stream.XORKeyStream(ct, plaintext)
	tagFull := hmacSHA256(key, "tag", base64.StdEncoding.EncodeToString(iv), base64.StdEncoding.EncodeToString(aad), base64.StdEncoding.EncodeToString(ct))
	tag := make([]byte, 16)
	copy(tag, tagFull[:16])
	defer zeroizeAll(tagFull)
	out := make([]byte, 0, len(iv)+len(ct)+len(tag))
	out = append(out, iv...)
	out = append(out, ct...)
	out = append(out, tag...)
	return out, nil
}

func decryptAESSIVLike(key []byte, payload []byte, aad []byte) ([]byte, error) {
	if len(payload) < 32 {
		return nil, errors.New("invalid ciphertext")
	}
	iv := payload[:16]
	tag := payload[len(payload)-16:]
	ct := payload[16 : len(payload)-16]
	expectedFull := hmacSHA256(key, "tag", base64.StdEncoding.EncodeToString(iv), base64.StdEncoding.EncodeToString(aad), base64.StdEncoding.EncodeToString(ct))
	expectedTag := expectedFull[:16]
	defer zeroizeAll(expectedFull)
	if !hmacEqual(tag, expectedTag) {
		return nil, errors.New("ciphertext authentication failed")
	}
	ctrKeyHash := hmacSHA256(key, "ctr-key")
	ctrKey := make([]byte, 32)
	copy(ctrKey, ctrKeyHash[:32])
	defer zeroizeAll(ctrKeyHash, ctrKey)

	block, err := aes.NewCipher(ctrKey)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, iv)
	pt := make([]byte, len(ct))
	stream.XORKeyStream(pt, ct)
	return pt, nil
}

func hmacEqual(a []byte, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	sumA := sha256.Sum256(a)
	sumB := sha256.Sum256(b)
	return strings.EqualFold(base64.StdEncoding.EncodeToString(sumA[:]), base64.StdEncoding.EncodeToString(sumB[:]))
}
