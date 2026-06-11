package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

// Field-level AEAD for data protection: randomized or deterministic
// (searchable-equality) encryption of individual field values. Algorithms:
// "AES-GCM", "CHACHA20-POLY1305" (XChaCha20), and "AES-SIV" — a synthetic-IV
// deterministic construction (not full RFC 5297, but stable, authenticated
// deterministic semantics). The HMAC derivations here are wire-compatible
// with previously stored dataprotect ciphertexts and must not change.

// FieldEncrypt encrypts one field value. For AES-GCM and CHACHA20-POLY1305 it
// returns (nonce, ciphertext); for AES-SIV it returns (nil, iv||ct||tag).
// Deterministic mode derives the nonce from the key and inputs so equal
// plaintexts produce equal ciphertexts.
func FieldEncrypt(key []byte, algorithm string, plaintext []byte, aad []byte, deterministic bool) ([]byte, []byte, error) {
	switch algorithm {
	case "AES-GCM":
		return fieldEncryptAESGCM(key, plaintext, aad, deterministic)
	case "CHACHA20-POLY1305":
		return fieldEncryptChaCha(key, plaintext, aad, deterministic)
	case "AES-SIV":
		ct, err := fieldEncryptAESSIV(key, plaintext, aad)
		return []byte{}, ct, err
	default:
		return nil, nil, errors.New("unsupported algorithm")
	}
}

// FieldDecrypt reverses FieldEncrypt.
func FieldDecrypt(key []byte, algorithm string, iv []byte, ciphertext []byte, aad []byte) ([]byte, error) {
	switch algorithm {
	case "AES-GCM":
		return fieldDecryptAESGCM(key, iv, ciphertext, aad)
	case "CHACHA20-POLY1305":
		return fieldDecryptChaCha(key, iv, ciphertext, aad)
	case "AES-SIV":
		return fieldDecryptAESSIV(key, ciphertext, aad)
	default:
		return nil, errors.New("unsupported algorithm")
	}
}

// fieldHMAC chains values with zero-byte separators; this exact construction
// is what deployed deterministic nonces and SIV tags were derived with.
func fieldHMAC(key []byte, values ...string) []byte {
	m := hmac.New(sha256.New, key)
	for _, v := range values {
		_, _ = m.Write([]byte(v))
		_, _ = m.Write([]byte{0})
	}
	return m.Sum(nil)
}

func fieldEncryptAESGCM(key []byte, plaintext []byte, aad []byte, deterministic bool) ([]byte, []byte, error) {
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
		tag := fieldHMAC(key, string(aad), string(plaintext))
		nonce = make([]byte, gcm.NonceSize())
		copy(nonce, tag[:gcm.NonceSize()])
		Zeroize(tag)
	} else {
		nonce, err = RandomBytes(gcm.NonceSize())
		if err != nil {
			return nil, nil, err
		}
	}
	return nonce, gcm.Seal(nil, nonce, plaintext, aad), nil
}

func fieldDecryptAESGCM(key []byte, nonce []byte, ciphertext []byte, aad []byte) ([]byte, error) {
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

func fieldEncryptChaCha(key []byte, plaintext []byte, aad []byte, deterministic bool) ([]byte, []byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, err
	}
	var nonce []byte
	if deterministic {
		tag := fieldHMAC(key, string(aad), string(plaintext), "xchacha")
		nonce = make([]byte, chacha20poly1305.NonceSizeX)
		copy(nonce, tag[:chacha20poly1305.NonceSizeX])
		Zeroize(tag)
	} else {
		nonce, err = RandomBytes(chacha20poly1305.NonceSizeX)
		if err != nil {
			return nil, nil, err
		}
	}
	return nonce, aead.Seal(nil, nonce, plaintext, aad), nil
}

func fieldDecryptChaCha(key []byte, nonce []byte, ciphertext []byte, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, errors.New("invalid nonce")
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}

func fieldEncryptAESSIV(key []byte, plaintext []byte, aad []byte) ([]byte, error) {
	siv := fieldHMAC(key, "siv", string(aad), string(plaintext))
	iv := make([]byte, 16)
	copy(iv, siv[:16])
	ctrKeyHash := fieldHMAC(key, "ctr-key")
	ctrKey := make([]byte, 32)
	copy(ctrKey, ctrKeyHash[:32])
	defer Zeroize(siv)
	defer Zeroize(ctrKeyHash)
	defer Zeroize(ctrKey)

	block, err := aes.NewCipher(ctrKey)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, iv)
	ct := make([]byte, len(plaintext))
	stream.XORKeyStream(ct, plaintext)
	tagFull := fieldHMAC(key, "tag", base64.StdEncoding.EncodeToString(iv), base64.StdEncoding.EncodeToString(aad), base64.StdEncoding.EncodeToString(ct))
	tag := make([]byte, 16)
	copy(tag, tagFull[:16])
	defer Zeroize(tagFull)
	out := make([]byte, 0, len(iv)+len(ct)+len(tag))
	out = append(out, iv...)
	out = append(out, ct...)
	out = append(out, tag...)
	return out, nil
}

func fieldDecryptAESSIV(key []byte, payload []byte, aad []byte) ([]byte, error) {
	if len(payload) < 32 {
		return nil, errors.New("invalid ciphertext")
	}
	iv := payload[:16]
	tag := payload[len(payload)-16:]
	ct := payload[16 : len(payload)-16]
	expectedFull := fieldHMAC(key, "tag", base64.StdEncoding.EncodeToString(iv), base64.StdEncoding.EncodeToString(aad), base64.StdEncoding.EncodeToString(ct))
	defer Zeroize(expectedFull)
	if !hmac.Equal(tag, expectedFull[:16]) {
		return nil, errors.New("ciphertext authentication failed")
	}
	ctrKeyHash := fieldHMAC(key, "ctr-key")
	ctrKey := make([]byte, 32)
	copy(ctrKey, ctrKeyHash[:32])
	defer Zeroize(ctrKeyHash)
	defer Zeroize(ctrKey)

	block, err := aes.NewCipher(ctrKey)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, iv)
	pt := make([]byte, len(ct))
	stream.XORKeyStream(pt, ct)
	return pt, nil
}
