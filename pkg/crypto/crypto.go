package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
)

type IVMode string

const (
	IVInternal      IVMode = "internal"
	IVExternal      IVMode = "external"
	IVDeterministic IVMode = "deterministic"
)

type EnvelopeCiphertext struct {
	WrappedDEK   []byte
	WrappedDEKIV []byte
	Ciphertext   []byte
	DataIV       []byte
}

func ComputeKCV(algorithm string, key []byte) (string, error) {
	if len(key) == 0 {
		return "", errors.New("empty key")
	}
	tag := []byte(algorithm)
	sum := sha256.Sum256(append(tag, key...))
	return hex.EncodeToString(sum[:3]), nil
}

func GenerateIV(mode IVMode, keyMaterial []byte, externalIV []byte, payload []byte) ([]byte, error) {
	switch mode {
	case IVInternal:
		iv := make([]byte, aes.BlockSize)
		_, err := rand.Read(iv)
		return iv, err
	case IVExternal:
		if len(externalIV) != aes.BlockSize {
			return nil, errors.New("external IV must be 16 bytes")
		}
		out := make([]byte, len(externalIV))
		copy(out, externalIV)
		return out, nil
	case IVDeterministic:
		mac := hmac.New(sha256.New, keyMaterial)
		_, _ = mac.Write(payload)
		sum := mac.Sum(nil)
		return sum[:aes.BlockSize], nil
	default:
		return nil, errors.New("unsupported IV mode")
	}
}

func EncryptEnvelope(mek []byte, plaintext []byte) (*EnvelopeCiphertext, error) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	defer Zeroize(dek)

	dataIV, err := GenerateIV(IVInternal, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	ciphertext, err := aesGCMEncrypt(dek, dataIV, plaintext)
	if err != nil {
		return nil, err
	}

	wrappedIV, err := GenerateIV(IVInternal, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	wrappedDEK, err := aesGCMEncrypt(mek, wrappedIV, dek)
	if err != nil {
		return nil, err
	}
	return &EnvelopeCiphertext{
		WrappedDEK:   wrappedDEK,
		WrappedDEKIV: wrappedIV,
		Ciphertext:   ciphertext,
		DataIV:       dataIV,
	}, nil
}

func DecryptEnvelope(mek []byte, env *EnvelopeCiphertext) ([]byte, error) {
	dek, err := aesGCMDecrypt(mek, env.WrappedDEKIV, env.WrappedDEK)
	if err != nil {
		return nil, err
	}
	defer Zeroize(dek)
	return aesGCMDecrypt(dek, env.DataIV, env.Ciphertext)
}

func ConstantTimeEqual(a []byte, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func aesGCMEncrypt(key []byte, iv []byte, plaintext []byte) ([]byte, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, iv[:gcm.NonceSize()], plaintext, nil), nil
}

func aesGCMDecrypt(key []byte, iv []byte, ciphertext []byte) ([]byte, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, iv[:gcm.NonceSize()], ciphertext, nil)
}
