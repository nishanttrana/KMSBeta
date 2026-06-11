package main

import (
	pkgcrypto "vecta-kms/pkg/crypto"
)

// Field encryption is implemented centrally in pkg/crypto (FieldEncrypt /
// FieldDecrypt); these wrappers add the service's algorithm normalization.

func encryptWithAlgorithm(key []byte, algorithm string, plaintext []byte, aad []byte, deterministic bool) ([]byte, []byte, error) {
	return pkgcrypto.FieldEncrypt(key, normalizeFieldAlgorithm(algorithm, deterministic), plaintext, aad, deterministic)
}

func decryptWithAlgorithm(key []byte, algorithm string, iv []byte, ciphertext []byte, aad []byte, deterministic bool) ([]byte, error) {
	return pkgcrypto.FieldDecrypt(key, normalizeFieldAlgorithm(algorithm, deterministic), iv, ciphertext, aad)
}
