package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
)

// HMACSHA256 returns HMAC-SHA256(key, data) (FIPS 198-1, approved).
func HMACSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// SHA256 returns the SHA-256 digest of data.
func SHA256(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}
