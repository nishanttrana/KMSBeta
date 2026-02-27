package clustersync

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

func BuildSignature(secret []byte, method string, path string, tenantID string, sourceNodeID string, timestamp string, nonce string, body []byte) string {
	normalized := canonicalSignatureInput(method, path, tenantID, sourceNodeID, timestamp, nonce, body)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(normalized))
	return hex.EncodeToString(mac.Sum(nil))
}

func VerifySignature(secret []byte, signatureHex string, method string, path string, tenantID string, sourceNodeID string, timestamp string, nonce string, body []byte) bool {
	sigRaw, err := hex.DecodeString(strings.TrimSpace(signatureHex))
	if err != nil {
		return false
	}
	expected := BuildSignature(secret, method, path, tenantID, sourceNodeID, timestamp, nonce, body)
	expectedRaw, err := hex.DecodeString(expected)
	if err != nil {
		return false
	}
	return hmac.Equal(sigRaw, expectedRaw)
}

func canonicalSignatureInput(method string, path string, tenantID string, sourceNodeID string, timestamp string, nonce string, body []byte) string {
	bodyHash := sha256.Sum256(body)
	parts := []string{
		strings.ToUpper(strings.TrimSpace(method)),
		strings.TrimSpace(path),
		strings.TrimSpace(tenantID),
		strings.TrimSpace(sourceNodeID),
		strings.TrimSpace(timestamp),
		strings.TrimSpace(nonce),
		hex.EncodeToString(bodyHash[:]),
	}
	return strings.Join(parts, "\n")
}
