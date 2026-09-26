package main

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	pkgcrypto "vecta-kms/pkg/crypto"
)

// Master encryption key (MEK) configuration. Every stored secret value is
// envelope-encrypted: a per-value DEK encrypts the value, and the MEK wraps
// the DEK. There is no fallback. Without a valid SECRETS_MEK_B64 the service
// refuses to start (docs/SECURITY/SECURE_DEFAULTS.md).
const (
	envMEK         = "SECRETS_MEK_B64"
	envPreviousMEK = "SECRETS_MEK_PREVIOUS_B64"
	mekLen         = 32
	// A random 32-byte key has about 30 distinct byte values; fewer than 20
	// means a typed or patterned value, not a generated one.
	mekMinDistinctBytes = 20
	mekHelp             = "generate one with: openssl rand -base64 32 (docs/SECURITY/SECRET_ROTATION.md)"
)

// mekKeys is the configured MEK and, during a rotation, the one it replaces.
type mekKeys struct {
	Current  []byte
	Previous []byte // nil unless SECRETS_MEK_PREVIOUS_B64 is set
}

// loadMEKs reads and validates the MEK configuration from getenv.
func loadMEKs(getenv func(string) string) (mekKeys, error) {
	cur, err := parseMEK(envMEK, getenv(envMEK))
	if err != nil {
		return mekKeys{}, err
	}
	keys := mekKeys{Current: cur}
	if strings.TrimSpace(getenv(envPreviousMEK)) != "" {
		prev, err := parseMEK(envPreviousMEK, getenv(envPreviousMEK))
		if err != nil {
			return mekKeys{}, err
		}
		if pkgcrypto.ConstantTimeEqual(prev, cur) {
			return mekKeys{}, fmt.Errorf("%s equals %s; set it to the key being replaced, or unset it", envPreviousMEK, envMEK)
		}
		keys.Previous = prev
	}
	return keys, nil
}

func parseMEK(name, raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("%s is required; %s", name, mekHelp)
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("%s is not valid base64; %s", name, mekHelp)
	}
	if len(key) != mekLen {
		return nil, fmt.Errorf("%s must decode to exactly %d bytes, got %d; %s", name, mekLen, len(key), mekHelp)
	}
	if pkgcrypto.ConstantTimeEqual(key, legacyDevMEK()) {
		return nil, fmt.Errorf("%s is the public development key from the source code; %s", name, mekHelp)
	}
	distinct := map[byte]bool{}
	for _, b := range key {
		distinct[b] = true
	}
	if len(distinct) < mekMinDistinctBytes {
		return nil, fmt.Errorf("%s is not random (%d distinct bytes); %s", name, len(distinct), mekHelp)
	}
	return key, nil
}

// mekFingerprint identifies a MEK without revealing it: a keyed HMAC,
// truncated to 64 bits. It's stored so a node configured with a different
// MEK refuses to start instead of failing every read.
func mekFingerprint(mek []byte) string {
	sum, err := pkgcrypto.HMAC("SHA-256", mek, []byte("vecta/secrets/mek-fingerprint/v1"))
	if err != nil {
		panic("secrets: HMAC-SHA-256 unavailable: " + err.Error())
	}
	return hex.EncodeToString(sum[:8])
}

var errMEKMismatch = errors.New("configured MEK does not match the key this deployment's secrets are wrapped under")
