package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"unicode/utf8"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"

	pkgcrypto "vecta-kms/pkg/crypto"
)

func thresholdSignWithSecret(secret *big.Int, algorithm string, messageInput string) (map[string]interface{}, error) {
	message, digestHex, err := parseThresholdMessage(messageInput)
	if err != nil {
		return nil, err
	}

	alg := strings.ToUpper(strings.TrimSpace(algorithm))
	if usesFROST(alg) {
		return signEd25519(secret, alg, message, digestHex)
	}
	return signECDSA(secret, alg, message, digestHex)
}

func thresholdDecryptWithSecret(secret *big.Int, ciphertextInput string) ([]byte, map[string]interface{}, error) {
	key := deriveAES256Key(secret)
	defer pkgcrypto.Zeroize(key)

	nonce, ciphertext, aad, payloadType, parseErr := parseThresholdCiphertext(ciphertextInput)
	if parseErr == nil && len(ciphertext) > 0 && len(nonce) > 0 {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, nil, fmt.Errorf("cipher init failed: %w", err)
		}
		gcm, err := cipher.NewGCMWithNonceSize(block, len(nonce))
		if err != nil {
			return nil, nil, fmt.Errorf("gcm init failed: %w", err)
		}
		plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
		if err == nil {
			meta := map[string]interface{}{
				"cipher":       "AES-256-GCM",
				"nonce_size":   len(nonce),
				"aad_len":      len(aad),
				"payload_type": payloadType,
			}
			if utf8.Valid(plaintext) {
				meta["plaintext_utf8"] = string(plaintext)
			}
			return plaintext, meta, nil
		}
		if !strings.Contains(strings.ToLower(err.Error()), "message authentication failed") {
			return nil, nil, fmt.Errorf("aes-gcm decrypt failed: %w", err)
		}
	}

	legacyCiphertext, err := decodeFlexibleBinary(ciphertextInput)
	if err != nil {
		if parseErr != nil {
			return nil, nil, parseErr
		}
		return nil, nil, fmt.Errorf("invalid ciphertext encoding")
	}
	plaintext := xorDecryptWithSecret(secret, legacyCiphertext)
	meta := map[string]interface{}{
		"cipher":              "XOR-LEGACY",
		"compatibility_mode":  "legacy_xor_fallback",
		"fallback_reason":     "ciphertext_not_aes_gcm_payload",
		"legacy_payload_size": len(legacyCiphertext),
	}
	if utf8.Valid(plaintext) {
		meta["plaintext_utf8"] = string(plaintext)
	}
	return plaintext, meta, nil
}

func signECDSA(secret *big.Int, algorithm string, message []byte, digestHex string) (map[string]interface{}, error) {
	curve, curveName, compat := resolveECDSACurve(algorithm)
	orderMinusOne := new(big.Int).Sub(curve.Params().N, big.NewInt(1))
	d := new(big.Int).Mod(secret, orderMinusOne)
	d.Add(d, big.NewInt(1))

	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve},
		D:         d,
	}
	priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(d.Bytes())

	sigASN1, err := ecdsa.SignASN1(rand.Reader, priv, message)
	if err != nil {
		return nil, fmt.Errorf("ecdsa sign failed: %w", err)
	}
	out := map[string]interface{}{
		"signature":              base64.StdEncoding.EncodeToString(sigASN1),
		"signature_b64":          base64.StdEncoding.EncodeToString(sigASN1),
		"signature_hex":          hex.EncodeToString(sigASN1),
		"signature_encoding":     "ASN.1 DER",
		"algorithm":              fmt.Sprintf("ECDSA-%s", curveName),
		"message_digest":         digestHex,
	}
	pubDER, pubErr := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if pubErr == nil {
		pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
		pubFP := sha256.Sum256(pubDER)
		out["public_key_pem"] = string(pubPEM)
		out["public_key_fingerprint"] = hex.EncodeToString(pubFP[:])
	} else {
		pubRaw := elliptic.Marshal(curve, priv.PublicKey.X, priv.PublicKey.Y)
		pubFP := sha256.Sum256(pubRaw)
		out["public_key_format"] = "SEC1_UNCOMPRESSED"
		out["public_key_uncompressed_hex"] = hex.EncodeToString(pubRaw)
		out["public_key_fingerprint"] = hex.EncodeToString(pubFP[:])
		compat = append(compat, "pkix_public_key_encoding_unavailable_for_curve")
	}
	if len(compat) > 0 {
		out["compatibility_notes"] = compat
	}
	return out, nil
}

func signEd25519(secret *big.Int, algorithm string, message []byte, digestHex string) (map[string]interface{}, error) {
	seedHash := sha256.Sum256(secret.Bytes())
	seed := make([]byte, ed25519.SeedSize)
	copy(seed, seedHash[:])
	defer pkgcrypto.Zeroize(seed)

	priv := ed25519.NewKeyFromSeed(seed)
	defer pkgcrypto.Zeroize(priv)
	pub := priv.Public().(ed25519.PublicKey)
	sig := ed25519.Sign(priv, message)

	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshal public key failed: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	pubFP := sha256.Sum256(pubDER)

	return map[string]interface{}{
		"signature":              base64.StdEncoding.EncodeToString(sig),
		"signature_b64":          base64.StdEncoding.EncodeToString(sig),
		"signature_hex":          hex.EncodeToString(sig),
		"signature_encoding":     "RAW",
		"algorithm":              defaultString(strings.TrimSpace(algorithm), "Ed25519"),
		"message_digest":         digestHex,
		"public_key_pem":         string(pubPEM),
		"public_key_fingerprint": hex.EncodeToString(pubFP[:]),
	}, nil
}

func resolveECDSACurve(algorithm string) (elliptic.Curve, string, []string) {
	alg := strings.ToUpper(strings.TrimSpace(algorithm))
	switch {
	case strings.Contains(alg, "P521"):
		return elliptic.P521(), "P-521", nil
	case strings.Contains(alg, "P384"):
		return elliptic.P384(), "P-384", nil
	case strings.Contains(alg, "SECP256K1"):
		return secp256k1.S256(), "secp256k1", nil
	default:
		return elliptic.P256(), "P-256", nil
	}
}

func parseThresholdMessage(messageInput string) ([]byte, string, error) {
	raw := strings.TrimSpace(messageInput)
	if raw == "" {
		return nil, "", errors.New("message hash is required")
	}
	if strings.HasPrefix(raw, "0x") || strings.HasPrefix(raw, "0X") {
		raw = raw[2:]
	}
	if b, err := tryDecodeHex(raw); err == nil && len(b) > 0 {
		return b, strings.ToLower(hex.EncodeToString(b)), nil
	}
	if b, err := base64.StdEncoding.DecodeString(raw); err == nil && len(b) > 0 {
		return b, strings.ToLower(hex.EncodeToString(b)), nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(raw); err == nil && len(b) > 0 {
		return b, strings.ToLower(hex.EncodeToString(b)), nil
	}
	b := []byte(raw)
	sum := sha256.Sum256(b)
	return sum[:], strings.ToLower(hex.EncodeToString(sum[:])), nil
}

func parseThresholdCiphertext(raw string) ([]byte, []byte, []byte, string, error) {
	input := strings.TrimSpace(raw)
	if input == "" {
		return nil, nil, nil, "", errors.New("ciphertext is required")
	}

	if strings.HasPrefix(input, "{") {
		var payload map[string]interface{}
		if err := json.Unmarshal([]byte(input), &payload); err == nil {
			nonceRaw := firstString(payload["nonce"], payload["iv"])
			cipherRaw := firstString(payload["ciphertext"], payload["ct"], payload["data"])
			if nonceRaw == "" || cipherRaw == "" {
				return nil, nil, nil, "", errors.New("json payload requires nonce/iv and ciphertext")
			}
			nonce, err := decodeFlexibleBinary(nonceRaw)
			if err != nil {
				return nil, nil, nil, "", fmt.Errorf("invalid nonce/iv encoding")
			}
			ciphertext, err := decodeFlexibleBinary(cipherRaw)
			if err != nil {
				return nil, nil, nil, "", fmt.Errorf("invalid ciphertext encoding")
			}

			aad := []byte{}
			if aadRaw := firstString(payload["aad"], payload["associated_data"]); aadRaw != "" {
				aadEncoding := strings.ToLower(firstString(payload["aad_encoding"]))
				if aadEncoding == "utf8" || aadEncoding == "text" {
					aad = []byte(aadRaw)
				} else if decodedAAD, err := decodeFlexibleBinary(aadRaw); err == nil {
					aad = decodedAAD
				} else {
					aad = []byte(aadRaw)
				}
			}
			return nonce, ciphertext, aad, "json", nil
		}
	}

	if strings.Contains(input, ":") {
		parts := strings.SplitN(input, ":", 2)
		if len(parts) == 2 {
			nonce, err := decodeFlexibleBinary(parts[0])
			if err != nil {
				return nil, nil, nil, "", fmt.Errorf("invalid nonce encoding")
			}
			ciphertext, err := decodeFlexibleBinary(parts[1])
			if err != nil {
				return nil, nil, nil, "", fmt.Errorf("invalid ciphertext encoding")
			}
			return nonce, ciphertext, nil, "nonce:ciphertext", nil
		}
	}

	packed, err := decodeFlexibleBinary(input)
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("invalid ciphertext encoding")
	}
	if len(packed) <= 12 {
		return nil, nil, nil, "", errors.New("packed ciphertext must include 12-byte nonce + encrypted payload")
	}
	nonce := make([]byte, 12)
	copy(nonce, packed[:12])
	ciphertext := make([]byte, len(packed)-12)
	copy(ciphertext, packed[12:])
	return nonce, ciphertext, nil, "packed", nil
}

func deriveAES256Key(secret *big.Int) []byte {
	sum := sha256.Sum256(secret.Bytes())
	key := make([]byte, len(sum))
	copy(key, sum[:])
	return key
}

func tryDecodeHex(v string) ([]byte, error) {
	in := strings.TrimSpace(v)
	if in == "" {
		return nil, errors.New("empty")
	}
	if len(in)%2 != 0 {
		return nil, errors.New("odd length")
	}
	return hex.DecodeString(in)
}
