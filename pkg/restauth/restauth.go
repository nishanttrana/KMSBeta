package restauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

type XFCCInfo struct {
	HashHex string   `json:"hash_hex,omitempty"`
	Subject string   `json:"subject,omitempty"`
	URISANs []string `json:"uri_sans,omitempty"`
	DNSSANs []string `json:"dns_sans,omitempty"`
	CertPEM string   `json:"cert_pem,omitempty"`
}

func NormalizeCertFingerprint(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	value = strings.TrimPrefix(value, "sha256:")
	value = strings.TrimPrefix(value, "SHA256:")
	value = strings.ReplaceAll(value, ":", "")
	value = strings.ReplaceAll(value, "-", "")
	if decoded, err := hex.DecodeString(value); err == nil && len(decoded) > 0 {
		return strings.ToLower(hex.EncodeToString(decoded))
	}
	if decoded, err := base64.RawURLEncoding.DecodeString(value); err == nil && len(decoded) > 0 {
		return strings.ToLower(hex.EncodeToString(decoded))
	}
	if decoded, err := base64.StdEncoding.DecodeString(value); err == nil && len(decoded) > 0 {
		return strings.ToLower(hex.EncodeToString(decoded))
	}
	return strings.ToLower(value)
}

func FingerprintHexToThumbprintB64URL(raw string) string {
	value := NormalizeCertFingerprint(raw)
	if value == "" {
		return ""
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) == 0 {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(decoded)
}

func ParseForwardedClientCert(raw string) XFCCInfo {
	info := XFCCInfo{}
	value := strings.TrimSpace(raw)
	if value == "" {
		return info
	}
	segments := strings.Split(value, ";")
	for _, segment := range segments {
		parts := strings.SplitN(strings.TrimSpace(segment), "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		item := strings.Trim(strings.TrimSpace(parts[1]), "\"")
		switch key {
		case "hash":
			info.HashHex = NormalizeCertFingerprint(item)
		case "subject":
			info.Subject = item
		case "uri":
			info.URISANs = append(info.URISANs, item)
		case "dns":
			info.DNSSANs = append(info.DNSSANs, item)
		case "cert":
			if decoded, err := url.QueryUnescape(item); err == nil {
				info.CertPEM = decoded
			} else {
				info.CertPEM = item
			}
		}
	}
	return info
}

func RequestURLCandidates(r *http.Request) []string {
	if r == nil || r.URL == nil {
		return nil
	}
	schemeCandidates := dedupeStrings([]string{
		strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")),
		strings.TrimSpace(r.URL.Scheme),
		func() string {
			if r.TLS != nil {
				return "https"
			}
			return "http"
		}(),
	})
	hostCandidates := dedupeStrings([]string{
		strings.TrimSpace(r.Header.Get("X-Forwarded-Host")),
		strings.TrimSpace(r.Host),
		strings.TrimSpace(r.URL.Host),
	})
	pathCandidates := dedupeStrings([]string{
		requestPathWithQuery(strings.TrimSpace(r.Header.Get("X-Original-Uri"))),
		requestPathWithQuery(strings.TrimSpace(r.Header.Get("X-Envoy-Original-Path"))),
		requestPathWithQuery(strings.TrimSpace(r.URL.RequestURI())),
		requestPathWithQuery(r.URL.Path),
	})
	values := make([]string, 0, len(schemeCandidates)*len(hostCandidates)*len(pathCandidates))
	for _, scheme := range schemeCandidates {
		for _, host := range hostCandidates {
			if scheme == "" || host == "" {
				continue
			}
			for _, path := range pathCandidates {
				if path == "" {
					continue
				}
				values = append(values, scheme+"://"+host+path)
			}
		}
	}
	return dedupeStrings(values)
}

func requestPathWithQuery(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		if parsed, err := url.Parse(value); err == nil {
			if parsed.RawQuery != "" {
				return parsed.Path + "?" + parsed.RawQuery
			}
			return parsed.Path
		}
	}
	if !strings.HasPrefix(value, "/") {
		value = "/" + value
	}
	return value
}

func ParsePublicKeyPEM(raw string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(raw)))
	if block == nil {
		return nil, errors.New("invalid public key pem")
	}
	if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
		return cert.PublicKey, nil
	}
	if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, errors.New("unsupported public key format")
}

func VerifyAsymmetricSignature(publicKey crypto.PublicKey, algorithm string, signingInput []byte, signature []byte) error {
	switch key := publicKey.(type) {
	case ed25519.PublicKey:
		if !ed25519.Verify(key, signingInput, signature) {
			return errors.New("ed25519 signature verification failed")
		}
		return nil
	case *rsa.PublicKey:
		hash := selectHash(strings.TrimSpace(algorithm), crypto.SHA256)
		sum := digestBytes(hash, signingInput)
		switch strings.ToLower(strings.TrimSpace(algorithm)) {
		case "rsa-pss-sha512":
			return rsa.VerifyPSS(key, crypto.SHA512, sum, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		case "rsa-pss-sha384":
			return rsa.VerifyPSS(key, crypto.SHA384, sum, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		case "rsa-v1_5-sha512":
			return rsa.VerifyPKCS1v15(key, crypto.SHA512, sum, signature)
		case "rsa-v1_5-sha384":
			return rsa.VerifyPKCS1v15(key, crypto.SHA384, sum, signature)
		case "rsa-v1_5-sha256", "rs256", "":
			return rsa.VerifyPKCS1v15(key, crypto.SHA256, sum, signature)
		default:
			return rsa.VerifyPSS(key, hash, sum, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		}
	case *ecdsa.PublicKey:
		hash := selectHash(strings.TrimSpace(algorithm), crypto.SHA256)
		sum := digestBytes(hash, signingInput)
		if !ecdsa.VerifyASN1(key, sum, signature) {
			return errors.New("ecdsa signature verification failed")
		}
		return nil
	default:
		return errors.New("unsupported public key type")
	}
}

func digestBytes(hash crypto.Hash, input []byte) []byte {
	switch hash {
	case crypto.SHA384:
		sum := sha512Sum384(input)
		return sum[:]
	case crypto.SHA512:
		sum := sha512Sum512(input)
		return sum[:]
	default:
		sum := sha256.Sum256(input)
		return sum[:]
	}
}

func selectHash(algorithm string, fallback crypto.Hash) crypto.Hash {
	switch strings.ToLower(strings.TrimSpace(algorithm)) {
	case "rsa-pss-sha512", "rsa-v1_5-sha512", "ecdsa-p521-sha512":
		return crypto.SHA512
	case "rsa-pss-sha384", "rsa-v1_5-sha384", "ecdsa-p384-sha384":
		return crypto.SHA384
	default:
		return fallback
	}
}

func sha512Sum384(input []byte) [48]byte {
	hasher := crypto.SHA384.New()
	_, _ = hasher.Write(input)
	sum := hasher.Sum(nil)
	out := [48]byte{}
	copy(out[:], sum)
	return out
}

func sha512Sum512(input []byte) [64]byte {
	hasher := crypto.SHA512.New()
	_, _ = hasher.Write(input)
	sum := hasher.Sum(nil)
	out := [64]byte{}
	copy(out[:], sum)
	return out
}

func dedupeStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func JWKThumbprint(raw map[string]any) (string, error) {
	kty := strings.ToUpper(strings.TrimSpace(mapString(raw, "kty")))
	if kty == "" {
		return "", errors.New("jwk missing kty")
	}
	canonical := map[string]string{"kty": kty}
	switch kty {
	case "RSA":
		canonical["e"] = mapString(raw, "e")
		canonical["n"] = mapString(raw, "n")
		if canonical["e"] == "" || canonical["n"] == "" {
			return "", errors.New("rsa jwk missing e or n")
		}
	case "EC":
		canonical["crv"] = mapString(raw, "crv")
		canonical["x"] = mapString(raw, "x")
		canonical["y"] = mapString(raw, "y")
		if canonical["crv"] == "" || canonical["x"] == "" || canonical["y"] == "" {
			return "", errors.New("ec jwk missing crv, x, or y")
		}
	case "OKP":
		canonical["crv"] = mapString(raw, "crv")
		canonical["x"] = mapString(raw, "x")
		if canonical["crv"] == "" || canonical["x"] == "" {
			return "", errors.New("okp jwk missing crv or x")
		}
	default:
		return "", errors.New("unsupported jwk key type")
	}
	keys := make([]string, 0, len(canonical))
	for key := range canonical {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		valueBytes, _ := json.Marshal(canonical[key])
		parts = append(parts, `"`+key+`":`+string(valueBytes))
	}
	canonicalJSON := "{" + strings.Join(parts, ",") + "}"
	sum := sha256.Sum256([]byte(canonicalJSON))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func JWKPublicKey(raw map[string]any) (crypto.PublicKey, error) {
	kty := strings.ToUpper(strings.TrimSpace(mapString(raw, "kty")))
	switch kty {
	case "RSA":
		nRaw, err := base64.RawURLEncoding.DecodeString(mapString(raw, "n"))
		if err != nil {
			return nil, errors.New("invalid rsa jwk modulus")
		}
		eRaw, err := base64.RawURLEncoding.DecodeString(mapString(raw, "e"))
		if err != nil {
			return nil, errors.New("invalid rsa jwk exponent")
		}
		e := 0
		for _, b := range eRaw {
			e = (e << 8) | int(b)
		}
		if e == 0 {
			return nil, errors.New("invalid rsa jwk exponent")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nRaw), E: e}, nil
	case "EC":
		crv := strings.TrimSpace(mapString(raw, "crv"))
		xRaw, err := base64.RawURLEncoding.DecodeString(mapString(raw, "x"))
		if err != nil {
			return nil, errors.New("invalid ec jwk x coordinate")
		}
		yRaw, err := base64.RawURLEncoding.DecodeString(mapString(raw, "y"))
		if err != nil {
			return nil, errors.New("invalid ec jwk y coordinate")
		}
		curve := ecCurve(crv)
		if curve == nil {
			return nil, errors.New("unsupported ec jwk curve")
		}
		return &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(xRaw), Y: new(big.Int).SetBytes(yRaw)}, nil
	case "OKP":
		if !strings.EqualFold(strings.TrimSpace(mapString(raw, "crv")), "Ed25519") {
			return nil, errors.New("unsupported okp jwk curve")
		}
		xRaw, err := base64.RawURLEncoding.DecodeString(mapString(raw, "x"))
		if err != nil {
			return nil, errors.New("invalid okp jwk x coordinate")
		}
		return ed25519.PublicKey(xRaw), nil
	default:
		return nil, errors.New("unsupported jwk key type")
	}
}

func mapString(raw map[string]any, key string) string {
	if raw == nil {
		return ""
	}
	if value, ok := raw[key]; ok {
		return strings.TrimSpace(valueToString(value))
	}
	return ""
}

func valueToString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	default:
		raw, _ := json.Marshal(v)
		return strings.TrimSpace(strings.Trim(string(raw), "\""))
	}
}

func ecCurve(raw string) elliptic.Curve {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "P-256", "SECP256R1":
		return elliptic.P256()
	case "P-384", "SECP384R1":
		return elliptic.P384()
	case "P-521", "SECP521R1":
		return elliptic.P521()
	default:
		return nil
	}
}
