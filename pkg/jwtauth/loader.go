// Package jwtauth centralises JWT-parser construction for the HTTP
// services. Every service that fronts tenant-scoped data wires the same
// parser via LoadParser so the parsing rules (issuer, audience, leeway,
// algorithm) stay consistent and operators rotate keys in one place.
package jwtauth

import (
	"encoding/base64"
	"encoding/pem"
	"errors"
	"crypto/rsa"
	"crypto/x509"
	"os"
	"strings"
	"time"

	pkgauth "vecta-kms/pkg/auth"
)

// Config describes what LoadParser reads from the environment. Prefix
// names the per-service variable prefix (e.g. "AI_GATEWAY" reads
// AI_GATEWAY_JWT_PUBLIC_KEY_PEM / _B64). Issuer and Audience are passed
// through to the JWT parser so claims with mismatched iss/aud are
// rejected.
type Config struct {
	Prefix   string
	Issuer   string
	Audience string
}

// LoadParser reads the PEM (or base64-encoded PEM) public key from
// environment and returns a parser closure suitable for
// pkgauth.HTTPMiddleware.
//
// Behaviour:
//   - Both <PREFIX>_JWT_PUBLIC_KEY_PEM and <PREFIX>_JWT_PUBLIC_KEY_B64
//     unset → returns (nil, nil). Callers MUST treat nil as fail-closed
//     in their middleware wiring (i.e., refuse to start).
//   - PEM present but unparseable → returns (nil, error).
//   - Valid RSA public key → returns a parser that validates RS256
//     signatures with the supplied issuer/audience and a 30-second
//     clock skew tolerance.
//
// We never silently disable JWT verification: empty env produces
// (nil, nil) so the caller's startup logic can make the disable choice
// explicit instead of inheriting it implicitly.
func LoadParser(cfg Config) (func(string) (*pkgauth.Claims, error), error) {
	if strings.TrimSpace(cfg.Prefix) == "" {
		return nil, errors.New("jwtauth: prefix is required")
	}
	// Lookup order per source format: per-service env first (so a single
	// service can override the cluster value), then a shared
	// JWT_PUBLIC_KEY_* fallback so the common deployment supplies one
	// env var across every service.
	pubPEM := strings.TrimSpace(os.Getenv(cfg.Prefix + "_JWT_PUBLIC_KEY_PEM"))
	if pubPEM == "" {
		pubPEM = strings.TrimSpace(os.Getenv("JWT_PUBLIC_KEY_PEM"))
	}
	if pubPEM == "" {
		b64 := strings.TrimSpace(os.Getenv(cfg.Prefix + "_JWT_PUBLIC_KEY_B64"))
		if b64 == "" {
			b64 = strings.TrimSpace(os.Getenv("JWT_PUBLIC_KEY_B64"))
		}
		if b64 != "" {
			raw, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				return nil, err
			}
			pubPEM = string(raw)
		}
	}
	pubPEM = strings.ReplaceAll(pubPEM, `\n`, "\n")
	if pubPEM == "" {
		return nil, nil
	}
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, errors.New("jwtauth: invalid public key PEM")
	}
	var pub *rsa.PublicKey
	if parsed, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		if p, ok := parsed.(*rsa.PublicKey); ok {
			pub = p
		}
	}
	if pub == nil {
		if p, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
			pub = p
		}
	}
	if pub == nil {
		return nil, errors.New("jwtauth: unable to parse RSA public key")
	}
	issuer := cfg.Issuer
	audience := cfg.Audience
	return func(token string) (*pkgauth.Claims, error) {
		return pkgauth.ParseRS256WithOptions(token, pub, pkgauth.ParseOptions{
			Issuer:   issuer,
			Audience: audience,
			Leeway:   30 * time.Second,
		})
	}, nil
}
