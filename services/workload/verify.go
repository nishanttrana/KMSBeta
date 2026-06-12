package main

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	pkgcrypto "vecta-kms/pkg/crypto"
)

type verificationResult struct {
	SpiffeID      string
	TrustDomain   string
	SVIDType      string
	ExpiresAt     time.Time
	DocumentHash  string
	SerialOrKeyID string
	Audiences     []string
}

func generateSigningMaterial(trustDomain string) (string, string, string, string, string, string, error) {
	caKP, err := pkgcrypto.GenerateKeyPair(pkgcrypto.AlgRSA2048)
	if err != nil {
		return "", "", "", "", "", "", err
	}
	jwtKP, err := pkgcrypto.GenerateKeyPair(pkgcrypto.AlgRSA2048)
	if err != nil {
		return "", "", "", "", "", "", err
	}
	now := time.Now().UTC()
	serial, _ := pkgcrypto.RandomInt(new(big.Int).Lsh(big.NewInt(1), 62))
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "SPIFFE Root CA " + trustDomain},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        false,
	}
	der, err := x509.CreateCertificate(pkgcrypto.Reader, tpl, tpl, caKP.Public, caKP.Private)
	if err != nil {
		return "", "", "", "", "", "", err
	}
	caCertPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	caKeyPEMBytes, err := pkgcrypto.MarshalPrivateKeyPEM(caKP)
	if err != nil {
		return "", "", "", "", "", "", err
	}
	caKeyPEM := string(caKeyPEMBytes)

	jwtPrivPEMBytes, err := pkgcrypto.MarshalPrivateKeyPEM(jwtKP)
	if err != nil {
		return "", "", "", "", "", "", err
	}
	jwtPrivPEM := string(jwtPrivPEMBytes)
	jwtPubPEMBytes, err := pkgcrypto.MarshalPublicKeyPEM(jwtKP.Public)
	if err != nil {
		return "", "", "", "", "", "", err
	}
	jwtPubPEM := string(jwtPubPEMBytes)
	kid := sha256Hex(trustDomain, jwtPubPEM)[:16]
	jwksJSON, err := buildJWKSJSON(kid, jwtKP.Public)
	if err != nil {
		return "", "", "", "", "", "", err
	}
	return caCertPEM, caKeyPEM, jwtPrivPEM, jwtPubPEM, kid, jwksJSON, nil
}

func buildJWKSJSON(kid string, pub crypto.PublicKey) (string, error) {
	n, e, err := pkgcrypto.RSAPublicKeyJWK(pub)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"alg": "RS256",
				"use": "sig",
				"kid": strings.TrimSpace(kid),
				"n":   n,
				"e":   e,
			},
		},
	})
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func parseRSAPrivateKeyFromPEM(raw string) (crypto.Signer, error) {
	kp, err := pkgcrypto.ParsePrivateKeyPEM([]byte(strings.TrimSpace(raw)))
	if err != nil {
		return nil, errors.New("failed to decode private key pem")
	}
	if !strings.HasPrefix(kp.Algorithm, "RSA-") {
		return nil, errors.New("private key is not RSA")
	}
	return kp.Private, nil
}

func parseRSAPublicKeyFromPEM(raw string) (crypto.PublicKey, error) {
	pub, err := pkgcrypto.ParseRSAPublicKeyPEM(strings.TrimSpace(raw))
	if err != nil {
		return nil, errors.New("public key is not RSA")
	}
	return pub, nil
}

func issueX509SVID(settings WorkloadIdentitySettings, reg WorkloadRegistration, ttl time.Duration) (IssuedSVID, error) {
	caKey, err := parseRSAPrivateKeyFromPEM(settings.LocalCAKeyPEM)
	if err != nil {
		return IssuedSVID{}, err
	}
	caCert, err := parseFirstCertificatePEM(settings.LocalCACertificatePEM)
	if err != nil {
		return IssuedSVID{}, err
	}
	workloadKP, err := pkgcrypto.GenerateKeyPair(pkgcrypto.AlgRSA2048)
	if err != nil {
		return IssuedSVID{}, err
	}
	serial, _ := pkgcrypto.RandomInt(new(big.Int).Lsh(big.NewInt(1), 62))
	now := time.Now().UTC()
	if ttl <= 0 {
		ttl = time.Duration(settings.DefaultX509TTLSeconds) * time.Second
	}
	spiffeURL, err := url.Parse(reg.SpiffeID)
	if err != nil {
		return IssuedSVID{}, err
	}
	leaf := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: firstNonEmpty(reg.Name, reg.SpiffeID),
		},
		NotBefore:   now.Add(-time.Minute),
		NotAfter:    now.Add(ttl),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:        []*url.URL{spiffeURL},
	}
	der, err := x509.CreateCertificate(pkgcrypto.Reader, leaf, caCert, workloadKP.Public, caKey)
	if err != nil {
		return IssuedSVID{}, err
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEMBytes, err := pkgcrypto.MarshalPrivateKeyPEM(workloadKP)
	if err != nil {
		return IssuedSVID{}, err
	}
	keyPEM := string(keyPEMBytes)
	expiresAt := leaf.NotAfter.UTC()
	rotationDueAt := expiresAt.Add(-time.Duration(settings.RotationWindowSeconds) * time.Second)
	return IssuedSVID{
		SpiffeID:                reg.SpiffeID,
		RegistrationID:          reg.ID,
		SVIDType:                "x509",
		CertificatePEM:          certPEM,
		PrivateKeyPEM:           keyPEM,
		BundlePEM:               settings.LocalCACertificatePEM,
		SerialOrKeyID:           serial.String(),
		ExpiresAt:               expiresAt,
		RotationDueAt:           rotationDueAt,
		CryptographicallySigned: true,
	}, nil
}

func issueJWTSVID(settings WorkloadIdentitySettings, reg WorkloadRegistration, audiences []string, ttl time.Duration) (IssuedSVID, error) {
	signingKey, err := parseRSAPrivateKeyFromPEM(settings.JWTSignerPrivatePEM)
	if err != nil {
		return IssuedSVID{}, err
	}
	if ttl <= 0 {
		ttl = time.Duration(settings.DefaultJWTTTLSeconds) * time.Second
	}
	now := time.Now().UTC()
	expiresAt := now.Add(ttl)
	if len(audiences) == 0 {
		audiences = append([]string{}, settings.AllowedAudiences...)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":          "spiffe://" + settings.TrustDomain,
		"sub":          reg.SpiffeID,
		"aud":          audiences,
		"iat":          now.Unix(),
		"nbf":          now.Add(-5 * time.Second).Unix(),
		"exp":          expiresAt.Unix(),
		"spiffe_id":    reg.SpiffeID,
		"trust_domain": settings.TrustDomain,
	})
	token.Header["kid"] = settings.JWTSignerKeyID
	signed, err := token.SignedString(signingKey)
	if err != nil {
		return IssuedSVID{}, err
	}
	rotationDueAt := expiresAt.Add(-time.Duration(settings.RotationWindowSeconds) * time.Second)
	return IssuedSVID{
		RegistrationID:          reg.ID,
		SpiffeID:                reg.SpiffeID,
		SVIDType:                "jwt",
		JWTSVID:                 signed,
		JWKSJSON:                settings.LocalBundleJWKS,
		SerialOrKeyID:           settings.JWTSignerKeyID,
		ExpiresAt:               expiresAt,
		RotationDueAt:           rotationDueAt,
		CryptographicallySigned: true,
	}, nil
}

func verifyJWTSVID(tokenString string, settings WorkloadIdentitySettings, bundles []WorkloadFederationBundle, expectedAudience string) (verificationResult, error) {
	tokenString = strings.TrimSpace(tokenString)
	if tokenString == "" {
		return verificationResult{}, errors.New("jwt_svid is required")
	}
	unverified, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return verificationResult{}, err
	}
	claims, _ := unverified.Claims.(jwt.MapClaims)
	subject := strings.TrimSpace(toString(claims["sub"]))
	if subject == "" || !strings.HasPrefix(strings.ToLower(subject), "spiffe://") {
		return verificationResult{}, errors.New("jwt_svid subject must be a SPIFFE ID")
	}
	trustDomain := spiffeTrustDomain(subject)
	if trustDomain == "" {
		issuer := strings.TrimSpace(toString(claims["iss"]))
		trustDomain = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(issuer)), "spiffe://")
	}
	kid := strings.TrimSpace(toString(unverified.Header["kid"]))
	pub, err := resolveJWTVerificationKey(settings, bundles, trustDomain, kid)
	if err != nil {
		return verificationResult{}, err
	}
	parserOpts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	}
	if expectedAudience != "" {
		parserOpts = append(parserOpts, jwt.WithAudience(expectedAudience))
	}
	verified, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return pub, nil
	}, parserOpts...)
	if err != nil {
		return verificationResult{}, err
	}
	if !verified.Valid {
		return verificationResult{}, errors.New("jwt_svid verification failed")
	}
	verifiedClaims, _ := verified.Claims.(jwt.MapClaims)
	exp, _ := verifiedClaims.GetExpirationTime()
	aud, _ := verifiedClaims.GetAudience()
	if expectedAudience == "" && len(settings.AllowedAudiences) > 0 && !audienceIntersects(aud, settings.AllowedAudiences) {
		return verificationResult{}, errors.New("jwt_svid audience is not allowed by tenant policy")
	}
	return verificationResult{
		SpiffeID:      subject,
		TrustDomain:   firstNonEmpty(trustDomain, settings.TrustDomain),
		SVIDType:      "jwt",
		ExpiresAt:     exp.Time.UTC(),
		DocumentHash:  sha256Hex(tokenString),
		SerialOrKeyID: firstNonEmpty(kid, settings.JWTSignerKeyID),
		Audiences:     aud,
	}, nil
}

func verifyX509SVID(chainPEM string, settings WorkloadIdentitySettings, bundles []WorkloadFederationBundle) (verificationResult, error) {
	chain, err := parseCertificateChainPEM(chainPEM)
	if err != nil {
		return verificationResult{}, err
	}
	if len(chain) == 0 {
		return verificationResult{}, errors.New("x509_svid_chain_pem is required")
	}
	leaf := chain[0]
	spiffeID := firstURISAN(leaf)
	if spiffeID == "" {
		return verificationResult{}, errors.New("x509_svid leaf certificate must contain a SPIFFE URI SAN")
	}
	trustDomain := spiffeTrustDomain(spiffeID)
	roots := x509.NewCertPool()
	if trustDomain == settings.TrustDomain {
		if cert, err := parseFirstCertificatePEM(settings.LocalCACertificatePEM); err == nil {
			roots.AddCert(cert)
		}
	} else {
		for _, bundle := range bundles {
			if !bundle.Enabled || bundle.TrustDomain != trustDomain {
				continue
			}
			for _, cert := range parseAllCertificatesPEM(bundle.CABundlePEM) {
				roots.AddCert(cert)
			}
		}
	}
	if len(roots.Subjects()) == 0 {
		return verificationResult{}, fmt.Errorf("no trusted CA bundle configured for trust domain %s", trustDomain)
	}
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now().UTC(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return verificationResult{}, err
	}
	return verificationResult{
		SpiffeID:      spiffeID,
		TrustDomain:   trustDomain,
		SVIDType:      "x509",
		ExpiresAt:     leaf.NotAfter.UTC(),
		DocumentHash:  sha256Hex(chainPEM),
		SerialOrKeyID: leaf.SerialNumber.String(),
	}, nil
}

func resolveJWTVerificationKey(settings WorkloadIdentitySettings, bundles []WorkloadFederationBundle, trustDomain string, kid string) (crypto.PublicKey, error) {
	if trustDomain == settings.TrustDomain {
		return parseRSAPublicKeyFromPEM(settings.JWTSignerPublicPEM)
	}
	for _, bundle := range bundles {
		if !bundle.Enabled || !strings.EqualFold(bundle.TrustDomain, trustDomain) {
			continue
		}
		if pub, err := resolveRSAPublicKeyFromJWKS(bundle.JWKSJSON, kid); err == nil {
			return pub, nil
		}
	}
	return nil, fmt.Errorf("no trusted JWT verifier for trust domain %s", trustDomain)
}

func resolveRSAPublicKeyFromJWKS(jwksJSON string, kid string) (crypto.PublicKey, error) {
	var doc struct {
		Keys []struct {
			KeyType string `json:"kty"`
			KeyID   string `json:"kid"`
			N       string `json:"n"`
			E       string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(jwksJSON)), &doc); err != nil {
		return nil, err
	}
	for _, key := range doc.Keys {
		if strings.ToUpper(strings.TrimSpace(key.KeyType)) != "RSA" {
			continue
		}
		if kid != "" && strings.TrimSpace(key.KeyID) != kid {
			continue
		}
		return pkgcrypto.RSAPublicKeyFromJWK(strings.TrimSpace(key.N), strings.TrimSpace(key.E))
	}
	return nil, errors.New("rsa jwk not found")
}

func parseFirstCertificatePEM(raw string) (*x509.Certificate, error) {
	certs := parseAllCertificatesPEM(raw)
	if len(certs) == 0 {
		return nil, errors.New("certificate pem is empty")
	}
	return certs[0], nil
}

func parseAllCertificatesPEM(raw string) []*x509.Certificate {
	var certs []*x509.Certificate
	remaining := []byte(strings.TrimSpace(raw))
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		remaining = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			certs = append(certs, cert)
		}
	}
	return certs
}

func parseCertificateChainPEM(raw string) ([]*x509.Certificate, error) {
	certs := parseAllCertificatesPEM(raw)
	if len(certs) == 0 {
		return nil, errors.New("failed to parse certificate chain")
	}
	return certs, nil
}

func firstURISAN(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	for _, uri := range cert.URIs {
		if uri == nil {
			continue
		}
		value := strings.TrimSpace(uri.String())
		if strings.HasPrefix(strings.ToLower(value), "spiffe://") {
			return value
		}
	}
	return ""
}

func spiffeTrustDomain(spiffeID string) string {
	raw := strings.TrimSpace(spiffeID)
	if !strings.HasPrefix(strings.ToLower(raw), "spiffe://") {
		return ""
	}
	trimmed := strings.TrimPrefix(raw, "spiffe://")
	if idx := strings.Index(trimmed, "/"); idx >= 0 {
		return strings.TrimSpace(trimmed[:idx])
	}
	return strings.TrimSpace(trimmed)
}

func audienceIntersects(left []string, right []string) bool {
	set := map[string]struct{}{}
	for _, value := range left {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			set[trimmed] = struct{}{}
		}
	}
	for _, value := range right {
		if _, ok := set[strings.TrimSpace(value)]; ok {
			return true
		}
	}
	return false
}
