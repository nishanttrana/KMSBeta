package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// GoogleCSEProvider implements the KACLS (Key Access Control List Service) API
// for Google Workspace Client-Side Encryption. Google calls this service to
// wrap/unwrap DEKs used to encrypt Gmail, Drive, Calendar, and Meet data.
type GoogleCSEProvider struct {
	httpClient *http.Client
	logger     *log.Logger

	// Google OIDC public key cache
	googleKeysMu    sync.RWMutex
	googleKeysCache map[string]*rsa.PublicKey
	googleKeysTTL   time.Time
}

// GoogleCSEClaims holds validated claims from Google's JWT tokens.
type GoogleCSEClaims struct {
	Email        string `json:"email"`
	HD           string `json:"hd"`            // hosted domain
	ResourceName string `json:"resource_name"` // from authorization JWT
	KeyURI       string `json:"kacls_url"`     // KACLS key URI from authorization JWT
	Issuer       string `json:"iss"`
	Subject      string `json:"sub"`
	Audience     string `json:"aud"`
	ExpiresAt    int64  `json:"exp"`
	IssuedAt     int64  `json:"iat"`
}

// googleJWKSResponse represents Google's JWKS endpoint response.
type googleJWKSResponse struct {
	Keys []googleJWK `json:"keys"`
}

type googleJWK struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// googleOAuth2TokenResponse is the response from Google's OAuth2 token endpoint.
type googleOAuth2TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Error       string `json:"error,omitempty"`
	ErrorDesc   string `json:"error_description,omitempty"`
}

func NewGoogleCSEProvider(logger *log.Logger) *GoogleCSEProvider {
	if logger == nil {
		logger = log.Default()
	}
	return &GoogleCSEProvider{
		httpClient:      &http.Client{Timeout: 30 * time.Second},
		logger:          logger,
		googleKeysCache: make(map[string]*rsa.PublicKey),
	}
}

// fetchGooglePublicKeys retrieves Google's OIDC public keys from the JWKS endpoint.
// Keys are cached for 1 hour to reduce API calls.
func (p *GoogleCSEProvider) fetchGooglePublicKeys() (map[string]*rsa.PublicKey, error) {
	p.googleKeysMu.RLock()
	if time.Now().Before(p.googleKeysTTL) && len(p.googleKeysCache) > 0 {
		keys := p.googleKeysCache
		p.googleKeysMu.RUnlock()
		return keys, nil
	}
	p.googleKeysMu.RUnlock()

	p.googleKeysMu.Lock()
	defer p.googleKeysMu.Unlock()

	// Double-check after acquiring write lock
	if time.Now().Before(p.googleKeysTTL) && len(p.googleKeysCache) > 0 {
		return p.googleKeysCache, nil
	}

	resp, err := p.httpClient.Get("https://www.googleapis.com/oauth2/v3/certs")
	if err != nil {
		return nil, fmt.Errorf("google cse: fetch JWKS: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("google cse: read JWKS body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google cse: JWKS returned HTTP %d", resp.StatusCode)
	}

	var jwks googleJWKSResponse
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("google cse: decode JWKS: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey)
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" {
			continue
		}
		nBytes, decErr := base64.RawURLEncoding.DecodeString(k.N)
		if decErr != nil {
			continue
		}
		eBytes, decErr := base64.RawURLEncoding.DecodeString(k.E)
		if decErr != nil {
			continue
		}
		n := new(big.Int).SetBytes(nBytes)
		e := 0
		for _, b := range eBytes {
			e = e<<8 + int(b)
		}
		keys[k.Kid] = &rsa.PublicKey{N: n, E: e}
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("google cse: no RSA keys in JWKS response")
	}

	p.googleKeysCache = keys
	p.googleKeysTTL = time.Now().Add(1 * time.Hour)
	p.logger.Printf("[google-cse] refreshed %d OIDC public keys from Google", len(keys))
	return keys, nil
}

// ValidateGoogleJWT validates a JWT from Google's CSE infrastructure.
// It verifies the signature using Google's OIDC public keys, checks issuer and expiry,
// and validates the hosted domain (hd) against the allowed domains.
func (p *GoogleCSEProvider) ValidateGoogleJWT(tokenString string, allowedDomains []string) (*GoogleCSEClaims, error) {
	tokenString = strings.TrimSpace(tokenString)
	if tokenString == "" {
		return nil, fmt.Errorf("google cse: empty JWT token")
	}

	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("google cse: invalid JWT format")
	}

	// Decode header to get kid
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("google cse: decode JWT header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("google cse: parse JWT header: %w", err)
	}
	if header.Alg != "RS256" {
		return nil, fmt.Errorf("google cse: unsupported JWT algorithm: %s", header.Alg)
	}

	// Fetch Google's public keys
	publicKeys, err := p.fetchGooglePublicKeys()
	if err != nil {
		return nil, err
	}

	pubKey, ok := publicKeys[header.Kid]
	if !ok {
		return nil, fmt.Errorf("google cse: unknown key ID: %s", header.Kid)
	}

	// Verify RS256 signature
	signedContent := parts[0] + "." + parts[1]
	signatureBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("google cse: decode JWT signature: %w", err)
	}

	hashed := sha256.Sum256([]byte(signedContent))
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], signatureBytes); err != nil {
		return nil, fmt.Errorf("google cse: JWT signature verification failed: %w", err)
	}

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("google cse: decode JWT payload: %w", err)
	}

	var claims GoogleCSEClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("google cse: parse JWT claims: %w", err)
	}

	// Verify issuer
	if claims.Issuer != "accounts.google.com" && claims.Issuer != "https://accounts.google.com" {
		return nil, fmt.Errorf("google cse: invalid JWT issuer: %s", claims.Issuer)
	}

	// Verify expiry with 60s leeway
	now := time.Now().Unix()
	if claims.ExpiresAt > 0 && now > claims.ExpiresAt+60 {
		return nil, fmt.Errorf("google cse: JWT expired at %d, now %d", claims.ExpiresAt, now)
	}
	if claims.IssuedAt > 0 && now < claims.IssuedAt-60 {
		return nil, fmt.Errorf("google cse: JWT issued in the future: iat=%d, now=%d", claims.IssuedAt, now)
	}

	// Verify hosted domain is in allowed list
	if len(allowedDomains) > 0 && claims.HD != "" {
		domainAllowed := false
		for _, d := range allowedDomains {
			if strings.EqualFold(strings.TrimSpace(d), strings.TrimSpace(claims.HD)) {
				domainAllowed = true
				break
			}
		}
		if !domainAllowed {
			return nil, fmt.Errorf("google cse: domain %q not in allowed domains", claims.HD)
		}
	}

	return &claims, nil
}

// WrapDEK wraps a DEK (Data Encryption Key) using the Vecta KMS key via KeyCore.
func (p *GoogleCSEProvider) WrapDEK(ctx context.Context, vectaKeyID string, dek []byte, keycore KeyCoreClient, tenantID string) ([]byte, error) {
	if len(dek) == 0 {
		return nil, fmt.Errorf("google cse: empty DEK")
	}

	dekB64 := base64.StdEncoding.EncodeToString(dek)
	result, err := keycore.Wrap(ctx, tenantID, vectaKeyID, dekB64, "", "google-cse")
	if err != nil {
		return nil, fmt.Errorf("google cse: keycore wrap failed: %w", err)
	}

	ciphertextB64, ok := result["ciphertext"].(string)
	if !ok || ciphertextB64 == "" {
		return nil, fmt.Errorf("google cse: keycore wrap returned no ciphertext")
	}

	wrappedBytes, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, fmt.Errorf("google cse: decode wrapped DEK: %w", err)
	}

	return wrappedBytes, nil
}

// UnwrapDEK unwraps a wrapped DEK using the Vecta KMS key via KeyCore.
func (p *GoogleCSEProvider) UnwrapDEK(ctx context.Context, vectaKeyID string, wrappedDEK []byte, keycore KeyCoreClient, tenantID string) ([]byte, error) {
	if len(wrappedDEK) == 0 {
		return nil, fmt.Errorf("google cse: empty wrapped DEK")
	}

	wrappedB64 := base64.StdEncoding.EncodeToString(wrappedDEK)
	result, err := keycore.Unwrap(ctx, tenantID, vectaKeyID, wrappedB64, "")
	if err != nil {
		return nil, fmt.Errorf("google cse: keycore unwrap failed: %w", err)
	}

	plaintextB64, ok := result["plaintext"].(string)
	if !ok || plaintextB64 == "" {
		return nil, fmt.Errorf("google cse: keycore unwrap returned no plaintext")
	}

	dekBytes, err := base64.StdEncoding.DecodeString(plaintextB64)
	if err != nil {
		return nil, fmt.Errorf("google cse: decode unwrapped DEK: %w", err)
	}

	return dekBytes, nil
}

// ValidatePrivilegedAccess checks that the reason for privileged unwrap is valid.
func (p *GoogleCSEProvider) ValidatePrivilegedAccess(reason string) error {
	reason = strings.TrimSpace(strings.ToUpper(reason))
	if reason != "ADMIN_ACCESS" && reason != "LEGAL_HOLD" {
		return fmt.Errorf("google cse: privileged unwrap reason must be ADMIN_ACCESS or LEGAL_HOLD, got %q", reason)
	}
	return nil
}

// FetchGoogleWorkspaceDirectory uses the Google Admin SDK to list verified domains
// for the given Workspace customer. Uses service account JWT assertion for authentication.
func (p *GoogleCSEProvider) FetchGoogleWorkspaceDirectory(ctx context.Context, serviceAccountKeyJSON, customerID string) ([]string, error) {
	if strings.TrimSpace(serviceAccountKeyJSON) == "" {
		return nil, fmt.Errorf("google cse: service account key JSON is required")
	}
	if strings.TrimSpace(customerID) == "" {
		return nil, fmt.Errorf("google cse: customer ID is required")
	}

	// Parse the service account key
	var saKey struct {
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
		TokenURI    string `json:"token_uri"`
	}
	if err := json.Unmarshal([]byte(serviceAccountKeyJSON), &saKey); err != nil {
		return nil, fmt.Errorf("google cse: parse service account key: %w", err)
	}

	// Create JWT assertion for Google OAuth2
	now := time.Now()
	jwtHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	jwtPayload := map[string]interface{}{
		"iss":   saKey.ClientEmail,
		"scope": "https://www.googleapis.com/auth/admin.directory.domain.readonly",
		"aud":   "https://oauth2.googleapis.com/token",
		"exp":   now.Add(1 * time.Hour).Unix(),
		"iat":   now.Unix(),
	}
	payloadBytes, _ := json.Marshal(jwtPayload)
	jwtPayloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)

	signingInput := jwtHeader + "." + jwtPayloadB64
	signedBytes, err := signRS256WithPEM(signingInput, saKey.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("google cse: sign JWT assertion: %w", err)
	}

	assertionToken := signingInput + "." + base64.RawURLEncoding.EncodeToString(signedBytes)

	// Exchange assertion for access token
	tokenURL := saKey.TokenURI
	if tokenURL == "" {
		tokenURL = "https://oauth2.googleapis.com/token"
	}
	tokenReq, _ := http.NewRequestWithContext(ctx, "POST", tokenURL,
		strings.NewReader("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion="+assertionToken))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	tokenResp, err := p.httpClient.Do(tokenReq)
	if err != nil {
		return nil, fmt.Errorf("google cse: token exchange failed: %w", err)
	}
	defer tokenResp.Body.Close() //nolint:errcheck

	tokenBody, _ := io.ReadAll(io.LimitReader(tokenResp.Body, 1<<20))
	var tokenResult googleOAuth2TokenResponse
	if err := json.Unmarshal(tokenBody, &tokenResult); err != nil {
		return nil, fmt.Errorf("google cse: decode token response: %w", err)
	}
	if tokenResult.AccessToken == "" {
		errMsg := tokenResult.ErrorDesc
		if errMsg == "" {
			errMsg = tokenResult.Error
		}
		if errMsg == "" {
			errMsg = fmt.Sprintf("HTTP %d", tokenResp.StatusCode)
		}
		return nil, fmt.Errorf("google cse: token exchange: %s", errMsg)
	}

	// Fetch domains from Admin SDK Directory API
	domainsURL := fmt.Sprintf("https://admin.googleapis.com/admin/directory/v1/customer/%s/domains", customerID)
	domainsReq, _ := http.NewRequestWithContext(ctx, "GET", domainsURL, nil)
	domainsReq.Header.Set("Authorization", "Bearer "+tokenResult.AccessToken)

	domainsResp, err := p.httpClient.Do(domainsReq)
	if err != nil {
		return nil, fmt.Errorf("google cse: fetch domains failed: %w", err)
	}
	defer domainsResp.Body.Close() //nolint:errcheck

	domainsBody, _ := io.ReadAll(io.LimitReader(domainsResp.Body, 1<<20))
	if domainsResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google cse: Admin SDK domains returned HTTP %d: %s", domainsResp.StatusCode, string(domainsBody))
	}

	var domainsResult struct {
		Domains []struct {
			DomainName string `json:"domainName"`
			IsPrimary  bool   `json:"isPrimary"`
			Verified   bool   `json:"verified"`
		} `json:"domains"`
	}
	if err := json.Unmarshal(domainsBody, &domainsResult); err != nil {
		return nil, fmt.Errorf("google cse: decode domains response: %w", err)
	}

	domains := make([]string, 0, len(domainsResult.Domains))
	for _, d := range domainsResult.Domains {
		if d.Verified {
			domains = append(domains, d.DomainName)
		}
	}

	p.logger.Printf("[google-cse] fetched %d verified domains for customer %s", len(domains), customerID)
	return domains, nil
}

// signRS256WithPEM signs data with an RSA private key in PEM format using RS256.
func signRS256WithPEM(data string, pemKey string) ([]byte, error) {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		privKey2, err2 := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("parse private key: %w (pkcs8: %w)", err2, err)
		}
		privKey = privKey2
	}

	rsaKey, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA")
	}

	hashed := sha256.Sum256([]byte(data))
	return rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hashed[:])
}
