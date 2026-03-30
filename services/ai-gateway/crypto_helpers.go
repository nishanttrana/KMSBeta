package main

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"crypto"
	"crypto/rand"
)

// obtainGoogleAccessToken exchanges a service account JSON key for a short-lived access token.
func obtainGoogleAccessToken(ctx context.Context, authJSON string, client *http.Client) (string, error) {
	var sa struct {
		ClientEmail  string `json:"client_email"`
		PrivateKey   string `json:"private_key"`
		TokenURI     string `json:"token_uri"`
	}
	if err := json.Unmarshal([]byte(authJSON), &sa); err != nil {
		return "", fmt.Errorf("parse service account json: %w", err)
	}
	if sa.TokenURI == "" {
		sa.TokenURI = "https://oauth2.googleapis.com/token"
	}

	// Build JWT
	now := time.Now().UTC()
	header := base64URLEncode([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims := fmt.Sprintf(`{"iss":"%s","scope":"https://www.googleapis.com/auth/cloud-platform","aud":"%s","iat":%d,"exp":%d}`,
		sa.ClientEmail, sa.TokenURI, now.Unix(), now.Add(time.Hour).Unix())
	claimsEnc := base64URLEncode([]byte(claims))
	unsigned := header + "." + claimsEnc

	// Parse private key
	block, _ := pem.Decode([]byte(sa.PrivateKey))
	if block == nil {
		return "", fmt.Errorf("invalid PEM in service account key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse private key: %w", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("private key is not RSA")
	}

	// Sign
	hashed := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}
	jwt := unsigned + "." + base64URLEncode(sig)

	// Exchange for access token
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {jwt},
	}
	req, err := http.NewRequestWithContext(ctx, "POST", sa.TokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("token exchange: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token exchange failed (%d): %s", resp.StatusCode, string(body))
	}

	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("parse token response: %w", err)
	}
	return tok.AccessToken, nil
}
