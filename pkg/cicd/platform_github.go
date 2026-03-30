package cicd

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const gitHubActionsJWKSURL = "https://token.actions.githubusercontent.com/.well-known/jwks"
const gitHubActionsIssuer = "https://token.actions.githubusercontent.com"

// GitHubClaims represents the claims extracted from a GitHub Actions OIDC token.
type GitHubClaims struct {
	Repository    string `json:"repository"`
	RepositoryOwner string `json:"repository_owner"`
	Workflow      string `json:"workflow"`
	Ref           string `json:"ref"`
	SHA           string `json:"sha"`
	Actor         string `json:"actor"`
	RunID         string `json:"run_id"`
	RunNumber     string `json:"run_number"`
	EventName     string `json:"event_name"`
	JobWorkflowRef string `json:"job_workflow_ref"`
}

// jwksResponse represents the JSON Web Key Set response.
type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

// jwkKey represents a single JSON Web Key.
type jwkKey struct {
	KTY string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// ValidateGitHubActionsToken validates a GitHub Actions OIDC JWT token.
// If expectedOrg is non-empty, the token's repository_owner must match.
func ValidateGitHubActionsToken(tokenString string, expectedOrg string) (*GitHubClaims, error) {
	if tokenString == "" {
		return nil, fmt.Errorf("empty token")
	}

	// Fetch JWKS from GitHub Actions
	keys, err := fetchJWKS(gitHubActionsJWKSURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch GitHub Actions JWKS: %w", err)
	}

	// Parse the token header to find kid
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT header: %w", err)
	}

	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("failed to parse JWT header: %w", err)
	}

	// Find the matching key
	publicKey, err := findAndParseKey(keys, header.Kid)
	if err != nil {
		return nil, fmt.Errorf("key lookup failed: %w", err)
	}

	// Parse and validate the token
	claims := &githubJWTClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return publicKey, nil
	},
		jwt.WithIssuer(gitHubActionsIssuer),
		jwt.WithLeeway(30*time.Second),
		jwt.WithValidMethods([]string{"RS256", "ES256"}),
	)
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("token is not valid")
	}

	result := &GitHubClaims{
		Repository:      claims.Repository,
		RepositoryOwner: claims.RepositoryOwner,
		Workflow:        claims.Workflow,
		Ref:             claims.Ref,
		SHA:             claims.SHA,
		Actor:           claims.Actor,
		RunID:           claims.RunID,
		RunNumber:       claims.RunNumber,
		EventName:       claims.EventName,
		JobWorkflowRef:  claims.JobWorkflowRef,
	}

	// Verify org if required
	if expectedOrg != "" && result.RepositoryOwner != expectedOrg {
		return nil, fmt.Errorf("token repository_owner %q does not match expected org %q", result.RepositoryOwner, expectedOrg)
	}

	return result, nil
}

// githubJWTClaims extends jwt.RegisteredClaims with GitHub-specific fields.
type githubJWTClaims struct {
	jwt.RegisteredClaims
	Repository      string `json:"repository"`
	RepositoryOwner string `json:"repository_owner"`
	Workflow        string `json:"workflow"`
	Ref             string `json:"ref"`
	SHA             string `json:"sha"`
	Actor           string `json:"actor"`
	RunID           string `json:"run_id"`
	RunNumber       string `json:"run_number"`
	EventName       string `json:"event_name"`
	JobWorkflowRef  string `json:"job_workflow_ref"`
}

// fetchJWKS retrieves the JSON Web Key Set from the given URL.
func fetchJWKS(url string) ([]jwkKey, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS response: %w", err)
	}

	var jwks jwksResponse
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	return jwks.Keys, nil
}

// findAndParseKey locates a key by kid and converts it to a crypto.PublicKey.
func findAndParseKey(keys []jwkKey, kid string) (crypto.PublicKey, error) {
	for _, k := range keys {
		if k.Kid == kid {
			return parseJWK(k)
		}
	}
	return nil, fmt.Errorf("no key found with kid %q", kid)
}

// parseJWK converts a JWK to a Go crypto.PublicKey.
func parseJWK(k jwkKey) (crypto.PublicKey, error) {
	switch k.KTY {
	case "RSA":
		return parseRSAJWK(k)
	case "EC":
		return parseECJWK(k)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", k.KTY)
	}
}

func parseRSAJWK(k jwkKey) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode RSA N: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode RSA E: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}

func parseECJWK(k jwkKey) (*ecdsa.PublicKey, error) {
	xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode EC X: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, fmt.Errorf("failed to decode EC Y: %w", err)
	}

	var curve elliptic.Curve
	switch k.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported EC curve: %s", k.Crv)
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}
