package cicd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// GitLabClaims represents the claims extracted from a GitLab CI JWT token.
type GitLabClaims struct {
	ProjectID     int    `json:"project_id"`
	ProjectPath   string `json:"project_path"`
	PipelineID    int    `json:"pipeline_id"`
	Ref           string `json:"ref"`
	RefType       string `json:"ref_type"`
	RefProtected  string `json:"ref_protected"`
	NamespaceID   int    `json:"namespace_id"`
	NamespacePath string `json:"namespace_path"`
	JobID         int    `json:"job_id"`
	Environment   string `json:"environment"`
	UserLogin     string `json:"user_login"`
	UserEmail     string `json:"user_email"`
}

// gitlabJWTClaims extends jwt.RegisteredClaims with GitLab-specific fields.
type gitlabJWTClaims struct {
	jwt.RegisteredClaims
	ProjectID     int    `json:"project_id"`
	ProjectPath   string `json:"project_path"`
	PipelineID    int    `json:"pipeline_id"`
	Ref           string `json:"ref"`
	RefType       string `json:"ref_type"`
	RefProtected  string `json:"ref_protected"`
	NamespaceID   int    `json:"namespace_id"`
	NamespacePath string `json:"namespace_path"`
	JobID         int    `json:"job_id"`
	Environment   string `json:"environment"`
	UserLogin     string `json:"user_login"`
	UserEmail     string `json:"user_email"`
}

// ValidateGitLabCIToken validates a GitLab CI JWT token using the GitLab instance's JWKS endpoint.
// gitlabURL should be the base URL of the GitLab instance (e.g., "https://gitlab.com").
func ValidateGitLabCIToken(tokenString, gitlabURL string) (*GitLabClaims, error) {
	if tokenString == "" {
		return nil, fmt.Errorf("empty token")
	}
	if gitlabURL == "" {
		return nil, fmt.Errorf("gitlab URL is required")
	}

	// Normalize GitLab URL
	gitlabURL = strings.TrimRight(gitlabURL, "/")
	jwksURL := gitlabURL + "/-/jwks"
	expectedIssuer := gitlabURL

	// Fetch JWKS from GitLab
	keys, err := fetchJWKS(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch GitLab JWKS from %s: %w", jwksURL, err)
	}

	// Parse header to get kid
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT header: %w", err)
	}

	var header struct {
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("failed to parse JWT header: %w", err)
	}

	// Find matching public key
	publicKey, err := findAndParseKey(keys, header.Kid)
	if err != nil {
		return nil, fmt.Errorf("key lookup failed: %w", err)
	}

	// Parse and validate the token
	claims := &gitlabJWTClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return publicKey, nil
	},
		jwt.WithIssuer(expectedIssuer),
		jwt.WithLeeway(30*time.Second),
		jwt.WithValidMethods([]string{"RS256", "ES256"}),
	)
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("token is not valid")
	}

	return &GitLabClaims{
		ProjectID:     claims.ProjectID,
		ProjectPath:   claims.ProjectPath,
		PipelineID:    claims.PipelineID,
		Ref:           claims.Ref,
		RefType:       claims.RefType,
		RefProtected:  claims.RefProtected,
		NamespaceID:   claims.NamespaceID,
		NamespacePath: claims.NamespacePath,
		JobID:         claims.JobID,
		Environment:   claims.Environment,
		UserLogin:     claims.UserLogin,
		UserEmail:     claims.UserEmail,
	}, nil
}
