package cicd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// SecretStore abstracts the underlying secret storage backend.
type SecretStore interface {
	GetSecret(ctx context.Context, tenantID, path string, version int) (string, error)
}

// AuditPublisher sends audit events for secret injection operations.
type AuditPublisher interface {
	Publish(ctx context.Context, subject string, payload []byte) error
}

// Injector handles CI/CD secret injection with identity validation and lease tracking.
type Injector struct {
	store   SecretStore
	audit   AuditPublisher
	leases  LeaseStore
	maxTTL  time.Duration
}

// SecretRef identifies a single secret to inject.
type SecretRef struct {
	SecretPath string `json:"secret_path"`
	EnvVarName string `json:"env_var_name"`
	Version    int    `json:"version,omitempty"` // 0 means latest
}

// InjectionRequest represents a request to inject secrets into a CI/CD pipeline.
type InjectionRequest struct {
	TenantID         string      `json:"tenant_id"`
	PipelineID       string      `json:"pipeline_id"`
	Platform         Platform    `json:"platform"`
	SecretsRequested []SecretRef `json:"secrets_requested"`
	RunnerIdentity   string      `json:"runner_identity"`
	TTL              time.Duration `json:"ttl"`
}

// InjectionResponse contains the injected secrets and lease metadata.
type InjectionResponse struct {
	Secrets   map[string]string `json:"secrets"`
	LeaseID   string            `json:"lease_id"`
	ExpiresAt time.Time         `json:"expires_at"`
}

// Platform represents a supported CI/CD platform.
type Platform string

const (
	PlatformGitHubActions Platform = "github_actions"
	PlatformGitLabCI      Platform = "gitlab_ci"
	PlatformJenkins       Platform = "jenkins"
	PlatformArgoCD        Platform = "argocd"
)

// NewInjector creates a new CI/CD secret injector.
func NewInjector(store SecretStore, audit AuditPublisher, leases LeaseStore, maxTTL time.Duration) *Injector {
	if maxTTL <= 0 {
		maxTTL = 15 * time.Minute
	}
	return &Injector{
		store:  store,
		audit:  audit,
		leases: leases,
		maxTTL: maxTTL,
	}
}

// Inject validates the runner identity, fetches requested secrets, creates a lease, and returns env vars.
func (inj *Injector) Inject(ctx context.Context, req InjectionRequest) (*InjectionResponse, error) {
	if req.TenantID == "" {
		return nil, fmt.Errorf("tenant_id is required")
	}
	if req.PipelineID == "" {
		return nil, fmt.Errorf("pipeline_id is required")
	}
	if len(req.SecretsRequested) == 0 {
		return nil, fmt.Errorf("at least one secret must be requested")
	}

	// Validate runner identity for the given platform
	if err := inj.ValidateRunnerIdentity(ctx, req.Platform, req.RunnerIdentity); err != nil {
		return nil, fmt.Errorf("runner identity validation failed: %w", err)
	}

	// Clamp TTL to max
	ttl := req.TTL
	if ttl <= 0 || ttl > inj.maxTTL {
		ttl = inj.maxTTL
	}

	// Fetch all requested secrets
	secrets := make(map[string]string, len(req.SecretsRequested))
	for _, ref := range req.SecretsRequested {
		if ref.SecretPath == "" {
			return nil, fmt.Errorf("secret_path is required for env var %q", ref.EnvVarName)
		}
		if ref.EnvVarName == "" {
			return nil, fmt.Errorf("env_var_name is required for secret path %q", ref.SecretPath)
		}

		val, err := inj.store.GetSecret(ctx, req.TenantID, ref.SecretPath, ref.Version)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch secret %q: %w", ref.SecretPath, err)
		}
		secrets[ref.EnvVarName] = val
	}

	// Generate lease ID
	leaseID, err := generateLeaseID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate lease ID: %w", err)
	}

	expiresAt := time.Now().UTC().Add(ttl)

	// Record the lease
	lease := Lease{
		ID:             leaseID,
		TenantID:       req.TenantID,
		Platform:       string(req.Platform),
		PipelineID:     req.PipelineID,
		RunnerIdentity: req.RunnerIdentity,
		SecretsCount:   len(secrets),
		ExpiresAt:      expiresAt,
		Revoked:        false,
		CreatedAt:      time.Now().UTC(),
	}
	if err := inj.leases.CreateLease(ctx, lease); err != nil {
		return nil, fmt.Errorf("failed to record injection lease: %w", err)
	}

	// Publish audit event (best-effort)
	auditPayload := fmt.Sprintf(
		`{"event":"cicd.secrets.injected","tenant_id":%q,"platform":%q,"pipeline_id":%q,"runner":%q,"secrets_count":%d,"lease_id":%q,"expires_at":%q}`,
		req.TenantID, req.Platform, req.PipelineID, req.RunnerIdentity, len(secrets), leaseID, expiresAt.Format(time.RFC3339),
	)
	_ = inj.audit.Publish(ctx, "audit.cicd.inject", []byte(auditPayload))

	return &InjectionResponse{
		Secrets:   secrets,
		LeaseID:   leaseID,
		ExpiresAt: expiresAt,
	}, nil
}

// ValidateRunnerIdentity validates the runner identity token for the given platform.
func (inj *Injector) ValidateRunnerIdentity(ctx context.Context, platform Platform, identity string) error {
	if identity == "" {
		return fmt.Errorf("runner identity is required")
	}

	switch platform {
	case PlatformGitHubActions:
		// GitHub Actions uses OIDC tokens; full validation in platform_github.go
		_, err := ValidateGitHubActionsToken(identity, "")
		return err
	case PlatformGitLabCI:
		// GitLab CI uses JWT tokens; full validation in platform_gitlab.go
		_, err := ValidateGitLabCIToken(identity, "https://gitlab.com")
		return err
	case PlatformJenkins:
		// Jenkins uses API tokens; this is a pass-through since Jenkins validation
		// requires the URL and job name, which are validated at a higher layer.
		return nil
	case PlatformArgoCD:
		// ArgoCD uses bearer tokens; basic non-empty check here.
		if len(identity) < 10 {
			return fmt.Errorf("argocd token too short")
		}
		return nil
	default:
		return fmt.Errorf("unsupported platform: %s", platform)
	}
}

func generateLeaseID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "lease-" + hex.EncodeToString(b), nil
}
