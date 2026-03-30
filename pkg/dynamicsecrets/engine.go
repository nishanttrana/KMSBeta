package dynamicsecrets

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// AuditPublisher defines the interface for publishing audit events.
type AuditPublisher interface {
	Publish(ctx context.Context, subject string, payload []byte) error
}

// Provider generates and revokes dynamic credentials for a specific backend.
type Provider interface {
	Generate(ctx context.Context, req LeaseRequest) (*Credential, error)
	Revoke(ctx context.Context, credentialID string) error
}

// LeaseRequest describes a request for dynamic credentials.
type LeaseRequest struct {
	TenantID string            `json:"tenant_id"`
	Role     string            `json:"role"`
	TTL      time.Duration     `json:"ttl"`
	MaxTTL   time.Duration     `json:"max_ttl"`
	Metadata map[string]string `json:"metadata"`
}

// Credential holds the generated dynamic secret.
type Credential struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Provider  string    `json:"provider"`
	Username  string    `json:"username"`
	Password  string    `json:"password,omitempty"`
	Token     string    `json:"token,omitempty"`
	Endpoint  string    `json:"endpoint"`
	ExpiresAt time.Time `json:"expires_at"`
	LeaseID   string    `json:"lease_id"`
}

// Lease tracks the lifecycle of a dynamic credential.
type Lease struct {
	ID           string     `json:"id"`
	CredentialID string     `json:"credential_id"`
	TenantID     string     `json:"tenant_id"`
	TTL          time.Duration `json:"ttl"`
	MaxTTL       time.Duration `json:"max_ttl"`
	Renewable    bool       `json:"renewable"`
	ExpiresAt    time.Time  `json:"expires_at"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
}

// Engine is the central coordinator for dynamic secret generation.
type Engine struct {
	mu        sync.RWMutex
	providers map[string]Provider
	store     Store
	audit     AuditPublisher
	logger    *log.Logger
}

// NewEngine creates a new dynamic secrets engine.
func NewEngine(store Store, audit AuditPublisher, logger *log.Logger) *Engine {
	if logger == nil {
		logger = log.Default()
	}
	return &Engine{
		providers: make(map[string]Provider),
		store:     store,
		audit:     audit,
		logger:    logger,
	}
}

// RegisterProvider adds a named provider to the engine.
func (e *Engine) RegisterProvider(name string, p Provider) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.providers[name] = p
}

// GenerateCredential creates new dynamic credentials using the named provider.
func (e *Engine) GenerateCredential(ctx context.Context, providerName string, req LeaseRequest) (*Credential, *Lease, error) {
	e.mu.RLock()
	p, ok := e.providers[providerName]
	e.mu.RUnlock()
	if !ok {
		return nil, nil, fmt.Errorf("dynamicsecrets: unknown provider %q", providerName)
	}

	cred, err := p.Generate(ctx, req)
	if err != nil {
		return nil, nil, fmt.Errorf("dynamicsecrets: generate failed for provider %q: %w", providerName, err)
	}
	cred.Provider = providerName

	lease := &Lease{
		ID:           cred.LeaseID,
		CredentialID: cred.ID,
		TenantID:     req.TenantID,
		TTL:          req.TTL,
		MaxTTL:       req.MaxTTL,
		Renewable:    req.MaxTTL > req.TTL,
		ExpiresAt:    cred.ExpiresAt,
	}

	if err := e.store.CreateLease(ctx, lease, cred); err != nil {
		// Best-effort revoke on store failure to avoid orphaned creds
		_ = p.Revoke(ctx, cred.ID)
		return nil, nil, fmt.Errorf("dynamicsecrets: store lease failed: %w", err)
	}

	e.publishAudit(ctx, "dynamic_secret.generated", map[string]string{
		"provider":      providerName,
		"tenant_id":     req.TenantID,
		"credential_id": cred.ID,
		"lease_id":      lease.ID,
		"username":      cred.Username,
	})

	return cred, lease, nil
}

// RevokeCredential explicitly revokes a lease and its credential.
func (e *Engine) RevokeCredential(ctx context.Context, leaseID string) error {
	lease, err := e.store.GetLease(ctx, leaseID)
	if err != nil {
		return fmt.Errorf("dynamicsecrets: get lease %q: %w", leaseID, err)
	}

	e.mu.RLock()
	p, ok := e.providers[lease.Provider]
	e.mu.RUnlock()
	if !ok {
		return fmt.Errorf("dynamicsecrets: unknown provider %q for lease %q", lease.Provider, leaseID)
	}

	// Use the username for revocation since providers revoke by username
	if err := p.Revoke(ctx, lease.Username); err != nil {
		return fmt.Errorf("dynamicsecrets: revoke credential %q (user %s): %w", lease.CredentialID, lease.Username, err)
	}

	if err := e.store.RevokeLease(ctx, leaseID); err != nil {
		return fmt.Errorf("dynamicsecrets: mark lease revoked %q: %w", leaseID, err)
	}

	e.publishAudit(ctx, "dynamic_secret.revoked", map[string]string{
		"lease_id":      leaseID,
		"credential_id": lease.CredentialID,
		"tenant_id":     lease.TenantID,
	})

	return nil
}

// RenewLease extends the lifetime of an existing lease.
func (e *Engine) RenewLease(ctx context.Context, leaseID string, increment time.Duration) (*StoredLease, error) {
	lease, err := e.store.GetLease(ctx, leaseID)
	if err != nil {
		return nil, fmt.Errorf("dynamicsecrets: get lease %q: %w", leaseID, err)
	}
	if lease.Revoked {
		return nil, fmt.Errorf("dynamicsecrets: lease %q is already revoked", leaseID)
	}
	if lease.RevokedAt != nil {
		return nil, fmt.Errorf("dynamicsecrets: lease %q is already revoked", leaseID)
	}

	newExpiry := time.Now().Add(increment)
	// Cap at a reasonable maximum: no more than 24h past the original expiry
	maxExpiry := lease.ExpiresAt.Add(24 * time.Hour)
	if newExpiry.After(maxExpiry) {
		newExpiry = maxExpiry
	}

	if err := e.store.RenewLease(ctx, leaseID, newExpiry); err != nil {
		return nil, fmt.Errorf("dynamicsecrets: renew lease %q: %w", leaseID, err)
	}

	lease.ExpiresAt = newExpiry

	e.publishAudit(ctx, "dynamic_secret.renewed", map[string]string{
		"lease_id":   leaseID,
		"tenant_id":  lease.TenantID,
		"new_expiry": newExpiry.Format(time.RFC3339),
	})

	return lease, nil
}

func (e *Engine) publishAudit(ctx context.Context, subject string, fields map[string]string) {
	if e.audit == nil {
		return
	}
	// Build a simple JSON payload
	payload := `{"event":"` + subject + `","timestamp":"` + time.Now().UTC().Format(time.RFC3339) + `"`
	for k, v := range fields {
		payload += `,"` + k + `":"` + v + `"`
	}
	payload += `}`
	if err := e.audit.Publish(ctx, "kms.audit."+subject, []byte(payload)); err != nil {
		e.logger.Printf("audit publish failed for %s: %v", subject, err)
	}
}
