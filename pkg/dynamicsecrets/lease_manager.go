package dynamicsecrets

import (
	"context"
	"log"
	"sync"
	"time"
)

const defaultCheckInterval = 30 * time.Second

// LeaseManager runs a background loop to revoke expired dynamic credentials.
type LeaseManager struct {
	engine   *Engine
	store    Store
	audit    AuditPublisher
	interval time.Duration
	logger   *log.Logger

	stopOnce sync.Once
	stopCh   chan struct{}
	doneCh   chan struct{}
}

// NewLeaseManager creates a new lease manager that periodically revokes expired leases.
func NewLeaseManager(engine *Engine, store Store, audit AuditPublisher, logger *log.Logger) *LeaseManager {
	if logger == nil {
		logger = log.Default()
	}
	return &LeaseManager{
		engine:   engine,
		store:    store,
		audit:    audit,
		interval: defaultCheckInterval,
		logger:   logger,
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}
}

// Start begins the background expiration check loop.
func (lm *LeaseManager) Start(ctx context.Context) {
	go lm.run(ctx)
}

// Stop signals the background loop to stop and waits for it to finish.
func (lm *LeaseManager) Stop() {
	lm.stopOnce.Do(func() {
		close(lm.stopCh)
	})
	<-lm.doneCh
}

func (lm *LeaseManager) run(ctx context.Context) {
	defer close(lm.doneCh)
	ticker := time.NewTicker(lm.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-lm.stopCh:
			return
		case <-ticker.C:
			lm.revokeExpired(ctx)
		}
	}
}

func (lm *LeaseManager) revokeExpired(ctx context.Context) {
	expired, err := lm.store.ListExpiredLeases(ctx)
	if err != nil {
		lm.logger.Printf("lease_manager: list expired leases: %v", err)
		return
	}

	for _, lease := range expired {
		if lease.RevokedAt != nil {
			continue
		}

		lm.logger.Printf("lease_manager: revoking expired lease %s (credential %s, provider %s)",
			lease.ID, lease.CredentialID, lease.Provider)

		lm.engine.mu.RLock()
		provider, ok := lm.engine.providers[lease.Provider]
		lm.engine.mu.RUnlock()

		if !ok {
			lm.logger.Printf("lease_manager: unknown provider %q for lease %s, marking revoked", lease.Provider, lease.ID)
			_ = lm.store.RevokeLease(ctx, lease.ID)
			continue
		}

		// Use the stored username (CredentialID in the lease maps to the username for revocation)
		if err := provider.Revoke(ctx, lease.Username); err != nil {
			lm.logger.Printf("lease_manager: failed to revoke credential for lease %s: %v", lease.ID, err)
			continue
		}

		if err := lm.store.RevokeLease(ctx, lease.ID); err != nil {
			lm.logger.Printf("lease_manager: failed to mark lease %s as revoked: %v", lease.ID, err)
			continue
		}

		lm.publishAudit(ctx, "dynamic_secret.expired", map[string]string{
			"lease_id":      lease.ID,
			"credential_id": lease.CredentialID,
			"tenant_id":     lease.TenantID,
			"provider":      lease.Provider,
		})
	}
}

func (lm *LeaseManager) publishAudit(ctx context.Context, subject string, fields map[string]string) {
	if lm.audit == nil {
		return
	}
	payload := `{"event":"` + subject + `","timestamp":"` + time.Now().UTC().Format(time.RFC3339) + `"`
	for k, v := range fields {
		payload += `,"` + k + `":"` + v + `"`
	}
	payload += `}`
	if err := lm.audit.Publish(ctx, "kms.audit."+subject, []byte(payload)); err != nil {
		lm.logger.Printf("lease_manager: audit publish failed for %s: %v", subject, err)
	}
}

// Renew extends the TTL of an active lease. Delegates to Engine.RenewLease.
func (lm *LeaseManager) Renew(ctx context.Context, leaseID string, increment time.Duration) error {
	_, err := lm.engine.RenewLease(ctx, leaseID, increment)
	return err
}
