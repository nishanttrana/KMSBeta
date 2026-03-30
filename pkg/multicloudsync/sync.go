package multicloudsync

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"
)

// CloudProvider abstracts a remote cloud KMS for key import/rotation/inventory.
type CloudProvider interface {
	// ImportKey imports wrapped key material into the remote cloud KMS.
	ImportKey(ctx context.Context, target ProviderTarget, wrappedKey []byte) (remoteKeyVersion string, err error)
	// RotateKey rotates an existing key in the remote cloud KMS with new material.
	RotateKey(ctx context.Context, target ProviderTarget, wrappedKey []byte) (remoteKeyVersion string, err error)
	// GetKeyVersion returns the current key version/metadata in the remote cloud KMS.
	GetKeyVersion(ctx context.Context, target ProviderTarget) (version string, err error)
	// DeleteKey removes a key from the remote cloud KMS.
	DeleteKey(ctx context.Context, target ProviderTarget) error
}

// KeyFetcher retrieves wrapped key material from Vecta KeyCore.
type KeyFetcher interface {
	FetchWrappedKey(ctx context.Context, keyID string) (wrappedKey []byte, version string, err error)
}

// AuditPublisher publishes audit events for compliance tracking.
type AuditPublisher interface {
	Publish(ctx context.Context, event AuditEvent) error
}

// AuditEvent represents a sync-related audit entry.
type AuditEvent struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	TenantID  string    `json:"tenant_id"`
	PolicyID  string    `json:"policy_id"`
	Action    string    `json:"action"`
	Provider  string    `json:"provider"`
	KeyID     string    `json:"key_id"`
	Status    string    `json:"status"`
	Detail    string    `json:"detail"`
}

// SyncPolicy defines a multi-cloud key synchronization policy.
type SyncPolicy struct {
	ID                 string           `json:"id"`
	TenantID           string           `json:"tenant_id"`
	VectaKeyID         string           `json:"vecta_key_id"`
	TargetProviders    []ProviderTarget `json:"target_providers"`
	SyncMode           string           `json:"sync_mode"`           // "active" or "passive"
	SyncInterval       time.Duration    `json:"sync_interval"`       // how often to sync
	ConflictResolution string           `json:"conflict_resolution"` // "source_wins", "latest_wins", "manual"
	Enabled            bool             `json:"enabled"`
	CreatedAt          time.Time        `json:"created_at"`
	UpdatedAt          time.Time        `json:"updated_at"`
}

// ProviderTarget identifies a specific cloud KMS destination.
type ProviderTarget struct {
	Provider  string `json:"provider"`   // aws, azure, gcp, oci, alibaba
	AccountID string `json:"account_id"`
	Region    string `json:"region"`
	KeyName   string `json:"key_name"`
}

// SyncStatus tracks the synchronization state for one provider target.
type SyncStatus struct {
	PolicyID        string    `json:"policy_id"`
	Provider        string    `json:"provider"`
	AccountID       string    `json:"account_id"`
	Region          string    `json:"region"`
	Status          string    `json:"status"` // "synced", "pending", "error", "conflict"
	LastSync        time.Time `json:"last_sync"`
	NextSync        time.Time `json:"next_sync"`
	ErrorMsg        string    `json:"error_msg,omitempty"`
	RemoteKeyVer    string    `json:"remote_key_version"`
	LocalKeyVersion string    `json:"local_key_version"`
}

// DriftReport describes version mismatch between local and remote keys.
type DriftReport struct {
	PolicyID       string `json:"policy_id"`
	Provider       string `json:"provider"`
	AccountID      string `json:"account_id"`
	Region         string `json:"region"`
	LocalVersion   string `json:"local_version"`
	RemoteVersion  string `json:"remote_version"`
	Drifted        bool   `json:"drifted"`
	DetectedAt     time.Time `json:"detected_at"`
}

// SyncEngine orchestrates multi-cloud key synchronization.
type SyncEngine struct {
	mu        sync.RWMutex
	providers map[string]CloudProvider // keyed by provider name (aws, azure, gcp, etc.)
	store     *SQLStore
	fetcher   KeyFetcher
	audit     AuditPublisher
	logf      func(string, ...interface{})
}

// NewSyncEngine creates a new multi-cloud sync engine.
func NewSyncEngine(store *SQLStore, fetcher KeyFetcher, audit AuditPublisher, logf func(string, ...interface{})) *SyncEngine {
	if logf == nil {
		logf = log.Printf
	}
	return &SyncEngine{
		providers: make(map[string]CloudProvider),
		store:     store,
		fetcher:   fetcher,
		audit:     audit,
		logf:      logf,
	}
}

// RegisterProvider adds a cloud provider to the sync engine.
func (e *SyncEngine) RegisterProvider(name string, provider CloudProvider) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.providers[name] = provider
}

// getProvider returns a registered cloud provider by name.
func (e *SyncEngine) getProvider(name string) (CloudProvider, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	p, ok := e.providers[name]
	if !ok {
		return nil, fmt.Errorf("multicloudsync: provider %q not registered", name)
	}
	return p, nil
}

// StartSyncLoop runs a background goroutine that checks all enabled policies every minute
// and executes synchronization for those whose interval has elapsed.
func (e *SyncEngine) StartSyncLoop(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		e.logf("[multicloudsync] sync loop started")
		for {
			select {
			case <-ctx.Done():
				e.logf("[multicloudsync] sync loop stopped")
				return
			case <-ticker.C:
				e.runSyncCycle(ctx)
			}
		}
	}()
}

// runSyncCycle checks all policies and syncs those that are due.
func (e *SyncEngine) runSyncCycle(ctx context.Context) {
	policies, err := e.store.ListEnabledPolicies(ctx)
	if err != nil {
		e.logf("[multicloudsync] failed to list policies: %v", err)
		return
	}

	for _, policy := range policies {
		if policy.SyncMode != "active" {
			continue
		}
		// Check if any target is past its next_sync time
		statuses, err := e.store.ListSyncStatuses(ctx, policy.ID)
		if err != nil {
			e.logf("[multicloudsync] failed to list statuses for policy %s: %v", policy.ID, err)
			continue
		}

		needsSync := false
		if len(statuses) == 0 {
			needsSync = true
		}
		for _, st := range statuses {
			if time.Now().After(st.NextSync) {
				needsSync = true
				break
			}
		}

		if needsSync {
			if _, err := e.SyncKey(ctx, policy.ID); err != nil {
				e.logf("[multicloudsync] sync failed for policy %s: %v", policy.ID, err)
			}
		}
	}
}

// SyncKey synchronizes a single key to all target providers defined in the policy.
func (e *SyncEngine) SyncKey(ctx context.Context, policyID string) ([]SyncStatus, error) {
	policy, err := e.store.GetPolicy(ctx, policyID)
	if err != nil {
		return nil, fmt.Errorf("multicloudsync: get policy: %w", err)
	}

	// Fetch wrapped key material from Vecta KeyCore
	wrappedKey, localVersion, err := e.fetcher.FetchWrappedKey(ctx, policy.VectaKeyID)
	if err != nil {
		return nil, fmt.Errorf("multicloudsync: fetch key %s: %w", policy.VectaKeyID, err)
	}

	var results []SyncStatus
	for _, target := range policy.TargetProviders {
		status := e.syncToTarget(ctx, policy, target, wrappedKey, localVersion)
		results = append(results, status)

		// Persist status
		if err := e.store.UpsertSyncStatus(ctx, &status); err != nil {
			e.logf("[multicloudsync] failed to persist status for %s/%s: %v", policyID, target.Provider, err)
		}

		// Publish audit event
		e.publishAudit(ctx, policy, target, status)
	}

	return results, nil
}

// syncToTarget handles syncing to a single cloud provider target.
func (e *SyncEngine) syncToTarget(ctx context.Context, policy *SyncPolicy, target ProviderTarget, wrappedKey []byte, localVersion string) SyncStatus {
	status := SyncStatus{
		PolicyID:        policy.ID,
		Provider:        target.Provider,
		AccountID:       target.AccountID,
		Region:          target.Region,
		LocalKeyVersion: localVersion,
		LastSync:        time.Now(),
		NextSync:        time.Now().Add(policy.SyncInterval),
	}

	provider, err := e.getProvider(target.Provider)
	if err != nil {
		status.Status = "error"
		status.ErrorMsg = err.Error()
		return status
	}

	// Check existing remote version to decide import vs rotate
	existingStatuses, _ := e.store.ListSyncStatuses(ctx, policy.ID)
	var existingStatus *SyncStatus
	for i, s := range existingStatuses {
		if s.Provider == target.Provider && s.AccountID == target.AccountID && s.Region == target.Region {
			existingStatus = &existingStatuses[i]
			break
		}
	}

	var remoteVersion string
	if existingStatus == nil || existingStatus.RemoteKeyVer == "" {
		// First sync: import key
		remoteVersion, err = provider.ImportKey(ctx, target, wrappedKey)
	} else {
		// Subsequent sync: rotate key
		remoteVersion, err = provider.RotateKey(ctx, target, wrappedKey)
	}

	if err != nil {
		status.Status = "error"
		status.ErrorMsg = fmt.Sprintf("sync to %s/%s/%s failed: %v", target.Provider, target.AccountID, target.Region, err)
		return status
	}

	status.Status = "synced"
	status.RemoteKeyVer = remoteVersion
	return status
}

// publishAudit sends an audit event for a sync operation.
func (e *SyncEngine) publishAudit(ctx context.Context, policy *SyncPolicy, target ProviderTarget, status SyncStatus) {
	if e.audit == nil {
		return
	}

	event := AuditEvent{
		ID:        generateID(),
		Timestamp: time.Now(),
		TenantID:  policy.TenantID,
		PolicyID:  policy.ID,
		Action:    "key_sync",
		Provider:  target.Provider,
		KeyID:     policy.VectaKeyID,
		Status:    status.Status,
		Detail:    fmt.Sprintf("remote_version=%s local_version=%s", status.RemoteKeyVer, status.LocalKeyVersion),
	}
	if status.ErrorMsg != "" {
		event.Detail = status.ErrorMsg
	}

	if err := e.audit.Publish(ctx, event); err != nil {
		e.logf("[multicloudsync] audit publish failed: %v", err)
	}
}

// ResolveConflict resolves a sync conflict for a specific provider target.
func (e *SyncEngine) ResolveConflict(ctx context.Context, policyID, provider, resolution string) error {
	if resolution != "source_wins" && resolution != "latest_wins" && resolution != "manual" {
		return fmt.Errorf("multicloudsync: invalid resolution %q, must be source_wins, latest_wins, or manual", resolution)
	}

	policy, err := e.store.GetPolicy(ctx, policyID)
	if err != nil {
		return fmt.Errorf("multicloudsync: get policy: %w", err)
	}

	statuses, err := e.store.ListSyncStatuses(ctx, policyID)
	if err != nil {
		return fmt.Errorf("multicloudsync: list statuses: %w", err)
	}

	var conflictStatus *SyncStatus
	for i, s := range statuses {
		if s.Provider == provider && s.Status == "conflict" {
			conflictStatus = &statuses[i]
			break
		}
	}
	if conflictStatus == nil {
		return fmt.Errorf("multicloudsync: no conflict found for policy %s provider %s", policyID, provider)
	}

	switch resolution {
	case "source_wins":
		// Re-sync from Vecta KeyCore, overwriting remote
		var target ProviderTarget
		for _, t := range policy.TargetProviders {
			if t.Provider == provider {
				target = t
				break
			}
		}
		wrappedKey, localVer, err := e.fetcher.FetchWrappedKey(ctx, policy.VectaKeyID)
		if err != nil {
			return fmt.Errorf("multicloudsync: fetch key for conflict resolution: %w", err)
		}
		cloudProvider, err := e.getProvider(provider)
		if err != nil {
			return err
		}
		remoteVer, err := cloudProvider.RotateKey(ctx, target, wrappedKey)
		if err != nil {
			return fmt.Errorf("multicloudsync: conflict resolution rotate failed: %w", err)
		}
		conflictStatus.Status = "synced"
		conflictStatus.RemoteKeyVer = remoteVer
		conflictStatus.LocalKeyVersion = localVer
		conflictStatus.ErrorMsg = ""
		conflictStatus.LastSync = time.Now()
		conflictStatus.NextSync = time.Now().Add(policy.SyncInterval)

	case "latest_wins":
		// Compare versions and keep the latest
		cloudProvider, err := e.getProvider(provider)
		if err != nil {
			return err
		}
		var target ProviderTarget
		for _, t := range policy.TargetProviders {
			if t.Provider == provider {
				target = t
				break
			}
		}
		remoteVer, err := cloudProvider.GetKeyVersion(ctx, target)
		if err != nil {
			return fmt.Errorf("multicloudsync: get remote version: %w", err)
		}
		// If remote is newer, mark as synced with remote version
		// If local is newer, push local to remote
		if remoteVer > conflictStatus.LocalKeyVersion {
			conflictStatus.Status = "synced"
			conflictStatus.RemoteKeyVer = remoteVer
			conflictStatus.ErrorMsg = ""
		} else {
			wrappedKey, localVer, err := e.fetcher.FetchWrappedKey(ctx, policy.VectaKeyID)
			if err != nil {
				return err
			}
			newRemoteVer, err := cloudProvider.RotateKey(ctx, target, wrappedKey)
			if err != nil {
				return err
			}
			conflictStatus.Status = "synced"
			conflictStatus.RemoteKeyVer = newRemoteVer
			conflictStatus.LocalKeyVersion = localVer
			conflictStatus.ErrorMsg = ""
		}
		conflictStatus.LastSync = time.Now()
		conflictStatus.NextSync = time.Now().Add(policy.SyncInterval)

	case "manual":
		// Mark as pending manual resolution; clear conflict but don't sync
		conflictStatus.Status = "pending"
		conflictStatus.ErrorMsg = "awaiting manual resolution"
	}

	return e.store.UpsertSyncStatus(ctx, conflictStatus)
}

// DetectDrift compares local key versions with remote versions for all targets in a policy.
func (e *SyncEngine) DetectDrift(ctx context.Context, policyID string) ([]DriftReport, error) {
	policy, err := e.store.GetPolicy(ctx, policyID)
	if err != nil {
		return nil, fmt.Errorf("multicloudsync: get policy: %w", err)
	}

	_, localVersion, err := e.fetcher.FetchWrappedKey(ctx, policy.VectaKeyID)
	if err != nil {
		return nil, fmt.Errorf("multicloudsync: fetch key version: %w", err)
	}

	var reports []DriftReport
	for _, target := range policy.TargetProviders {
		report := DriftReport{
			PolicyID:     policyID,
			Provider:     target.Provider,
			AccountID:    target.AccountID,
			Region:       target.Region,
			LocalVersion: localVersion,
			DetectedAt:   time.Now(),
		}

		cloudProvider, err := e.getProvider(target.Provider)
		if err != nil {
			report.Drifted = true
			report.RemoteVersion = "unknown"
			reports = append(reports, report)
			continue
		}

		remoteVersion, err := cloudProvider.GetKeyVersion(ctx, target)
		if err != nil {
			report.Drifted = true
			report.RemoteVersion = "error: " + err.Error()
			reports = append(reports, report)
			continue
		}

		report.RemoteVersion = remoteVersion
		report.Drifted = remoteVersion != localVersion

		// If drifted, update sync status to conflict
		if report.Drifted {
			st := &SyncStatus{
				PolicyID:        policyID,
				Provider:        target.Provider,
				AccountID:       target.AccountID,
				Region:          target.Region,
				Status:          "conflict",
				LastSync:        time.Now(),
				NextSync:        time.Now().Add(policy.SyncInterval),
				ErrorMsg:        fmt.Sprintf("drift detected: local=%s remote=%s", localVersion, remoteVersion),
				RemoteKeyVer:    remoteVersion,
				LocalKeyVersion: localVersion,
			}
			if storeErr := e.store.UpsertSyncStatus(ctx, st); storeErr != nil {
				e.logf("[multicloudsync] failed to update drift status: %v", storeErr)
			}
		}

		reports = append(reports, report)
	}

	return reports, nil
}

// generateID produces a random hex ID.
func generateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
