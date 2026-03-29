package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// BackupService orchestrates backup runs and policy management.
type BackupService struct {
	store Store
}

// NewBackupService creates a new BackupService.
func NewBackupService(store Store) *BackupService {
	return &BackupService{store: store}
}

// RunBackup executes a backup run for a policy (simulated).
// It creates a BackupRun record, simulates work, then finalises the record
// and creates a RestorePoint. Designed to run in a goroutine.
func (svc *BackupService) RunBackup(ctx context.Context, tenantID, policyID, policyName, scope, destination, triggeredBy string) {
	run := BackupRun{
		ID:          newBackupID("run"),
		TenantID:    tenantID,
		PolicyID:    policyID,
		PolicyName:  policyName,
		Status:      "running",
		Scope:       scope,
		Destination: destination,
		TriggeredBy: triggeredBy,
		StartedAt:   time.Now().UTC(),
	}

	saved, err := svc.store.CreateRun(ctx, run)
	if err != nil {
		logger.Printf("backup: failed to create run record for policy %s: %v", policyID, err)
		return
	}

	// Simulate backup work.
	time.Sleep(2 * time.Second)

	totalKeys := 50 + int(randByte()%100)    // 50-149 keys
	failedKeys := int(randByte() % 3)         // 0-2 failures
	backedUp := totalKeys - failedKeys
	sizeBytes := int64(backedUp) * (4096 + int64(randByte())*16)
	destPath := fmt.Sprintf("/backups/%s/%s/%s.bak", tenantID, time.Now().UTC().Format("2006/01/02"), saved.ID)
	completedAt := time.Now().UTC()

	runStatus := "completed"
	runErr := ""
	if failedKeys > 0 && failedKeys >= totalKeys {
		runStatus = "failed"
		runErr = "all keys failed to backup"
	}

	if updateErr := svc.store.UpdateRun(ctx, tenantID, saved.ID, runStatus, backedUp, failedKeys, sizeBytes, destPath, completedAt, runErr); updateErr != nil {
		logger.Printf("backup: failed to update run %s: %v", saved.ID, updateErr)
		return
	}

	// Update policy last_run_at.
	if strings.TrimSpace(policyID) != "" {
		svc.store.(*SQLStore).markPolicyRun(ctx, tenantID, policyID, completedAt)
	}

	if runStatus == "completed" {
		checksum := svc.computeChecksum(tenantID, saved.ID, backedUp, sizeBytes)
		expiresAt := completedAt.Add(90 * 24 * time.Hour)
		rp := RestorePoint{
			ID:              newBackupID("rp"),
			TenantID:        tenantID,
			RunID:           saved.ID,
			Name:            fmt.Sprintf("backup-%s", saved.ID),
			KeyCount:        backedUp,
			BackupSizeBytes: sizeBytes,
			CreatedAt:       completedAt,
			ExpiresAt:       &expiresAt,
			Checksum:        checksum,
			Status:          "available",
		}
		if _, rpErr := svc.store.CreateRestorePoint(ctx, rp); rpErr != nil {
			logger.Printf("backup: failed to create restore point for run %s: %v", saved.ID, rpErr)
		}
	}

	logger.Printf("backup: run %s completed (status=%s, keys=%d/%d, size=%d bytes)", saved.ID, runStatus, backedUp, totalKeys, sizeBytes)
}

// RestoreFromPoint simulates a restore operation from a restore point.
// Marks the restore point as 'restoring' briefly, then 'available' again.
func (svc *BackupService) RestoreFromPoint(ctx context.Context, tenantID, id string) error {
	rp, err := svc.store.GetRestorePoint(ctx, tenantID, id)
	if err != nil {
		return err
	}
	if rp.Status != "available" {
		return fmt.Errorf("restore point %s is not in available state (current: %s)", id, rp.Status)
	}

	if err := svc.store.UpdateRestorePointStatus(ctx, tenantID, id, "restoring"); err != nil {
		return err
	}

	// Simulate restore work in background.
	go func() {
		time.Sleep(3 * time.Second)
		restoreCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := svc.store.UpdateRestorePointStatus(restoreCtx, tenantID, id, "available"); err != nil {
			logger.Printf("backup: failed to finalise restore for point %s: %v", id, err)
		} else {
			logger.Printf("backup: restore completed for point %s (tenant %s, %d keys)", id, tenantID, rp.KeyCount)
		}
	}()
	return nil
}

// computeChecksum produces a deterministic SHA-256-based checksum for a backup run.
func (svc *BackupService) computeChecksum(tenantID, runID string, keyCount int, sizeBytes int64) string {
	raw := fmt.Sprintf("%s|%s|%d|%d", tenantID, runID, keyCount, sizeBytes)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func randByte() byte {
	b := make([]byte, 1)
	_, _ = rand.Read(b)
	return b[0]
}
