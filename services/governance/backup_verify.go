package main

import (
	"context"
	"strings"
	"time"
)

// VerifyBackupResult is what a verification proved: the artifact opened
// with the key given, and holds these tables and rows. Nothing was applied.
type VerifyBackupResult struct {
	Verified         bool             `json:"verified"`
	Scope            string           `json:"scope"`
	TargetTenantID   string           `json:"target_tenant_id,omitempty"`
	BackupCapturedAt string           `json:"backup_captured_at"`
	TableCount       int              `json:"table_count"`
	RowCountTotal    int64            `json:"row_count_total"`
	TableRowCounts   map[string]int64 `json:"table_row_counts"`
	KeySource        string           `json:"key_source"`
	ShareGuardians   []string         `json:"share_guardians,omitempty"`
	ElapsedMs        int64            `json:"elapsed_ms"`
	DataModified     bool             `json:"data_modified"`
}

// VerifyBackup opens a backup exactly as restore does (key resolution,
// guardian shares, AES-GCM under its AAD, snapshot parse) and reports what it
// holds, without touching the database. It doesn't prove the owning services
// can re-wrap retired-key rows; restore checks that before applying.
func (s *Service) VerifyBackup(ctx context.Context, in RestoreBackupInput) (VerifyBackupResult, error) {
	started := time.Now()
	opened, err := s.openBackup(ctx, in)
	elapsed := time.Since(started).Milliseconds()
	tenantID := strings.TrimSpace(in.TenantID)
	if err != nil {
		_ = s.publishAudit(ctx, "audit.governance.backup_verify_refused", tenantID, map[string]interface{}{
			"artifact_file_name": strings.TrimSpace(in.ArtifactFileName),
			"key_file_name":      strings.TrimSpace(in.KeyFileName),
			"key_shares_given":   len(in.KeyShares),
			"requested_by":       strings.TrimSpace(in.CreatedBy),
			"reason":             err.Error(),
			"result":             "refused",
			"severity":           "warning",
			"description":        "backup verification failed: the backup did not open with the key given",
		})
		return VerifyBackupResult{}, err
	}
	var rows int64
	for _, n := range opened.Snapshot.TableRowCounts {
		rows += n
	}
	out := VerifyBackupResult{
		Verified:         true,
		Scope:            opened.Scope,
		TargetTenantID:   opened.TargetTenantID,
		BackupCapturedAt: strings.TrimSpace(opened.Snapshot.CapturedAt),
		TableCount:       len(opened.Snapshot.Tables),
		RowCountTotal:    rows,
		TableRowCounts:   opened.Snapshot.TableRowCounts,
		KeySource:        restoreKeySource(opened.ShareGuardians),
		ShareGuardians:   opened.ShareGuardians,
		ElapsedMs:        elapsed,
	}
	_ = s.publishAudit(ctx, "audit.governance.backup_verified", tenantID, map[string]interface{}{
		"scope":              out.Scope,
		"target_tenant_id":   out.TargetTenantID,
		"backup_captured_at": out.BackupCapturedAt,
		"table_count":        out.TableCount,
		"row_count_total":    out.RowCountTotal,
		"key_source":         out.KeySource,
		"share_guardians":    out.ShareGuardians,
		"elapsed_ms":         out.ElapsedMs,
		"verified_by":        strings.TrimSpace(in.CreatedBy),
		"description":        "backup opened and parsed with the key given; no data was changed",
	})
	return out, nil
}
