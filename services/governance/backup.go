package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	backupScopeSystem = "system"
	backupScopeTenant = "tenant"

	backupFormatJSONGzAESGCM = "json.gz+aes256gcm"
	backupArtifactVersion    = "v1"
	backupArtifactExtension  = ".vbk"
	backupKeyExtension       = ".key.json"
)

type backupHSMBinding struct {
	Enabled         bool
	ProviderName    string
	LibraryPath     string
	SlotID          string
	PartitionLabel  string
	TokenLabel      string
	Fingerprint     string
	FingerprintHash string
}

type backupSnapshotPayload struct {
	Version         string                     `json:"version"`
	CapturedAt      string                     `json:"captured_at"`
	Scope           string                     `json:"scope"`
	RequestTenantID string                     `json:"request_tenant_id"`
	TargetTenantID  string                     `json:"target_tenant_id,omitempty"`
	Coverage        backupCoverageSummary      `json:"coverage"`
	TableRowCounts  map[string]int64           `json:"table_row_counts"`
	Tables          map[string]json.RawMessage `json:"tables"`
}

type backupArtifactEnvelope struct {
	Version          string                `json:"version"`
	Encryption       string                `json:"encryption"`
	BackupFormat     string                `json:"backup_format"`
	Scope            string                `json:"scope"`
	RequestTenantID  string                `json:"request_tenant_id"`
	TargetTenantID   string                `json:"target_tenant_id,omitempty"`
	CapturedAt       string                `json:"captured_at,omitempty"`
	Coverage         backupCoverageSummary `json:"coverage"`
	CiphertextB64    string                `json:"ciphertext_base64"`
	NonceB64         string                `json:"nonce_base64"`
	CiphertextSHA256 string                `json:"ciphertext_sha256,omitempty"`
}

type backupCoverageSummary struct {
	IncludedCapabilities []string `json:"included_capabilities"`
	IncludedTables       []string `json:"included_tables,omitempty"`
	ExcludedCategories   []string `json:"excluded_categories,omitempty"`
	Notes                []string `json:"notes,omitempty"`
}

func normalizeBackupScope(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case backupScopeSystem:
		return backupScopeSystem
	case backupScopeTenant:
		return backupScopeTenant
	default:
		return ""
	}
}

func (s *Service) CreateBackup(ctx context.Context, in CreateBackupInput) (BackupJob, error) {
	store, ok := s.store.(*SQLStore)
	if !ok || store == nil || store.db == nil || store.db.SQL() == nil {
		return BackupJob{}, errors.New("backup store is unavailable")
	}
	in.TenantID = strings.TrimSpace(in.TenantID)
	if in.TenantID == "" {
		return BackupJob{}, errors.New("tenant_id is required")
	}
	scope := normalizeBackupScope(in.Scope)
	if scope == "" {
		return BackupJob{}, errors.New("scope must be system or tenant")
	}
	targetTenantID := strings.TrimSpace(in.TargetTenantID)
	if scope == backupScopeTenant && targetTenantID == "" {
		targetTenantID = in.TenantID
	}
	if scope == backupScopeSystem {
		targetTenantID = ""
	}
	createdBy := strings.TrimSpace(in.CreatedBy)
	if createdBy == "" {
		createdBy = "system"
	}
	bindToHSM := true
	if in.BindToHSM != nil {
		bindToHSM = *in.BindToHSM
	}

	payload, rowCountTotal, tableCount, coverage, err := s.captureBackupPayload(ctx, store, in.TenantID, scope, targetTenantID)
	if err != nil {
		return BackupJob{}, err
	}
	if len(payload) == 0 {
		return BackupJob{}, errors.New("backup payload is empty")
	}
	backupKey, err := randomBytes(32)
	if err != nil {
		return BackupJob{}, err
	}
	aad, err := json.Marshal(map[string]interface{}{
		"service":          "governance",
		"scope":            scope,
		"tenant_id":        in.TenantID,
		"target_tenant_id": targetTenantID,
		"format":           backupFormatJSONGzAESGCM,
	})
	if err != nil {
		return BackupJob{}, err
	}
	ciphertext, nonce, err := encryptAESGCM(payload, backupKey, aad)
	if err != nil {
		return BackupJob{}, err
	}
	hsmTenantID := in.TenantID
	if scope == backupScopeTenant {
		hsmTenantID = targetTenantID
	}
	binding := store.loadHSMBinding(ctx, hsmTenantID)
	hsmBound := bindToHSM && binding.Enabled
	keyPackage, keyPackageRaw, err := buildBackupKeyPackage(backupKey, hsmBound, binding, in.TenantID, targetTenantID, coverage)
	if err != nil {
		return BackupJob{}, err
	}
	job := BackupJob{
		ID:                    newID("bkp"),
		TenantID:              in.TenantID,
		Scope:                 scope,
		TargetTenantID:        targetTenantID,
		Status:                "completed",
		BackupFormat:          backupFormatJSONGzAESGCM,
		EncryptionAlgorithm:   "AES-256-GCM",
		CiphertextSHA256:      sha256Hex(string(ciphertext)),
		ArtifactCiphertext:    ciphertext,
		ArtifactNonce:         nonce,
		ArtifactSizeBytes:     int64(len(ciphertext)),
		RowCountTotal:         rowCountTotal,
		TableCount:            tableCount,
		HSMBound:              hsmBound,
		HSMProviderName:       binding.ProviderName,
		HSMSlotID:             binding.SlotID,
		HSMPartitionLabel:     binding.PartitionLabel,
		HSMTokenLabel:         binding.TokenLabel,
		HSMBindingFingerprint: binding.FingerprintHash,
		KeyPackage:            keyPackage,
		KeyPackageRaw:         keyPackageRaw,
		CreatedBy:             createdBy,
		CompletedAt:           time.Now().UTC(),
	}
	if err := store.insertBackupJob(ctx, job); err != nil {
		return BackupJob{}, err
	}
	_ = s.publishAudit(ctx, "audit.governance.backup_created", in.TenantID, map[string]interface{}{
		"backup_id":           job.ID,
		"scope":               job.Scope,
		"target_tenant_id":    job.TargetTenantID,
		"artifact_size_bytes": job.ArtifactSizeBytes,
		"hsm_bound":           job.HSMBound,
		"row_count_total":     job.RowCountTotal,
		"table_count":         job.TableCount,
	})
	sanitizeBackupJobSummary(&job)
	return job, nil
}

func (s *Service) ListBackups(ctx context.Context, tenantID string, scope string, status string, limit int) ([]BackupJob, error) {
	store, ok := s.store.(*SQLStore)
	if !ok || store == nil || store.db == nil || store.db.SQL() == nil {
		return nil, errors.New("backup store is unavailable")
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, errors.New("tenant_id is required")
	}
	scope = strings.ToLower(strings.TrimSpace(scope))
	status = strings.ToLower(strings.TrimSpace(status))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	items, err := store.listBackupJobs(ctx, tenantID, scope, status, limit)
	if err != nil {
		return nil, err
	}
	for i := range items {
		sanitizeBackupJobSummary(&items[i])
	}
	return items, nil
}

func (s *Service) GetBackup(ctx context.Context, tenantID string, backupID string) (BackupJob, error) {
	store, ok := s.store.(*SQLStore)
	if !ok || store == nil || store.db == nil || store.db.SQL() == nil {
		return BackupJob{}, errors.New("backup store is unavailable")
	}
	tenantID = strings.TrimSpace(tenantID)
	backupID = strings.TrimSpace(backupID)
	if tenantID == "" || backupID == "" {
		return BackupJob{}, errors.New("tenant_id and backup_id are required")
	}
	item, err := store.getBackupJob(ctx, tenantID, backupID, false)
	if err != nil {
		return BackupJob{}, err
	}
	sanitizeBackupJobSummary(&item)
	return item, nil
}

func (s *Service) DeleteBackup(ctx context.Context, tenantID string, backupID string, deletedBy string) error {
	store, ok := s.store.(*SQLStore)
	if !ok || store == nil || store.db == nil || store.db.SQL() == nil {
		return errors.New("backup store is unavailable")
	}
	tenantID = strings.TrimSpace(tenantID)
	backupID = strings.TrimSpace(backupID)
	if tenantID == "" || backupID == "" {
		return errors.New("tenant_id and backup_id are required")
	}
	item, err := store.getBackupJob(ctx, tenantID, backupID, false)
	if err != nil {
		return err
	}
	if err := store.deleteBackupJob(ctx, tenantID, backupID); err != nil {
		return err
	}
	deletedBy = strings.TrimSpace(deletedBy)
	if deletedBy == "" {
		deletedBy = "system"
	}
	_ = s.publishAudit(ctx, "audit.governance.backup_deleted", tenantID, map[string]interface{}{
		"backup_id":         backupID,
		"deleted_by":        deletedBy,
		"scope":             item.Scope,
		"target_tenant_id":  item.TargetTenantID,
		"artifact_size":     item.ArtifactSizeBytes,
		"row_count_total":   item.RowCountTotal,
		"table_count_total": item.TableCount,
	})
	return nil
}

func (s *Service) GetBackupArtifactDownload(ctx context.Context, tenantID string, backupID string) (map[string]interface{}, error) {
	store, ok := s.store.(*SQLStore)
	if !ok || store == nil || store.db == nil || store.db.SQL() == nil {
		return nil, errors.New("backup store is unavailable")
	}
	item, err := store.getBackupJob(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(backupID), true)
	if err != nil {
		return nil, err
	}
	if len(item.ArtifactCiphertext) == 0 {
		return nil, errors.New("backup artifact is empty")
	}
	envelope := backupArtifactEnvelope{
		Version:          backupArtifactVersion,
		Encryption:       item.EncryptionAlgorithm,
		BackupFormat:     item.BackupFormat,
		Scope:            item.Scope,
		RequestTenantID:  item.TenantID,
		TargetTenantID:   item.TargetTenantID,
		CapturedAt:       item.CompletedAt.UTC().Format(time.RFC3339Nano),
		Coverage:         backupCoverageFromJob(item),
		CiphertextB64:    base64.StdEncoding.EncodeToString(item.ArtifactCiphertext),
		NonceB64:         base64.StdEncoding.EncodeToString(item.ArtifactNonce),
		CiphertextSHA256: item.CiphertextSHA256,
	}
	envelopeRaw, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"file_name":            fmt.Sprintf("vecta-backup-%s%s", item.ID, backupArtifactExtension),
		"content_type":         "application/octet-stream",
		"content_base64":       base64.StdEncoding.EncodeToString(envelopeRaw),
		"nonce_base64":         base64.StdEncoding.EncodeToString(item.ArtifactNonce),
		"ciphertext_sha256":    item.CiphertextSHA256,
		"backup_format":        item.BackupFormat,
		"encryption_algorithm": item.EncryptionAlgorithm,
		"hsm_bound":            item.HSMBound,
		"coverage":             envelope.Coverage,
	}, nil
}

func (s *Service) GetBackupKeyDownload(ctx context.Context, tenantID string, backupID string) (map[string]interface{}, error) {
	store, ok := s.store.(*SQLStore)
	if !ok || store == nil || store.db == nil || store.db.SQL() == nil {
		return nil, errors.New("backup store is unavailable")
	}
	item, err := store.getBackupJob(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(backupID), true)
	if err != nil {
		return nil, err
	}
	if len(item.KeyPackageRaw) == 0 {
		return nil, errors.New("backup key package is empty")
	}
	var keyPackage map[string]interface{}
	if err := json.Unmarshal(item.KeyPackageRaw, &keyPackage); err != nil {
		return nil, err
	}
	if keyPackage == nil {
		keyPackage = map[string]interface{}{}
	}
	if len(item.ArtifactNonce) > 0 {
		keyPackage["backup_artifact_nonce_b64"] = base64.StdEncoding.EncodeToString(item.ArtifactNonce)
	}
	if strings.TrimSpace(item.BackupFormat) != "" {
		keyPackage["backup_format"] = item.BackupFormat
	}
	keyPackage["backup_scope"] = item.Scope
	if strings.TrimSpace(item.TargetTenantID) != "" {
		keyPackage["target_tenant_id"] = item.TargetTenantID
	}
	return map[string]interface{}{
		"file_name":    fmt.Sprintf("vecta-backup-%s%s", item.ID, backupKeyExtension),
		"content_type": "application/json",
		"key_package":  keyPackage,
	}, nil
}

func (s *Service) RestoreBackup(ctx context.Context, in RestoreBackupInput) (RestoreBackupResult, error) {
	store, ok := s.store.(*SQLStore)
	if !ok || store == nil || store.db == nil || store.db.SQL() == nil {
		return RestoreBackupResult{}, errors.New("backup store is unavailable")
	}
	in.TenantID = strings.TrimSpace(in.TenantID)
	in.ArtifactFileName = strings.TrimSpace(in.ArtifactFileName)
	in.KeyFileName = strings.TrimSpace(in.KeyFileName)
	if in.TenantID == "" {
		return RestoreBackupResult{}, errors.New("tenant_id is required")
	}
	if !hasApprovedBackupArtifactName(in.ArtifactFileName) {
		return RestoreBackupResult{}, fmt.Errorf("artifact file must use %s extension", backupArtifactExtension)
	}
	if !hasApprovedBackupKeyName(in.KeyFileName) {
		return RestoreBackupResult{}, fmt.Errorf("key file must use %s extension", backupKeyExtension)
	}
	artifactRaw, err := decodeBase64Payload(in.ArtifactContentBase)
	if err != nil {
		return RestoreBackupResult{}, fmt.Errorf("invalid backup artifact: %w", err)
	}
	keyRaw, err := decodeBase64Payload(in.KeyContentBase)
	if err != nil {
		return RestoreBackupResult{}, fmt.Errorf("invalid backup key package: %w", err)
	}
	var keyPackage map[string]interface{}
	if err := json.Unmarshal(keyRaw, &keyPackage); err != nil {
		return RestoreBackupResult{}, errors.New("backup key package is not valid JSON")
	}
	var envelope backupArtifactEnvelope
	var ciphertext []byte
	var nonce []byte
	if err := json.Unmarshal(artifactRaw, &envelope); err == nil {
		if strings.TrimSpace(envelope.CiphertextB64) == "" || strings.TrimSpace(envelope.NonceB64) == "" {
			return RestoreBackupResult{}, errors.New("backup artifact is missing required encryption fields")
		}
		ciphertext, err = base64.StdEncoding.DecodeString(strings.TrimSpace(envelope.CiphertextB64))
		if err != nil {
			return RestoreBackupResult{}, fmt.Errorf("invalid backup ciphertext: %w", err)
		}
		nonce, err = base64.StdEncoding.DecodeString(strings.TrimSpace(envelope.NonceB64))
		if err != nil {
			return RestoreBackupResult{}, fmt.Errorf("invalid backup nonce: %w", err)
		}
	} else {
		// Compatibility mode: previous .vbk files stored raw ciphertext only.
		ciphertext = artifactRaw
		nonceRaw := strings.TrimSpace(fmt.Sprintf("%v", keyPackage["backup_artifact_nonce_b64"]))
		if nonceRaw == "" {
			return RestoreBackupResult{}, errors.New("backup artifact format is invalid (missing nonce for legacy artifact)")
		}
		nonce, err = base64.StdEncoding.DecodeString(nonceRaw)
		if err != nil {
			return RestoreBackupResult{}, fmt.Errorf("invalid backup nonce in key package: %w", err)
		}
		envelope = backupArtifactEnvelope{
			Version:         backupArtifactVersion,
			BackupFormat:    strings.TrimSpace(fmt.Sprintf("%v", keyPackage["backup_format"])),
			Scope:           strings.TrimSpace(fmt.Sprintf("%v", keyPackage["backup_scope"])),
			RequestTenantID: strings.TrimSpace(fmt.Sprintf("%v", keyPackage["request_tenant_id"])),
			TargetTenantID:  strings.TrimSpace(fmt.Sprintf("%v", keyPackage["target_tenant_id"])),
		}
	}
	backupKey, err := s.resolveRestoreBackupKey(ctx, store, in.TenantID, keyPackage)
	if err != nil {
		return RestoreBackupResult{}, err
	}
	scope := normalizeBackupScope(envelope.Scope)
	if scope == "" {
		scope = backupScopeSystem
	}
	requestTenantID := strings.TrimSpace(envelope.RequestTenantID)
	if requestTenantID == "" {
		requestTenantID = in.TenantID
	}
	targetTenantID := strings.TrimSpace(envelope.TargetTenantID)
	if scope == backupScopeTenant && targetTenantID == "" {
		targetTenantID = requestTenantID
	}
	if scope == backupScopeSystem {
		targetTenantID = ""
	}
	backupFormat := strings.TrimSpace(envelope.BackupFormat)
	if backupFormat == "" {
		backupFormat = backupFormatJSONGzAESGCM
	}
	if backupFormat != backupFormatJSONGzAESGCM {
		return RestoreBackupResult{}, fmt.Errorf("unsupported backup format: %s", backupFormat)
	}
	aad, err := json.Marshal(map[string]interface{}{
		"service":          "governance",
		"scope":            scope,
		"tenant_id":        requestTenantID,
		"target_tenant_id": targetTenantID,
		"format":           backupFormat,
	})
	if err != nil {
		return RestoreBackupResult{}, err
	}
	plaintext, err := decryptAESGCM(ciphertext, backupKey, nonce, aad)
	if err != nil {
		legacyAAD := map[string]interface{}{
			"service":          "governance",
			"scope":            scope,
			"tenant_id":        requestTenantID,
			"target_tenant_id": targetTenantID,
			"format":           backupFormat,
			"captured_at":      strings.TrimSpace(envelope.CapturedAt),
		}
		legacyAADRaw, _ := json.Marshal(legacyAAD)
		plaintext, err = decryptAESGCM(ciphertext, backupKey, nonce, legacyAADRaw)
		if err != nil {
			plaintext, err = decryptAESGCM(ciphertext, backupKey, nonce, nil)
			if err != nil {
				return RestoreBackupResult{}, errors.New("backup decryption failed: invalid key package or artifact")
			}
		}
	}
	gzReader, err := gzip.NewReader(bytes.NewReader(plaintext))
	if err != nil {
		return RestoreBackupResult{}, fmt.Errorf("backup payload is not gzip content: %w", err)
	}
	defer gzReader.Close() //nolint:errcheck
	uncompressed, err := io.ReadAll(gzReader)
	if err != nil {
		return RestoreBackupResult{}, err
	}
	var snapshot backupSnapshotPayload
	if err := json.Unmarshal(uncompressed, &snapshot); err != nil {
		return RestoreBackupResult{}, errors.New("backup payload JSON is invalid")
	}
	snapshotScope := normalizeBackupScope(snapshot.Scope)
	if snapshotScope == "" {
		snapshotScope = scope
	}
	snapshotTargetTenantID := strings.TrimSpace(snapshot.TargetTenantID)
	if snapshotScope == backupScopeTenant && snapshotTargetTenantID == "" {
		snapshotTargetTenantID = targetTenantID
	}
	if snapshotScope == backupScopeSystem {
		snapshotTargetTenantID = ""
	}
	rowsRestored, tablesProcessed, tablesSkipped, excludedTables, err := store.restoreSnapshot(ctx, snapshotScope, snapshotTargetTenantID, snapshot.Tables)
	if err != nil {
		return RestoreBackupResult{}, err
	}
	createdBy := strings.TrimSpace(in.CreatedBy)
	if createdBy == "" {
		createdBy = "system"
	}
	_ = s.publishAudit(ctx, "audit.governance.backup_restored", in.TenantID, map[string]interface{}{
		"scope":            snapshotScope,
		"target_tenant_id": snapshotTargetTenantID,
		"rows_restored":    rowsRestored,
		"tables_processed": tablesProcessed,
		"tables_skipped":   tablesSkipped,
		"excluded_tables":  excludedTables,
		"restored_by":      createdBy,
	})
	return RestoreBackupResult{
		Scope:            snapshotScope,
		TargetTenantID:   snapshotTargetTenantID,
		RowsRestored:     rowsRestored,
		TablesProcessed:  tablesProcessed,
		TablesSkipped:    tablesSkipped,
		ExcludedTables:   excludedTables,
		BackupCapturedAt: strings.TrimSpace(snapshot.CapturedAt),
	}, nil
}

func (s *Service) resolveRestoreBackupKey(ctx context.Context, store *SQLStore, tenantID string, keyPackage map[string]interface{}) ([]byte, error) {
	mode := strings.TrimSpace(strings.ToLower(fmt.Sprintf("%v", keyPackage["mode"])))
	switch mode {
	case "software":
		raw := strings.TrimSpace(fmt.Sprintf("%v", keyPackage["backup_key_b64"]))
		if raw == "" {
			return nil, errors.New("backup key package is missing backup_key_b64")
		}
		key, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return nil, err
		}
		if len(key) != 32 {
			return nil, errors.New("backup key size is invalid")
		}
		return key, nil
	case "hsm_bound":
		wrappedRaw := strings.TrimSpace(fmt.Sprintf("%v", keyPackage["wrapped_key_b64"]))
		nonceRaw := strings.TrimSpace(fmt.Sprintf("%v", keyPackage["wrap_nonce_b64"]))
		aadRaw := strings.TrimSpace(fmt.Sprintf("%v", keyPackage["wrap_aad_b64"]))
		if wrappedRaw == "" || nonceRaw == "" {
			return nil, errors.New("backup key package is missing wrapped key fields")
		}
		wrapped, err := base64.StdEncoding.DecodeString(wrappedRaw)
		if err != nil {
			return nil, err
		}
		wrapNonce, err := base64.StdEncoding.DecodeString(nonceRaw)
		if err != nil {
			return nil, err
		}
		var wrapAAD []byte
		if aadRaw != "" {
			wrapAAD, err = base64.StdEncoding.DecodeString(aadRaw)
			if err != nil {
				return nil, err
			}
		}
		binding := store.loadHSMBinding(ctx, tenantID)
		if !binding.Enabled {
			return nil, errors.New("restore requires enabled HSM configuration for hsm_bound backup")
		}
		secret := strings.TrimSpace(os.Getenv("BACKUP_HSM_WRAP_SECRET"))
		if secret == "" {
			secret = "vecta-backup-wrap-secret-change-me"
		}
		requestTenantID := strings.TrimSpace(fmt.Sprintf("%v", keyPackage["request_tenant_id"]))
		targetTenantID := strings.TrimSpace(fmt.Sprintf("%v", keyPackage["target_tenant_id"]))
		candidates := []string{
			secret + "|" + binding.Fingerprint + "|" + requestTenantID + "|" + targetTenantID,
			secret + "|" + binding.Fingerprint + "|" + tenantID + "|" + targetTenantID,
			secret + "|" + binding.Fingerprint,
		}
		seen := map[string]struct{}{}
		for _, candidate := range candidates {
			keyID := sha256Hex(candidate)
			if _, exists := seen[keyID]; exists {
				continue
			}
			seen[keyID] = struct{}{}
			derived := sha256.Sum256([]byte(candidate))
			backupKey, err := decryptAESGCM(wrapped, derived[:], wrapNonce, wrapAAD)
			if err != nil {
				continue
			}
			if len(backupKey) != 32 {
				continue
			}
			return backupKey, nil
		}
		return nil, errors.New("unable to unwrap hsm_bound backup key with current HSM binding")
	default:
		return nil, errors.New("unsupported backup key package mode")
	}
}

func (s *Service) captureBackupPayload(ctx context.Context, store *SQLStore, requestTenantID string, scope string, targetTenantID string) ([]byte, int64, int, backupCoverageSummary, error) {
	tables, err := store.listBackupTables(ctx)
	if err != nil {
		return nil, 0, 0, backupCoverageSummary{}, err
	}
	sort.Strings(tables)
	payload := backupSnapshotPayload{
		Version:         "v1",
		CapturedAt:      time.Now().UTC().Format(time.RFC3339Nano),
		Scope:           scope,
		RequestTenantID: requestTenantID,
		TargetTenantID:  targetTenantID,
		Coverage:        backupCoverageSummary{},
		TableRowCounts:  map[string]int64{},
		Tables:          map[string]json.RawMessage{},
	}
	var rowCountTotal int64
	includedTables := make([]string, 0, len(tables))
	for _, table := range tables {
		if table == "" {
			continue
		}
		if isExcludedFromBackupTable(table) {
			continue
		}
		hasTenantID, err := store.tableHasTenantIDColumn(ctx, table)
		if err != nil {
			return nil, 0, 0, backupCoverageSummary{}, err
		}
		if scope == backupScopeTenant && !hasTenantID {
			continue
		}
		rowsJSON, rowCount, err := store.dumpTableRows(ctx, table, scope, targetTenantID, hasTenantID)
		if err != nil {
			return nil, 0, 0, backupCoverageSummary{}, err
		}
		if rowCount == 0 {
			continue
		}
		includedTables = append(includedTables, table)
		payload.Tables[table] = rowsJSON
		payload.TableRowCounts[table] = rowCount
		rowCountTotal += rowCount
	}
	payload.Coverage = buildBackupCoverageSummary(includedTables)
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, 0, backupCoverageSummary{}, err
	}
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write(raw); err != nil {
		_ = gz.Close()
		return nil, 0, 0, backupCoverageSummary{}, err
	}
	if err := gz.Close(); err != nil {
		return nil, 0, 0, backupCoverageSummary{}, err
	}
	return compressed.Bytes(), rowCountTotal, len(payload.Tables), payload.Coverage, nil
}

func buildBackupKeyPackage(backupKey []byte, hsmBound bool, binding backupHSMBinding, requestTenantID string, targetTenantID string, coverage backupCoverageSummary) (map[string]interface{}, []byte, error) {
	if hsmBound {
		secret := strings.TrimSpace(os.Getenv("BACKUP_HSM_WRAP_SECRET"))
		if secret == "" {
			secret = "vecta-backup-wrap-secret-change-me"
		}
		derived := sha256.Sum256([]byte(secret + "|" + binding.Fingerprint + "|" + requestTenantID + "|" + targetTenantID))
		aad := []byte("vecta-kms:backup:hsm-binding:" + binding.FingerprintHash)
		wrapped, wrapNonce, err := encryptAESGCM(backupKey, derived[:], aad)
		if err != nil {
			return nil, nil, err
		}
		pkg := map[string]interface{}{
			"version":           1,
			"mode":              "hsm_bound",
			"algorithm":         "AES-256-GCM",
			"key_derivation":    "v1",
			"request_tenant_id": requestTenantID,
			"target_tenant_id":  targetTenantID,
			"wrapped_key_b64":   base64.StdEncoding.EncodeToString(wrapped),
			"wrap_nonce_b64":    base64.StdEncoding.EncodeToString(wrapNonce),
			"wrap_aad_b64":      base64.StdEncoding.EncodeToString(aad),
			"hsm_binding_hash":  binding.FingerprintHash,
			"hsm_binding": map[string]interface{}{
				"provider_name":    binding.ProviderName,
				"slot_id":          binding.SlotID,
				"partition_label":  binding.PartitionLabel,
				"token_label":      binding.TokenLabel,
				"library_path_sha": sha256Hex(binding.LibraryPath),
			},
			"backup_coverage": coverage,
			"note":            "Backup key is wrapped using local HSM binding metadata. Keep this package with backup artifact for restore.",
		}
		raw, err := json.Marshal(pkg)
		if err != nil {
			return nil, nil, err
		}
		return pkg, raw, nil
	}
	pkg := map[string]interface{}{
		"version":           1,
		"mode":              "software",
		"algorithm":         "AES-256",
		"request_tenant_id": requestTenantID,
		"target_tenant_id":  targetTenantID,
		"backup_key_b64":    base64.StdEncoding.EncodeToString(backupKey),
		"backup_key_sha256": sha256Hex(string(backupKey)),
		"backup_coverage":   coverage,
		"note":              "Store this key package separately from the encrypted backup artifact.",
	}
	raw, err := json.Marshal(pkg)
	if err != nil {
		return nil, nil, err
	}
	return pkg, raw, nil
}

func sanitizeBackupJobSummary(job *BackupJob) {
	if job == nil {
		return
	}
	if len(job.KeyPackageRaw) > 0 && len(job.KeyPackage) == 0 {
		var parsed map[string]interface{}
		if err := json.Unmarshal(job.KeyPackageRaw, &parsed); err == nil {
			job.KeyPackage = parsed
		}
	}
	if len(job.KeyPackage) > 0 {
		mode := strings.TrimSpace(fmt.Sprintf("%v", job.KeyPackage["mode"]))
		summary := map[string]interface{}{}
		if mode != "" {
			summary["mode"] = mode
		}
		if coverage, ok := job.KeyPackage["backup_coverage"].(map[string]interface{}); ok && len(coverage) > 0 {
			summary["backup_coverage"] = coverage
		}
		if hsmBinding, ok := job.KeyPackage["hsm_binding"].(map[string]interface{}); ok {
			summary["hsm_binding"] = hsmBinding
		}
		job.KeyPackage = summary
	}
	job.ArtifactCiphertext = nil
	job.ArtifactNonce = nil
	job.KeyPackageRaw = nil
}

func (s *SQLStore) insertBackupJob(ctx context.Context, job BackupJob) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO governance_backup_jobs (
    id, tenant_id, scope, target_tenant_id, status, backup_format, encryption_algorithm,
    ciphertext_sha256, artifact_ciphertext, artifact_nonce, artifact_size_bytes, row_count_total, table_count,
    hsm_bound, hsm_provider_name, hsm_slot_id, hsm_partition_label, hsm_token_label, hsm_binding_fingerprint,
    key_package_json, created_by, created_at, completed_at, failure_reason
) VALUES (
    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20::jsonb,$21,CURRENT_TIMESTAMP,$22,$23
)
`, job.ID, job.TenantID, job.Scope, strings.TrimSpace(job.TargetTenantID), job.Status, job.BackupFormat, job.EncryptionAlgorithm,
		job.CiphertextSHA256, job.ArtifactCiphertext, job.ArtifactNonce, job.ArtifactSizeBytes, job.RowCountTotal, job.TableCount,
		job.HSMBound, nullable(job.HSMProviderName), nullable(job.HSMSlotID), nullable(job.HSMPartitionLabel), nullable(job.HSMTokenLabel), nullable(job.HSMBindingFingerprint),
		string(job.KeyPackageRaw), nullable(job.CreatedBy), nullableTime(job.CompletedAt), nullable(job.FailureReason))
	return err
}

func (s *SQLStore) getBackupJob(ctx context.Context, tenantID string, backupID string, includeBlob bool) (BackupJob, error) {
	query := `
SELECT id, tenant_id, scope, COALESCE(target_tenant_id,''), status, backup_format, encryption_algorithm,
       ciphertext_sha256, artifact_size_bytes, row_count_total, table_count, hsm_bound,
       COALESCE(hsm_provider_name,''), COALESCE(hsm_slot_id,''), COALESCE(hsm_partition_label,''), COALESCE(hsm_token_label,''), COALESCE(hsm_binding_fingerprint,''),
       key_package_json::text, COALESCE(created_by,''), created_at, completed_at, COALESCE(failure_reason,'')
FROM governance_backup_jobs
WHERE tenant_id=$1 AND id=$2
`
	if includeBlob {
		query = `
SELECT id, tenant_id, scope, COALESCE(target_tenant_id,''), status, backup_format, encryption_algorithm,
       ciphertext_sha256, artifact_size_bytes, row_count_total, table_count, hsm_bound,
       COALESCE(hsm_provider_name,''), COALESCE(hsm_slot_id,''), COALESCE(hsm_partition_label,''), COALESCE(hsm_token_label,''), COALESCE(hsm_binding_fingerprint,''),
       key_package_json::text, COALESCE(created_by,''), created_at, completed_at, COALESCE(failure_reason,''),
       artifact_ciphertext, artifact_nonce
FROM governance_backup_jobs
WHERE tenant_id=$1 AND id=$2
`
	}
	row := s.db.SQL().QueryRowContext(ctx, query, tenantID, backupID)
	var out BackupJob
	var keyJSON string
	var createdRaw interface{}
	var completedRaw interface{}
	if includeBlob {
		err := row.Scan(
			&out.ID, &out.TenantID, &out.Scope, &out.TargetTenantID, &out.Status, &out.BackupFormat, &out.EncryptionAlgorithm,
			&out.CiphertextSHA256, &out.ArtifactSizeBytes, &out.RowCountTotal, &out.TableCount, &out.HSMBound,
			&out.HSMProviderName, &out.HSMSlotID, &out.HSMPartitionLabel, &out.HSMTokenLabel, &out.HSMBindingFingerprint,
			&keyJSON, &out.CreatedBy, &createdRaw, &completedRaw, &out.FailureReason,
			&out.ArtifactCiphertext, &out.ArtifactNonce,
		)
		if errors.Is(err, sql.ErrNoRows) {
			return BackupJob{}, errNotFound
		}
		if err != nil {
			return BackupJob{}, err
		}
	} else {
		err := row.Scan(
			&out.ID, &out.TenantID, &out.Scope, &out.TargetTenantID, &out.Status, &out.BackupFormat, &out.EncryptionAlgorithm,
			&out.CiphertextSHA256, &out.ArtifactSizeBytes, &out.RowCountTotal, &out.TableCount, &out.HSMBound,
			&out.HSMProviderName, &out.HSMSlotID, &out.HSMPartitionLabel, &out.HSMTokenLabel, &out.HSMBindingFingerprint,
			&keyJSON, &out.CreatedBy, &createdRaw, &completedRaw, &out.FailureReason,
		)
		if errors.Is(err, sql.ErrNoRows) {
			return BackupJob{}, errNotFound
		}
		if err != nil {
			return BackupJob{}, err
		}
	}
	out.CreatedAt = parseTimeValue(createdRaw)
	out.CompletedAt = parseTimeValue(completedRaw)
	out.KeyPackageRaw = []byte(strings.TrimSpace(keyJSON))
	if len(out.KeyPackageRaw) > 0 {
		var parsed map[string]interface{}
		if err := json.Unmarshal(out.KeyPackageRaw, &parsed); err == nil {
			out.KeyPackage = parsed
		}
	}
	return out, nil
}

func (s *SQLStore) deleteBackupJob(ctx context.Context, tenantID string, backupID string) error {
	result, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM governance_backup_jobs
WHERE tenant_id=$1 AND id=$2
`, tenantID, backupID)
	if err != nil {
		return err
	}
	if result == nil {
		return errNotFound
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected <= 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) listBackupJobs(ctx context.Context, tenantID string, scope string, status string, limit int) ([]BackupJob, error) {
	query := `
SELECT id, tenant_id, scope, COALESCE(target_tenant_id,''), status, backup_format, encryption_algorithm,
       ciphertext_sha256, artifact_size_bytes, row_count_total, table_count, hsm_bound,
       COALESCE(hsm_provider_name,''), COALESCE(hsm_slot_id,''), COALESCE(hsm_partition_label,''), COALESCE(hsm_token_label,''), COALESCE(hsm_binding_fingerprint,''),
       key_package_json::text, COALESCE(created_by,''), created_at, completed_at, COALESCE(failure_reason,'')
FROM governance_backup_jobs
WHERE tenant_id=$1
`
	args := []interface{}{tenantID}
	if scope != "" {
		args = append(args, scope)
		query += fmt.Sprintf("  AND scope=$%d\n", len(args))
	}
	if status != "" {
		args = append(args, status)
		query += fmt.Sprintf("  AND status=$%d\n", len(args))
	}
	args = append(args, limit)
	query += fmt.Sprintf("ORDER BY created_at DESC\nLIMIT $%d\n", len(args))
	rows, err := s.db.SQL().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]BackupJob, 0)
	for rows.Next() {
		var item BackupJob
		var keyJSON string
		var createdRaw interface{}
		var completedRaw interface{}
		if err := rows.Scan(
			&item.ID, &item.TenantID, &item.Scope, &item.TargetTenantID, &item.Status, &item.BackupFormat, &item.EncryptionAlgorithm,
			&item.CiphertextSHA256, &item.ArtifactSizeBytes, &item.RowCountTotal, &item.TableCount, &item.HSMBound,
			&item.HSMProviderName, &item.HSMSlotID, &item.HSMPartitionLabel, &item.HSMTokenLabel, &item.HSMBindingFingerprint,
			&keyJSON, &item.CreatedBy, &createdRaw, &completedRaw, &item.FailureReason,
		); err != nil {
			return nil, err
		}
		item.CreatedAt = parseTimeValue(createdRaw)
		item.CompletedAt = parseTimeValue(completedRaw)
		item.KeyPackageRaw = []byte(strings.TrimSpace(keyJSON))
		if len(item.KeyPackageRaw) > 0 {
			var parsed map[string]interface{}
			if err := json.Unmarshal(item.KeyPackageRaw, &parsed); err == nil {
				item.KeyPackage = parsed
			}
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *SQLStore) restoreSnapshot(ctx context.Context, scope string, targetTenantID string, tables map[string]json.RawMessage) (int64, int, []string, []string, error) {
	if len(tables) == 0 {
		return 0, 0, nil, nil, errors.New("backup payload has no tables")
	}
	tableNames := make([]string, 0, len(tables))
	for name := range tables {
		trimmed := strings.TrimSpace(name)
		if trimmed == "" {
			continue
		}
		tableNames = append(tableNames, trimmed)
	}
	sort.Strings(tableNames)
	restorableTables := make([]string, 0, len(tableNames))
	skipped := make([]string, 0)
	excluded := make([]string, 0)
	for _, tableName := range tableNames {
		if isExcludedFromBackupTable(tableName) {
			excluded = append(excluded, tableName)
			continue
		}
		exists, err := s.tableExists(ctx, tableName)
		if err != nil {
			return 0, 0, skipped, excluded, err
		}
		if !exists {
			skipped = append(skipped, tableName)
			continue
		}
		if scope == backupScopeTenant {
			hasTenantID, err := s.tableHasTenantIDColumn(ctx, tableName)
			if err != nil {
				return 0, 0, skipped, excluded, err
			}
			if !hasTenantID {
				skipped = append(skipped, tableName)
				continue
			}
		}
		restorableTables = append(restorableTables, tableName)
	}
	if len(restorableTables) == 0 {
		return 0, 0, skipped, excluded, errors.New("no valid tables found in backup for restore")
	}
	tx, err := s.db.SQL().BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, skipped, excluded, err
	}
	rollback := true
	defer func() {
		if rollback {
			_ = tx.Rollback()
		}
	}()
	if _, err := tx.ExecContext(ctx, `SET LOCAL session_replication_role = 'replica'`); err != nil {
		return 0, 0, skipped, excluded, err
	}
	if scope == backupScopeSystem {
		quoted := make([]string, 0, len(restorableTables))
		for _, tableName := range restorableTables {
			quoted = append(quoted, quoteIdentifier(tableName))
		}
		if len(quoted) > 0 {
			query := fmt.Sprintf(`TRUNCATE TABLE %s RESTART IDENTITY CASCADE`, strings.Join(quoted, ","))
			if _, err := tx.ExecContext(ctx, query); err != nil {
				return 0, 0, skipped, excluded, err
			}
		}
	}
	var rowsRestored int64
	tablesProcessed := 0
	for _, tableName := range restorableTables {
		rawRows := strings.TrimSpace(string(tables[tableName]))
		if rawRows == "" || rawRows == "null" {
			rawRows = "[]"
		}
		quotedTable := quoteIdentifier(tableName)
		if scope == backupScopeTenant {
			deleteQuery := fmt.Sprintf(`DELETE FROM %s WHERE tenant_id=$1`, quotedTable)
			if _, err := tx.ExecContext(ctx, deleteQuery, targetTenantID); err != nil {
				return 0, 0, skipped, excluded, err
			}
		}
		if rawRows != "[]" {
			insertQuery := fmt.Sprintf(`INSERT INTO %s SELECT * FROM json_populate_recordset(NULL::%s, $1::json)`, quotedTable, quotedTable)
			result, err := tx.ExecContext(ctx, insertQuery, rawRows)
			if err != nil {
				return 0, 0, skipped, excluded, err
			}
			if result != nil {
				if count, err := result.RowsAffected(); err == nil && count > 0 {
					rowsRestored += count
				}
			}
		}
		tablesProcessed++
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, skipped, excluded, err
	}
	rollback = false
	return rowsRestored, tablesProcessed, skipped, excluded, nil
}

func (s *SQLStore) tableExists(ctx context.Context, tableName string) (bool, error) {
	var exists bool
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
      AND c.relname = $1
)
`, strings.TrimSpace(tableName)).Scan(&exists)
	return exists, err
}

func (s *SQLStore) listBackupTables(ctx context.Context) ([]string, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT table_name
FROM information_schema.tables
WHERE table_schema='public' AND table_type='BASE TABLE'
ORDER BY table_name
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]string, 0)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		out = append(out, name)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *SQLStore) tableHasTenantIDColumn(ctx context.Context, tableName string) (bool, error) {
	var count int
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT COUNT(*)::int
FROM information_schema.columns
WHERE table_schema='public'
  AND table_name=$1
  AND column_name='tenant_id'
`, tableName).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *SQLStore) dumpTableRows(ctx context.Context, tableName string, scope string, targetTenantID string, hasTenantID bool) (json.RawMessage, int64, error) {
	quotedTable := quoteIdentifier(tableName)
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM %s`, quotedTable)
	rowsQuery := fmt.Sprintf(`SELECT COALESCE(json_agg(row_to_json(t)),'[]'::json)::text FROM (SELECT * FROM %s) AS t`, quotedTable)
	var countArgs []interface{}
	var rowsArgs []interface{}
	if scope == backupScopeTenant && hasTenantID {
		countQuery = fmt.Sprintf(`SELECT COUNT(*) FROM %s WHERE tenant_id=$1`, quotedTable)
		rowsQuery = fmt.Sprintf(`SELECT COALESCE(json_agg(row_to_json(t)),'[]'::json)::text FROM (SELECT * FROM %s WHERE tenant_id=$1) AS t`, quotedTable)
		countArgs = append(countArgs, targetTenantID)
		rowsArgs = append(rowsArgs, targetTenantID)
	}
	var rowCount int64
	if err := s.db.SQL().QueryRowContext(ctx, countQuery, countArgs...).Scan(&rowCount); err != nil {
		return nil, 0, err
	}
	if rowCount <= 0 {
		return json.RawMessage("[]"), 0, nil
	}
	var raw string
	if err := s.db.SQL().QueryRowContext(ctx, rowsQuery, rowsArgs...).Scan(&raw); err != nil {
		return nil, 0, err
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "null" {
		trimmed = "[]"
	}
	return json.RawMessage(trimmed), rowCount, nil
}

func (s *SQLStore) loadHSMBinding(ctx context.Context, tenantID string) backupHSMBinding {
	if strings.TrimSpace(tenantID) == "" {
		return backupHSMBinding{}
	}
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT COALESCE(provider_name,''), COALESCE(library_path,''), COALESCE(slot_id,''), COALESCE(partition_label,''), COALESCE(token_label,''), enabled
FROM auth_hsm_provider_configs
WHERE tenant_id=$1
`, tenantID)
	var provider string
	var libraryPath string
	var slotID string
	var partitionLabel string
	var tokenLabel string
	var enabled bool
	if err := row.Scan(&provider, &libraryPath, &slotID, &partitionLabel, &tokenLabel, &enabled); err != nil {
		return backupHSMBinding{}
	}
	if !enabled {
		return backupHSMBinding{}
	}
	fingerprint := strings.Join([]string{
		strings.TrimSpace(strings.ToLower(provider)),
		strings.TrimSpace(strings.ToLower(slotID)),
		strings.TrimSpace(strings.ToLower(partitionLabel)),
		strings.TrimSpace(strings.ToLower(tokenLabel)),
		sha256Hex(strings.TrimSpace(strings.ToLower(libraryPath))),
	}, "|")
	return backupHSMBinding{
		Enabled:         true,
		ProviderName:    strings.TrimSpace(provider),
		LibraryPath:     strings.TrimSpace(libraryPath),
		SlotID:          strings.TrimSpace(slotID),
		PartitionLabel:  strings.TrimSpace(partitionLabel),
		TokenLabel:      strings.TrimSpace(tokenLabel),
		Fingerprint:     fingerprint,
		FingerprintHash: sha256Hex(fingerprint),
	}
}

func isExcludedFromBackupTable(tableName string) bool {
	name := strings.TrimSpace(strings.ToLower(tableName))
	if name == "" {
		return true
	}
	if name == "governance_backup_jobs" {
		return true
	}
	if strings.Contains(name, "audit") {
		return true
	}
	if strings.Contains(name, "alert") {
		return true
	}
	if strings.Contains(name, "_log") || strings.HasSuffix(name, "log") || strings.Contains(name, "logs") {
		return true
	}
	return false
}

func buildBackupCoverageSummary(tables []string) backupCoverageSummary {
	seenTables := map[string]struct{}{}
	capabilities := map[string]struct{}{}
	includedTables := make([]string, 0, len(tables))
	addCapability := func(value string) {
		value = strings.TrimSpace(value)
		if value != "" {
			capabilities[value] = struct{}{}
		}
	}
	for _, table := range tables {
		table = strings.ToLower(strings.TrimSpace(table))
		if table == "" {
			continue
		}
		if _, exists := seenTables[table]; exists {
			continue
		}
		seenTables[table] = struct{}{}
		includedTables = append(includedTables, table)
		switch {
		case strings.HasPrefix(table, "posture_"):
			addCapability("security_posture_management")
		case strings.HasPrefix(table, "compliance_"):
			addCapability("compliance_assessments")
		case strings.HasPrefix(table, "payment_"):
			addCapability("payment_cryptography_and_ap2_policy")
		case strings.HasPrefix(table, "reporting_"):
			addCapability("reporting_jobs_and_incidents")
		case strings.HasPrefix(table, "governance_"):
			addCapability("governance_and_approvals")
		case strings.HasPrefix(table, "cert") || strings.Contains(table, "_cert"):
			addCapability("certificate_pki")
		case strings.HasPrefix(table, "key") || strings.Contains(table, "_key"):
			addCapability("key_management")
		case strings.HasPrefix(table, "policy_") || table == "policies" || table == "policy_versions" || table == "policy_evaluations":
			addCapability("policy_controls")
		}
	}
	capabilityList := make([]string, 0, len(capabilities))
	for capability := range capabilities {
		capabilityList = append(capabilityList, capability)
	}
	sort.Strings(capabilityList)
	sort.Strings(includedTables)
	notes := []string{}
	if containsString(capabilityList, "security_posture_management") || containsString(capabilityList, "compliance_assessments") || containsString(capabilityList, "reporting_jobs_and_incidents") {
		notes = append(notes, "Posture findings, compliance assessments, report jobs, incidents, and evidence-pack inputs are preserved when their service tables are present.")
	}
	notes = append(notes, "Audit event partitions, alert runtime tables, and operational log tables remain excluded from encrypted backup payloads.")
	return backupCoverageSummary{
		IncludedCapabilities: capabilityList,
		IncludedTables:       includedTables,
		ExcludedCategories: []string{
			"audit_event_partitions",
			"alert_runtime_tables",
			"operational_log_tables",
			"backup_job_catalog",
		},
		Notes: notes,
	}
}

func backupCoverageFromJob(job BackupJob) backupCoverageSummary {
	var summary backupCoverageSummary
	if len(job.KeyPackageRaw) > 0 {
		var parsed map[string]interface{}
		if err := json.Unmarshal(job.KeyPackageRaw, &parsed); err == nil {
			if raw, ok := parsed["backup_coverage"]; ok {
				summary = parseBackupCoverageSummary(raw)
			}
		}
	}
	if len(summary.IncludedCapabilities) == 0 && len(summary.IncludedTables) == 0 && len(job.KeyPackage) > 0 {
		if raw, ok := job.KeyPackage["backup_coverage"]; ok {
			summary = parseBackupCoverageSummary(raw)
		}
	}
	return summary
}

func parseBackupCoverageSummary(raw interface{}) backupCoverageSummary {
	coverageMap, ok := raw.(map[string]interface{})
	if !ok {
		return backupCoverageSummary{}
	}
	return backupCoverageSummary{
		IncludedCapabilities: interfaceStrings(coverageMap["included_capabilities"]),
		IncludedTables:       interfaceStrings(coverageMap["included_tables"]),
		ExcludedCategories:   interfaceStrings(coverageMap["excluded_categories"]),
		Notes:                interfaceStrings(coverageMap["notes"]),
	}
}

func interfaceStrings(raw interface{}) []string {
	items, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if value := strings.TrimSpace(fmt.Sprintf("%v", item)); value != "" {
			out = append(out, value)
		}
	}
	return out
}

func containsString(items []string, expected string) bool {
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item), strings.TrimSpace(expected)) {
			return true
		}
	}
	return false
}

func quoteIdentifier(name string) string {
	return `"` + strings.ReplaceAll(strings.TrimSpace(name), `"`, `""`) + `"`
}

func randomBytes(size int) ([]byte, error) {
	if size <= 0 {
		return nil, errors.New("size must be > 0")
	}
	out := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, out); err != nil {
		return nil, err
	}
	return out, nil
}

func encryptAESGCM(plaintext []byte, key []byte, aad []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce, err := randomBytes(gcm.NonceSize())
	if err != nil {
		return nil, nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	return ciphertext, nonce, nil
}

func decryptAESGCM(ciphertext []byte, key []byte, nonce []byte, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("invalid nonce size")
	}
	return gcm.Open(nil, nonce, ciphertext, aad)
}

func decodeBase64Payload(raw string) ([]byte, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, errors.New("payload is empty")
	}
	return base64.StdEncoding.DecodeString(trimmed)
}

func hasApprovedBackupArtifactName(fileName string) bool {
	trimmed := strings.TrimSpace(strings.ToLower(fileName))
	return strings.HasSuffix(trimmed, backupArtifactExtension)
}

func hasApprovedBackupKeyName(fileName string) bool {
	trimmed := strings.TrimSpace(strings.ToLower(fileName))
	return strings.HasSuffix(trimmed, backupKeyExtension)
}

func parseBackupLimit(raw string, fallback int) int {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fallback
	}
	n, err := strconv.Atoi(trimmed)
	if err != nil {
		return fallback
	}
	if n <= 0 {
		return fallback
	}
	if n > 200 {
		return 200
	}
	return n
}
