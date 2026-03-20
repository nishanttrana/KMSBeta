package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

var (
	errStoreNotFound = errors.New("not found")
	errOpsLimit      = errors.New("operation limit reached")
)

type Store interface {
	CreateKeyWithVersion(ctx context.Context, key Key, ver KeyVersion) error
	ListKeys(ctx context.Context, tenantID string, limit int, offset int) ([]Key, error)
	ListKeysCursor(ctx context.Context, tenantID string, limit int, afterCreatedAt *time.Time, afterID string) ([]Key, error)
	GetKey(ctx context.Context, tenantID string, keyID string) (Key, error)
	UpdateKeyMetadata(ctx context.Context, tenantID string, keyID string, req UpdateKeyRequest) error
	UpdateIVMode(ctx context.Context, tenantID string, keyID string, ivMode string) error
	SetKeyStatus(ctx context.Context, tenantID string, keyID string, status string) error
	SetKeyActivation(ctx context.Context, tenantID string, keyID string, status string, activationAt *time.Time) error
	ActivateDueKeys(ctx context.Context, tenantID string, now time.Time) ([]string, error)
	ScheduleDestroy(ctx context.Context, tenantID string, keyID string, destroyAt time.Time) error
	MarkKeyDestroyed(ctx context.Context, tenantID string, keyID string, destroyedAt time.Time) (KeyDeletionRecord, error)
	HardDeleteKey(ctx context.Context, tenantID string, keyID string) error
	PurgeDueDestroyed(ctx context.Context, tenantID string, now time.Time) ([]KeyDeletionRecord, error)
	SetUsageLimit(ctx context.Context, tenantID string, keyID string, limit int64, window string) error
	SetExportAllowed(ctx context.Context, tenantID string, keyID string, allowed bool) error
	ResetUsage(ctx context.Context, tenantID string, keyID string) error
	SetApproval(ctx context.Context, tenantID string, keyID string, required bool, policyID string) error
	GetApproval(ctx context.Context, tenantID string, keyID string) (ApprovalConfig, error)
	GetUsage(ctx context.Context, tenantID string, keyID string) (Usage, error)
	EnsureDefaultTags(ctx context.Context, tenantID string) error
	ListTagCatalog(ctx context.Context, tenantID string) ([]TagDefinition, error)
	UpsertTag(ctx context.Context, tag TagDefinition) (TagDefinition, error)
	DeleteTag(ctx context.Context, tenantID string, name string) error
	ListAccessGroups(ctx context.Context, tenantID string) ([]AccessGroup, error)
	CreateAccessGroup(ctx context.Context, group AccessGroup) (AccessGroup, error)
	DeleteAccessGroup(ctx context.Context, tenantID string, groupID string) error
	ReplaceAccessGroupMembers(ctx context.Context, tenantID string, groupID string, userIDs []string) error
	ListAccessGroupIDsForUser(ctx context.Context, tenantID string, userID string) ([]string, error)
	ListKeyAccessGrants(ctx context.Context, tenantID string, keyID string) ([]KeyAccessGrant, error)
	ReplaceKeyAccessGrants(ctx context.Context, tenantID string, keyID string, grants []KeyAccessGrant, createdBy string) error
	GetKeyAccessSettings(ctx context.Context, tenantID string) (KeyAccessSettings, error)
	UpsertKeyAccessSettings(ctx context.Context, settings KeyAccessSettings) (KeyAccessSettings, error)
	ListKeyInterfaceSubjectPolicies(ctx context.Context, tenantID string, interfaceName string) ([]KeyInterfaceSubjectPolicy, error)
	UpsertKeyInterfaceSubjectPolicy(ctx context.Context, policy KeyInterfaceSubjectPolicy) (KeyInterfaceSubjectPolicy, error)
	DeleteKeyInterfaceSubjectPolicy(ctx context.Context, tenantID string, id string) error
	GetKeyInterfaceTLSConfig(ctx context.Context, tenantID string) (KeyInterfaceTLSConfig, error)
	UpsertKeyInterfaceTLSConfig(ctx context.Context, cfg KeyInterfaceTLSConfig) (KeyInterfaceTLSConfig, error)
	ListKeyInterfacePorts(ctx context.Context, tenantID string) ([]KeyInterfacePort, error)
	UpsertKeyInterfacePort(ctx context.Context, port KeyInterfacePort) (KeyInterfacePort, error)
	DeleteKeyInterfacePort(ctx context.Context, tenantID string, interfaceName string) error
	ReserveRequestNonce(ctx context.Context, tenantID string, nonce string, expiresAt time.Time) error
	GetRESTClientSecurityBinding(ctx context.Context, tenantID string, clientID string) (RESTClientSecurityBinding, error)
	RecordRESTClientSecurityObservation(ctx context.Context, tenantID string, clientID string, observation RESTClientSecurityObservation) error

	ListVersions(ctx context.Context, tenantID string, keyID string) ([]KeyVersion, error)
	GetVersion(ctx context.Context, tenantID string, keyID string, version int) (KeyVersion, error)
	RotateVersion(ctx context.Context, tenantID string, keyID string, newVer KeyVersion, reason string, oldVersionAction string) error
	UpdateVersionStatus(ctx context.Context, tenantID string, keyID string, version int, status string) error
	DeleteVersion(ctx context.Context, tenantID string, keyID string, version int) error

	GetIVLog(ctx context.Context, tenantID string, keyID string, limit int) ([]IVLogRecord, error)
	GetIVByReference(ctx context.Context, tenantID string, keyID string, reference string) (IVLogRecord, error)

	RunCryptoTx(ctx context.Context, tenantID string, keyID string, op string, fn func(k Key, kv KeyVersion) (CryptoTxResult, error)) (CryptoTxResult, error)
}

type SQLStore struct {
	db *pkgdb.DB
}

func NewSQLStore(db *pkgdb.DB) *SQLStore {
	return &SQLStore{db: db}
}

type Key struct {
	ID               string     `json:"id"`
	TenantID         string     `json:"tenant_id"`
	Name             string     `json:"name"`
	Algorithm        string     `json:"algorithm"`
	KeyType          string     `json:"key_type"`
	Purpose          string     `json:"purpose"`
	Status           string     `json:"status"`
	ActivationDate   *time.Time `json:"activation_date,omitempty"`
	ExpiryDate       *time.Time `json:"expiry_date,omitempty"`
	DestroyDate      *time.Time `json:"destroy_date,omitempty"`
	CurrentVersion   int        `json:"current_version"`
	KCV              []byte     `json:"-"`
	KCVAlgorithm     string     `json:"kcv_algorithm"`
	IVMode           string     `json:"iv_mode"`
	Owner            string     `json:"owner"`
	Cloud            string     `json:"cloud"`
	Region           string     `json:"region"`
	Compliance       []string   `json:"compliance"`
	Tags             []string   `json:"tags"`
	Labels           KeyLabels  `json:"labels"`
	ExportAllowed    bool       `json:"export_allowed"`
	OpsTotal         int64      `json:"ops_total"`
	OpsEncrypt       int64      `json:"ops_encrypt"`
	OpsDecrypt       int64      `json:"ops_decrypt"`
	OpsSign          int64      `json:"ops_sign"`
	OpsLimit         int64      `json:"ops_limit"`
	OpsLimitWindow   string     `json:"ops_limit_window"`
	OpsLastReset     time.Time  `json:"ops_last_reset"`
	ApprovalRequired bool       `json:"approval_required"`
	ApprovalPolicyID string     `json:"approval_policy_id"`
	CreatedBy        string     `json:"created_by"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

type KeyDeletionRecord struct {
	KeyID               string     `json:"key_id"`
	KeyName             string     `json:"key_name"`
	Algorithm           string     `json:"algorithm"`
	KeyType             string     `json:"key_type"`
	Purpose             string     `json:"purpose"`
	Owner               string     `json:"owner"`
	Cloud               string     `json:"cloud"`
	Region              string     `json:"region"`
	StatusBefore        string     `json:"status_before"`
	CurrentVersion      int        `json:"current_version"`
	ExportAllowed       bool       `json:"export_allowed"`
	ApprovalRequired    bool       `json:"approval_required"`
	ApprovalPolicyID    string     `json:"approval_policy_id"`
	Tags                []string   `json:"tags"`
	Compliance          []string   `json:"compliance"`
	Labels              KeyLabels  `json:"labels"`
	ScheduledDestroyAt  *time.Time `json:"scheduled_destroy_at,omitempty"`
	DeletedVersionCount int64      `json:"deleted_version_count"`
	DeletedIVLogCount   int64      `json:"deleted_iv_log_count"`
	DeletedAccessGrants int64      `json:"deleted_access_grants"`
}

type KeyLabels map[string]string

type TagDefinition struct {
	TenantID   string    `json:"tenant_id"`
	Name       string    `json:"name"`
	Color      string    `json:"color"`
	IsSystem   bool      `json:"is_system"`
	UsageCount int64     `json:"usage_count,omitempty"`
	CreatedBy  string    `json:"created_by,omitempty"`
	CreatedAt  time.Time `json:"created_at,omitempty"`
	UpdatedAt  time.Time `json:"updated_at,omitempty"`
}

type KeyVersion struct {
	ID                string    `json:"id"`
	TenantID          string    `json:"tenant_id"`
	KeyID             string    `json:"key_id"`
	Version           int       `json:"version"`
	EncryptedMaterial []byte    `json:"-"`
	MaterialIV        []byte    `json:"-"`
	WrappedDEK        []byte    `json:"-"`
	PublicKey         []byte    `json:"public_key,omitempty"`
	KCV               []byte    `json:"-"`
	RotatedFrom       int       `json:"rotated_from,omitempty"`
	RotationReason    string    `json:"rotation_reason,omitempty"`
	Status            string    `json:"status"`
	CreatedAt         time.Time `json:"created_at"`
}

type IVLogRecord struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	KeyID      string    `json:"key_id"`
	KeyVersion int       `json:"key_version"`
	IV         []byte    `json:"iv"`
	Operation  string    `json:"operation"`
	Reference  string    `json:"reference_id"`
	CreatedAt  time.Time `json:"created_at"`
}

type Usage struct {
	OpsTotal   int64  `json:"ops_total"`
	OpsEncrypt int64  `json:"ops_encrypt"`
	OpsDecrypt int64  `json:"ops_decrypt"`
	OpsSign    int64  `json:"ops_sign"`
	OpsLimit   int64  `json:"ops_limit"`
	Window     string `json:"ops_limit_window"`
}

type ApprovalConfig struct {
	Required bool   `json:"required"`
	PolicyID string `json:"policy_id"`
}

type CryptoTxResult struct {
	Payload     []byte
	IV          []byte
	KeyVersion  int
	ReferenceID string
	StoreIV     bool
}

func (s *SQLStore) CreateKeyWithVersion(ctx context.Context, key Key, ver KeyVersion) error {
	return s.withTenantTx(ctx, key.TenantID, func(tx *sql.Tx) error {
		labels, _ := json.Marshal(key.Labels)
		compliance, _ := json.Marshal(key.Compliance)
		tags, _ := json.Marshal(key.Tags)
		_, err := tx.ExecContext(ctx, `
INSERT INTO keys (
    id, tenant_id, name, algorithm, key_type, purpose, status, current_version, kcv, kcv_algorithm,
    iv_mode, owner, cloud, region, compliance, labels, tags, export_allowed, activation_date, expiry_date, ops_total, ops_encrypt, ops_decrypt, ops_sign,
    ops_limit, ops_limit_window, ops_last_reset, approval_required, approval_policy_id, created_by, created_at, updated_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,0,0,0,0,$21,$22,CURRENT_TIMESTAMP,$23,$24,$25,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
`, key.ID, key.TenantID, key.Name, key.Algorithm, key.KeyType, key.Purpose, key.Status, key.CurrentVersion, key.KCV, key.KCVAlgorithm,
			key.IVMode, key.Owner, key.Cloud, key.Region, compliance, labels, tags, key.ExportAllowed, nullableTime(key.ActivationDate), nullableTime(key.ExpiryDate), key.OpsLimit, key.OpsLimitWindow, key.ApprovalRequired, nullable(key.ApprovalPolicyID), key.CreatedBy)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `
INSERT INTO key_versions (
    id, tenant_id, key_id, version, encrypted_material, material_iv, wrapped_dek, public_key, kcv,
    rotated_from, rotation_reason, status, created_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,CURRENT_TIMESTAMP)
`, ver.ID, ver.TenantID, ver.KeyID, ver.Version, ver.EncryptedMaterial, ver.MaterialIV, ver.WrappedDEK, nullableBytes(ver.PublicKey), ver.KCV, nullableInt(ver.RotatedFrom), nullable(ver.RotationReason), ver.Status)
		return err
	})
}

func (s *SQLStore) ListKeys(ctx context.Context, tenantID string, limit int, offset int) ([]Key, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.ROSQL().QueryContext(ctx, `
SELECT id, tenant_id, name, algorithm, key_type, purpose, status, destroy_date, current_version, kcv, kcv_algorithm, iv_mode,
       owner, cloud, region, compliance, labels, tags, export_allowed, activation_date, expiry_date, ops_total, ops_encrypt, ops_decrypt, ops_sign,
       ops_limit, COALESCE(ops_limit_window, ''), ops_last_reset, approval_required,
       COALESCE(approval_policy_id,''), created_by, created_at, updated_at
FROM keys WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2 OFFSET $3
`, tenantID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []Key
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *SQLStore) ListKeysCursor(ctx context.Context, tenantID string, limit int, afterCreatedAt *time.Time, afterID string) ([]Key, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	var rows *sql.Rows
	var err error
	if afterCreatedAt != nil && afterID != "" {
		rows, err = s.db.ROSQL().QueryContext(ctx, `
SELECT id, tenant_id, name, algorithm, key_type, purpose, status, destroy_date, current_version, kcv, kcv_algorithm, iv_mode,
       owner, cloud, region, compliance, labels, tags, export_allowed, activation_date, expiry_date, ops_total, ops_encrypt, ops_decrypt, ops_sign,
       ops_limit, COALESCE(ops_limit_window, ''), ops_last_reset, approval_required,
       COALESCE(approval_policy_id,''), created_by, created_at, updated_at
FROM keys WHERE tenant_id=$1 AND (created_at, id) < ($2, $3)
ORDER BY created_at DESC, id DESC LIMIT $4
`, tenantID, afterCreatedAt.UTC(), afterID, limit)
	} else {
		rows, err = s.db.ROSQL().QueryContext(ctx, `
SELECT id, tenant_id, name, algorithm, key_type, purpose, status, destroy_date, current_version, kcv, kcv_algorithm, iv_mode,
       owner, cloud, region, compliance, labels, tags, export_allowed, activation_date, expiry_date, ops_total, ops_encrypt, ops_decrypt, ops_sign,
       ops_limit, COALESCE(ops_limit_window, ''), ops_last_reset, approval_required,
       COALESCE(approval_policy_id,''), created_by, created_at, updated_at
FROM keys WHERE tenant_id=$1
ORDER BY created_at DESC, id DESC LIMIT $2
`, tenantID, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []Key
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetKey(ctx context.Context, tenantID string, keyID string) (Key, error) {
	row := s.db.ROSQL().QueryRowContext(ctx, `
SELECT id, tenant_id, name, algorithm, key_type, purpose, status, destroy_date, current_version, kcv, kcv_algorithm, iv_mode,
       owner, cloud, region, compliance, labels, tags, export_allowed, activation_date, expiry_date, ops_total, ops_encrypt, ops_decrypt, ops_sign,
       ops_limit, COALESCE(ops_limit_window, ''), ops_last_reset, approval_required,
       COALESCE(approval_policy_id,''), created_by, created_at, updated_at
FROM keys WHERE tenant_id=$1 AND id=$2
`, tenantID, keyID)
	k, err := scanKey(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Key{}, errStoreNotFound
	}
	return k, err
}

func (s *SQLStore) UpdateKeyMetadata(ctx context.Context, tenantID string, keyID string, req UpdateKeyRequest) error {
	labels, _ := json.Marshal(req.Labels)
	compliance, _ := json.Marshal(req.Compliance)
	tags, _ := json.Marshal(req.Tags)
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE keys
SET name=$1, purpose=$2, owner=$3, cloud=$4, region=$5, labels=$6, compliance=$7, tags=$8, iv_mode=$9, updated_at=CURRENT_TIMESTAMP
WHERE tenant_id=$10 AND id=$11
`, req.Name, req.Purpose, req.Owner, req.Cloud, req.Region, labels, compliance, tags, req.IVMode, tenantID, keyID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errStoreNotFound
	}
	return nil
}

func (s *SQLStore) UpdateIVMode(ctx context.Context, tenantID string, keyID string, ivMode string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE keys SET iv_mode=$1, updated_at=CURRENT_TIMESTAMP WHERE tenant_id=$2 AND id=$3
`, ivMode, tenantID, keyID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errStoreNotFound
	}
	return nil
}

func (s *SQLStore) SetKeyStatus(ctx context.Context, tenantID string, keyID string, status string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE keys
SET status=$1,
    destroy_date=NULL,
    activation_date=CASE WHEN $1='active' THEN NULL ELSE activation_date END,
    updated_at=CURRENT_TIMESTAMP
WHERE tenant_id=$2 AND id=$3
`, status, tenantID, keyID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errStoreNotFound
	}
	return nil
}

func (s *SQLStore) SetKeyActivation(ctx context.Context, tenantID string, keyID string, status string, activationAt *time.Time) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE keys
SET status=$1,
    activation_date=$2,
    destroy_date=NULL,
    updated_at=CURRENT_TIMESTAMP
WHERE tenant_id=$3 AND id=$4
`, status, nullableTime(activationAt), tenantID, keyID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errStoreNotFound
	}
	return nil
}

func (s *SQLStore) ActivateDueKeys(ctx context.Context, tenantID string, now time.Time) ([]string, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id
FROM keys
WHERE tenant_id=$1
  AND status='pre-active'
  AND activation_date IS NOT NULL
  AND activation_date <= $2
`, tenantID, now.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var activated []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		activated = append(activated, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, id := range activated {
		if _, err := s.db.SQL().ExecContext(ctx, `
UPDATE keys
SET status='active', activation_date=NULL, updated_at=CURRENT_TIMESTAMP
WHERE tenant_id=$1 AND id=$2
`, tenantID, id); err != nil {
			return nil, err
		}
	}
	return activated, nil
}

func (s *SQLStore) ScheduleDestroy(ctx context.Context, tenantID string, keyID string, destroyAt time.Time) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE keys
SET status='destroy-pending', destroy_date=$1, updated_at=CURRENT_TIMESTAMP
WHERE tenant_id=$2 AND id=$3
`, destroyAt.UTC(), tenantID, keyID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errStoreNotFound
	}
	return nil
}

func (s *SQLStore) MarkKeyDestroyed(ctx context.Context, tenantID string, keyID string, destroyedAt time.Time) (KeyDeletionRecord, error) {
	var record KeyDeletionRecord
	err := s.withTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		var txErr error
		record, txErr = s.markDestroyedTx(ctx, tx, tenantID, keyID, destroyedAt)
		return txErr
	})
	if err != nil {
		return KeyDeletionRecord{}, err
	}
	return record, nil
}

func (s *SQLStore) HardDeleteKey(ctx context.Context, tenantID string, keyID string) error {
	return s.withTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		return s.deleteKeyTx(ctx, tx, tenantID, keyID)
	})
}

func (s *SQLStore) PurgeDueDestroyed(ctx context.Context, tenantID string, now time.Time) ([]KeyDeletionRecord, error) {
	var converted []KeyDeletionRecord
	err := s.withTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
SELECT id
FROM keys
WHERE tenant_id=$1
  AND status='destroy-pending'
  AND destroy_date IS NOT NULL
  AND destroy_date <= $2
`, tenantID, now.UTC())
		if err != nil {
			return err
		}
		defer rows.Close() //nolint:errcheck

		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		if err := rows.Err(); err != nil {
			return err
		}

		for _, keyID := range ids {
			record, err := s.markDestroyedTx(ctx, tx, tenantID, keyID, now.UTC())
			if err != nil {
				return err
			}
			converted = append(converted, record)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return converted, nil
}

func (s *SQLStore) SetUsageLimit(ctx context.Context, tenantID string, keyID string, limit int64, window string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE keys
SET ops_limit=$1, ops_limit_window=$2, updated_at=CURRENT_TIMESTAMP
WHERE tenant_id=$3 AND id=$4
`, limit, window, tenantID, keyID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errStoreNotFound
	}
	return nil
}

func (s *SQLStore) SetExportAllowed(ctx context.Context, tenantID string, keyID string, allowed bool) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE keys
SET export_allowed=$1, updated_at=CURRENT_TIMESTAMP
WHERE tenant_id=$2 AND id=$3
`, allowed, tenantID, keyID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errStoreNotFound
	}
	return nil
}

var defaultTagDefinitions = []TagDefinition{
	{Name: "environment-production", Color: "#14B8A6", IsSystem: true},
	{Name: "team-platform", Color: "#F59E0B", IsSystem: true},
	{Name: "compliance-pci-dss", Color: "#8B5CF6", IsSystem: true},
	{Name: "compliance-hipaa", Color: "#22C55E", IsSystem: true},
	{Name: "tier-critical", Color: "#EF4444", IsSystem: true},
	{Name: "region-us-east", Color: "#3B82F6", IsSystem: true},
}

func (s *SQLStore) EnsureDefaultTags(ctx context.Context, tenantID string) error {
	for _, preset := range defaultTagDefinitions {
		_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO key_tags (tenant_id, name, color, is_system, created_by, created_at, updated_at)
VALUES ($1,$2,$3,$4,'system',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
ON CONFLICT (tenant_id, name)
DO UPDATE SET
  color=EXCLUDED.color,
  is_system=EXCLUDED.is_system,
  updated_at=CURRENT_TIMESTAMP
`, tenantID, preset.Name, preset.Color, true)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLStore) ListTagCatalog(ctx context.Context, tenantID string) ([]TagDefinition, error) {
	rows, err := s.db.ROSQL().QueryContext(ctx, `
SELECT tenant_id, name, color, is_system, COALESCE(created_by,''), created_at, updated_at
FROM key_tags
WHERE tenant_id=$1
ORDER BY is_system DESC, name ASC
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []TagDefinition
	for rows.Next() {
		var item TagDefinition
		if err := rows.Scan(&item.TenantID, &item.Name, &item.Color, &item.IsSystem, &item.CreatedBy, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpsertTag(ctx context.Context, tag TagDefinition) (TagDefinition, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO key_tags (tenant_id, name, color, is_system, created_by, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
ON CONFLICT (tenant_id, name)
DO UPDATE SET
  color=EXCLUDED.color,
  is_system=CASE WHEN key_tags.is_system THEN TRUE ELSE EXCLUDED.is_system END,
  updated_at=CURRENT_TIMESTAMP
RETURNING tenant_id, name, color, is_system, COALESCE(created_by,''), created_at, updated_at
`, tag.TenantID, tag.Name, tag.Color, tag.IsSystem, nullable(tag.CreatedBy))
	var out TagDefinition
	if err := row.Scan(&out.TenantID, &out.Name, &out.Color, &out.IsSystem, &out.CreatedBy, &out.CreatedAt, &out.UpdatedAt); err != nil {
		return TagDefinition{}, err
	}
	return out, nil
}

func (s *SQLStore) DeleteTag(ctx context.Context, tenantID string, name string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM key_tags
WHERE tenant_id=$1 AND name=$2 AND is_system=FALSE
`, tenantID, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errStoreNotFound
	}
	return nil
}

func (s *SQLStore) ResetUsage(ctx context.Context, tenantID string, keyID string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE keys
SET ops_total=0, ops_encrypt=0, ops_decrypt=0, ops_sign=0, ops_last_reset=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP
WHERE tenant_id=$1 AND id=$2
`, tenantID, keyID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errStoreNotFound
	}
	return nil
}

func (s *SQLStore) SetApproval(ctx context.Context, tenantID string, keyID string, required bool, policyID string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE keys SET approval_required=$1, approval_policy_id=$2, updated_at=CURRENT_TIMESTAMP
WHERE tenant_id=$3 AND id=$4
`, required, nullable(policyID), tenantID, keyID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errStoreNotFound
	}
	return nil
}

func (s *SQLStore) GetApproval(ctx context.Context, tenantID string, keyID string) (ApprovalConfig, error) {
	var cfg ApprovalConfig
	err := s.db.ROSQL().QueryRowContext(ctx, `
SELECT approval_required, COALESCE(approval_policy_id,'') FROM keys WHERE tenant_id=$1 AND id=$2
`, tenantID, keyID).Scan(&cfg.Required, &cfg.PolicyID)
	if errors.Is(err, sql.ErrNoRows) {
		return ApprovalConfig{}, errStoreNotFound
	}
	return cfg, err
}

func (s *SQLStore) GetUsage(ctx context.Context, tenantID string, keyID string) (Usage, error) {
	var u Usage
	err := s.db.ROSQL().QueryRowContext(ctx, `
SELECT ops_total, ops_encrypt, ops_decrypt, ops_sign, ops_limit, COALESCE(ops_limit_window,'')
FROM keys WHERE tenant_id=$1 AND id=$2
`, tenantID, keyID).Scan(&u.OpsTotal, &u.OpsEncrypt, &u.OpsDecrypt, &u.OpsSign, &u.OpsLimit, &u.Window)
	if errors.Is(err, sql.ErrNoRows) {
		return Usage{}, errStoreNotFound
	}
	return u, err
}

func (s *SQLStore) ListVersions(ctx context.Context, tenantID string, keyID string) ([]KeyVersion, error) {
	rows, err := s.db.ROSQL().QueryContext(ctx, `
SELECT id, tenant_id, key_id, version, encrypted_material, material_iv, wrapped_dek, public_key, kcv,
       COALESCE(rotated_from,0), COALESCE(rotation_reason,''), status, created_at
FROM key_versions
WHERE tenant_id=$1 AND key_id=$2
ORDER BY version DESC
`, tenantID, keyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []KeyVersion
	for rows.Next() {
		var v KeyVersion
		if err := rows.Scan(&v.ID, &v.TenantID, &v.KeyID, &v.Version, &v.EncryptedMaterial, &v.MaterialIV, &v.WrappedDEK, &v.PublicKey, &v.KCV,
			&v.RotatedFrom, &v.RotationReason, &v.Status, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetVersion(ctx context.Context, tenantID string, keyID string, version int) (KeyVersion, error) {
	var v KeyVersion
	err := s.db.ROSQL().QueryRowContext(ctx, `
SELECT id, tenant_id, key_id, version, encrypted_material, material_iv, wrapped_dek, public_key, kcv,
       COALESCE(rotated_from,0), COALESCE(rotation_reason,''), status, created_at
FROM key_versions
WHERE tenant_id=$1 AND key_id=$2 AND version=$3
`, tenantID, keyID, version).Scan(&v.ID, &v.TenantID, &v.KeyID, &v.Version, &v.EncryptedMaterial, &v.MaterialIV, &v.WrappedDEK, &v.PublicKey, &v.KCV,
		&v.RotatedFrom, &v.RotationReason, &v.Status, &v.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return KeyVersion{}, errStoreNotFound
	}
	return v, err
}

func (s *SQLStore) RotateVersion(ctx context.Context, tenantID string, keyID string, newVer KeyVersion, reason string, oldVersionAction string) error {
	return s.withTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		var current int
		if err := tx.QueryRowContext(ctx, `SELECT current_version FROM keys WHERE tenant_id=$1 AND id=$2`, tenantID, keyID).Scan(&current); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return errStoreNotFound
			}
			return err
		}
		switch strings.ToLower(strings.TrimSpace(oldVersionAction)) {
		case "", "deactivate":
			if _, err := tx.ExecContext(ctx, `
UPDATE key_versions
SET status='deactivated'
WHERE tenant_id=$1 AND key_id=$2 AND version=$3
`, tenantID, keyID, current); err != nil {
				return err
			}
		case "keep-active":
			// No-op: leave old version active for overlap period.
		case "destroy":
			if _, err := tx.ExecContext(ctx, `
UPDATE key_versions
SET status='deleted'
WHERE tenant_id=$1 AND key_id=$2 AND version=$3
`, tenantID, keyID, current); err != nil {
				return err
			}
		default:
			return fmt.Errorf("invalid old_version_action: %s", oldVersionAction)
		}
		_, err := tx.ExecContext(ctx, `
INSERT INTO key_versions (
    id, tenant_id, key_id, version, encrypted_material, material_iv, wrapped_dek, public_key, kcv,
    rotated_from, rotation_reason, status, created_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,CURRENT_TIMESTAMP)
`, newVer.ID, tenantID, keyID, current+1, newVer.EncryptedMaterial, newVer.MaterialIV, newVer.WrappedDEK, nullableBytes(newVer.PublicKey), newVer.KCV, current, reason, "active")
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `
UPDATE keys SET current_version=$1, kcv=$2, updated_at=CURRENT_TIMESTAMP WHERE tenant_id=$3 AND id=$4
`, current+1, newVer.KCV, tenantID, keyID)
		return err
	})
}

func (s *SQLStore) UpdateVersionStatus(ctx context.Context, tenantID string, keyID string, version int, status string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE key_versions SET status=$1 WHERE tenant_id=$2 AND key_id=$3 AND version=$4
`, status, tenantID, keyID, version)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errStoreNotFound
	}
	return nil
}

func (s *SQLStore) DeleteVersion(ctx context.Context, tenantID string, keyID string, version int) error {
	res, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM key_versions WHERE tenant_id=$1 AND key_id=$2 AND version=$3
`, tenantID, keyID, version)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errStoreNotFound
	}
	return nil
}

func (s *SQLStore) GetIVLog(ctx context.Context, tenantID string, keyID string, limit int) ([]IVLogRecord, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.ROSQL().QueryContext(ctx, `
SELECT id, tenant_id, key_id, key_version, iv, operation, COALESCE(reference_id,''), created_at
FROM key_iv_log WHERE tenant_id=$1 AND key_id=$2 ORDER BY created_at DESC LIMIT $3
`, tenantID, keyID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []IVLogRecord
	for rows.Next() {
		var rec IVLogRecord
		if err := rows.Scan(&rec.ID, &rec.TenantID, &rec.KeyID, &rec.KeyVersion, &rec.IV, &rec.Operation, &rec.Reference, &rec.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetIVByReference(ctx context.Context, tenantID string, keyID string, reference string) (IVLogRecord, error) {
	var rec IVLogRecord
	err := s.db.ROSQL().QueryRowContext(ctx, `
SELECT id, tenant_id, key_id, key_version, iv, operation, COALESCE(reference_id,''), created_at
FROM key_iv_log WHERE tenant_id=$1 AND key_id=$2 AND reference_id=$3
ORDER BY created_at DESC LIMIT 1
`, tenantID, keyID, reference).Scan(&rec.ID, &rec.TenantID, &rec.KeyID, &rec.KeyVersion, &rec.IV, &rec.Operation, &rec.Reference, &rec.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return IVLogRecord{}, errStoreNotFound
	}
	return rec, err
}

func (s *SQLStore) RunCryptoTx(ctx context.Context, tenantID string, keyID string, op string, fn func(k Key, kv KeyVersion) (CryptoTxResult, error)) (CryptoTxResult, error) {
	tx, err := s.db.SQL().BeginTx(ctx, nil)
	if err != nil {
		return CryptoTxResult{}, err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.ExecContext(ctx, "SELECT set_config('app.tenant_id', $1, true)", tenantID); err != nil {
		// SQLite does not support this; ignore non-postgres errors.
		_ = err
	}

	row := tx.QueryRowContext(ctx, `
SELECT id, tenant_id, name, algorithm, key_type, purpose, status, destroy_date, current_version, kcv, kcv_algorithm, iv_mode,
       owner, cloud, region, compliance, labels, tags, export_allowed, activation_date, expiry_date, ops_total, ops_encrypt, ops_decrypt, ops_sign,
       ops_limit, COALESCE(ops_limit_window, ''), ops_last_reset, approval_required,
       COALESCE(approval_policy_id,''), created_by, created_at, updated_at
FROM keys WHERE tenant_id=$1 AND id=$2
`, tenantID, keyID)
	key, err := scanKey(row)
	if errors.Is(err, sql.ErrNoRows) {
		return CryptoTxResult{}, errStoreNotFound
	}
	if err != nil {
		return CryptoTxResult{}, err
	}
	if err := maybeResetWindow(ctx, tx, key); err != nil {
		return CryptoTxResult{}, err
	}
	if key.OpsLimit > 0 && key.OpsTotal >= key.OpsLimit {
		return CryptoTxResult{}, errOpsLimit
	}
	keyStatus := normalizeLifecycleStatus(key.Status)
	switch keyStatus {
	case "active":
	case "deactivated":
		if op != "decrypt" {
			return CryptoTxResult{}, fmt.Errorf("key status is %s (only decrypt allowed)", keyStatus)
		}
	default:
		return CryptoTxResult{}, fmt.Errorf("key status is %s", keyStatus)
	}

	var ver KeyVersion
	err = tx.QueryRowContext(ctx, `
SELECT id, tenant_id, key_id, version, encrypted_material, material_iv, wrapped_dek, public_key, kcv,
       COALESCE(rotated_from,0), COALESCE(rotation_reason,''), status, created_at
FROM key_versions
WHERE tenant_id=$1 AND key_id=$2 AND version=$3
`, tenantID, keyID, key.CurrentVersion).Scan(&ver.ID, &ver.TenantID, &ver.KeyID, &ver.Version, &ver.EncryptedMaterial, &ver.MaterialIV, &ver.WrappedDEK, &ver.PublicKey, &ver.KCV,
		&ver.RotatedFrom, &ver.RotationReason, &ver.Status, &ver.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return CryptoTxResult{}, errStoreNotFound
	}
	if err != nil {
		return CryptoTxResult{}, err
	}
	if ver.Status != "active" {
		return CryptoTxResult{}, fmt.Errorf("key version status is %s", ver.Status)
	}

	result, err := fn(key, ver)
	if err != nil {
		return CryptoTxResult{}, err
	}
	if err := updateCounters(ctx, tx, tenantID, keyID, op); err != nil {
		return CryptoTxResult{}, err
	}
	if result.StoreIV && len(result.IV) > 0 {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO key_iv_log (id, tenant_id, key_id, key_version, iv, operation, reference_id, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,CURRENT_TIMESTAMP)
`, newID("iv"), tenantID, keyID, ver.Version, result.IV, op, nullable(result.ReferenceID)); err != nil {
			return CryptoTxResult{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return CryptoTxResult{}, err
	}
	result.KeyVersion = ver.Version
	return result, nil
}

func updateCounters(ctx context.Context, tx *sql.Tx, tenantID string, keyID string, op string) error {
	query := `
UPDATE keys
SET ops_total = ops_total + 1,
    ops_encrypt = ops_encrypt + $1,
    ops_decrypt = ops_decrypt + $2,
    ops_sign = ops_sign + $3,
    updated_at = CURRENT_TIMESTAMP
WHERE tenant_id=$4 AND id=$5
`
	incE, incD, incS := 0, 0, 0
	switch op {
	case "encrypt":
		incE = 1
	case "decrypt":
		incD = 1
	case "sign":
		incS = 1
	}
	_, err := tx.ExecContext(ctx, query, incE, incD, incS, tenantID, keyID)
	return err
}

func maybeResetWindow(ctx context.Context, tx *sql.Tx, key Key) error {
	if key.OpsLimitWindow == "" || key.OpsLimitWindow == "total" {
		return nil
	}
	now := time.Now().UTC()
	reset := false
	switch key.OpsLimitWindow {
	case "daily":
		y1, m1, d1 := key.OpsLastReset.UTC().Date()
		y2, m2, d2 := now.Date()
		reset = y1 != y2 || m1 != m2 || d1 != d2
	case "monthly":
		y1, m1, _ := key.OpsLastReset.UTC().Date()
		y2, m2, _ := now.Date()
		reset = y1 != y2 || m1 != m2
	}
	if !reset {
		return nil
	}
	_, err := tx.ExecContext(ctx, `
UPDATE keys
SET ops_total=0, ops_encrypt=0, ops_decrypt=0, ops_sign=0, ops_last_reset=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP
WHERE tenant_id=$1 AND id=$2
`, key.TenantID, key.ID)
	return err
}

func (s *SQLStore) deleteKeyTx(ctx context.Context, tx *sql.Tx, tenantID string, keyID string) error {
	if _, err := tx.ExecContext(ctx, `
DELETE FROM key_access_grants WHERE tenant_id=$1 AND key_id=$2
`, tenantID, keyID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM key_iv_log WHERE tenant_id=$1 AND key_id=$2
`, tenantID, keyID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM key_versions WHERE tenant_id=$1 AND key_id=$2
`, tenantID, keyID); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `
DELETE FROM keys WHERE tenant_id=$1 AND id=$2
`, tenantID, keyID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errStoreNotFound
	}
	return nil
}

func (s *SQLStore) markDestroyedTx(ctx context.Context, tx *sql.Tx, tenantID string, keyID string, destroyedAt time.Time) (KeyDeletionRecord, error) {
	record, err := s.collectKeyDeletionRecordTx(ctx, tx, tenantID, keyID)
	if err != nil {
		return KeyDeletionRecord{}, err
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM key_access_grants WHERE tenant_id=$1 AND key_id=$2
`, tenantID, keyID); err != nil {
		return KeyDeletionRecord{}, err
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM key_iv_log WHERE tenant_id=$1 AND key_id=$2
`, tenantID, keyID); err != nil {
		return KeyDeletionRecord{}, err
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM key_versions WHERE tenant_id=$1 AND key_id=$2
`, tenantID, keyID); err != nil {
		return KeyDeletionRecord{}, err
	}
	res, err := tx.ExecContext(ctx, `
UPDATE keys
SET status='deleted',
    current_version=0,
    kcv=NULL,
    kcv_algorithm='',
    purpose='deleted',
    iv_mode='internal',
    owner='deleted',
    cloud='',
    region='',
    compliance='[]',
    labels='{}',
    tags='[]',
    export_allowed=FALSE,
    activation_date=NULL,
    expiry_date=NULL,
    ops_total=0,
    ops_encrypt=0,
    ops_decrypt=0,
    ops_sign=0,
    ops_limit=0,
    ops_limit_window='',
    ops_last_reset=NULL,
    approval_required=FALSE,
    approval_policy_id=NULL,
    destroy_date=$1,
    updated_at=CURRENT_TIMESTAMP
WHERE tenant_id=$2 AND id=$3
`, destroyedAt.UTC(), tenantID, keyID)
	if err != nil {
		return KeyDeletionRecord{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return KeyDeletionRecord{}, errStoreNotFound
	}
	return record, nil
}

func (s *SQLStore) collectKeyDeletionRecordTx(ctx context.Context, tx *sql.Tx, tenantID string, keyID string) (KeyDeletionRecord, error) {
	row := tx.QueryRowContext(ctx, `
SELECT id, tenant_id, name, algorithm, key_type, purpose, status, destroy_date, current_version, kcv, kcv_algorithm, iv_mode,
       owner, cloud, region, compliance, labels, tags, export_allowed, activation_date, expiry_date, ops_total, ops_encrypt, ops_decrypt, ops_sign,
       ops_limit, COALESCE(ops_limit_window, ''), ops_last_reset, approval_required,
       COALESCE(approval_policy_id,''), created_by, created_at, updated_at
FROM keys WHERE tenant_id=$1 AND id=$2
`, tenantID, keyID)
	key, err := scanKey(row)
	if errors.Is(err, sql.ErrNoRows) {
		return KeyDeletionRecord{}, errStoreNotFound
	}
	if err != nil {
		return KeyDeletionRecord{}, err
	}

	deletedVersions, err := s.countByKeyTx(ctx, tx, `SELECT COUNT(1) FROM key_versions WHERE tenant_id=$1 AND key_id=$2`, tenantID, keyID)
	if err != nil {
		return KeyDeletionRecord{}, err
	}
	deletedIVLogs, err := s.countByKeyTx(ctx, tx, `SELECT COUNT(1) FROM key_iv_log WHERE tenant_id=$1 AND key_id=$2`, tenantID, keyID)
	if err != nil {
		return KeyDeletionRecord{}, err
	}
	deletedGrants, err := s.countByKeyTx(ctx, tx, `SELECT COUNT(1) FROM key_access_grants WHERE tenant_id=$1 AND key_id=$2`, tenantID, keyID)
	if err != nil {
		return KeyDeletionRecord{}, err
	}

	record := KeyDeletionRecord{
		KeyID:               key.ID,
		KeyName:             key.Name,
		Algorithm:           key.Algorithm,
		KeyType:             key.KeyType,
		Purpose:             key.Purpose,
		Owner:               key.Owner,
		Cloud:               key.Cloud,
		Region:              key.Region,
		StatusBefore:        key.Status,
		CurrentVersion:      key.CurrentVersion,
		ExportAllowed:       key.ExportAllowed,
		ApprovalRequired:    key.ApprovalRequired,
		ApprovalPolicyID:    key.ApprovalPolicyID,
		Tags:                append([]string(nil), key.Tags...),
		Compliance:          append([]string(nil), key.Compliance...),
		Labels:              cloneKeyLabels(key.Labels),
		ScheduledDestroyAt:  key.DestroyDate,
		DeletedVersionCount: deletedVersions,
		DeletedIVLogCount:   deletedIVLogs,
		DeletedAccessGrants: deletedGrants,
	}
	return record, nil
}

func (s *SQLStore) countByKeyTx(ctx context.Context, tx *sql.Tx, query string, tenantID string, keyID string) (int64, error) {
	var count int64
	if err := tx.QueryRowContext(ctx, query, tenantID, keyID).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func cloneKeyLabels(in KeyLabels) KeyLabels {
	if len(in) == 0 {
		return KeyLabels{}
	}
	out := make(KeyLabels, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (s *SQLStore) withTenantTx(ctx context.Context, tenantID string, fn func(tx *sql.Tx) error) error {
	tx, err := s.db.SQL().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	_, _ = tx.ExecContext(ctx, "SELECT set_config('app.tenant_id', $1, true)", tenantID)
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func scanKey(scanner interface {
	Scan(dest ...interface{}) error
}) (Key, error) {
	var (
		k          Key
		rawComp    []byte
		rawLabels  []byte
		rawTags    []byte
		rawPolicy  string
		rawWindow  string
		rawAct     sql.NullTime
		rawExpiry  sql.NullTime
		rawDestroy sql.NullTime
		rawOpsTime sql.NullTime
	)
	err := scanner.Scan(
		&k.ID, &k.TenantID, &k.Name, &k.Algorithm, &k.KeyType, &k.Purpose, &k.Status, &rawDestroy, &k.CurrentVersion, &k.KCV, &k.KCVAlgorithm,
		&k.IVMode, &k.Owner, &k.Cloud, &k.Region, &rawComp, &rawLabels, &rawTags, &k.ExportAllowed, &rawAct, &rawExpiry, &k.OpsTotal, &k.OpsEncrypt, &k.OpsDecrypt, &k.OpsSign,
		&k.OpsLimit, &rawWindow, &rawOpsTime, &k.ApprovalRequired, &rawPolicy, &k.CreatedBy, &k.CreatedAt, &k.UpdatedAt,
	)
	if err != nil {
		return Key{}, err
	}
	if rawAct.Valid {
		v := rawAct.Time.UTC()
		k.ActivationDate = &v
	}
	if rawExpiry.Valid {
		v := rawExpiry.Time.UTC()
		k.ExpiryDate = &v
	}
	k.OpsLimitWindow = rawWindow
	if rawDestroy.Valid {
		v := rawDestroy.Time.UTC()
		k.DestroyDate = &v
	} else {
		k.DestroyDate = nil
	}
	if rawOpsTime.Valid {
		k.OpsLastReset = rawOpsTime.Time
	} else {
		k.OpsLastReset = time.Now().UTC()
	}
	k.ApprovalPolicyID = rawPolicy
	if len(rawComp) > 0 {
		_ = json.Unmarshal(rawComp, &k.Compliance)
	}
	if len(rawLabels) > 0 {
		_ = json.Unmarshal(rawLabels, &k.Labels)
	}
	if len(rawTags) > 0 {
		_ = json.Unmarshal(rawTags, &k.Tags)
	}
	if k.Tags == nil {
		k.Tags = []string{}
	}
	if k.Labels == nil {
		k.Labels = KeyLabels{}
	}
	return k, nil
}

func nullable(v string) interface{} {
	if v == "" {
		return nil
	}
	return v
}

func nullableBytes(v []byte) interface{} {
	if len(v) == 0 {
		return nil
	}
	return v
}

func nullableInt(v int) interface{} {
	if v == 0 {
		return nil
	}
	return v
}

func nullableTime(v *time.Time) interface{} {
	if v == nil {
		return nil
	}
	return v.UTC()
}
