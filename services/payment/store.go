package main

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	pkgdb "vecta-kms/pkg/db"
)

var errNotFound = errors.New("not found")

type Store interface {
	CreatePaymentKey(ctx context.Context, key PaymentKey) error
	UpdatePaymentKey(ctx context.Context, key PaymentKey) error
	UpdatePaymentKeyVersion(ctx context.Context, tenantID string, id string, keyVersionNum string) error
	GetPaymentKey(ctx context.Context, tenantID string, id string) (PaymentKey, error)
	ListPaymentKeys(ctx context.Context, tenantID string) ([]PaymentKey, error)

	CreateTR31Translation(ctx context.Context, tr TR31Translation) error
	CreatePINOperationLog(ctx context.Context, item PINOperationLog) error

	GetPaymentPolicy(ctx context.Context, tenantID string) (PaymentPolicy, error)
	UpsertPaymentPolicy(ctx context.Context, item PaymentPolicy) (PaymentPolicy, error)
}

type SQLStore struct {
	db *pkgdb.DB
}

func NewSQLStore(db *pkgdb.DB) *SQLStore {
	return &SQLStore{db: db}
}

func (s *SQLStore) CreatePaymentKey(ctx context.Context, key PaymentKey) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO payment_keys (
	tenant_id, id, key_id, payment_type, usage_code, mode_of_use, key_version_num,
	exportability, tr31_header, kcv, iso20022_party_id, iso20022_msg_types,
	created_at, updated_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,
	$8,$9,$10,$11,$12,
	CURRENT_TIMESTAMP,CURRENT_TIMESTAMP
)
`, key.TenantID, key.ID, key.KeyID, key.PaymentType, key.UsageCode, key.ModeOfUse, key.KeyVersionNum,
		key.Exportability, key.TR31Header, key.KCV, key.ISO20022PartyID, validJSONOr(key.ISO20022MsgTypes, "[]"))
	return err
}

func (s *SQLStore) UpdatePaymentKey(ctx context.Context, key PaymentKey) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE payment_keys
SET payment_type = $1,
	usage_code = $2,
	mode_of_use = $3,
	key_version_num = $4,
	exportability = $5,
	tr31_header = $6,
	iso20022_party_id = $7,
	iso20022_msg_types = $8,
	updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $9 AND id = $10
`, key.PaymentType, key.UsageCode, key.ModeOfUse, key.KeyVersionNum, key.Exportability, key.TR31Header, key.ISO20022PartyID, validJSONOr(key.ISO20022MsgTypes, "[]"), key.TenantID, key.ID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) UpdatePaymentKeyVersion(ctx context.Context, tenantID string, id string, keyVersionNum string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE payment_keys
SET key_version_num = $1,
	updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $2 AND id = $3
`, keyVersionNum, tenantID, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) GetPaymentKey(ctx context.Context, tenantID string, id string) (PaymentKey, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, key_id, payment_type, usage_code, mode_of_use, key_version_num,
	   exportability, tr31_header, kcv, iso20022_party_id, iso20022_msg_types, created_at, updated_at
FROM payment_keys
WHERE tenant_id = $1 AND id = $2
`, tenantID, id)
	out, err := scanPaymentKey(row)
	if errors.Is(err, sql.ErrNoRows) {
		return PaymentKey{}, errNotFound
	}
	return out, err
}

func (s *SQLStore) ListPaymentKeys(ctx context.Context, tenantID string) ([]PaymentKey, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, key_id, payment_type, usage_code, mode_of_use, key_version_num,
	   exportability, tr31_header, kcv, iso20022_party_id, iso20022_msg_types, created_at, updated_at
FROM payment_keys
WHERE tenant_id = $1
ORDER BY created_at DESC
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]PaymentKey, 0)
	for rows.Next() {
		item, err := scanPaymentKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) CreateTR31Translation(ctx context.Context, tr TR31Translation) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO tr31_translations (
	tenant_id, id, source_key_id, source_format, target_format, kek_key_id, result_block, status, created_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,CURRENT_TIMESTAMP
)
`, tr.TenantID, tr.ID, tr.SourceKeyID, tr.SourceFormat, tr.TargetFormat, tr.KEKKeyID, tr.ResultBlock, tr.Status)
	return err
}

func (s *SQLStore) CreatePINOperationLog(ctx context.Context, item PINOperationLog) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO pin_operations_log (
	tenant_id, id, operation, source_format, target_format, zpk_key_id, result, created_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,CURRENT_TIMESTAMP
)
`, item.TenantID, item.ID, item.Operation, item.SourceFormat, item.TargetFormat, item.ZPKKeyID, item.Result)
	return err
}

func (s *SQLStore) GetPaymentPolicy(ctx context.Context, tenantID string) (PaymentPolicy, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id,
       allowed_tr31_versions_json,
       require_kbpk_for_tr31,
       allow_inline_key_material,
       max_iso20022_payload_bytes,
       require_iso20022_lau_context,
       strict_pci_dss_4_0,
       require_key_id_for_operations,
       allow_tcp_interface,
       require_jwt_on_tcp,
       max_tcp_payload_bytes,
       allowed_tcp_operations_json,
       allowed_pin_block_formats_json,
       disable_iso0_pin_block,
       decimalization_table,
       block_wildcard_pan,
       COALESCE(updated_by,''),
       updated_at
FROM payment_policy
WHERE tenant_id = $1
`, strings.TrimSpace(tenantID))
	var (
		out            PaymentPolicy
		versionsJSON   string
		tcpOpsJSON     string
		pinFormatsJSON string
		updatedRaw     interface{}
	)
	if err := row.Scan(
		&out.TenantID,
		&versionsJSON,
		&out.RequireKBPKForTR31,
		&out.AllowInlineKeyMaterial,
		&out.MaxISO20022PayloadBytes,
		&out.RequireISO20022LAUContext,
		&out.StrictPCIDSS40,
		&out.RequireKeyIDForOperations,
		&out.AllowTCPInterface,
		&out.RequireJWTOnTCP,
		&out.MaxTCPPayloadBytes,
		&tcpOpsJSON,
		&pinFormatsJSON,
		&out.DisableISO0PINBlock,
		&out.DecimalizationTable,
		&out.BlockWildcardPAN,
		&out.UpdatedBy,
		&updatedRaw,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return PaymentPolicy{}, errNotFound
		}
		return PaymentPolicy{}, err
	}
	out.AllowedTR31Versions = parseJSONArrayString(versionsJSON)
	out.AllowedTCPOperations = parseJSONArrayString(tcpOpsJSON)
	out.AllowedPINBlockFormats = parseJSONArrayString(pinFormatsJSON)
	out.UpdatedAt = parseTimeValue(updatedRaw)
	return out, nil
}

func (s *SQLStore) UpsertPaymentPolicy(ctx context.Context, item PaymentPolicy) (PaymentPolicy, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO payment_policy (
    tenant_id,
    allowed_tr31_versions_json,
    require_kbpk_for_tr31,
    allow_inline_key_material,
    max_iso20022_payload_bytes,
    require_iso20022_lau_context,
    strict_pci_dss_4_0,
    require_key_id_for_operations,
    allow_tcp_interface,
    require_jwt_on_tcp,
    max_tcp_payload_bytes,
    allowed_tcp_operations_json,
    allowed_pin_block_formats_json,
    disable_iso0_pin_block,
    decimalization_table,
    block_wildcard_pan,
    updated_by,
    updated_at
) VALUES (
    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,CURRENT_TIMESTAMP
)
ON CONFLICT (tenant_id) DO UPDATE SET
    allowed_tr31_versions_json = EXCLUDED.allowed_tr31_versions_json,
    require_kbpk_for_tr31 = EXCLUDED.require_kbpk_for_tr31,
    allow_inline_key_material = EXCLUDED.allow_inline_key_material,
    max_iso20022_payload_bytes = EXCLUDED.max_iso20022_payload_bytes,
    require_iso20022_lau_context = EXCLUDED.require_iso20022_lau_context,
    strict_pci_dss_4_0 = EXCLUDED.strict_pci_dss_4_0,
    require_key_id_for_operations = EXCLUDED.require_key_id_for_operations,
    allow_tcp_interface = EXCLUDED.allow_tcp_interface,
    require_jwt_on_tcp = EXCLUDED.require_jwt_on_tcp,
    max_tcp_payload_bytes = EXCLUDED.max_tcp_payload_bytes,
    allowed_tcp_operations_json = EXCLUDED.allowed_tcp_operations_json,
    allowed_pin_block_formats_json = EXCLUDED.allowed_pin_block_formats_json,
    disable_iso0_pin_block = EXCLUDED.disable_iso0_pin_block,
    decimalization_table = EXCLUDED.decimalization_table,
    block_wildcard_pan = EXCLUDED.block_wildcard_pan,
    updated_by = EXCLUDED.updated_by,
    updated_at = CURRENT_TIMESTAMP
RETURNING tenant_id,
          allowed_tr31_versions_json,
          require_kbpk_for_tr31,
          allow_inline_key_material,
          max_iso20022_payload_bytes,
          require_iso20022_lau_context,
          strict_pci_dss_4_0,
          require_key_id_for_operations,
          allow_tcp_interface,
          require_jwt_on_tcp,
          max_tcp_payload_bytes,
          allowed_tcp_operations_json,
          allowed_pin_block_formats_json,
          disable_iso0_pin_block,
          decimalization_table,
          block_wildcard_pan,
          COALESCE(updated_by,''),
          updated_at
`, item.TenantID, validJSONOr(mustJSON(item.AllowedTR31Versions), "[]"), item.RequireKBPKForTR31, item.AllowInlineKeyMaterial, item.MaxISO20022PayloadBytes, item.RequireISO20022LAUContext, item.StrictPCIDSS40, item.RequireKeyIDForOperations, item.AllowTCPInterface, item.RequireJWTOnTCP, item.MaxTCPPayloadBytes, validJSONOr(mustJSON(item.AllowedTCPOperations), "[]"), validJSONOr(mustJSON(item.AllowedPINBlockFormats), "[]"), item.DisableISO0PINBlock, item.DecimalizationTable, item.BlockWildcardPAN, item.UpdatedBy)
	var (
		out            PaymentPolicy
		versionsJSON   string
		tcpOpsJSON     string
		pinFormatsJSON string
		updatedRaw     interface{}
	)
	if err := row.Scan(
		&out.TenantID,
		&versionsJSON,
		&out.RequireKBPKForTR31,
		&out.AllowInlineKeyMaterial,
		&out.MaxISO20022PayloadBytes,
		&out.RequireISO20022LAUContext,
		&out.StrictPCIDSS40,
		&out.RequireKeyIDForOperations,
		&out.AllowTCPInterface,
		&out.RequireJWTOnTCP,
		&out.MaxTCPPayloadBytes,
		&tcpOpsJSON,
		&pinFormatsJSON,
		&out.DisableISO0PINBlock,
		&out.DecimalizationTable,
		&out.BlockWildcardPAN,
		&out.UpdatedBy,
		&updatedRaw,
	); err != nil {
		return PaymentPolicy{}, err
	}
	out.AllowedTR31Versions = parseJSONArrayString(versionsJSON)
	out.AllowedTCPOperations = parseJSONArrayString(tcpOpsJSON)
	out.AllowedPINBlockFormats = parseJSONArrayString(pinFormatsJSON)
	out.UpdatedAt = parseTimeValue(updatedRaw)
	return out, nil
}

func scanPaymentKey(scanner interface {
	Scan(dest ...interface{}) error
}) (PaymentKey, error) {
	var (
		out        PaymentKey
		createdRaw interface{}
		updatedRaw interface{}
	)
	err := scanner.Scan(
		&out.TenantID, &out.ID, &out.KeyID, &out.PaymentType, &out.UsageCode, &out.ModeOfUse, &out.KeyVersionNum,
		&out.Exportability, &out.TR31Header, &out.KCV, &out.ISO20022PartyID, &out.ISO20022MsgTypes, &createdRaw, &updatedRaw,
	)
	if err != nil {
		return PaymentKey{}, err
	}
	out.CreatedAt = parseTimeValue(createdRaw)
	out.UpdatedAt = parseTimeValue(updatedRaw)
	out.KCVHex = formatKCVHex(out.KCV)
	out.ISO20022MsgTypes = strings.TrimSpace(out.ISO20022MsgTypes)
	if out.ISO20022MsgTypes == "" {
		out.ISO20022MsgTypes = "[]"
	}
	return out, nil
}
