package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"
)

func (s *SQLStore) UpsertEnterpriseControlRecord(ctx context.Context, record EnterpriseControlRecord) (EnterpriseControlRecord, error) {
	now := time.Now().UTC()
	if strings.TrimSpace(record.RecordID) == "" {
		record.RecordID = newID("ectl")
	}
	record.TenantID = strings.TrimSpace(record.TenantID)
	record.Category = strings.ToLower(strings.TrimSpace(record.Category))
	record.Status = normalizeControlStatus(record.Status)
	record.Severity = normalizeSeverityLoose(record.Severity)
	record.RiskScore = clampScore(record.RiskScore)
	if record.Metadata == nil {
		record.Metadata = map[string]any{}
	}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = now
	}
	record.UpdatedAt = now
	metadata, _ := json.Marshal(nonNilMap(record.Metadata))

	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO enterprise_control_records (
	record_id, tenant_id, category, key_id, name, status, severity, risk_score,
	expires_at, metadata_json, created_at, updated_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
ON CONFLICT (tenant_id, category, record_id) DO UPDATE SET
	key_id = EXCLUDED.key_id,
	name = EXCLUDED.name,
	status = EXCLUDED.status,
	severity = EXCLUDED.severity,
	risk_score = EXCLUDED.risk_score,
	expires_at = EXCLUDED.expires_at,
	metadata_json = EXCLUDED.metadata_json,
	updated_at = CURRENT_TIMESTAMP
RETURNING record_id, tenant_id, category, COALESCE(key_id,''), name, status,
          COALESCE(severity,''), risk_score, expires_at, COALESCE(metadata_json,'{}'),
          created_at, updated_at
`, record.RecordID, record.TenantID, record.Category, nullable(record.KeyID), record.Name,
		record.Status, nullable(record.Severity), record.RiskScore, nullableTime(record.ExpiresAt),
		metadata, record.CreatedAt, record.UpdatedAt)
	return scanEnterpriseControlRecord(row)
}

func (s *SQLStore) GetEnterpriseControlRecord(ctx context.Context, tenantID, category, recordID string) (EnterpriseControlRecord, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT record_id, tenant_id, category, COALESCE(key_id,''), name, status,
       COALESCE(severity,''), risk_score, expires_at, COALESCE(metadata_json,'{}'),
       created_at, updated_at
FROM enterprise_control_records
WHERE tenant_id=$1 AND category=$2 AND record_id=$3
`, strings.TrimSpace(tenantID), strings.ToLower(strings.TrimSpace(category)), strings.TrimSpace(recordID))
	item, err := scanEnterpriseControlRecord(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return EnterpriseControlRecord{}, errStoreNotFound
		}
		return EnterpriseControlRecord{}, err
	}
	return item, nil
}

func (s *SQLStore) ListEnterpriseControlRecords(ctx context.Context, tenantID string, q EnterpriseControlQuery) ([]EnterpriseControlRecord, error) {
	limit := clampAuditLimit(q.Limit, 200)
	offset := q.Offset
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT record_id, tenant_id, category, COALESCE(key_id,''), name, status,
       COALESCE(severity,''), risk_score, expires_at, COALESCE(metadata_json,'{}'),
       created_at, updated_at
FROM enterprise_control_records
WHERE tenant_id=$1
  AND ($2='' OR category=$2)
  AND ($3='' OR key_id=$3)
  AND ($4='' OR status=$4)
ORDER BY updated_at DESC
LIMIT $5 OFFSET $6
`, strings.TrimSpace(tenantID), strings.ToLower(strings.TrimSpace(q.Category)),
		strings.TrimSpace(q.KeyID), strings.ToLower(strings.TrimSpace(q.Status)), limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	out := make([]EnterpriseControlRecord, 0)
	for rows.Next() {
		item, err := scanEnterpriseControlRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpsertDSPMFinding(ctx context.Context, finding DSPMFinding) (DSPMFinding, error) {
	now := time.Now().UTC()
	if strings.TrimSpace(finding.FindingID) == "" {
		finding.FindingID = newID("dspm")
	}
	finding.TenantID = strings.TrimSpace(finding.TenantID)
	finding.Source = firstNonEmpty(finding.Source, "keycore")
	finding.FindingType = strings.ToLower(strings.TrimSpace(finding.FindingType))
	finding.Severity = normalizeSeverityLoose(finding.Severity)
	finding.Status = normalizeControlStatus(finding.Status)
	finding.RiskScore = clampScore(finding.RiskScore)
	if finding.Evidence == nil {
		finding.Evidence = map[string]any{}
	}
	if finding.CreatedAt.IsZero() {
		finding.CreatedAt = now
	}
	finding.UpdatedAt = now
	evidence, _ := json.Marshal(nonNilMap(finding.Evidence))

	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO key_dspm_findings (
	finding_id, tenant_id, source, finding_type, title, description, severity,
	risk_score, status, key_id, recommended_action, evidence_json, created_at, updated_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
ON CONFLICT (tenant_id, finding_id) DO UPDATE SET
	source = EXCLUDED.source,
	finding_type = EXCLUDED.finding_type,
	title = EXCLUDED.title,
	description = EXCLUDED.description,
	severity = EXCLUDED.severity,
	risk_score = EXCLUDED.risk_score,
	status = EXCLUDED.status,
	key_id = EXCLUDED.key_id,
	recommended_action = EXCLUDED.recommended_action,
	evidence_json = EXCLUDED.evidence_json,
	updated_at = CURRENT_TIMESTAMP
RETURNING finding_id, tenant_id, source, finding_type, title, description, severity,
          risk_score, status, COALESCE(key_id,''), recommended_action,
          COALESCE(evidence_json,'{}'), created_at, updated_at
`, finding.FindingID, finding.TenantID, finding.Source, finding.FindingType, finding.Title,
		finding.Description, finding.Severity, finding.RiskScore, finding.Status,
		nullable(finding.KeyID), finding.RecommendedAction, evidence, finding.CreatedAt, finding.UpdatedAt)
	return scanDSPMFinding(row)
}

func (s *SQLStore) ListDSPMFindings(ctx context.Context, tenantID string, q DSPMFindingQuery) ([]DSPMFinding, error) {
	limit := clampAuditLimit(q.Limit, 200)
	offset := q.Offset
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT finding_id, tenant_id, source, finding_type, title, description, severity,
       risk_score, status, COALESCE(key_id,''), recommended_action,
       COALESCE(evidence_json,'{}'), created_at, updated_at
FROM key_dspm_findings
WHERE tenant_id=$1
  AND ($2='' OR source=$2)
  AND ($3='' OR finding_type=$3)
  AND ($4='' OR status=$4)
  AND ($5='' OR severity=$5)
  AND ($6='' OR key_id=$6)
ORDER BY risk_score DESC, updated_at DESC
LIMIT $7 OFFSET $8
`, strings.TrimSpace(tenantID), strings.TrimSpace(q.Source), strings.ToLower(strings.TrimSpace(q.FindingType)),
		strings.ToLower(strings.TrimSpace(q.Status)), normalizeSeverityFilter(q.Severity), strings.TrimSpace(q.KeyID), limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	out := make([]DSPMFinding, 0)
	for rows.Next() {
		item, err := scanDSPMFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) RecordAuditChainAnchor(ctx context.Context, anchor AuditChainAnchor) (AuditChainAnchor, error) {
	now := time.Now().UTC()
	if strings.TrimSpace(anchor.AnchorID) == "" {
		anchor.AnchorID = newID("anch")
	}
	if anchor.Metadata == nil {
		anchor.Metadata = map[string]any{}
	}
	if anchor.AnchoredAt.IsZero() {
		anchor.AnchoredAt = now
	}
	if strings.TrimSpace(anchor.Status) == "" {
		anchor.Status = "anchored"
	}
	metadata, _ := json.Marshal(nonNilMap(anchor.Metadata))
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO key_audit_chain_anchors (
	anchor_id, tenant_id, anchor_type, merkle_root, previous_hash, anchor_hash,
	external_reference, status, metadata_json, anchored_at, verified_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
ON CONFLICT (tenant_id, anchor_id) DO UPDATE SET
	anchor_type = EXCLUDED.anchor_type,
	merkle_root = EXCLUDED.merkle_root,
	previous_hash = EXCLUDED.previous_hash,
	anchor_hash = EXCLUDED.anchor_hash,
	external_reference = EXCLUDED.external_reference,
	status = EXCLUDED.status,
	metadata_json = EXCLUDED.metadata_json,
	verified_at = EXCLUDED.verified_at
RETURNING anchor_id, tenant_id, anchor_type, merkle_root, COALESCE(previous_hash,''),
          anchor_hash, COALESCE(external_reference,''), status, COALESCE(metadata_json,'{}'),
          anchored_at, verified_at
`, anchor.AnchorID, anchor.TenantID, anchor.AnchorType, anchor.MerkleRoot,
		nullable(anchor.PreviousHash), anchor.AnchorHash, nullable(anchor.ExternalReference),
		anchor.Status, metadata, anchor.AnchoredAt, nullableTime(anchor.VerifiedAt))
	return scanAuditChainAnchor(row)
}

func (s *SQLStore) GetAuditChainAnchor(ctx context.Context, tenantID, anchorID string) (AuditChainAnchor, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT anchor_id, tenant_id, anchor_type, merkle_root, COALESCE(previous_hash,''),
       anchor_hash, COALESCE(external_reference,''), status, COALESCE(metadata_json,'{}'),
       anchored_at, verified_at
FROM key_audit_chain_anchors
WHERE tenant_id=$1 AND anchor_id=$2
`, strings.TrimSpace(tenantID), strings.TrimSpace(anchorID))
	item, err := scanAuditChainAnchor(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return AuditChainAnchor{}, errStoreNotFound
		}
		return AuditChainAnchor{}, err
	}
	return item, nil
}

func (s *SQLStore) ListAuditChainAnchors(ctx context.Context, tenantID string, limit int) ([]AuditChainAnchor, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT anchor_id, tenant_id, anchor_type, merkle_root, COALESCE(previous_hash,''),
       anchor_hash, COALESCE(external_reference,''), status, COALESCE(metadata_json,'{}'),
       anchored_at, verified_at
FROM key_audit_chain_anchors
WHERE tenant_id=$1
ORDER BY anchored_at DESC
LIMIT $2
`, strings.TrimSpace(tenantID), clampAuditLimit(limit, 100))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	out := make([]AuditChainAnchor, 0)
	for rows.Next() {
		item, err := scanAuditChainAnchor(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func scanEnterpriseControlRecord(scanner interface{ Scan(...any) error }) (EnterpriseControlRecord, error) {
	var (
		item      EnterpriseControlRecord
		expiresAt sql.NullTime
		rawMeta   string
	)
	if err := scanner.Scan(
		&item.RecordID, &item.TenantID, &item.Category, &item.KeyID, &item.Name,
		&item.Status, &item.Severity, &item.RiskScore, &expiresAt, &rawMeta,
		&item.CreatedAt, &item.UpdatedAt,
	); err != nil {
		return EnterpriseControlRecord{}, err
	}
	item.ExpiresAt = nullTimePtr(expiresAt)
	item.Metadata = parseMap(rawMeta)
	item.CreatedAt = item.CreatedAt.UTC()
	item.UpdatedAt = item.UpdatedAt.UTC()
	return item, nil
}

func scanDSPMFinding(scanner interface{ Scan(...any) error }) (DSPMFinding, error) {
	var (
		item    DSPMFinding
		rawJSON string
	)
	if err := scanner.Scan(
		&item.FindingID, &item.TenantID, &item.Source, &item.FindingType, &item.Title,
		&item.Description, &item.Severity, &item.RiskScore, &item.Status, &item.KeyID,
		&item.RecommendedAction, &rawJSON, &item.CreatedAt, &item.UpdatedAt,
	); err != nil {
		return DSPMFinding{}, err
	}
	item.Evidence = parseMap(rawJSON)
	item.CreatedAt = item.CreatedAt.UTC()
	item.UpdatedAt = item.UpdatedAt.UTC()
	return item, nil
}

func scanAuditChainAnchor(scanner interface{ Scan(...any) error }) (AuditChainAnchor, error) {
	var (
		item       AuditChainAnchor
		rawJSON    string
		verifiedAt sql.NullTime
	)
	if err := scanner.Scan(
		&item.AnchorID, &item.TenantID, &item.AnchorType, &item.MerkleRoot,
		&item.PreviousHash, &item.AnchorHash, &item.ExternalReference, &item.Status,
		&rawJSON, &item.AnchoredAt, &verifiedAt,
	); err != nil {
		return AuditChainAnchor{}, err
	}
	item.Metadata = parseMap(rawJSON)
	item.VerifiedAt = nullTimePtr(verifiedAt)
	item.AnchoredAt = item.AnchoredAt.UTC()
	return item, nil
}

func normalizeControlStatus(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "open", "active", "pending", "running", "completed", "resolved", "revoked", "expired", "failed", "verified", "blocked", "approved", "denied":
		return strings.ToLower(strings.TrimSpace(raw))
	case "":
		return "active"
	default:
		return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(raw), " ", "_"))
	}
}

func normalizeSeverityLoose(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical", "high", "medium", "warning", "low", "info":
		if strings.ToLower(strings.TrimSpace(raw)) == "warning" {
			return "medium"
		}
		return strings.ToLower(strings.TrimSpace(raw))
	case "":
		return "info"
	default:
		return "medium"
	}
}

func normalizeSeverityFilter(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	return normalizeSeverityLoose(raw)
}
