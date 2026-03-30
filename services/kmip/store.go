package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

var errNotFound = errors.New("not found")

type Store interface {
	CreateSession(ctx context.Context, s Session) error
	CloseSession(ctx context.Context, sessionID string) error
	RecordOperation(ctx context.Context, op OperationRecord) error

	UpsertObject(ctx context.Context, obj ObjectMapping) error
	GetObject(ctx context.Context, tenantID string, objectID string) (ObjectMapping, error)
	DeleteObject(ctx context.Context, tenantID string, objectID string) error
	LocateObjects(ctx context.Context, tenantID string, req LocateRequest) ([]ObjectMapping, error)

	CreateClientProfile(ctx context.Context, profile KMIPClientProfile) error
	ListClientProfiles(ctx context.Context, tenantID string) ([]KMIPClientProfile, error)
	GetClientProfile(ctx context.Context, tenantID string, profileID string) (KMIPClientProfile, error)
	DeleteClientProfile(ctx context.Context, tenantID string, profileID string) error
	CountClientsByProfile(ctx context.Context, tenantID string, profileID string) (int, error)

	CreateClient(ctx context.Context, client KMIPClient) error
	ListClients(ctx context.Context, tenantID string) ([]KMIPClient, error)
	GetClientByID(ctx context.Context, tenantID string, clientID string) (KMIPClient, error)
	GetClientByFingerprint(ctx context.Context, fingerprint string) (KMIPClient, error)
	DeleteClient(ctx context.Context, tenantID string, clientID string) error

	CreateInteropTarget(ctx context.Context, target KMIPInteropTarget) error
	ListInteropTargets(ctx context.Context, tenantID string) ([]KMIPInteropTarget, error)
	GetInteropTarget(ctx context.Context, tenantID string, targetID string) (KMIPInteropTarget, error)
	DeleteInteropTarget(ctx context.Context, tenantID string, targetID string) error
	UpdateInteropTargetValidation(ctx context.Context, tenantID string, targetID string, status string, lastErr string, reportJSON string, checkedAt time.Time) error
}

type SQLStore struct {
	db *pkgdb.DB
}

func NewSQLStore(db *pkgdb.DB) *SQLStore {
	return &SQLStore{db: db}
}

func (s *SQLStore) CreateSession(ctx context.Context, ses Session) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO kmip_sessions (
	id, tenant_id, client_cn, role, remote_addr, tls_subject, tls_issuer, connected_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8
)
`, ses.ID, ses.TenantID, ses.ClientCN, ses.Role, ses.RemoteAddr, ses.TLSSubject, ses.TLSIssuer, ses.ConnectedAt.UTC())
	return err
}

func (s *SQLStore) CloseSession(ctx context.Context, sessionID string) error {
	_, err := s.db.SQL().ExecContext(ctx, `
UPDATE kmip_sessions SET disconnected_at = $1 WHERE id = $2
`, time.Now().UTC(), sessionID)
	return err
}

func (s *SQLStore) RecordOperation(ctx context.Context, op OperationRecord) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO kmip_operations (
	id, tenant_id, session_id, request_id, operation, object_id, status, error_message, request_bytes, response_bytes, created_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11
)
`, op.ID, op.TenantID, op.SessionID, op.RequestID, op.Operation, op.ObjectID, op.Status, op.ErrorMessage, op.RequestBytes, op.ResponseBytes, op.CreatedAt.UTC())
	return err
}

func (s *SQLStore) UpsertObject(ctx context.Context, obj ObjectMapping) error {
	attrs := strings.TrimSpace(obj.AttributesJSON)
	if attrs == "" {
		attrs = "{}"
	}
	now := time.Now().UTC()
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO kmip_objects (
	tenant_id, object_id, key_id, object_type, name, state, algorithm, attributes_json, created_at, updated_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,$9,$10
)
ON CONFLICT (tenant_id, object_id) DO UPDATE SET
	key_id = excluded.key_id,
	object_type = excluded.object_type,
	name = excluded.name,
	state = excluded.state,
	algorithm = excluded.algorithm,
	attributes_json = excluded.attributes_json,
	updated_at = excluded.updated_at
`, obj.TenantID, obj.ObjectID, obj.KeyID, obj.ObjectType, obj.Name, obj.State, obj.Algorithm, attrs, now, now)
	return err
}

func (s *SQLStore) GetObject(ctx context.Context, tenantID string, objectID string) (ObjectMapping, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, object_id, key_id, object_type, name, state, algorithm, attributes_json, created_at, updated_at
FROM kmip_objects
WHERE tenant_id = $1 AND object_id = $2
`, tenantID, objectID)
	out, err := scanObject(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ObjectMapping{}, errNotFound
	}
	return out, err
}

func (s *SQLStore) DeleteObject(ctx context.Context, tenantID string, objectID string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM kmip_objects WHERE tenant_id = $1 AND object_id = $2
`, tenantID, objectID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) LocateObjects(ctx context.Context, tenantID string, req LocateRequest) ([]ObjectMapping, error) {
	if req.Limit <= 0 || req.Limit > 500 {
		req.Limit = 100
	}
	var (
		args  []interface{}
		where strings.Builder
	)
	args = append(args, tenantID)
	where.WriteString(" WHERE tenant_id = $1")
	idx := 2
	if strings.TrimSpace(req.Name) != "" {
		where.WriteString(" AND name = $" + itoa(idx))
		args = append(args, strings.TrimSpace(req.Name))
		idx++
	}
	if strings.TrimSpace(req.ObjectType) != "" {
		where.WriteString(" AND object_type = $" + itoa(idx))
		args = append(args, strings.TrimSpace(req.ObjectType))
		idx++
	}
	if strings.TrimSpace(req.Algorithm) != "" {
		where.WriteString(" AND algorithm = $" + itoa(idx))
		args = append(args, strings.TrimSpace(req.Algorithm))
		idx++
	}
	if strings.TrimSpace(req.State) != "" {
		where.WriteString(" AND state = $" + itoa(idx))
		args = append(args, strings.TrimSpace(req.State))
		idx++
	}
	args = append(args, req.Limit)
	query := `
SELECT tenant_id, object_id, key_id, object_type, name, state, algorithm, attributes_json, created_at, updated_at
FROM kmip_objects
` + where.String() + `
ORDER BY updated_at DESC
LIMIT $` + itoa(idx)

	rows, err := s.db.SQL().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]ObjectMapping, 0)
	for rows.Next() {
		obj, err := scanObject(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, obj)
	}
	return out, rows.Err()
}

func (s *SQLStore) CreateClientProfile(ctx context.Context, profile KMIPClientProfile) error {
	now := time.Now().UTC()
	doNotModify := 0
	if profile.DoNotModifySubjectDN {
		doNotModify = 1
	}
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO kmip_client_profiles (
	id, tenant_id, name, ca_id, username_location, subject_field_to_modify,
	do_not_modify_subject_dn, certificate_duration_days, role, metadata_json, created_at, updated_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12
)
`, profile.ID, profile.TenantID, profile.Name, profile.CAID, profile.UsernameLocation, profile.SubjectFieldToModify,
		doNotModify, profile.CertificateDurationDays, profile.Role, validJSONOr(profile.MetadataJSON, "{}"), now, now)
	return err
}

func (s *SQLStore) ListClientProfiles(ctx context.Context, tenantID string) ([]KMIPClientProfile, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, name, ca_id, username_location, subject_field_to_modify,
	   do_not_modify_subject_dn, certificate_duration_days, role, metadata_json, created_at, updated_at
FROM kmip_client_profiles
WHERE tenant_id = $1
ORDER BY created_at DESC
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]KMIPClientProfile, 0)
	for rows.Next() {
		item, err := scanClientProfile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetClientProfile(ctx context.Context, tenantID string, profileID string) (KMIPClientProfile, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, name, ca_id, username_location, subject_field_to_modify,
	   do_not_modify_subject_dn, certificate_duration_days, role, metadata_json, created_at, updated_at
FROM kmip_client_profiles
WHERE tenant_id = $1 AND id = $2
`, tenantID, profileID)
	out, err := scanClientProfile(row)
	if errors.Is(err, sql.ErrNoRows) {
		return KMIPClientProfile{}, errNotFound
	}
	return out, err
}

func (s *SQLStore) DeleteClientProfile(ctx context.Context, tenantID string, profileID string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM kmip_client_profiles
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(profileID))
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) CountClientsByProfile(ctx context.Context, tenantID string, profileID string) (int, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT COUNT(*)
FROM kmip_clients
WHERE tenant_id = $1 AND profile_id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(profileID))
	var count int
	if err := row.Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (s *SQLStore) CreateClient(ctx context.Context, client KMIPClient) error {
	now := time.Now().UTC()
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO kmip_clients (
	id, tenant_id, profile_id, name, role, status, enrollment_mode, registration_token, cert_id,
	cert_subject, cert_issuer, cert_serial, cert_fingerprint_sha256, cert_not_before, cert_not_after,
	certificate_pem, ca_bundle_pem, metadata_json, created_at, updated_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,$9,
	$10,$11,$12,$13,$14,$15,
	$16,$17,$18,$19,$20
)
`, client.ID, client.TenantID, client.ProfileID, client.Name, client.Role, client.Status, client.EnrollmentMode, client.RegistrationToken, client.CertID,
		client.CertSubject, client.CertIssuer, client.CertSerial, strings.ToUpper(strings.TrimSpace(client.CertFingerprintSHA256)),
		nullTime(client.CertNotBefore), nullTime(client.CertNotAfter),
		client.CertificatePEM, client.CABundlePEM, validJSONOr(client.MetadataJSON, "{}"), now, now)
	return err
}

func (s *SQLStore) ListClients(ctx context.Context, tenantID string) ([]KMIPClient, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, profile_id, name, role, status, enrollment_mode, registration_token, cert_id,
	   cert_subject, cert_issuer, cert_serial, cert_fingerprint_sha256, cert_not_before, cert_not_after,
	   certificate_pem, ca_bundle_pem, metadata_json, created_at, updated_at
FROM kmip_clients
WHERE tenant_id = $1
ORDER BY created_at DESC
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]KMIPClient, 0)
	for rows.Next() {
		item, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetClientByID(ctx context.Context, tenantID string, clientID string) (KMIPClient, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, profile_id, name, role, status, enrollment_mode, registration_token, cert_id,
	   cert_subject, cert_issuer, cert_serial, cert_fingerprint_sha256, cert_not_before, cert_not_after,
	   certificate_pem, ca_bundle_pem, metadata_json, created_at, updated_at
FROM kmip_clients
WHERE tenant_id = $1 AND id = $2
`, tenantID, clientID)
	out, err := scanClient(row)
	if errors.Is(err, sql.ErrNoRows) {
		return KMIPClient{}, errNotFound
	}
	return out, err
}

func (s *SQLStore) GetClientByFingerprint(ctx context.Context, fingerprint string) (KMIPClient, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, profile_id, name, role, status, enrollment_mode, registration_token, cert_id,
	   cert_subject, cert_issuer, cert_serial, cert_fingerprint_sha256, cert_not_before, cert_not_after,
	   certificate_pem, ca_bundle_pem, metadata_json, created_at, updated_at
FROM kmip_clients
WHERE cert_fingerprint_sha256 = $1
ORDER BY updated_at DESC
LIMIT 1
`, strings.ToUpper(strings.TrimSpace(fingerprint)))
	out, err := scanClient(row)
	if errors.Is(err, sql.ErrNoRows) {
		return KMIPClient{}, errNotFound
	}
	return out, err
}

func (s *SQLStore) DeleteClient(ctx context.Context, tenantID string, clientID string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM kmip_clients
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(clientID))
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) CreateInteropTarget(ctx context.Context, target KMIPInteropTarget) error {
	now := time.Now().UTC()
	testKeyOperation := 0
	if target.TestKeyOperation {
		testKeyOperation = 1
	}
	lastChecked := nullTime(target.LastCheckedAt)
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO kmip_interop_targets (
	id, tenant_id, name, vendor, endpoint, server_name, expected_min_version, test_key_operation,
	ca_pem, client_cert_pem, client_key_pem,
	last_status, last_error, last_report_json, last_checked_at, created_at, updated_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,
	$9,$10,$11,
	$12,$13,$14,$15,$16,$17
)
`, target.ID, target.TenantID, target.Name, target.Vendor, target.Endpoint, target.ServerName, target.ExpectedMinVersion, testKeyOperation,
		strings.TrimSpace(target.CAPEM), strings.TrimSpace(target.ClientCertPEM), strings.TrimSpace(target.ClientKeyPEM),
		strings.TrimSpace(target.LastStatus), strings.TrimSpace(target.LastError), validJSONOr(target.LastReportJSON, "{}"), lastChecked, now, now)
	return err
}

func (s *SQLStore) ListInteropTargets(ctx context.Context, tenantID string) ([]KMIPInteropTarget, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, name, vendor, endpoint, server_name, expected_min_version, test_key_operation,
	   ca_pem, client_cert_pem, client_key_pem,
	   last_status, last_error, last_report_json, last_checked_at, created_at, updated_at
FROM kmip_interop_targets
WHERE tenant_id = $1
ORDER BY created_at DESC
`, strings.TrimSpace(tenantID))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]KMIPInteropTarget, 0)
	for rows.Next() {
		item, scanErr := scanInteropTarget(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetInteropTarget(ctx context.Context, tenantID string, targetID string) (KMIPInteropTarget, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, name, vendor, endpoint, server_name, expected_min_version, test_key_operation,
	   ca_pem, client_cert_pem, client_key_pem,
	   last_status, last_error, last_report_json, last_checked_at, created_at, updated_at
FROM kmip_interop_targets
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(targetID))
	out, err := scanInteropTarget(row)
	if errors.Is(err, sql.ErrNoRows) {
		return KMIPInteropTarget{}, errNotFound
	}
	return out, err
}

func (s *SQLStore) DeleteInteropTarget(ctx context.Context, tenantID string, targetID string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM kmip_interop_targets
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(targetID))
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) UpdateInteropTargetValidation(ctx context.Context, tenantID string, targetID string, status string, lastErr string, reportJSON string, checkedAt time.Time) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE kmip_interop_targets
SET last_status = $1,
	last_error = $2,
	last_report_json = $3,
	last_checked_at = $4,
	updated_at = $5
WHERE tenant_id = $6 AND id = $7
`, strings.TrimSpace(status), strings.TrimSpace(lastErr), validJSONOr(reportJSON, "{}"), nullTime(checkedAt), time.Now().UTC(), strings.TrimSpace(tenantID), strings.TrimSpace(targetID))
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func scanObject(scanner interface {
	Scan(dest ...interface{}) error
}) (ObjectMapping, error) {
	var (
		out        ObjectMapping
		createdRaw interface{}
		updatedRaw interface{}
		attrsRaw   string
	)
	err := scanner.Scan(
		&out.TenantID, &out.ObjectID, &out.KeyID, &out.ObjectType, &out.Name, &out.State, &out.Algorithm, &attrsRaw, &createdRaw, &updatedRaw,
	)
	if err != nil {
		return ObjectMapping{}, err
	}
	if strings.TrimSpace(attrsRaw) == "" {
		attrsRaw = "{}"
	}
	if !json.Valid([]byte(attrsRaw)) {
		attrsRaw = "{}"
	}
	out.AttributesJSON = attrsRaw
	out.CreatedAt = parseTimeValue(createdRaw)
	out.UpdatedAt = parseTimeValue(updatedRaw)
	return out, nil
}

func parseTimeValue(v interface{}) time.Time {
	switch x := v.(type) {
	case time.Time:
		return x.UTC()
	case string:
		return parseTimeString(x)
	case []byte:
		return parseTimeString(string(x))
	default:
		return time.Time{}
	}
}

func parseTimeString(v string) time.Time {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}
	}
	formats := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
	}
	for _, f := range formats {
		if ts, err := time.Parse(f, v); err == nil {
			return ts.UTC()
		}
	}
	return time.Time{}
}

func scanClientProfile(scanner interface {
	Scan(dest ...interface{}) error
}) (KMIPClientProfile, error) {
	var (
		out        KMIPClientProfile
		rawFlag    interface{}
		metadata   string
		createdRaw interface{}
		updatedRaw interface{}
	)
	err := scanner.Scan(
		&out.ID, &out.TenantID, &out.Name, &out.CAID, &out.UsernameLocation, &out.SubjectFieldToModify,
		&rawFlag, &out.CertificateDurationDays, &out.Role, &metadata, &createdRaw, &updatedRaw,
	)
	if err != nil {
		return KMIPClientProfile{}, err
	}
	out.DoNotModifySubjectDN = parseBoolValue(rawFlag)
	if strings.TrimSpace(metadata) == "" || !json.Valid([]byte(metadata)) {
		metadata = "{}"
	}
	out.MetadataJSON = metadata
	out.CreatedAt = parseTimeValue(createdRaw)
	out.UpdatedAt = parseTimeValue(updatedRaw)
	return out, nil
}

func scanClient(scanner interface {
	Scan(dest ...interface{}) error
}) (KMIPClient, error) {
	var (
		out            KMIPClient
		certBeforeRaw  interface{}
		certAfterRaw   interface{}
		createdRaw     interface{}
		updatedRaw     interface{}
		metadata       string
		fingerprintRaw string
	)
	err := scanner.Scan(
		&out.ID, &out.TenantID, &out.ProfileID, &out.Name, &out.Role, &out.Status, &out.EnrollmentMode, &out.RegistrationToken, &out.CertID,
		&out.CertSubject, &out.CertIssuer, &out.CertSerial, &fingerprintRaw, &certBeforeRaw, &certAfterRaw,
		&out.CertificatePEM, &out.CABundlePEM, &metadata, &createdRaw, &updatedRaw,
	)
	if err != nil {
		return KMIPClient{}, err
	}
	if strings.TrimSpace(metadata) == "" || !json.Valid([]byte(metadata)) {
		metadata = "{}"
	}
	out.MetadataJSON = metadata
	out.CertFingerprintSHA256 = strings.ToUpper(strings.TrimSpace(fingerprintRaw))
	out.CertNotBefore = parseTimeValue(certBeforeRaw)
	out.CertNotAfter = parseTimeValue(certAfterRaw)
	out.CreatedAt = parseTimeValue(createdRaw)
	out.UpdatedAt = parseTimeValue(updatedRaw)
	return out, nil
}

func scanInteropTarget(scanner interface {
	Scan(dest ...interface{}) error
}) (KMIPInteropTarget, error) {
	var (
		out            KMIPInteropTarget
		testKeyRaw     interface{}
		lastCheckedRaw interface{}
		createdRaw     interface{}
		updatedRaw     interface{}
		reportRaw      string
	)
	err := scanner.Scan(
		&out.ID, &out.TenantID, &out.Name, &out.Vendor, &out.Endpoint, &out.ServerName, &out.ExpectedMinVersion, &testKeyRaw,
		&out.CAPEM, &out.ClientCertPEM, &out.ClientKeyPEM,
		&out.LastStatus, &out.LastError, &reportRaw, &lastCheckedRaw, &createdRaw, &updatedRaw,
	)
	if err != nil {
		return KMIPInteropTarget{}, err
	}
	out.TestKeyOperation = parseBoolValue(testKeyRaw)
	if strings.TrimSpace(reportRaw) == "" || !json.Valid([]byte(reportRaw)) {
		reportRaw = "{}"
	}
	out.LastReportJSON = reportRaw
	out.LastCheckedAt = parseTimeValue(lastCheckedRaw)
	out.CreatedAt = parseTimeValue(createdRaw)
	out.UpdatedAt = parseTimeValue(updatedRaw)
	return out, nil
}

func validJSONOr(v string, fallback string) string {
	raw := strings.TrimSpace(v)
	if raw == "" {
		return fallback
	}
	if !json.Valid([]byte(raw)) {
		return fallback
	}
	return raw
}

func nullTime(ts time.Time) interface{} {
	if ts.IsZero() {
		return nil
	}
	return ts.UTC()
}

func parseBoolValue(v interface{}) bool {
	switch x := v.(type) {
	case bool:
		return x
	case int:
		return x != 0
	case int8:
		return x != 0
	case int16:
		return x != 0
	case int32:
		return x != 0
	case int64:
		return x != 0
	case uint:
		return x != 0
	case uint8:
		return x != 0
	case uint16:
		return x != 0
	case uint32:
		return x != 0
	case uint64:
		return x != 0
	case string:
		s := strings.ToLower(strings.TrimSpace(x))
		return s == "1" || s == "true" || s == "yes" || s == "on"
	case []byte:
		s := strings.ToLower(strings.TrimSpace(string(x)))
		return s == "1" || s == "true" || s == "yes" || s == "on"
	default:
		return false
	}
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := false
	if v < 0 {
		neg = true
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
