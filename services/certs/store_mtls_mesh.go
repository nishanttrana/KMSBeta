package main

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// ListMeshServices returns all registered mesh services for a tenant.
func (s *SQLStore) ListMeshServices(ctx context.Context, tenantID string) ([]MeshService, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, name, namespace, endpoint,
       COALESCE(cert_id, ''), COALESCE(cert_cn, ''), cert_expiry,
       cert_status, last_renewed_at, auto_renew, renew_days_before,
       trust_anchors_json, mtls_enabled, created_at
FROM mesh_services
WHERE tenant_id = $1
ORDER BY created_at DESC
`, strings.TrimSpace(tenantID))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]MeshService, 0)
	for rows.Next() {
		svc, scanErr := scanMeshService(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, svc)
	}
	return out, rows.Err()
}

// GetMeshService returns a single mesh service by ID.
func (s *SQLStore) GetMeshService(ctx context.Context, tenantID, id string) (MeshService, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, name, namespace, endpoint,
       COALESCE(cert_id, ''), COALESCE(cert_cn, ''), cert_expiry,
       cert_status, last_renewed_at, auto_renew, renew_days_before,
       trust_anchors_json, mtls_enabled, created_at
FROM mesh_services
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	svc, err := scanMeshService(row)
	if errors.Is(err, sql.ErrNoRows) {
		return MeshService{}, errStoreNotFound
	}
	return svc, err
}

// CreateMeshService inserts a new mesh service record.
func (s *SQLStore) CreateMeshService(ctx context.Context, svc MeshService) (MeshService, error) {
	anchorsJSON := mustJSON(svc.TrustAnchors)
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO mesh_services (
    id, tenant_id, name, namespace, endpoint,
    cert_status, auto_renew, renew_days_before,
    trust_anchors_json, mtls_enabled, created_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
`,
		strings.TrimSpace(svc.ID),
		strings.TrimSpace(svc.TenantID),
		strings.TrimSpace(svc.Name),
		strings.TrimSpace(svc.Namespace),
		strings.TrimSpace(svc.Endpoint),
		strings.TrimSpace(svc.CertStatus),
		svc.AutoRenew,
		svc.RenewDaysBefore,
		anchorsJSON,
		svc.MTLSEnabled,
		svc.CreatedAt.UTC(),
	)
	if err != nil {
		return MeshService{}, err
	}
	return s.GetMeshService(ctx, svc.TenantID, svc.ID)
}

// UpdateMeshServiceCert updates a service's cert fields after a renewal.
func (s *SQLStore) UpdateMeshServiceCert(ctx context.Context, tenantID, id, certID, certCN string, certExpiry time.Time) error {
	_, err := s.db.SQL().ExecContext(ctx, `
UPDATE mesh_services
SET cert_id = $1, cert_cn = $2, cert_expiry = $3,
    cert_status = 'valid', last_renewed_at = CURRENT_TIMESTAMP
WHERE tenant_id = $4 AND id = $5
`,
		strings.TrimSpace(certID),
		strings.TrimSpace(certCN),
		certExpiry.UTC(),
		strings.TrimSpace(tenantID),
		strings.TrimSpace(id),
	)
	return err
}

// CreateMeshCertificate inserts a new mesh certificate record.
func (s *SQLStore) CreateMeshCertificate(ctx context.Context, cert MeshCertificate) (MeshCertificate, error) {
	sanJSON := mustJSON(cert.SANs)
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO mesh_certificates (
    id, tenant_id, service_id, service_name, cn, san_json, issuer,
    not_before, not_after, serial, fingerprint, key_algorithm, revoked, created_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
`,
		strings.TrimSpace(cert.ID),
		strings.TrimSpace(cert.TenantID),
		strings.TrimSpace(cert.ServiceID),
		strings.TrimSpace(cert.ServiceName),
		strings.TrimSpace(cert.CN),
		sanJSON,
		strings.TrimSpace(cert.Issuer),
		cert.NotBefore.UTC(),
		cert.NotAfter.UTC(),
		strings.TrimSpace(cert.Serial),
		strings.TrimSpace(cert.Fingerprint),
		strings.TrimSpace(cert.KeyAlgorithm),
		cert.Revoked,
		cert.CreatedAt.UTC(),
	)
	if err != nil {
		return MeshCertificate{}, err
	}
	return cert, nil
}

// ListMeshCertificates returns all mesh certificates for a tenant.
func (s *SQLStore) ListMeshCertificates(ctx context.Context, tenantID string) ([]MeshCertificate, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, service_id, service_name, cn, san_json, issuer,
       not_before, not_after, serial, fingerprint, key_algorithm, revoked, created_at
FROM mesh_certificates
WHERE tenant_id = $1
ORDER BY created_at DESC
`, strings.TrimSpace(tenantID))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]MeshCertificate, 0)
	for rows.Next() {
		c, scanErr := scanMeshCertificate(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListTrustAnchors returns all trust anchors for a tenant.
func (s *SQLStore) ListTrustAnchors(ctx context.Context, tenantID string) ([]TrustAnchor, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, name, fingerprint, subject, not_before, not_after, created_at
FROM mesh_trust_anchors
WHERE tenant_id = $1
ORDER BY created_at DESC
`, strings.TrimSpace(tenantID))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]TrustAnchor, 0)
	for rows.Next() {
		ta, scanErr := scanTrustAnchor(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, ta)
	}
	return out, rows.Err()
}

// CreateTrustAnchor inserts a new trust anchor.
func (s *SQLStore) CreateTrustAnchor(ctx context.Context, ta TrustAnchor) (TrustAnchor, error) {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO mesh_trust_anchors (
    id, tenant_id, name, fingerprint, subject, not_before, not_after, created_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
`,
		strings.TrimSpace(ta.ID),
		strings.TrimSpace(ta.TenantID),
		strings.TrimSpace(ta.Name),
		strings.TrimSpace(ta.Fingerprint),
		strings.TrimSpace(ta.Subject),
		ta.NotBefore.UTC(),
		ta.NotAfter.UTC(),
		ta.CreatedAt.UTC(),
	)
	if err != nil {
		return TrustAnchor{}, err
	}
	return ta, nil
}

// GetMeshTopology returns the topology edges for a tenant.
func (s *SQLStore) GetMeshTopology(ctx context.Context, tenantID string) ([]MeshTopologyEdge, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, from_service, to_service, mtls_verified, last_handshake_at
FROM mesh_topology
WHERE tenant_id = $1
ORDER BY from_service, to_service
`, strings.TrimSpace(tenantID))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]MeshTopologyEdge, 0)
	for rows.Next() {
		var edge MeshTopologyEdge
		var lastHsRaw interface{}
		if scanErr := rows.Scan(&edge.TenantID, &edge.FromService, &edge.ToService, &edge.MTLSVerified, &lastHsRaw); scanErr != nil {
			return nil, scanErr
		}
		if lastHsRaw != nil {
			t := parseTimeValue(lastHsRaw)
			if !t.IsZero() {
				edge.LastHandshakeAt = &t
			}
		}
		out = append(out, edge)
	}
	return out, rows.Err()
}

// UpsertTopologyEdge inserts or updates a topology edge.
func (s *SQLStore) UpsertTopologyEdge(ctx context.Context, edge MeshTopologyEdge) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO mesh_topology (tenant_id, from_service, to_service, mtls_verified, last_handshake_at)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (tenant_id, from_service, to_service) DO UPDATE SET
    mtls_verified = EXCLUDED.mtls_verified,
    last_handshake_at = EXCLUDED.last_handshake_at
`,
		strings.TrimSpace(edge.TenantID),
		strings.TrimSpace(edge.FromService),
		strings.TrimSpace(edge.ToService),
		edge.MTLSVerified,
		nullableTime(func() time.Time {
			if edge.LastHandshakeAt != nil {
				return *edge.LastHandshakeAt
			}
			return time.Time{}
		}()),
	)
	return err
}

// --- scan helpers ---

func scanMeshService(row interface{ Scan(...interface{}) error }) (MeshService, error) {
	var svc MeshService
	var certExpiryRaw, lastRenewedRaw, createdAtRaw interface{}
	var anchorsJSON string
	err := row.Scan(
		&svc.ID, &svc.TenantID, &svc.Name, &svc.Namespace, &svc.Endpoint,
		&svc.CertID, &svc.CertCN, &certExpiryRaw,
		&svc.CertStatus, &lastRenewedRaw, &svc.AutoRenew, &svc.RenewDaysBefore,
		&anchorsJSON, &svc.MTLSEnabled, &createdAtRaw,
	)
	if err != nil {
		return MeshService{}, err
	}
	svc.CreatedAt = parseTimeValue(createdAtRaw)
	if certExpiryRaw != nil {
		t := parseTimeValue(certExpiryRaw)
		if !t.IsZero() {
			svc.CertExpiry = &t
		}
	}
	if lastRenewedRaw != nil {
		t := parseTimeValue(lastRenewedRaw)
		if !t.IsZero() {
			svc.LastRenewedAt = &t
		}
	}
	svc.TrustAnchors = parseJSONArrayStringCT(anchorsJSON)
	return svc, nil
}

func scanMeshCertificate(row interface{ Scan(...interface{}) error }) (MeshCertificate, error) {
	var c MeshCertificate
	var sanJSON string
	var notBeforeRaw, notAfterRaw, createdAtRaw interface{}
	err := row.Scan(
		&c.ID, &c.TenantID, &c.ServiceID, &c.ServiceName,
		&c.CN, &sanJSON, &c.Issuer,
		&notBeforeRaw, &notAfterRaw,
		&c.Serial, &c.Fingerprint, &c.KeyAlgorithm, &c.Revoked, &createdAtRaw,
	)
	if err != nil {
		return MeshCertificate{}, err
	}
	c.NotBefore = parseTimeValue(notBeforeRaw)
	c.NotAfter = parseTimeValue(notAfterRaw)
	c.CreatedAt = parseTimeValue(createdAtRaw)
	c.SANs = parseJSONArrayStringCT(sanJSON)
	return c, nil
}

func scanTrustAnchor(row interface{ Scan(...interface{}) error }) (TrustAnchor, error) {
	var ta TrustAnchor
	var notBeforeRaw, notAfterRaw, createdAtRaw interface{}
	err := row.Scan(
		&ta.ID, &ta.TenantID, &ta.Name, &ta.Fingerprint, &ta.Subject,
		&notBeforeRaw, &notAfterRaw, &createdAtRaw,
	)
	if err != nil {
		return TrustAnchor{}, err
	}
	ta.NotBefore = parseTimeValue(notBeforeRaw)
	ta.NotAfter = parseTimeValue(notAfterRaw)
	ta.CreatedAt = parseTimeValue(createdAtRaw)
	return ta, nil
}
