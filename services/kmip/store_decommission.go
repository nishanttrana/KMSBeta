package main

import (
	"context"
	"time"
)

// ListAllKMIPClients returns every registered client across all tenants.
// Used by the auto-decommission reconciler; the per-tenant List variant
// remains the right call for tenant-scoped UIs.
func (s *SQLStore) ListAllKMIPClients(ctx context.Context) ([]KMIPClient, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, profile_id, name, role, status, enrollment_mode,
       cert_id, cert_subject, cert_issuer, cert_serial, cert_fingerprint_sha256,
       cert_not_before, cert_not_after, created_at, updated_at
FROM kmip_clients
ORDER BY tenant_id, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]KMIPClient, 0)
	for rows.Next() {
		var c KMIPClient
		var notBefore, notAfter, createdAt, updatedAt interface{}
		if err := rows.Scan(&c.ID, &c.TenantID, &c.ProfileID, &c.Name, &c.Role, &c.Status,
			&c.EnrollmentMode, &c.CertID, &c.CertSubject, &c.CertIssuer, &c.CertSerial,
			&c.CertFingerprintSHA256, &notBefore, &notAfter, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		c.CertNotBefore = parseTimeValue(notBefore)
		c.CertNotAfter = parseTimeValue(notAfter)
		c.CreatedAt = parseTimeValue(createdAt)
		c.UpdatedAt = parseTimeValue(updatedAt)
		out = append(out, c)
	}
	return out, rows.Err()
}

// UpdateKMIPClientStatus flips a client's status (active → dormant or
// dormant → revoked). The row's updated_at is bumped so subsequent
// decommission scans see fresh activity-or-revocation state.
func (s *SQLStore) UpdateKMIPClientStatus(ctx context.Context, tenantID, clientID, status string) error {
	_, err := s.db.SQL().ExecContext(ctx, `
UPDATE kmip_clients
SET status = $1, updated_at = $2
WHERE tenant_id = $3 AND id = $4`,
		status, time.Now().UTC(), tenantID, clientID)
	return err
}
