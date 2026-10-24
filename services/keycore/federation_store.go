package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Storage for key federation (federation.go, migration 038).

type FederationIdentity struct {
	TenantID      string
	KEMSeedSealed string // crypto.EnvelopeCiphertext JSON under the MEK
	SignKeySealed string
	KEMPublic     string // base64 ML-KEM-768 encapsulation key
	SignPublicPEM string
	Fingerprint   string
	CreatedAt     time.Time
}

type FederationPeer struct {
	TenantID      string    `json:"tenant_id"`
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	URL           string    `json:"url"`
	PeerTenantID  string    `json:"peer_tenant_id"`
	KEMPublic     string    `json:"kem_public"`
	SignPublicPEM string    `json:"sign_public_pem"`
	Fingerprint   string    `json:"fingerprint"`
	CAPEM         string    `json:"ca_pem,omitempty"`
	ClientID      string    `json:"client_id"`
	APIKeySealed  string    `json:"-"`
	CreatedBy     string    `json:"created_by"`
	CreatedAt     time.Time `json:"created_at"`
}

type FederationLink struct {
	TenantID   string     `json:"tenant_id"`
	ID         string     `json:"id"`
	KeyID      string     `json:"key_id"`
	PeerID     string     `json:"peer_id"`
	Status     string     `json:"status"`
	LastDigest string     `json:"-"`
	LastSyncAt *time.Time `json:"last_sync_at,omitempty"`
	LastError  string     `json:"last_error,omitempty"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
}

type FederationKeyState struct {
	TenantID           string     `json:"tenant_id"`
	KeyID              string     `json:"key_id"`
	Role               string     `json:"role"`
	Epoch              int64      `json:"epoch"`
	SourcePeerID       string     `json:"source_peer_id,omitempty"`
	PrimaryFingerprint string     `json:"primary_fingerprint,omitempty"`
	LastAppliedAt      *time.Time `json:"last_applied_at,omitempty"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

func (s *SQLStore) GetFederationIdentity(ctx context.Context, tenantID string) (FederationIdentity, error) {
	var id FederationIdentity
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, kem_seed_sealed, sign_key_sealed, kem_public, sign_public_pem, fingerprint, created_at
FROM key_federation_identities WHERE tenant_id=$1`, tenantID).Scan(&id.TenantID, &id.KEMSeedSealed, &id.SignKeySealed,
		&id.KEMPublic, &id.SignPublicPEM, &id.Fingerprint, &id.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return id, errStoreNotFound
	}
	return id, err
}

// CreateFederationIdentity stores the tenant's identity unless one exists
// (two nodes creating at once keep the first).
func (s *SQLStore) CreateFederationIdentity(ctx context.Context, id FederationIdentity) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO key_federation_identities (tenant_id, kem_seed_sealed, sign_key_sealed, kem_public, sign_public_pem, fingerprint, created_at)
VALUES ($1,$2,$3,$4,$5,$6,CURRENT_TIMESTAMP) ON CONFLICT (tenant_id) DO NOTHING`,
		id.TenantID, id.KEMSeedSealed, id.SignKeySealed, id.KEMPublic, id.SignPublicPEM, id.Fingerprint)
	return err
}

const peerColumns = `tenant_id, id, name, url, peer_tenant_id, kem_public, sign_public_pem, fingerprint, ca_pem, client_id, api_key_sealed, created_by, created_at`

func scanPeer(row interface{ Scan(...any) error }) (FederationPeer, error) {
	var p FederationPeer
	err := row.Scan(&p.TenantID, &p.ID, &p.Name, &p.URL, &p.PeerTenantID, &p.KEMPublic, &p.SignPublicPEM, &p.Fingerprint,
		&p.CAPEM, &p.ClientID, &p.APIKeySealed, &p.CreatedBy, &p.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return p, errStoreNotFound
	}
	return p, err
}

func (s *SQLStore) ListFederationPeers(ctx context.Context, tenantID string) ([]FederationPeer, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT `+peerColumns+` FROM key_federation_peers WHERE tenant_id=$1 ORDER BY name`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []FederationPeer{}
	for rows.Next() {
		p, err := scanPeer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetFederationPeer(ctx context.Context, tenantID, id string) (FederationPeer, error) {
	return scanPeer(s.db.SQL().QueryRowContext(ctx, `SELECT `+peerColumns+` FROM key_federation_peers WHERE tenant_id=$1 AND id=$2`, tenantID, id))
}

func (s *SQLStore) GetFederationPeerByFingerprint(ctx context.Context, tenantID, fingerprint string) (FederationPeer, error) {
	return scanPeer(s.db.SQL().QueryRowContext(ctx, `SELECT `+peerColumns+` FROM key_federation_peers WHERE tenant_id=$1 AND fingerprint=$2`, tenantID, fingerprint))
}

func (s *SQLStore) CreateFederationPeer(ctx context.Context, p FederationPeer) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO key_federation_peers (`+peerColumns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,CURRENT_TIMESTAMP)`,
		p.TenantID, p.ID, p.Name, p.URL, p.PeerTenantID, p.KEMPublic, p.SignPublicPEM, p.Fingerprint, p.CAPEM, p.ClientID, p.APIKeySealed, p.CreatedBy)
	if err != nil && isUniqueViolation(err) {
		return errFederationPeerExists
	}
	return err
}

func (s *SQLStore) DeleteFederationPeer(ctx context.Context, tenantID, id string) error {
	res, err := s.db.SQL().ExecContext(ctx, `DELETE FROM key_federation_peers WHERE tenant_id=$1 AND id=$2`, tenantID, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errStoreNotFound
	}
	return nil
}

const linkColumns = `tenant_id, id, key_id, peer_id, status, last_digest, last_sync_at, last_error, created_by, created_at`

func scanLink(row interface{ Scan(...any) error }) (FederationLink, error) {
	var l FederationLink
	var last sql.NullTime
	err := row.Scan(&l.TenantID, &l.ID, &l.KeyID, &l.PeerID, &l.Status, &l.LastDigest, &last, &l.LastError, &l.CreatedBy, &l.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return l, errStoreNotFound
	}
	if last.Valid {
		t := last.Time
		l.LastSyncAt = &t
	}
	return l, err
}

func (s *SQLStore) queryLinks(ctx context.Context, q string, args ...any) ([]FederationLink, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT `+linkColumns+` FROM key_federation_links `+q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []FederationLink{}
	for rows.Next() {
		l, err := scanLink(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func (s *SQLStore) ListFederationLinks(ctx context.Context, tenantID string) ([]FederationLink, error) {
	return s.queryLinks(ctx, `WHERE tenant_id=$1 ORDER BY created_at, id`, tenantID)
}

// ListAllFederationLinks is every tenant's links, for the sync loop.
func (s *SQLStore) ListAllFederationLinks(ctx context.Context) ([]FederationLink, error) {
	return s.queryLinks(ctx, `ORDER BY tenant_id, created_at, id`)
}

func (s *SQLStore) GetFederationLink(ctx context.Context, tenantID, id string) (FederationLink, error) {
	return scanLink(s.db.SQL().QueryRowContext(ctx, `SELECT `+linkColumns+` FROM key_federation_links WHERE tenant_id=$1 AND id=$2`, tenantID, id))
}

func (s *SQLStore) CreateFederationLink(ctx context.Context, l FederationLink) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO key_federation_links (tenant_id, id, key_id, peer_id, status, created_by, created_at)
VALUES ($1,$2,$3,$4,$5,$6,CURRENT_TIMESTAMP)`, l.TenantID, l.ID, l.KeyID, l.PeerID, l.Status, l.CreatedBy)
	if err != nil && isUniqueViolation(err) {
		return errFederationLinkExists
	}
	return err
}

func (s *SQLStore) UpdateFederationLinkSync(ctx context.Context, tenantID, id, status, digest, lastError string, at time.Time) error {
	_, err := s.db.SQL().ExecContext(ctx, `
UPDATE key_federation_links SET status=$3, last_digest=$4, last_error=$5, last_sync_at=$6 WHERE tenant_id=$1 AND id=$2`,
		tenantID, id, status, digest, lastError, at.UTC())
	return err
}

func (s *SQLStore) DeleteFederationLink(ctx context.Context, tenantID, id string) error {
	res, err := s.db.SQL().ExecContext(ctx, `DELETE FROM key_federation_links WHERE tenant_id=$1 AND id=$2`, tenantID, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errStoreNotFound
	}
	return nil
}

func (s *SQLStore) CountFederationLinksForPeer(ctx context.Context, tenantID, peerID string) (int, error) {
	var n int
	err := s.db.SQL().QueryRowContext(ctx, `SELECT COUNT(*) FROM key_federation_links WHERE tenant_id=$1 AND peer_id=$2`, tenantID, peerID).Scan(&n)
	return n, err
}

func (s *SQLStore) GetFederationKeyState(ctx context.Context, tenantID, keyID string) (FederationKeyState, error) {
	var st FederationKeyState
	var applied sql.NullTime
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, key_id, role, epoch, source_peer_id, primary_fingerprint, last_applied_at, updated_at
FROM key_federation_state WHERE tenant_id=$1 AND key_id=$2`, tenantID, keyID).Scan(&st.TenantID, &st.KeyID, &st.Role, &st.Epoch,
		&st.SourcePeerID, &st.PrimaryFingerprint, &applied, &st.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return st, errStoreNotFound
	}
	if applied.Valid {
		t := applied.Time
		st.LastAppliedAt = &t
	}
	return st, err
}

func upsertFederationStateTx(ctx context.Context, tx *sql.Tx, st FederationKeyState) error {
	var applied any
	if st.LastAppliedAt != nil {
		applied = st.LastAppliedAt.UTC()
	}
	_, err := tx.ExecContext(ctx, `
INSERT INTO key_federation_state (tenant_id, key_id, role, epoch, source_peer_id, primary_fingerprint, last_applied_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,CURRENT_TIMESTAMP)
ON CONFLICT (tenant_id, key_id) DO UPDATE SET role=excluded.role, epoch=excluded.epoch, source_peer_id=excluded.source_peer_id,
    primary_fingerprint=excluded.primary_fingerprint, last_applied_at=excluded.last_applied_at, updated_at=CURRENT_TIMESTAMP`,
		st.TenantID, st.KeyID, st.Role, st.Epoch, st.SourcePeerID, st.PrimaryFingerprint, applied)
	return err
}

func (s *SQLStore) PutFederationKeyState(ctx context.Context, st FederationKeyState) error {
	return s.withTenantTx(ctx, st.TenantID, func(tx *sql.Tx) error { return upsertFederationStateTx(ctx, tx, st) })
}

// ApplyFederatedKey writes a replica as one transaction: the key row
// (created, or its metadata and status replaced), versions it doesn't have
// yet, every version's status, and its federation state. Existing material
// is never replaced; the caller checked the versions agree.
func (s *SQLStore) ApplyFederatedKey(ctx context.Context, key Key, create bool, newVersions []KeyVersion, statuses map[int]string, st FederationKeyState) error {
	return s.withTenantTx(ctx, key.TenantID, func(tx *sql.Tx) error {
		labels, _ := json.Marshal(key.Labels)
		compliance, _ := json.Marshal(key.Compliance)
		tags, _ := json.Marshal(key.Tags)
		if create {
			if _, err := tx.ExecContext(ctx, `
INSERT INTO keys (
    id, tenant_id, name, algorithm, key_type, purpose, status, current_version, kcv, kcv_algorithm,
    iv_mode, owner, cloud, region, compliance, labels, tags, export_allowed, ops_total, ops_encrypt, ops_decrypt, ops_sign,
    ops_limit, ops_limit_window, ops_last_reset, approval_required, created_by, created_at, updated_at, description
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,0,0,0,0,0,'',CURRENT_TIMESTAMP,FALSE,$19,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,$20)`,
				key.ID, key.TenantID, key.Name, key.Algorithm, key.KeyType, key.Purpose, key.Status, key.CurrentVersion, key.KCV, key.KCVAlgorithm,
				key.IVMode, key.Owner, key.Cloud, key.Region, compliance, labels, tags, key.ExportAllowed, key.CreatedBy, key.Description); err != nil {
				return err
			}
		} else {
			if _, err := tx.ExecContext(ctx, `
UPDATE keys SET name=$3, description=$4, algorithm=$5, purpose=$6, status=$7, current_version=$8, kcv=$9, kcv_algorithm=$10,
    iv_mode=$11, owner=$12, labels=$13, tags=$14, export_allowed=$15, updated_at=CURRENT_TIMESTAMP
WHERE tenant_id=$1 AND id=$2`, key.TenantID, key.ID, key.Name, key.Description, key.Algorithm, key.Purpose, key.Status,
				key.CurrentVersion, key.KCV, key.KCVAlgorithm, key.IVMode, key.Owner, labels, tags, key.ExportAllowed); err != nil {
				return err
			}
		}
		for _, v := range newVersions {
			if _, err := tx.ExecContext(ctx, `
INSERT INTO key_versions (
    id, tenant_id, key_id, version, encrypted_material, material_iv, wrapped_dek, public_key, kcv,
    rotated_from, rotation_reason, status, created_at, protection, hsm_label, algorithm
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,CURRENT_TIMESTAMP,$13,$14,$15)`,
				v.ID, key.TenantID, key.ID, v.Version, v.EncryptedMaterial, v.MaterialIV, v.WrappedDEK, nullableBytes(v.PublicKey), v.KCV,
				nullableInt(v.RotatedFrom), "federation", v.Status, protectionOf(v), v.HSMLabel, nullable(v.Algorithm)); err != nil {
				return err
			}
		}
		for ver, status := range statuses {
			if _, err := tx.ExecContext(ctx, `UPDATE key_versions SET status=$4 WHERE tenant_id=$1 AND key_id=$2 AND version=$3`,
				key.TenantID, key.ID, ver, status); err != nil {
				return err
			}
		}
		return upsertFederationStateTx(ctx, tx, st)
	})
}

func isUniqueViolation(err error) bool {
	m := strings.ToLower(err.Error())
	return strings.Contains(m, "unique") || strings.Contains(m, "duplicate key")
}
