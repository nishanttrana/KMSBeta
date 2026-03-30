package imagesign

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"vecta-kms/pkg/db"
)

const imageSignMigration = `
CREATE TABLE IF NOT EXISTS image_signatures (
	id TEXT PRIMARY KEY,
	tenant_id TEXT NOT NULL,
	image_ref TEXT NOT NULL,
	digest TEXT NOT NULL,
	signature TEXT NOT NULL,
	signing_key_id TEXT NOT NULL,
	format TEXT NOT NULL DEFAULT 'atomic',
	payload TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_image_sig_tenant ON image_signatures(tenant_id);
CREATE INDEX IF NOT EXISTS idx_image_sig_digest ON image_signatures(digest);
CREATE INDEX IF NOT EXISTS idx_image_sig_image_ref ON image_signatures(image_ref);
`

// SignatureRecord is the persisted form of a container image signature.
type SignatureRecord struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	ImageRef     string    `json:"image_ref"`
	Digest       string    `json:"digest"`
	Signature    string    `json:"signature"`
	SigningKeyID string    `json:"signing_key_id"`
	Format       string    `json:"format"`
	Payload      string    `json:"payload"`
	CreatedAt    time.Time `json:"created_at"`
}

// Store persists image signatures in SQL.
type Store struct {
	database *db.DB
}

// NewStore creates a new image signature Store.
func NewStore(database *db.DB) *Store {
	return &Store{database: database}
}

// Migrate creates required tables.
func (s *Store) Migrate(ctx context.Context) error {
	_, err := s.database.SQL().ExecContext(ctx, imageSignMigration)
	if err != nil {
		return fmt.Errorf("imagesign: migrate: %w", err)
	}
	return nil
}

// Save inserts a signature record.
func (s *Store) Save(ctx context.Context, rec *SignatureRecord) error {
	const query = `
		INSERT INTO image_signatures (id, tenant_id, image_ref, digest, signature, signing_key_id, format, payload, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	_, err := s.database.SQL().ExecContext(ctx, query,
		rec.ID, rec.TenantID, rec.ImageRef, rec.Digest,
		rec.Signature, rec.SigningKeyID, rec.Format, rec.Payload, rec.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("imagesign: save: %w", err)
	}
	return nil
}

// GetByID retrieves a signature by ID.
func (s *Store) GetByID(ctx context.Context, id string) (*SignatureRecord, error) {
	const query = `
		SELECT id, tenant_id, image_ref, digest, signature, signing_key_id, format, payload, created_at
		FROM image_signatures WHERE id = $1
	`
	rec := &SignatureRecord{}
	err := s.database.SQL().QueryRowContext(ctx, query, id).Scan(
		&rec.ID, &rec.TenantID, &rec.ImageRef, &rec.Digest,
		&rec.Signature, &rec.SigningKeyID, &rec.Format, &rec.Payload, &rec.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("imagesign: signature %q not found", id)
	}
	if err != nil {
		return nil, fmt.Errorf("imagesign: get by id: %w", err)
	}
	return rec, nil
}

// GetByDigest retrieves all signatures for a given image digest.
func (s *Store) GetByDigest(ctx context.Context, digest string) ([]*SignatureRecord, error) {
	const query = `
		SELECT id, tenant_id, image_ref, digest, signature, signing_key_id, format, payload, created_at
		FROM image_signatures WHERE digest = $1 ORDER BY created_at DESC
	`
	rows, err := s.database.SQL().QueryContext(ctx, query, digest)
	if err != nil {
		return nil, fmt.Errorf("imagesign: get by digest: %w", err)
	}
	defer rows.Close()

	return scanSignatureRecords(rows)
}

// ListByImage retrieves all signatures for a given image reference.
func (s *Store) ListByImage(ctx context.Context, imageRef string) ([]*SignatureRecord, error) {
	const query = `
		SELECT id, tenant_id, image_ref, digest, signature, signing_key_id, format, payload, created_at
		FROM image_signatures WHERE image_ref = $1 ORDER BY created_at DESC
	`
	rows, err := s.database.SQL().QueryContext(ctx, query, imageRef)
	if err != nil {
		return nil, fmt.Errorf("imagesign: list by image: %w", err)
	}
	defer rows.Close()

	return scanSignatureRecords(rows)
}

// ListByTenant retrieves all signatures for a tenant.
func (s *Store) ListByTenant(ctx context.Context, tenantID string, limit int) ([]*SignatureRecord, error) {
	if limit <= 0 {
		limit = 100
	}
	const query = `
		SELECT id, tenant_id, image_ref, digest, signature, signing_key_id, format, payload, created_at
		FROM image_signatures WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2
	`
	rows, err := s.database.SQL().QueryContext(ctx, query, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("imagesign: list by tenant: %w", err)
	}
	defer rows.Close()

	return scanSignatureRecords(rows)
}

// Delete removes a signature record.
func (s *Store) Delete(ctx context.Context, id string) error {
	const query = `DELETE FROM image_signatures WHERE id = $1`
	result, err := s.database.SQL().ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("imagesign: delete: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("imagesign: signature %q not found", id)
	}
	return nil
}

func scanSignatureRecords(rows *sql.Rows) ([]*SignatureRecord, error) {
	var records []*SignatureRecord
	for rows.Next() {
		rec := &SignatureRecord{}
		if err := rows.Scan(
			&rec.ID, &rec.TenantID, &rec.ImageRef, &rec.Digest,
			&rec.Signature, &rec.SigningKeyID, &rec.Format, &rec.Payload, &rec.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("imagesign: scan: %w", err)
		}
		records = append(records, rec)
	}
	return records, rows.Err()
}
