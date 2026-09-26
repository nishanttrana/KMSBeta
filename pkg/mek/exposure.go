package mek

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	pkgaudit "vecta-kms/pkg/audit"
	pkgauth "vecta-kms/pkg/auth"
)

// The exposure register lists items whose material was stored under a public
// key. Moving the row onto the service key protects the live database, but a
// copy made before that (a pg_dump, a volume snapshot, a downloaded backup)
// still opens with the public key. So the item stays exposed until the
// material itself is replaced: the service marks it remediated when the value
// is rotated, re-issued or deleted, or an administrator acknowledges it with
// a reason. Every change is audited.

// Exposure is one register entry.
type Exposure struct {
	TenantID     string     `json:"tenant_id"`
	ItemType     string     `json:"item_type"`
	ItemID       string     `json:"item_id"`
	Source       string     `json:"source"`
	ExposedSince time.Time  `json:"exposed_since"`
	RemediatedAt *time.Time `json:"remediated_at,omitempty"`
	Remediation  string     `json:"remediation,omitempty"`
	RemediatedBy string     `json:"remediated_by,omitempty"`
}

// SchemaSQL is the DDL for a service's state and exposure tables. Each
// service's migration carries the same statements (checked by a test).
func SchemaSQL(st ServiceTables) string {
	return fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    key_id          TEXT NOT NULL,
    key_version     INTEGER NOT NULL,
    mek_fingerprint TEXT NOT NULL,
    rewrapped       BIGINT NOT NULL DEFAULT 0,
    unreadable      BIGINT NOT NULL DEFAULT 0,
    migrated_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS %s (
    tenant_id     TEXT NOT NULL,
    item_type     TEXT NOT NULL,
    item_id       TEXT NOT NULL,
    source        TEXT NOT NULL,
    exposed_since TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    remediated_at TIMESTAMP,
    remediation   TEXT NOT NULL DEFAULT '',
    remediated_by TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, item_type, item_id)
);
`, st.StateTable, st.ExposureTable)
}

// recordExposure opens (or re-opens) an item's register entry.
func recordExposure(ctx context.Context, db *sql.DB, table, tenant, itemType, itemID, source string) error {
	_, err := db.ExecContext(ctx, `
INSERT INTO `+table+` (tenant_id, item_type, item_id, source, exposed_since)
VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)
ON CONFLICT (tenant_id, item_type, item_id) DO UPDATE SET
  source = excluded.source, remediated_at = NULL, remediation = '', remediated_by = ''`,
		tenant, itemType, itemID, source)
	return err
}

// Exposures lists a tenant's register entries; openOnly drops remediated ones.
func (k *Keyring) Exposures(ctx context.Context, tenant string, openOnly bool) ([]Exposure, error) {
	q := `SELECT tenant_id, item_type, item_id, source, exposed_since, remediated_at, remediation, remediated_by
FROM ` + k.opts.Tables.ExposureTable + ` WHERE tenant_id = $1`
	if openOnly {
		q += ` AND remediated_at IS NULL`
	}
	rows, err := k.opts.DB.QueryContext(ctx, q+` ORDER BY exposed_since, item_type, item_id`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []Exposure{}
	for rows.Next() {
		var e Exposure
		var rem sql.NullTime
		if err := rows.Scan(&e.TenantID, &e.ItemType, &e.ItemID, &e.Source, &e.ExposedSince, &rem, &e.Remediation, &e.RemediatedBy); err != nil {
			return nil, err
		}
		if rem.Valid {
			t := rem.Time
			e.RemediatedAt = &t
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Remediate closes an open entry: the item's material was replaced (how:
// "rotated", "reissued", "deleted", ...) or acknowledged ("acknowledged: <reason>").
// It reports whether an open entry was closed, and audits it.
func (k *Keyring) Remediate(ctx context.Context, tenant, itemType, itemID, how, by string) (bool, error) {
	res, err := k.opts.DB.ExecContext(ctx, `
UPDATE `+k.opts.Tables.ExposureTable+` SET remediated_at = CURRENT_TIMESTAMP, remediation = $1, remediated_by = $2
WHERE tenant_id = $3 AND item_type = $4 AND item_id = $5 AND remediated_at IS NULL`,
		how, by, tenant, itemType, itemID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil || n == 0 {
		return false, err
	}
	severity := "info"
	if strings.HasPrefix(how, "acknowledged") {
		severity = "warning"
	}
	emit(ctx, k.opts.Audit, "mek_exposure_remediated", tenant, pkgaudit.Event{ActorID: by, TargetType: itemType, TargetID: itemID}, map[string]interface{}{
		"severity": severity, "remediation": how,
	})
	return true, nil
}

// Retire closes an item's entry because its material was replaced or
// deleted (how: "rotated", "deleted", "reissued"), attributed to the caller
// in ctx. It is safe on a nil Keyring (services built without one in tests).
func (k *Keyring) Retire(ctx context.Context, tenant, itemType, itemID, how string) {
	if k == nil {
		return
	}
	by := ""
	if c, ok := pkgauth.ClaimsFromContext(ctx); ok && c != nil {
		for _, v := range []string{c.UserID, c.ClientID, c.Subject} {
			if by = strings.TrimSpace(v); by != "" {
				break
			}
		}
	}
	if _, err := k.Remediate(ctx, tenant, itemType, itemID, how, by); err != nil {
		k.opts.Logf("exposure register: retire %s/%s: %v", itemType, itemID, err)
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func unb64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(strings.TrimSpace(s)) }
