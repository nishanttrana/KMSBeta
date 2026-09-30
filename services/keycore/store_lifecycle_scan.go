package main

import (
	"context"
	"strings"
	"time"
)

// LifecycleCandidate is the SQL projection consumed by the lifecycle
// scan. Only the fields required to decide on an action are pulled so
// the scan stays light: a single row per key, no labels, no KCV, no
// material. The full key record is fetched on-demand if the reconciler
// needs to act.
type LifecycleCandidate struct {
	ID         string
	TenantID   string
	Algorithm  string
	KeyType    string
	Purpose    string
	Status     string
	CreatedAt  time.Time
	UpdatedAt  time.Time
	OpsTotal   int64
	OpsLimit   int64
	ExpiryDate *time.Time
}

// ScanLifecycleCandidates walks the cross-tenant `keys` table and
// returns active rows that are plausibly due for rotation. "Plausibly" is
// intentional: the SQL filter is permissive (updated_at older than 1 day,
// ops_total near ops_limit, or expiry reached), and the Go-side evaluator
// applies the strict rules. Splitting the work this way keeps the query simple — it can
// run from a read replica without a custom expiry index — while
// preserving the full cryptoperiod / grace-period decision logic.
//
// The scan caps at `limit` rows; the reconciler asks for at most 200 so
// a single tick never blows up a downstream worker pool.
func (s *SQLStore) ScanLifecycleCandidates(ctx context.Context, limit int) ([]LifecycleCandidate, error) {
	if limit <= 0 || limit > 5000 {
		limit = 200
	}
	// updated_at < now() - 1 day OR ops_total >= 0.8 * ops_limit (when set).
	// The "1 day" floor avoids re-scanning keys that were just rotated.
	// The Postgres COALESCE keeps the comparison sane when ops_limit is
	// zero (i.e., no ops cap — the key is only a cryptoperiod candidate).
	rows, err := s.db.ROSQL().QueryContext(ctx, `
SELECT id, tenant_id, algorithm, key_type, purpose, status,
       created_at, updated_at,
       COALESCE(ops_total, 0), COALESCE(ops_limit, 0), expiry_date
FROM keys
WHERE status = 'active'
  AND (
        updated_at < $1
        OR (ops_limit > 0 AND ops_total >= ops_limit * 8 / 10)
        OR (expiry_date IS NOT NULL AND expiry_date <= $2)
      )
ORDER BY updated_at ASC
LIMIT $3
`, time.Now().UTC().Add(-24*time.Hour), time.Now().UTC(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]LifecycleCandidate, 0, limit)
	for rows.Next() {
		var c LifecycleCandidate
		var expiry *time.Time
		if err := rows.Scan(&c.ID, &c.TenantID, &c.Algorithm, &c.KeyType, &c.Purpose,
			&c.Status, &c.CreatedAt, &c.UpdatedAt, &c.OpsTotal, &c.OpsLimit, &expiry); err != nil {
			return nil, err
		}
		c.ExpiryDate = expiry
		out = append(out, c)
	}
	return out, rows.Err()
}

// EvaluateLifecycle applies keycore's rotation rules to one candidate and
// returns the action the reconciler should take ("rotate"), plus a short
// reason. Returns ("", "") when nothing is due.
//
// The rule order matters: an explicit operator date (expiry_date) wins over
// the policy cryptoperiod, which wins over the ops_limit threshold.
//
// Destroy is never automatic. Until 5.3.0-beta this also returned "destroy"
// for compromised keys and for deactivated keys past a 30-day grace, but
// keycore's destroy route requires pre-destroy acknowledgements the
// reconciler never sent, so every such call was refused; and an unattended,
// irreversible destroy belongs behind a governance approval (a playbook), not
// a timer.
func EvaluateLifecycle(c LifecycleCandidate, cp *CryptoperiodPolicy, now time.Time) (action, reason string) {
	return EvaluateLifecycleFor(c, cp, nil, now)
}

// EvaluateLifecycleFor is EvaluateLifecycle with the tenant's own
// cryptoperiods (by category) applied over the built-in table.
func EvaluateLifecycleFor(c LifecycleCandidate, cp *CryptoperiodPolicy, overrides map[string]time.Duration, now time.Time) (action, reason string) {
	if strings.ToLower(strings.TrimSpace(c.Status)) != StateActive {
		return "", ""
	}
	if c.ExpiryDate != nil && !c.ExpiryDate.IsZero() && !now.Before(*c.ExpiryDate) {
		return "rotate", "operator-set expiry reached"
	}
	if cp != nil && cp.IsExpiredFor(overrides, c.CreatedAt, c.Purpose, c.Algorithm, c.KeyType) {
		return "rotate", "cryptoperiod exceeded for category"
	}
	if c.OpsLimit > 0 && c.OpsTotal*10 >= c.OpsLimit*8 {
		return "rotate", "ops_total reached 80% of ops_limit"
	}
	return "", ""
}
