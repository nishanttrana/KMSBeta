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
// returns rows that are plausibly due for a lifecycle transition.
// "Plausibly" is intentional: the SQL filter is permissive (status in
// (active, deactivated) and updated_at older than 1 day, or ops_total
// near ops_limit), and the Go-side evaluator applies the strict policy
// rules. Splitting the work this way keeps the query simple — it can
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
WHERE status IN ('active', 'deactivated', 'compromised')
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

// EvaluateLifecycle applies the keycore's lifecycle rules to one
// candidate and returns the action the reconciler should take, plus a
// short human-readable reason. Returns ("", "") when no action is due.
//
// The rule order matters: explicit operator dates (expiry_date) win
// over policy-derived cryptoperiods, which win over predictive
// rotation triggers. Without that ordering we'd race the operator and
// pre-empt a deliberate destroy date.
func EvaluateLifecycle(c LifecycleCandidate, cp *CryptoperiodPolicy, now time.Time) (action, reason string) {
	status := strings.ToLower(strings.TrimSpace(c.Status))

	switch status {
	case StateActive:
		// Operator-set destroy date is the most explicit signal.
		if c.ExpiryDate != nil && !c.ExpiryDate.IsZero() && !now.Before(*c.ExpiryDate) {
			return "rotate", "operator-set expiry reached"
		}
		// Cryptoperiod expiry.
		if cp != nil && cp.IsExpired(c.CreatedAt, c.Purpose, c.Algorithm, c.KeyType) {
			return "rotate", "cryptoperiod exceeded for category"
		}
		// Predictive: 80% of ops_limit triggers a rotate with a 24h
		// successor pre-create window. The keycore handler decides
		// whether to honour the predictive rotate or queue the
		// successor key only.
		if c.OpsLimit > 0 && c.OpsTotal*10 >= c.OpsLimit*8 {
			return "rotate", "ops_total reached 80% of ops_limit"
		}
		return "", ""

	case StateDeactivated:
		// Promote to destroy once the grace window has elapsed.
		if PastGrace(c.UpdatedAt) {
			return "destroy", "deactivation grace window elapsed"
		}
		return "", ""

	case StateCompromised:
		// Compromised keys always advance to destroyed; the reconciler
		// performs the move so the audit chain records who triggered it.
		return "destroy", "compromised key auto-destroy"

	default:
		return "", ""
	}
}
