package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

// ListRecentEvaluations returns the most recent evaluation records for the
// tenant since the given moment, capped at limit. Used by the dry-run
// simulator to replay historical operations against a candidate policy.
func (s *SQLStore) ListRecentEvaluations(ctx context.Context, tenantID string, since time.Time, limit int) ([]EvaluationRecord, error) {
	if limit <= 0 || limit > 5_000 {
		limit = 1_000
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, COALESCE(policy_id,'') , operation, COALESCE(key_id,''),
       decision, COALESCE(reason,''), request_json, outcomes_json, occurred_at
FROM   policy_evaluations
WHERE  tenant_id = $1 AND occurred_at >= $2
ORDER  BY occurred_at DESC
LIMIT  $3`, tenantID, since.UTC(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	out := make([]EvaluationRecord, 0, limit)
	for rows.Next() {
		var (
			rec        EvaluationRecord
			reqJSON    string
			outJSON    string
			occurredAt time.Time
			decision   string
			policyID   string
			keyID      string
			reason     string
		)
		if err := rows.Scan(&rec.ID, &rec.TenantID, &policyID, &rec.Operation, &keyID,
			&decision, &reason, &reqJSON, &outJSON, &occurredAt); err != nil {
			return nil, err
		}
		rec.PolicyID = policyID
		rec.KeyID = keyID
		rec.Decision = Decision(decision)
		rec.Reason = reason
		rec.OccurredAt = occurredAt
		_ = json.Unmarshal([]byte(reqJSON), &rec.Request)
		_ = json.Unmarshal([]byte(outJSON), &rec.Outcomes)
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	return out, nil
}
