package main

import (
	"context"
	"encoding/hex"
	"time"

	"vecta-kms/pkg/clusterstate"
)

// Cluster-wide login lockout (docs/CLUSTERING.md, slice 3b).
//
// The in-memory limiter counts failures per node. In a cluster every node also
// records each attempt in auth_login_attempts, a shared-append table that
// replicates between all nodes, and a login is refused when the failures for
// its lockout key since the last success, across all nodes and within the
// lockout window, reach the policy maximum. Replication takes a moment, so a
// burst spread over nodes can exceed the maximum by what lands in flight.

type LoginAttempt struct {
	ID         string
	ChainNode  string
	TenantID   string
	KeyHash    string
	Succeeded  bool
	OccurredAt time.Time
}

func lockoutKeyHash(rlKey string) string { return hex.EncodeToString(tokenHash(rlKey)) }

// clusterChainNode is this node's cluster id, "" while standalone.
func clusterChainNode(ctx context.Context) string { return clusterstate.Default().Get(ctx).ChainNode() }

// recordLoginAttempt stores an attempt when this node is clustered.
func (h *Handler) recordLoginAttempt(ctx context.Context, tenantID, rlKey string, succeeded bool) {
	node := clusterChainNode(ctx)
	if node == "" {
		return
	}
	_ = h.store.RecordLoginAttempt(ctx, LoginAttempt{
		ID: NewID("lat"), ChainNode: node, TenantID: tenantID, KeyHash: lockoutKeyHash(rlKey),
		Succeeded: succeeded, OccurredAt: time.Now().UTC(),
	})
}

// clusterLocked reports whether the cluster's recorded failures lock rlKey.
func (h *Handler) clusterLocked(ctx context.Context, rlKey string, maxFails int, window time.Duration, now time.Time) (time.Time, bool) {
	if clusterChainNode(ctx) == "" || maxFails <= 0 || window <= 0 {
		return time.Time{}, false
	}
	attempts, err := h.store.RecentLoginAttempts(ctx, lockoutKeyHash(rlKey), now.Add(-window), maxFails+1)
	if err != nil {
		return time.Time{}, false // the per-node limiter still applies
	}
	failures := 0
	var newest time.Time
	for _, a := range attempts { // newest first
		if a.Succeeded {
			break
		}
		if failures == 0 {
			newest = a.OccurredAt
		}
		failures++
	}
	if failures < maxFails {
		return time.Time{}, false
	}
	until := newest.Add(window)
	return until, now.Before(until)
}

func (s *SQLStore) RecordLoginAttempt(ctx context.Context, a LoginAttempt) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO auth_login_attempts (id, chain_node, tenant_id, key_hash, succeeded, occurred_at) VALUES ($1,$2,$3,$4,$5,$6)`,
		a.ID, a.ChainNode, a.TenantID, a.KeyHash, a.Succeeded, a.OccurredAt.UTC())
	return err
}

func (s *SQLStore) RecentLoginAttempts(ctx context.Context, keyHash string, since time.Time, limit int) ([]LoginAttempt, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, chain_node, tenant_id, key_hash, succeeded, occurred_at FROM auth_login_attempts
WHERE key_hash = $1 AND occurred_at > $2 ORDER BY occurred_at DESC LIMIT $3`, keyHash, since.UTC(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []LoginAttempt{}
	for rows.Next() {
		var a LoginAttempt
		if err := rows.Scan(&a.ID, &a.ChainNode, &a.TenantID, &a.KeyHash, &a.Succeeded, &a.OccurredAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// PruneLoginAttempts deletes this node's copy of old attempts. The table is
// published insert-only, so deletes stay local to each node.
func (s *SQLStore) PruneLoginAttempts(ctx context.Context, before time.Time) error {
	_, err := s.db.SQL().ExecContext(ctx, `DELETE FROM auth_login_attempts WHERE occurred_at < $1`, before.UTC())
	return err
}
