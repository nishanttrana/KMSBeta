package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// failoverStore on Postgres (migrations/004_failover.sql).

func (s *SQLStore) LoadNode(ctx context.Context) (nodeState, error) {
	var st nodeState
	var until sql.NullTime
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT node_id, role, primary_node_id, primary_url, primary_fingerprint, forward_credential, epoch, writable_until, peer_secret
FROM cluster_local_state WHERE id = 1`).Scan(&st.NodeID, &st.Role, &st.PrimaryNodeID, &st.PrimaryURL, &st.PrimaryFingerprint,
		&st.ForwardCredential, &st.Epoch, &until, &st.PeerSecret)
	if errors.Is(err, sql.ErrNoRows) {
		return nodeState{}, nil
	}
	if until.Valid {
		st.WritableUntil = until.Time.UTC()
	}
	return st, err
}

func nullTime(t time.Time) interface{} {
	if t.IsZero() {
		return nil
	}
	return t.UTC()
}

func (s *SQLStore) SaveNode(ctx context.Context, st nodeState) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO cluster_local_state (id, node_id, role, primary_node_id, primary_url, primary_fingerprint, forward_credential, epoch, writable_until, peer_secret, updated_at)
VALUES (1,$1,$2,$3,$4,$5,$6,$7,$8,$9,CURRENT_TIMESTAMP)
ON CONFLICT (id) DO UPDATE SET node_id = EXCLUDED.node_id, role = EXCLUDED.role, primary_node_id = EXCLUDED.primary_node_id,
	primary_url = EXCLUDED.primary_url, primary_fingerprint = EXCLUDED.primary_fingerprint, forward_credential = EXCLUDED.forward_credential,
	epoch = EXCLUDED.epoch, writable_until = EXCLUDED.writable_until, peer_secret = EXCLUDED.peer_secret, updated_at = CURRENT_TIMESTAMP`,
		st.NodeID, st.Role, st.PrimaryNodeID, st.PrimaryURL, st.PrimaryFingerprint, st.ForwardCredential, st.Epoch, nullTime(st.WritableUntil), st.PeerSecret)
	return err
}

func (s *SQLStore) SetLease(ctx context.Context, until time.Time) error {
	_, err := s.db.SQL().ExecContext(ctx, `UPDATE cluster_local_state SET writable_until = $1 WHERE id = 1`, nullTime(until))
	return err
}

func (s *SQLStore) Peers(ctx context.Context) ([]peer, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT node_id, url, fingerprint, credential_hash, components_json, is_primary FROM cluster_peers ORDER BY node_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []peer{}
	for rows.Next() {
		var p peer
		var comps string
		if err := rows.Scan(&p.NodeID, &p.URL, &p.Fingerprint, &p.CredentialHash, &comps, &p.IsPrimary); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(comps), &p.Components)
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpsertPeer(ctx context.Context, p peer) error {
	comps, _ := json.Marshal(p.Components)
	if p.Components == nil {
		comps = []byte("[]")
	}
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO cluster_peers (node_id, url, fingerprint, credential_hash, components_json, is_primary, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,CURRENT_TIMESTAMP)
ON CONFLICT (node_id) DO UPDATE SET url = EXCLUDED.url, fingerprint = EXCLUDED.fingerprint, credential_hash = EXCLUDED.credential_hash,
	components_json = EXCLUDED.components_json, is_primary = EXCLUDED.is_primary, updated_at = CURRENT_TIMESTAMP`,
		p.NodeID, p.URL, p.Fingerprint, p.CredentialHash, string(comps), p.IsPrimary)
	return err
}

func (s *SQLStore) DeletePeer(ctx context.Context, nodeID string) error {
	_, err := s.db.SQL().ExecContext(ctx, `DELETE FROM cluster_peers WHERE node_id = $1`, nodeID)
	return err
}

// Vote records this node's vote in epoch; false if it already voted there
// for another candidate.
func (s *SQLStore) Vote(ctx context.Context, epoch int64, candidate string) (bool, error) {
	if _, err := s.db.SQL().ExecContext(ctx, `INSERT INTO cluster_votes (epoch, voted_for) VALUES ($1,$2) ON CONFLICT (epoch) DO NOTHING`, epoch, candidate); err != nil {
		return false, err
	}
	var got string
	if err := s.db.SQL().QueryRowContext(ctx, `SELECT voted_for FROM cluster_votes WHERE epoch = $1`, epoch).Scan(&got); err != nil {
		return false, err
	}
	return got == candidate, nil
}

func (s *SQLStore) MaxVoteEpoch(ctx context.Context) (int64, error) {
	var n sql.NullInt64
	err := s.db.SQL().QueryRowContext(ctx, `SELECT max(epoch) FROM cluster_votes`).Scan(&n)
	return n.Int64, err
}

func (s *SQLStore) ActiveMemberCredentials(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT node_id, credential_hash FROM cluster_member_credentials WHERE revoked_at IS NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := map[string]string{}
	for rows.Next() {
		var id, hash string
		if err := rows.Scan(&id, &hash); err != nil {
			return nil, err
		}
		out[id] = hash
	}
	return out, rows.Err()
}
