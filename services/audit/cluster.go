package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	pkgaudit "vecta-kms/pkg/audit"
	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/clusterkey"
	"vecta-kms/pkg/clusterstate"
	pkgcrypto "vecta-kms/pkg/crypto"
	pkgevents "vecta-kms/pkg/events"
)

// Audit in a cluster (docs/CLUSTERING.md, slice 3b).
//
//   - Every node appends its own hash chain (chain_node) and the chains
//     replicate to every node (shared-append), so any node can search and
//     verify the whole cluster's audit.
//   - One audit signing key serves the cluster: a joining member receives the
//     primary's key sealed with ML-KEM (pkg/clusterkey), so every node signs
//     with it and verifies every chain's HMACs. Keys a node used before are
//     kept for verifying its older events.
//   - The primary relays members' events onto its own AUDIT stream, so its
//     compliance playbook triggers see the whole cluster.

const (
	auditKeyLabel          = "audit-signing-key"
	defaultClusterAuditKey = "/app/data/audit-cluster-signing-key.b64"
)

// ---- signing keyring ----

type signingKeys struct {
	mu        sync.RWMutex
	currentID string
	byID      map[string][]byte
}

func auditKeyID(key []byte) string { return clusterkey.Fingerprint(auditKeyLabel, key) }

// install makes key the signing key; earlier keys stay for verification.
func (k *signingKeys) install(key []byte) string {
	if len(key) == 0 {
		return ""
	}
	id := auditKeyID(key)
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.byID == nil {
		k.byID = map[string][]byte{}
	}
	k.byID[id] = append([]byte(nil), key...)
	k.currentID = id
	return id
}

func (k *signingKeys) current() ([]byte, string) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.byID[k.currentID], k.currentID
}

func (k *signingKeys) configured() bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return len(k.byID) > 0
}

func hmacHex(key []byte, chainHash string) string {
	mac, err := pkgcrypto.HMAC("SHA-256", key, []byte(chainHash))
	if err != nil {
		return ""
	}
	return hex.EncodeToString(mac)
}

// sign returns HMAC-SHA256(chain_hash) under the current key and its id.
func (k *signingKeys) sign(chainHash string) (string, string) {
	key, id := k.current()
	if len(key) == 0 {
		return "", ""
	}
	return hmacHex(key, chainHash), id
}

// verify checks a signature; known is false when no held key has keyID.
// Events from before key ids were recorded are checked against every key.
func (k *signingKeys) verify(chainHash, sig, keyID string) (ok, known bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	check := func(key []byte) bool {
		want, _ := hex.DecodeString(hmacHex(key, chainHash))
		got, err := hex.DecodeString(sig)
		return err == nil && pkgcrypto.ConstantTimeEqual(want, got)
	}
	if keyID != "" {
		key, have := k.byID[keyID]
		if !have {
			return false, false
		}
		return check(key), true
	}
	for _, key := range k.byID {
		if check(key) {
			return true, true
		}
	}
	return false, true
}

func clusterAuditKeyFile() string {
	if p := strings.TrimSpace(os.Getenv("AUDIT_CLUSTER_SIGNING_KEY_FILE")); p != "" {
		return p
	}
	return defaultClusterAuditKey
}

// loadClusterSigningKey installs a cluster key received at join, over the
// node's own configured key (kept for verifying the node's older events).
func loadClusterSigningKey(store *SQLStore, path string) error {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != 32 {
		return fmt.Errorf("cluster audit signing key %s is malformed", path)
	}
	store.keys.install(key)
	pkgcrypto.Zeroize(key)
	return nil
}

// ---- key transfer (cluster-manager only) ----

type clusterKeyState struct {
	joinKeys clusterkey.JoinKeys
	keyFile  string
}

func (h *Handler) clusterCaller(w http.ResponseWriter, r *http.Request, op string) bool {
	claims, _ := pkgauth.ClaimsFromContext(r.Context())
	if err := clusterkey.Caller(claims); err != nil {
		caller := ""
		if claims != nil {
			caller = claims.ClientID + claims.UserID
		}
		h.svc.auditCluster(r.Context(), "cluster_signing_key_refused", "refused", "warning", map[string]interface{}{
			"operation": op, "caller": caller, "reason": "service_identity_required",
		})
		writeErr(w, http.StatusForbidden, "service_identity_required", err.Error(), requestID(r), "")
		return false
	}
	return true
}

func (h *Handler) handleClusterKeyJoinKey(w http.ResponseWriter, r *http.Request) {
	if !h.clusterCaller(w, r, "join_key") {
		return
	}
	id, ek, err := h.svc.cluster.joinKeys.Create()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "join_key_failed", err.Error(), requestID(r), "")
		return
	}
	h.svc.auditCluster(r.Context(), "cluster_join_key_created", "success", "info", map[string]interface{}{"join_key_id": id})
	writeJSON(w, http.StatusOK, map[string]interface{}{"join_key_id": id, "encapsulation_key": ek})
}

func (h *Handler) handleClusterKeyExport(w http.ResponseWriter, r *http.Request) {
	if !h.clusterCaller(w, r, "export") {
		return
	}
	var req struct {
		EncapsulationKey string `json:"encapsulation_key"`
		Context          string `json:"context"`
		MemberNodeID     string `json:"member_node_id"`
	}
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.MemberNodeID) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "encapsulation_key, context and member_node_id are required", requestID(r), "")
		return
	}
	key, _ := h.svc.signing().current()
	if len(key) == 0 {
		writeErr(w, http.StatusConflict, "no_signing_key", "this node has no audit signing key (AUDIT_EVENT_SIGNING_KEY_B64)", requestID(r), "")
		return
	}
	sealed, fp, err := clusterkey.Seal(req.EncapsulationKey, key, req.Context, auditKeyLabel)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), requestID(r), "")
		return
	}
	h.svc.auditCluster(r.Context(), "cluster_signing_key_exported", "success", "critical", map[string]interface{}{
		"member_node_id": req.MemberNodeID, "context": req.Context, "key_id": fp,
		"description": "audit signing key sealed (ML-KEM-768) to a joining cluster member",
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{"sealed_key": sealed, "key_id": fp})
}

func (h *Handler) handleClusterKeyImport(w http.ResponseWriter, r *http.Request) {
	if !h.clusterCaller(w, r, "import") {
		return
	}
	var req struct {
		JoinKeyID string `json:"join_key_id"`
		SealedKey string `json:"sealed_key"`
		Context   string `json:"context"`
		KeyID     string `json:"key_id"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), requestID(r), "")
		return
	}
	key, err := h.svc.cluster.joinKeys.Open(req.JoinKeyID, req.SealedKey, req.Context, auditKeyLabel, req.KeyID)
	if err != nil {
		h.svc.auditCluster(r.Context(), "cluster_signing_key_refused", "refused", "warning", map[string]interface{}{
			"operation": "import", "reason": err.Error(),
		})
		writeErr(w, http.StatusBadRequest, "import_refused", err.Error(), requestID(r), "")
		return
	}
	defer pkgcrypto.Zeroize(key)
	if len(key) != 32 {
		writeErr(w, http.StatusBadRequest, "import_refused", "audit signing key must be 32 bytes", requestID(r), "")
		return
	}
	if err := clusterkey.WriteFileAtomic(h.svc.cluster.keyFile, []byte(base64.StdEncoding.EncodeToString(key))); err != nil {
		writeErr(w, http.StatusInternalServerError, "store_failed", err.Error(), requestID(r), "")
		return
	}
	id := h.svc.signing().install(key)
	h.svc.auditCluster(r.Context(), "cluster_signing_key_imported", "success", "critical", map[string]interface{}{
		"context": req.Context, "key_id": id,
		"description": "cluster audit signing key installed; this node now signs its chain with it",
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{"key_id": id})
}

// auditCluster records one of the audit service's own cluster events.
func (s *Service) auditCluster(ctx context.Context, action, result, severity string, details map[string]interface{}) {
	details["severity"] = severity
	details["result"] = result
	_, _, _ = s.ProcessEvent(ctx, AuditEvent{
		TenantID: "root", Service: "audit", Action: "audit.audit." + action,
		ActorID: clusterkey.ClusterManager, ActorType: "service", Result: result,
		Timestamp: time.Now().UTC(), Details: details,
	})
}

func (s *Service) signing() *signingKeys {
	if sq, ok := s.store.(*SQLStore); ok {
		return sq.keys
	}
	return &signingKeys{}
}

// ---- relay of members' events on the primary ----

// RelayMemberEvents republishes events that other nodes' chains brought in by
// replication onto this node's AUDIT stream, once each (audit_relay_cursor).
// It runs only on a node that runs primary jobs and is clustered.
func (s *SQLStore) RelayMemberEvents(ctx context.Context, pub *pkgevents.Publisher, batch int) (int, error) {
	self := s.chainNode(ctx)
	if self == "" || !clusterstate.RunsPrimaryJobs(ctx) {
		return 0, nil
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT e.tenant_id, e.chain_node, COALESCE(MAX(c.last_sequence), 0)
FROM (SELECT DISTINCT tenant_id, chain_node FROM audit_events WHERE chain_node NOT IN ('', $1)) e
LEFT JOIN audit_relay_cursor c ON c.tenant_id = e.tenant_id AND c.chain_node = e.chain_node
GROUP BY e.tenant_id, e.chain_node`, self)
	if err != nil {
		return 0, err
	}
	type chain struct {
		tenant, node string
		after        int64
	}
	var chains []chain
	for rows.Next() {
		var c chain
		if err := rows.Scan(&c.tenant, &c.node, &c.after); err != nil {
			rows.Close() //nolint:errcheck
			return 0, err
		}
		chains = append(chains, c)
	}
	rows.Close() //nolint:errcheck
	relayed := 0
	for _, c := range chains {
		evs, err := s.eventsAfter(ctx, c.tenant, c.node, c.after, batch)
		if err != nil {
			return relayed, err
		}
		for _, ev := range evs {
			if err := pkgaudit.Relay(ctx, pub, relayEvent(ev)); err != nil {
				return relayed, err
			}
			if _, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO audit_relay_cursor (tenant_id, chain_node, last_sequence) VALUES ($1,$2,$3)
ON CONFLICT (tenant_id, chain_node) DO UPDATE SET last_sequence = EXCLUDED.last_sequence`, c.tenant, c.node, ev.Sequence); err != nil {
				return relayed, err
			}
			relayed++
		}
	}
	return relayed, nil
}

func (s *SQLStore) eventsAfter(ctx context.Context, tenantID, chainNode string, after int64, limit int) ([]AuditEvent, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, sequence, chain_hash, previous_hash,
       COALESCE(hmac_sig,''), COALESCE(category_group,''),
       timestamp, service, action, actor_id, actor_type,
       COALESCE(target_type,''), COALESCE(target_id,''), COALESCE(method,''), COALESCE(endpoint,''), COALESCE(CAST(source_ip AS TEXT),''), COALESCE(user_agent,''),
       COALESCE(request_hash,''), COALESCE(correlation_id,''), COALESCE(parent_event_id,''), COALESCE(session_id,''),
       result, COALESCE(status_code,0), COALESCE(error_message,''), COALESCE(duration_ms,0), COALESCE(fips_compliant,false), COALESCE(approval_id,''),
       COALESCE(risk_score,0), COALESCE(tags,'[]'), COALESCE(node_id,''), COALESCE(details,'{}'), created_at
FROM audit_events WHERE tenant_id=$1 AND chain_node=$2 AND sequence > $3
ORDER BY sequence ASC LIMIT $4`, tenantID, chainNode, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []AuditEvent{}
	for rows.Next() {
		ev, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		ev.ChainNode = chainNode
		out = append(out, ev)
	}
	return out, rows.Err()
}

func relayEvent(ev AuditEvent) pkgaudit.Event {
	nodeID := ev.NodeID
	if nodeID == "" {
		nodeID = ev.ChainNode
	}
	return pkgaudit.Event{
		ID: ev.ID, TenantID: ev.TenantID, Service: ev.Service, Action: ev.Action,
		ActorID: ev.ActorID, ActorType: ev.ActorType, TargetType: ev.TargetType, TargetID: ev.TargetID,
		Result: ev.Result, StatusCode: ev.StatusCode, ErrorMessage: ev.ErrorMessage,
		SourceIP: ev.SourceIP, UserAgent: ev.UserAgent, Method: ev.Method, Endpoint: ev.Endpoint,
		CorrelationID: ev.CorrelationID, ParentEventID: ev.ParentEventID, SessionID: ev.SessionID,
		RiskScore: ev.RiskScore, DurationMS: ev.DurationMS, Tags: ev.Tags, NodeID: nodeID,
		Details: ev.Details, Timestamp: ev.Timestamp.UTC().Format(time.RFC3339Nano),
	}
}

// EventExists reports whether the chain already holds an event id.
func (s *SQLStore) EventExists(ctx context.Context, tenantID, id string) (bool, error) {
	var n int
	err := s.db.SQL().QueryRowContext(ctx, `SELECT COUNT(1) FROM audit_events WHERE tenant_id=$1 AND id=$2`, tenantID, id).Scan(&n)
	return n > 0, err
}

// isRelayedDuplicate: a relayed event whose id is already persisted (it came
// in by replication). Anything else, relay-marked or not, is persisted.
func (s *Service) isRelayedDuplicate(ctx context.Context, ev AuditEvent) bool {
	if ev.ID == "" || ev.Details == nil || ev.Details["origin"] != pkgaudit.OriginClusterRelay {
		return false
	}
	sq, ok := s.store.(*SQLStore)
	if !ok {
		return false
	}
	exists, err := sq.EventExists(ctx, ev.TenantID, ev.ID)
	return err == nil && exists
}

// EnsureUpcomingPartitions creates this and next month's audit_events
// partitions. Replicated rows need their partition to exist on every node
// before they arrive, or the subscription stops.
func (s *SQLStore) EnsureUpcomingPartitions(ctx context.Context, now time.Time) error {
	if !s.isPostgres {
		return nil
	}
	tx, err := s.db.SQL().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	for _, t := range []time.Time{now, now.AddDate(0, 1, 0)} {
		if err := s.ensureAuditPartition(ctx, tx, t); err != nil {
			return err
		}
	}
	return tx.Commit()
}
