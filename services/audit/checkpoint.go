package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/route"
)

// Signed checkpoints (docs/SECURITY/AUDIT_INTEGRITY.md).
//
// Every checkpointInterval each node signs the head of each tenant chain it
// appends: {tenant, chain, sequence, chain_hash, signed_at}. The chain hash
// commits to every earlier event, so one signature covers the whole history
// up to the head.
//
// The key is ECDSA-P384, generated in memory when the service starts and
// never stored. Its public key is published as the audit event
// audit.audit.checkpoint_key_created, and each checkpoint is the audit
// event audit.audit.checkpoint_signed. Both are hash-chained, HMAC-signed,
// replicated like every audit event and delivered to event streams (SIEM),
// so copies of the keys and checkpoints exist outside this database.

const (
	actionCheckpointSigned     = "audit.audit.checkpoint_signed"
	actionCheckpointKeyCreated = "audit.audit.checkpoint_key_created"
	actionCheckpointRefused    = "audit.audit.checkpoint_refused"

	checkpointAlgorithm = pkgcrypto.AlgECDSAP384
	checkpointFormat    = "vecta-audit-checkpoint/1"
	checkpointInterval  = 10 * time.Minute
	// Key registrations are platform events, recorded under the root tenant.
	checkpointKeyTenant = "root"
)

// Checkpoint verification outcomes.
const (
	checkpointVerified     = "verified"
	checkpointKeyUnknown   = "key_unknown"
	checkpointBadSignature = "signature_invalid"
	checkpointHeadMismatch = "head_mismatch"
)

// checkpointHead is exactly what a checkpoint signs.
type checkpointHead struct {
	Format    string `json:"format"`
	TenantID  string `json:"tenant_id"`
	ChainNode string `json:"chain_node"`
	Sequence  int64  `json:"sequence"`
	ChainHash string `json:"chain_hash"`
	SignedAt  string `json:"signed_at"`
}

func (h checkpointHead) message() []byte {
	raw, _ := json.Marshal(h)
	return raw
}

// checkpoint is a checkpoint_signed event read back from the chain.
type checkpoint struct {
	EventID   string
	Head      checkpointHead
	KeyID     string
	Algorithm string
	Signature string
}

func checkpointFromEvent(ev AuditEvent) (checkpoint, bool) {
	if ev.Action != actionCheckpointSigned {
		return checkpoint{}, false
	}
	d := ev.Details
	cp := checkpoint{
		EventID: ev.ID, KeyID: str(d["key_id"]), Algorithm: str(d["algorithm"]), Signature: str(d["signature"]),
		Head: checkpointHead{
			Format: str(d["format"]), TenantID: ev.TenantID, ChainNode: str(d["chain_node"]),
			Sequence: detailInt(d["sequence"]), ChainHash: str(d["chain_hash"]), SignedAt: str(d["signed_at"]),
		},
	}
	return cp, cp.Head.Sequence > 0 && cp.Head.ChainHash != ""
}

func detailInt(v interface{}) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case int64:
		return x
	case int:
		return int64(x)
	case json.Number:
		n, _ := x.Int64()
		return n
	}
	return 0
}

// ---- signing ----

type checkpointSigner struct {
	keyID string
	sign  func(msg []byte) ([]byte, error)
}

type checkpointState struct {
	mu     sync.Mutex
	signer *checkpointSigner
}

// checkpointSigner returns this process's signer, creating the key and
// recording its public key on first use. No checkpoint is signed with a key
// whose registration was not recorded.
func (s *Service) checkpointSigner(ctx context.Context, sq *SQLStore) (*checkpointSigner, error) {
	s.checkpoints.mu.Lock()
	defer s.checkpoints.mu.Unlock()
	if s.checkpoints.signer != nil {
		return s.checkpoints.signer, nil
	}
	kp, err := pkgcrypto.GenerateKeyPair(checkpointAlgorithm)
	if err != nil {
		s.refuseCheckpoint(ctx, checkpointKeyTenant, "key_generation_failed", err)
		return nil, err
	}
	keyID, err := pkgcrypto.FingerprintPublicKey(kp.Public)
	if err != nil {
		return nil, err
	}
	pemBytes, err := pkgcrypto.MarshalPublicKeyPEM(kp.Public)
	if err != nil {
		return nil, err
	}
	if _, err := s.ProcessEvent(ctx, AuditEvent{
		TenantID: checkpointKeyTenant, Service: "audit", Action: actionCheckpointKeyCreated,
		ActorID: "system", ActorType: "service", TargetType: "audit_checkpoint_key", TargetID: keyID, Result: "success",
		Details: map[string]interface{}{
			"algorithm": checkpointAlgorithm, "public_key_pem": string(pemBytes), "chain_node": sq.chainNode(ctx),
			"description": "audit checkpoint signing key created in memory; the private key is never stored",
		},
	}); err != nil {
		return nil, fmt.Errorf("record checkpoint key: %w", err)
	}
	sq.cpKeys.add(keyID, kp.Public)
	s.checkpoints.signer = &checkpointSigner{keyID: keyID, sign: func(msg []byte) ([]byte, error) { return pkgcrypto.Sign(kp, msg) }}
	return s.checkpoints.signer, nil
}

// SignCheckpoints signs the head of every tenant chain this node appends
// that has moved since its last checkpoint, and returns how many it signed.
func (s *Service) SignCheckpoints(ctx context.Context) (int, error) {
	sq, ok := s.store.(*SQLStore)
	if !ok {
		return 0, nil
	}
	signer, err := s.checkpointSigner(ctx, sq)
	if err != nil {
		return 0, err
	}
	heads, err := sq.chainHeads(ctx)
	if err != nil {
		return 0, err
	}
	signed := 0
	for _, h := range heads {
		if h.action == actionCheckpointSigned {
			continue // nothing new since the last checkpoint
		}
		head := checkpointHead{
			Format: checkpointFormat, TenantID: h.tenant, ChainNode: h.node,
			Sequence: h.sequence, ChainHash: h.hash, SignedAt: canonicalTimestamp(time.Now()),
		}
		sig, err := signer.sign(head.message())
		if err != nil {
			s.refuseCheckpoint(ctx, h.tenant, "signing_failed", err)
			continue
		}
		if _, err := s.ProcessEvent(ctx, AuditEvent{
			TenantID: h.tenant, Service: "audit", Action: actionCheckpointSigned,
			ActorID: "system", ActorType: "service", TargetType: "audit_chain", TargetID: chainLabel(h.node), Result: "success",
			Details: map[string]interface{}{
				"format": head.Format, "chain_node": head.ChainNode, "sequence": head.Sequence, "chain_hash": head.ChainHash,
				"signed_at": head.SignedAt, "key_id": signer.keyID, "algorithm": checkpointAlgorithm,
				"signature": base64.StdEncoding.EncodeToString(sig),
			},
		}); err != nil {
			return signed, err
		}
		signed++
	}
	return signed, nil
}

// checkpointLoop signs checkpoints now and then every checkpointInterval.
func (s *Service) checkpointLoop(ctx context.Context, logf func(string, ...interface{})) {
	t := time.NewTicker(checkpointInterval)
	defer t.Stop()
	for {
		if n, err := s.SignCheckpoints(ctx); err != nil {
			logf("audit checkpoints: %v", err)
		} else if n > 0 {
			logf("audit checkpoints signed: %d", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Service) refuseCheckpoint(ctx context.Context, tenantID, reason string, err error) {
	_, _ = s.ProcessEvent(ctx, AuditEvent{
		TenantID: tenantID, Service: "audit", Action: actionCheckpointRefused,
		ActorID: "system", ActorType: "service", TargetType: "audit_chain", Result: "refused", ErrorMessage: err.Error(),
		Details: map[string]interface{}{"reason": reason, "error": err.Error(), "algorithm": checkpointAlgorithm},
	})
}

func chainLabel(node string) string {
	if node == "" {
		return "local"
	}
	return node
}

type chainHead struct {
	tenant, node, hash, action string
	sequence                   int64
}

// chainHeads returns the newest row of each tenant chain this node appends.
func (s *SQLStore) chainHeads(ctx context.Context) ([]chainHead, error) {
	self := s.chainNode(ctx)
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT DISTINCT tenant_id FROM audit_events WHERE chain_node IN ('', $1)`, self)
	if err != nil {
		return nil, err
	}
	var tenants []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			_ = rows.Close()
			return nil, err
		}
		tenants = append(tenants, t)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	heads := make([]chainHead, 0, len(tenants))
	for _, t := range tenants {
		h := chainHead{tenant: t, node: self}
		if err := s.db.SQL().QueryRowContext(ctx, `
SELECT sequence, chain_hash, action FROM audit_events
WHERE tenant_id=$1 AND chain_node IN ('', $2) ORDER BY sequence DESC LIMIT 1
`, t, self).Scan(&h.sequence, &h.hash, &h.action); err != nil {
			return nil, err
		}
		heads = append(heads, h)
	}
	return heads, nil
}

// ---- verification ----

// checkpointKeys holds the public keys checkpoints are verified with: this
// process's own key, and keys proven by a registration event whose content
// and HMAC verify. A key found in the database alone is never trusted.
type checkpointKeys struct {
	mu   sync.RWMutex
	byID map[string]interface{}
}

func (k *checkpointKeys) add(id string, pub interface{}) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.byID == nil {
		k.byID = map[string]interface{}{}
	}
	k.byID[id] = pub
}

func (k *checkpointKeys) get(id string) (interface{}, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	pub, ok := k.byID[id]
	return pub, ok
}

// checkpointKey returns the trusted public key keyID names.
func (s *SQLStore) checkpointKey(ctx context.Context, keyID string) (interface{}, bool, error) {
	if pub, ok := s.cpKeys.get(keyID); ok {
		return pub, true, nil
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT `+chainRowColumns+` FROM audit_events WHERE tenant_id=$1 AND action=$2 AND target_id=$3
`, checkpointKeyTenant, actionCheckpointKeyCreated, keyID)
	if err != nil {
		return nil, false, err
	}
	var regs []AuditEvent
	for rows.Next() {
		ev, err := scanChainRow(rows, checkpointKeyTenant)
		if err != nil {
			_ = rows.Close()
			return nil, false, err
		}
		regs = append(regs, ev)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	for _, ev := range regs {
		if chainHash(ev.PreviousHash, eventHashInput(ev)) != ev.ChainHash || ev.HMACSig == "" {
			continue
		}
		if ok, known := s.keys.verify(ev.ChainHash, ev.HMACSig, ev.HMACKeyID); !ok || !known {
			continue
		}
		if str(ev.Details["algorithm"]) != checkpointAlgorithm {
			continue
		}
		pub, err := pkgcrypto.ParsePublicKeyPEM(str(ev.Details["public_key_pem"]))
		if err != nil {
			continue
		}
		if fp, err := pkgcrypto.FingerprintPublicKey(pub); err != nil || fp != keyID {
			continue
		}
		s.cpKeys.add(keyID, pub)
		return pub, true, nil
	}
	return nil, false, nil
}

// verifyCheckpointSignature checks cp's signature under a trusted key.
func (s *SQLStore) verifyCheckpointSignature(ctx context.Context, cp checkpoint) (string, error) {
	pub, ok, err := s.checkpointKey(ctx, cp.KeyID)
	if err != nil {
		return "", err
	}
	if !ok {
		return checkpointKeyUnknown, nil
	}
	sig, err := base64.StdEncoding.DecodeString(cp.Signature)
	if err != nil || cp.Algorithm != checkpointAlgorithm || cp.Head.Format != checkpointFormat ||
		pkgcrypto.Verify(checkpointAlgorithm, pub, cp.Head.message(), sig) != nil {
		return checkpointBadSignature, nil
	}
	return checkpointVerified, nil
}

// chainNodes is the chain_node pair selecting ev's chain: this node's rows
// are ” or self, a replicated chain's are its node's.
func chainNodes(node, self string) []interface{} {
	if node == "" || node == self {
		return []interface{}{"", self}
	}
	return []interface{}{node, node}
}

// segmentLinked reports whether the stored rows from..to of one chain are
// contiguous, each linked to the one before, and end at the signed head.
func (s *SQLStore) segmentLinked(ctx context.Context, tenantID string, nodes []interface{}, from, to int64, head string) (bool, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT sequence, previous_hash, chain_hash FROM audit_events
WHERE tenant_id=$1 AND chain_node IN ($2, $3) AND sequence >= $4 AND sequence <= $5
ORDER BY sequence ASC
`, tenantID, nodes[0], nodes[1], from, to)
	if err != nil {
		return false, err
	}
	defer rows.Close() //nolint:errcheck
	next, last := from, ""
	for rows.Next() {
		var seq int64
		var prev, hash string
		if err := rows.Scan(&seq, &prev, &hash); err != nil {
			return false, err
		}
		if seq != next || (seq > from && prev != last) {
			return false, rows.Err()
		}
		last, next = hash, next+1
	}
	return next == to+1 && last == head, rows.Err()
}

// coveringCheckpoint returns the first checkpoint of ev's chain whose signed
// head is at or after ev.
func (s *SQLStore) coveringCheckpoint(ctx context.Context, tenantID string, nodes []interface{}, seq int64) (checkpoint, bool, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT `+chainRowColumns+` FROM audit_events
WHERE tenant_id=$1 AND action=$2 AND chain_node IN ($3, $4) AND sequence > $5
ORDER BY sequence ASC LIMIT 20
`, tenantID, actionCheckpointSigned, nodes[0], nodes[1], seq)
	if err != nil {
		return checkpoint{}, false, err
	}
	defer rows.Close() //nolint:errcheck
	for rows.Next() {
		ev, err := scanChainRow(rows, tenantID)
		if err != nil {
			return checkpoint{}, false, err
		}
		if cp, ok := checkpointFromEvent(ev); ok && cp.Head.Sequence >= seq {
			return cp, true, nil
		}
	}
	return checkpoint{}, false, rows.Err()
}

// loadCheckpoints returns every checkpoint recorded in a tenant's chains.
func (s *SQLStore) loadCheckpoints(ctx context.Context, tenantID string, limit int) ([]checkpoint, error) {
	q := `SELECT ` + chainRowColumns + ` FROM audit_events WHERE tenant_id=$1 AND action=$2 ORDER BY timestamp DESC, sequence DESC`
	args := []interface{}{tenantID, actionCheckpointSigned}
	if limit > 0 {
		q += ` LIMIT $3`
		args = append(args, limit)
	}
	rows, err := s.db.SQL().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []checkpoint
	for rows.Next() {
		ev, err := scanChainRow(rows, tenantID)
		if err != nil {
			return nil, err
		}
		if cp, ok := checkpointFromEvent(ev); ok {
			out = append(out, cp)
		}
	}
	return out, rows.Err()
}

// CheckpointStatus is one checkpoint as the API reports it: the signed
// message, signature and public key an outside verifier needs, and the
// result of checking it against what is stored now.
type CheckpointStatus struct {
	EventID      string `json:"event_id"`
	ChainNode    string `json:"chain_node,omitempty"`
	Sequence     int64  `json:"sequence"`
	ChainHash    string `json:"chain_hash"`
	SignedAt     string `json:"signed_at"`
	KeyID        string `json:"key_id"`
	Algorithm    string `json:"algorithm"`
	Message      string `json:"message"`
	Signature    string `json:"signature"`
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
	Status       string `json:"status"` // verified | key_unknown | signature_invalid | head_mismatch
}

// ListCheckpoints returns a tenant's newest checkpoints, each verified: the
// signature under a trusted key, and the signed head against the stored row.
func (s *SQLStore) ListCheckpoints(ctx context.Context, tenantID string, limit int) ([]CheckpointStatus, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	cps, err := s.loadCheckpoints(ctx, tenantID, limit)
	if err != nil {
		return nil, err
	}
	self := s.chainNode(ctx)
	out := make([]CheckpointStatus, 0, len(cps))
	for _, cp := range cps {
		st := CheckpointStatus{
			EventID: cp.EventID, ChainNode: cp.Head.ChainNode, Sequence: cp.Head.Sequence, ChainHash: cp.Head.ChainHash,
			SignedAt: cp.Head.SignedAt, KeyID: cp.KeyID, Algorithm: cp.Algorithm, Message: string(cp.Head.message()), Signature: cp.Signature,
		}
		if st.Status, err = s.verifyCheckpointSignature(ctx, cp); err != nil {
			return nil, err
		}
		if st.Status == checkpointVerified {
			if pub, ok := s.cpKeys.get(cp.KeyID); ok {
				if pemBytes, err := pkgcrypto.MarshalPublicKeyPEM(pub); err == nil {
					st.PublicKeyPEM = string(pemBytes)
				}
			}
			nodes := chainNodes(cp.Head.ChainNode, self)
			ok, err := s.segmentLinked(ctx, tenantID, nodes, cp.Head.Sequence, cp.Head.Sequence, cp.Head.ChainHash)
			if err != nil {
				return nil, err
			}
			if !ok {
				st.Status = checkpointHeadMismatch
			}
		}
		out = append(out, st)
	}
	return out, nil
}

// ListCheckpoints lists checkpoints; any that fail verification raise the
// critical audit.audit.chain_broken, as a whole-chain break does.
func (s *Service) ListCheckpoints(ctx context.Context, tenantID string, limit int) ([]CheckpointStatus, error) {
	items, err := s.store.ListCheckpoints(ctx, tenantID, limit)
	if err != nil {
		return nil, err
	}
	var breaks []map[string]interface{}
	for _, it := range items {
		if it.Status != checkpointVerified {
			breaks = append(breaks, map[string]interface{}{"event_id": it.EventID, "sequence": it.Sequence, "chain_node": it.ChainNode, "reason": "checkpoint_" + it.Status})
		}
	}
	if len(breaks) > 0 {
		s.reportChainBroken(ctx, AuditEvent{
			TenantID: tenantID, Service: "audit", Action: "audit.audit.chain_broken",
			ActorID: "system", ActorType: "system", Result: "failure", TargetType: "audit_trail",
			Details: map[string]interface{}{"scope": "checkpoints", "break_count": len(breaks), "breaks": breaks},
		})
	}
	return items, nil
}

func (h *Handler) listCheckpoints(c *route.Call) {
	items, err := h.svc.ListCheckpoints(c.R.Context(), c.Tenant, atoi(c.R.URL.Query().Get("limit")))
	if err != nil {
		c.Error(http.StatusInternalServerError, "query_failed", "checkpoints could not be read")
		return
	}
	failed := 0
	for _, it := range items {
		if it.Status != checkpointVerified {
			failed++
		}
	}
	c.Detail("checkpoints", len(items))
	c.Detail("failed", failed)
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}
