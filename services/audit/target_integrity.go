package main

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"

	"vecta-kms/pkg/route"
)

// Per-target audit integrity: the proof the key "History & usage" panel
// shows for one key's audit trail. Every check recomputes from what is
// stored now (the row, its neighbours, the epoch's leaves) and compares with
// an independent record: the chain link, the HMAC, the root sealed with the
// epoch. Nothing is compared with a value derived from itself (learning.md
// 2026-09-27: the lineage "tamper check" did exactly that and always passed).

const maxTargetIntegrityEvents = 500

// Per-event check outcomes. Only the values in integrityFailures fail an
// event; unsigned, not_checked and pending are reported, not failed.
const (
	integrityIntact             = "intact"
	integrityAltered            = "altered"
	integrityLinked             = "linked"
	integrityGenesis            = "genesis"
	integrityAnchor             = "anchor"
	integrityBrokenLink         = "broken"
	integrityPredecessorMissing = "predecessor_missing"
	integrityVerified           = "verified"
	integrityUnsigned           = "unsigned"
	integrityNotChecked         = "not_checked"
	integrityMismatch           = "mismatch"
	integrityKeyUnknown         = "key_unknown"
	integritySealed             = "sealed"
	integrityPending            = "pending"
	integrityLeafMismatch       = "leaf_mismatch"
	integrityRootMismatch       = "root_mismatch"
	integrityEpochUnlinked      = "epoch_unlinked"
)

// EventIntegrity is the verification of one audit event.
type EventIntegrity struct {
	EventID     string       `json:"event_id"`
	Sequence    int64        `json:"sequence"`
	ChainNode   string       `json:"chain_node,omitempty"`
	Timestamp   time.Time    `json:"timestamp"`
	Action      string       `json:"action"`
	ActorID     string       `json:"actor_id"`
	Result      string       `json:"result"`
	Content     string       `json:"content"`   // intact | altered
	Link        string       `json:"link"`      // linked | genesis | anchor | broken | predecessor_missing
	Signature   string       `json:"signature"` // verified | unsigned | not_checked | mismatch | key_unknown
	Seal        string       `json:"seal"`      // sealed | pending | leaf_mismatch | root_mismatch | epoch_unlinked
	EpochID     string       `json:"epoch_id,omitempty"`
	EpochNumber int          `json:"epoch_number,omitempty"`
	Proof       *MerkleProof `json:"proof,omitempty"`
	Failures    []string     `json:"failures,omitempty"`
}

// TargetIntegrity is the verification of every audit event naming a target.
type TargetIntegrity struct {
	TargetID             string           `json:"target_id"`
	Verdict              string           `json:"verdict"` // intact | tampered | no_events
	EventsChecked        int              `json:"events_checked"`
	Failed               int              `json:"failed"`
	Sealed               int              `json:"sealed"`
	Pending              int              `json:"pending"`
	Unsigned             int              `json:"unsigned"`
	Truncated            bool             `json:"truncated"`
	SigningKeyConfigured bool             `json:"signing_key_configured"`
	VerifiedAt           time.Time        `json:"verified_at"`
	Events               []EventIntegrity `json:"events"`
}

type sealedEpoch struct {
	number   int
	tree     MerkleTree
	rootOK   bool
	linkedOK bool
	root     string
}

// VerifyTarget checks the newest limit audit events whose target_id is
// targetID: each row's content against its chain hash, its links to both
// neighbours in its chain, its HMAC, and, once sealed, its inclusion in the
// epoch root stored at sealing time.
func (s *SQLStore) VerifyTarget(ctx context.Context, tenantID, targetID string, limit int) (TargetIntegrity, error) {
	if limit <= 0 || limit > maxTargetIntegrityEvents {
		limit = maxTargetIntegrityEvents
	}
	out := TargetIntegrity{TargetID: targetID, VerifiedAt: time.Now().UTC(), SigningKeyConfigured: s.keys.configured()}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT `+chainRowColumns+`
FROM audit_events
WHERE tenant_id=$1 AND target_id=$2
ORDER BY timestamp DESC, sequence DESC
LIMIT $3
`, tenantID, targetID, limit+1)
	if err != nil {
		return out, err
	}
	var events []AuditEvent
	for rows.Next() {
		ev, err := scanChainRow(rows, tenantID)
		if err != nil {
			_ = rows.Close()
			return out, err
		}
		events = append(events, ev)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return out, err
	}
	if len(events) > limit {
		events, out.Truncated = events[:limit], true
	}

	self := s.chainNode(ctx)
	epochs := map[string]*sealedEpoch{}
	for _, ev := range events {
		r, err := s.verifyEvent(ctx, tenantID, self, ev, epochs)
		if err != nil {
			return out, err
		}
		if len(r.Failures) > 0 {
			out.Failed++
		}
		switch r.Seal {
		case integritySealed:
			out.Sealed++
		case integrityPending:
			out.Pending++
		}
		if r.Signature == integrityUnsigned {
			out.Unsigned++
		}
		out.Events = append(out.Events, r)
	}
	out.EventsChecked = len(out.Events)
	switch {
	case out.EventsChecked == 0:
		out.Verdict = "no_events"
	case out.Failed > 0:
		out.Verdict = "tampered"
	default:
		out.Verdict = integrityIntact
	}
	return out, nil
}

func (s *SQLStore) verifyEvent(ctx context.Context, tenantID, self string, ev AuditEvent, epochs map[string]*sealedEpoch) (EventIntegrity, error) {
	r := EventIntegrity{
		EventID: ev.ID, Sequence: ev.Sequence, ChainNode: ev.ChainNode, Timestamp: ev.Timestamp,
		Action: ev.Action, ActorID: ev.ActorID, Result: ev.Result,
	}
	fail := func(reason string) { r.Failures = append(r.Failures, reason) }

	// Content: the stored fields must reproduce the stored chain hash.
	recomputed := chainHash(ev.PreviousHash, eventHashInput(ev))
	r.Content = integrityIntact
	if recomputed != ev.ChainHash {
		r.Content = integrityAltered
		fail("content_altered")
	}

	// Links: the predecessor's chain hash is this row's previous_hash, and
	// the successor's previous_hash is this row's chain hash. A row rewritten
	// with a fresh chain hash passes the content check but breaks a link.
	link, err := s.checkLinks(ctx, tenantID, self, ev)
	if err != nil {
		return r, err
	}
	r.Link = link
	if link == integrityBrokenLink || link == integrityPredecessorMissing {
		fail("link_" + link)
	}

	// Signature: HMAC over the chain hash under a key the database never holds.
	switch {
	case ev.HMACSig == "":
		r.Signature = integrityUnsigned
	case !s.keys.configured():
		r.Signature = integrityNotChecked
	default:
		switch ok, known := s.keys.verify(ev.ChainHash, ev.HMACSig, ev.HMACKeyID); {
		case !known:
			r.Signature = integrityKeyUnknown
			fail("hmac_key_unknown")
		case !ok:
			r.Signature = integrityMismatch
			fail("hmac_mismatch")
		default:
			r.Signature = integrityVerified
		}
	}

	// Seal: the recomputed hash, walked up the epoch's tree, must reach the
	// root stored when the epoch was sealed.
	var epochID string
	var leafIndex int
	var leafHash string
	err = s.db.SQL().QueryRowContext(ctx, `
SELECT epoch_id, leaf_index, leaf_hash FROM audit_merkle_leaves WHERE tenant_id=$1 AND event_id=$2
`, tenantID, ev.ID).Scan(&epochID, &leafIndex, &leafHash)
	if errors.Is(err, sql.ErrNoRows) {
		r.Seal = integrityPending
		return r, nil
	}
	if err != nil {
		return r, err
	}
	ep, err := s.loadSealedEpoch(ctx, tenantID, epochID, epochs)
	if err != nil {
		return r, err
	}
	r.EpochID, r.EpochNumber = epochID, ep.number
	r.Seal = integritySealed
	proof, ok := GenerateProof(ep.tree, leafIndex)
	if ok {
		proof.LeafHash, proof.Root = recomputed, ep.root
		r.Proof = &proof
	}
	switch {
	case leafHash != recomputed:
		r.Seal = integrityLeafMismatch
		fail("merkle_leaf_mismatch")
	case !ep.rootOK || !ok || !VerifyProof(proof):
		r.Seal = integrityRootMismatch
		fail("merkle_root_mismatch")
	case !ep.linkedOK:
		r.Seal = integrityEpochUnlinked
		fail("merkle_epoch_unlinked")
	}
	return r, nil
}

// checkLinks verifies ev against its neighbours in its own chain (this
// node's rows are chain_node ” or self; a replicated chain is its node's).
func (s *SQLStore) checkLinks(ctx context.Context, tenantID, self string, ev AuditEvent) (string, error) {
	nodes := []interface{}{ev.ChainNode, ev.ChainNode}
	own := ev.ChainNode == "" || ev.ChainNode == self
	if own {
		nodes = []interface{}{"", self}
	}
	neighbour := func(seq int64) (prev, hash string, found bool, err error) {
		args := append([]interface{}{tenantID, seq}, nodes...)
		err = s.db.SQL().QueryRowContext(ctx, `
SELECT previous_hash, chain_hash FROM audit_events
WHERE tenant_id=$1 AND sequence=$2 AND chain_node IN ($3, $4)
`, args...).Scan(&prev, &hash)
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", false, nil
		}
		return prev, hash, err == nil, err
	}

	link := integrityLinked
	_, predHash, found, err := neighbour(ev.Sequence - 1)
	if err != nil {
		return "", err
	}
	switch {
	case found:
		if predHash != ev.PreviousHash {
			return integrityBrokenLink, nil
		}
	case ev.Sequence == 1 && own:
		if ev.PreviousHash != "GENESIS" {
			return integrityBrokenLink, nil
		}
		link = integrityGenesis
	default:
		// No predecessor: a replicated chain's first row here is its anchor;
		// anywhere else a missing row was removed.
		var lower int
		args := append([]interface{}{tenantID, ev.Sequence}, nodes...)
		if err := s.db.SQL().QueryRowContext(ctx, `
SELECT COUNT(*) FROM audit_events WHERE tenant_id=$1 AND sequence<$2 AND chain_node IN ($3, $4)
`, args...).Scan(&lower); err != nil {
			return "", err
		}
		if lower > 0 || own {
			return integrityPredecessorMissing, nil
		}
		link = integrityAnchor
	}
	succPrev, _, found, err := neighbour(ev.Sequence + 1)
	if err != nil {
		return "", err
	}
	if found && succPrev != ev.ChainHash {
		return integrityBrokenLink, nil
	}
	return link, nil
}

// loadSealedEpoch rebuilds an epoch's tree from its stored leaves and checks
// it against the stored root, the stored epoch hash, and the next epoch's
// link back to it.
func (s *SQLStore) loadSealedEpoch(ctx context.Context, tenantID, epochID string, cache map[string]*sealedEpoch) (*sealedEpoch, error) {
	if ep, ok := cache[epochID]; ok {
		return ep, nil
	}
	var (
		ep                        sealedEpoch
		prevRoot, epHash, chainNd string
	)
	if err := s.db.SQL().QueryRowContext(ctx, `
SELECT epoch_number, tree_root, COALESCE(previous_epoch_root,''), COALESCE(epoch_hash,''), chain_node
FROM audit_merkle_epochs WHERE tenant_id=$1 AND id=$2
`, tenantID, epochID).Scan(&ep.number, &ep.root, &prevRoot, &epHash, &chainNd); err != nil {
		return nil, err
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT leaf_hash FROM audit_merkle_leaves WHERE tenant_id=$1 AND epoch_id=$2 ORDER BY leaf_index ASC
`, tenantID, epochID)
	if err != nil {
		return nil, err
	}
	var hashes []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			_ = rows.Close()
			return nil, err
		}
		hashes = append(hashes, h)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	ep.tree = BuildMerkleTree(hashes)
	ep.rootOK = ep.tree.Root() == ep.root && (epHash == "" || epHash == epochHash(prevRoot, ep.root))

	// The next epoch in this chain carries this root forward; rewriting this
	// epoch's root alone breaks that link.
	var nextPrev string
	err = s.db.SQL().QueryRowContext(ctx, `
SELECT COALESCE(previous_epoch_root,'') FROM audit_merkle_epochs
WHERE tenant_id=$1 AND chain_node=$2 AND epoch_number=$3
`, tenantID, chainNd, ep.number+1).Scan(&nextPrev)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		ep.linkedOK = true
	case err != nil:
		return nil, err
	default:
		ep.linkedOK = nextPrev == ep.root
	}
	cache[epochID] = &ep
	return &ep, nil
}

// VerifyTarget verifies a target's audit trail. A failure is itself a
// critical audit.audit.chain_broken event, as a whole-chain break is.
func (s *Service) VerifyTarget(ctx context.Context, tenantID, targetID string, limit int) (TargetIntegrity, error) {
	res, err := s.store.VerifyTarget(ctx, tenantID, targetID, limit)
	if err != nil || res.Verdict != "tampered" {
		return res, err
	}
	breaks := make([]map[string]interface{}, 0, res.Failed)
	for _, e := range res.Events {
		if len(e.Failures) > 0 {
			breaks = append(breaks, map[string]interface{}{"event_id": e.EventID, "sequence": e.Sequence, "chain_node": e.ChainNode, "reasons": e.Failures})
		}
	}
	_, _, _ = s.ProcessEvent(ctx, AuditEvent{
		TenantID: tenantID, Service: "audit", Action: "audit.audit.chain_broken",
		ActorID: "system", ActorType: "system", Result: "failure",
		TargetType: "audit_trail", TargetID: targetID,
		Details: map[string]interface{}{"scope": "target", "target_id": targetID, "breaks": breaks},
	})
	return res, nil
}

// integrityRouter serves per-target verification through the route kernel.
func (h *Handler) integrityRouter(audit route.Emitter) *route.Router {
	r := route.New("audit", audit, nil)
	r.Handle("GET /audit/targets/{target_id}/integrity", route.Spec{
		Action: "target_integrity_verified", Permission: "audit.integrity.read", Resource: "audit_trail", TargetParam: "target_id",
	}, h.verifyTargetIntegrity)
	return r
}

func (h *Handler) verifyTargetIntegrity(c *route.Call) {
	target := strings.TrimSpace(c.R.PathValue("target_id"))
	res, err := h.svc.VerifyTarget(c.R.Context(), c.Tenant, target, atoi(c.R.URL.Query().Get("limit")))
	if err != nil {
		c.Error(http.StatusInternalServerError, "verify_failed", "audit trail verification failed")
		return
	}
	c.Detail("verdict", res.Verdict)
	c.Detail("events_checked", res.EventsChecked)
	c.Detail("failed", res.Failed)
	c.JSON(http.StatusOK, map[string]interface{}{"integrity": res})
}
