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
// stored now (the row, its neighbours, the rows up to a signed checkpoint)
// and compares with an independent record: the chain link, the HMAC, the
// head a checkpoint signed. Nothing is compared with a value derived from
// itself (learning.md 2026-09-27: the lineage "tamper check" did exactly
// that and always passed).

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
)

// EventIntegrity is the verification of one audit event.
type EventIntegrity struct {
	EventID   string    `json:"event_id"`
	Sequence  int64     `json:"sequence"`
	ChainNode string    `json:"chain_node,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	ActorID   string    `json:"actor_id"`
	Result    string    `json:"result"`
	Content   string    `json:"content"`   // intact | altered
	Link      string    `json:"link"`      // linked | genesis | anchor | broken | predecessor_missing
	Signature string    `json:"signature"` // verified | unsigned | not_checked | mismatch | key_unknown
	// Seal: sealed (covered by a verified checkpoint) | pending (no
	// checkpoint yet) | key_unknown | signature_invalid | head_mismatch
	Seal               string   `json:"seal"`
	CheckpointID       string   `json:"checkpoint_id,omitempty"`
	CheckpointSequence int64    `json:"checkpoint_sequence,omitempty"`
	Failures           []string `json:"failures,omitempty"`
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

// VerifyTarget checks the newest limit audit events whose target_id is
// targetID: each row's content against its chain hash, its links to both
// neighbours in its chain, its HMAC, and, once a checkpoint covers it, that
// its row is in the history the checkpoint's signed head commits to.
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
	for _, ev := range events {
		r, err := s.verifyEvent(ctx, tenantID, self, ev)
		if err != nil {
			return out, err
		}
		out.Events = append(out.Events, r)
	}
	if err := s.sealWithCheckpoints(ctx, tenantID, self, events, out.Events); err != nil {
		return out, err
	}
	for _, r := range out.Events {
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

func (s *SQLStore) verifyEvent(ctx context.Context, tenantID, self string, ev AuditEvent) (EventIntegrity, error) {
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

	return r, nil
}

// sealWithCheckpoints sets each event's seal. An event is sealed when the
// first checkpoint of its chain at or after it verifies under a trusted key,
// and the stored rows from the event to the signed head are contiguous,
// linked, and end at the signed chain hash. With the content check, that
// ties the event's stored fields to the signature. Events under one
// checkpoint share one walk from the lowest of them.
func (s *SQLStore) sealWithCheckpoints(ctx context.Context, tenantID, self string, events []AuditEvent, results []EventIntegrity) error {
	type group struct {
		cp    checkpoint
		nodes []interface{}
		from  int64
		idx   []int
	}
	groups := map[string]*group{}
	var order []string
	for i, ev := range events {
		nodes := chainNodes(ev.ChainNode, self)
		cp, ok, err := s.coveringCheckpoint(ctx, tenantID, nodes, ev.Sequence)
		if err != nil {
			return err
		}
		if !ok {
			results[i].Seal = integrityPending
			continue
		}
		g := groups[cp.EventID]
		if g == nil {
			g = &group{cp: cp, nodes: nodes, from: ev.Sequence}
			groups[cp.EventID] = g
			order = append(order, cp.EventID)
		}
		if ev.Sequence < g.from {
			g.from = ev.Sequence
		}
		g.idx = append(g.idx, i)
	}
	for _, id := range order {
		g := groups[id]
		status, err := s.verifyCheckpointSignature(ctx, g.cp)
		if err != nil {
			return err
		}
		if status == checkpointVerified {
			linked, err := s.segmentLinked(ctx, tenantID, g.nodes, g.from, g.cp.Head.Sequence, g.cp.Head.ChainHash)
			if err != nil {
				return err
			}
			if !linked {
				status = checkpointHeadMismatch
			}
		}
		for _, i := range g.idx {
			r := &results[i]
			r.CheckpointID, r.CheckpointSequence = g.cp.EventID, g.cp.Head.Sequence
			r.Seal = integritySealed
			if status != checkpointVerified {
				r.Seal = status
				r.Failures = append(r.Failures, "checkpoint_"+status)
			}
		}
	}
	return nil
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
	s.reportChainBroken(ctx, AuditEvent{
		TenantID: tenantID, Service: "audit", Action: "audit.audit.chain_broken",
		ActorID: "system", ActorType: "system", Result: "failure",
		TargetType: "audit_trail", TargetID: targetID,
		Details: map[string]interface{}{"scope": "target", "target_id": targetID, "break_count": len(breaks), "breaks": breaks},
	})
	return res, nil
}

// integrityRouter serves per-target verification and the signed
// checkpoints through the route kernel.
func (h *Handler) integrityRouter(audit route.Emitter) *route.Router {
	r := route.New("audit", audit, nil)
	r.Handle("GET /audit/targets/{target_id}/integrity", route.Spec{
		Action: "target_integrity_verified", Permission: "audit.integrity.read", Resource: "audit_trail", TargetParam: "target_id",
	}, h.verifyTargetIntegrity)
	r.Handle("GET /audit/checkpoints", route.Spec{
		Action: "checkpoints_listed", Permission: "audit.integrity.read", Resource: "audit_trail",
	}, h.listCheckpoints)
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
