package main

import (
	"net/http"
)

// Failover routes (failover.go). /cluster/peer/* are node-to-node and
// authenticate themselves: heartbeat and resubscribe with the member's
// forwarding credential, the others with the peer secret's signature.
// /cluster/failover/* are for a root administrator.

func (h *Handler) failoverReady(w http.ResponseWriter, r *http.Request) bool {
	if h.svc.fo == nil {
		writeErr(w, http.StatusServiceUnavailable, "failover_unavailable", "failover is not configured on this node", requestID(r), "root")
		return false
	}
	return true
}

// peerRefused audits and answers a node-to-node call that did not
// authenticate.
func (h *Handler) peerRefused(w http.ResponseWriter, r *http.Request, err error) {
	_ = h.svc.publishAudit(r.Context(), "audit.cluster.peer_refused", "root", map[string]interface{}{
		"path": r.URL.Path, "peer_node_id": r.Header.Get(headerPeerNode), "reason": err.Error(),
		"severity": "warning", "result": "refused",
	})
	writeErr(w, http.StatusUnauthorized, "peer_unauthorized", "the call is not from a node of this cluster", requestID(r), "root")
}

func (h *Handler) handlePeerHeartbeat(w http.ResponseWriter, r *http.Request) {
	if !h.failoverReady(w, r) {
		return
	}
	member, err := h.svc.memberFromCredential(r.Context(), r)
	if err != nil {
		h.peerRefused(w, r, err)
		return
	}
	var in heartbeatInput
	if err := decodeJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), requestID(r), "root")
		return
	}
	res, err := h.svc.Heartbeat(r.Context(), member, in)
	if err != nil {
		h.writeServiceError(w, err, requestID(r), "root")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": res})
}

func (h *Handler) handlePeerResubscribe(w http.ResponseWriter, r *http.Request) {
	if !h.failoverReady(w, r) {
		return
	}
	member, err := h.svc.memberFromCredential(r.Context(), r)
	if err != nil {
		h.peerRefused(w, r, err)
		return
	}
	var in resubscribeInput
	if err := decodeJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), requestID(r), "root")
		return
	}
	res, err := h.svc.Resubscribe(r.Context(), member, in)
	if err != nil {
		h.writeServiceError(w, err, requestID(r), "root")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": res})
}

// signedPeer reads the body and verifies the peer signature over it.
func (h *Handler) signedPeer(w http.ResponseWriter, r *http.Request) (string, []byte, bool) {
	if !h.failoverReady(w, r) {
		return "", nil, false
	}
	raw := []byte{}
	if r.Method != http.MethodGet {
		var err error
		if raw, err = readRequestBody(r); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), requestID(r), "root")
			return "", nil, false
		}
	}
	from, err := h.svc.verifyPeer(r.Context(), r, raw)
	if err != nil {
		h.peerRefused(w, r, err)
		return "", nil, false
	}
	return from, raw, true
}

func (h *Handler) handlePeerStatus(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := h.signedPeer(w, r); !ok {
		return
	}
	st, err := h.svc.PeerStatus(r.Context())
	if err != nil {
		h.writeServiceError(w, err, requestID(r), "root")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"node_id": st.NodeID, "role": st.Role, "epoch": st.Epoch,
		"primary_node_id": st.PrimaryNodeID, "primary_url": st.PrimaryURL, "primary_fingerprint": st.PrimaryFP,
		"last_primary_contact_ago_ms": st.LastContactAgoMS, "applied_lsn": st.AppliedLSN, "primary_contact_ok": st.PrimaryContactOK})
}

func (h *Handler) handlePeerVote(w http.ResponseWriter, r *http.Request) {
	from, raw, ok := h.signedPeer(w, r)
	if !ok {
		return
	}
	var in voteRequest
	if err := decodeJSONBytes(raw, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), requestID(r), "root")
		return
	}
	res, err := h.svc.GrantVote(r.Context(), from, in)
	if err != nil {
		h.writeServiceError(w, err, requestID(r), "root")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"granted": res.Granted, "epoch": res.Epoch, "reason": res.Reason})
}

func (h *Handler) handlePeerAnnounce(w http.ResponseWriter, r *http.Request) {
	from, raw, ok := h.signedPeer(w, r)
	if !ok {
		return
	}
	var in announcement
	if err := decodeJSONBytes(raw, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), requestID(r), "root")
		return
	}
	fenced, err := h.svc.Announce(r.Context(), from, in)
	if err != nil {
		h.writeServiceError(w, err, requestID(r), "root")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"fenced": fenced})
}

func (h *Handler) handlePeerFence(w http.ResponseWriter, r *http.Request) {
	from, raw, ok := h.signedPeer(w, r)
	if !ok {
		return
	}
	var in struct {
		Epoch int64 `json:"epoch"`
	}
	if err := decodeJSONBytes(raw, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), requestID(r), "root")
		return
	}
	lsn, err := h.svc.Fence(r.Context(), from, in.Epoch)
	if err != nil {
		h.writeServiceError(w, err, requestID(r), "root")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"wal_lsn": lsn})
}

func (h *Handler) handleFailoverStatus(w http.ResponseWriter, r *http.Request) {
	out, err := h.svc.FailoverStatus(r.Context())
	if err != nil {
		h.writeServiceError(w, err, requestID(r), "root")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"failover": out, "request_id": requestID(r)})
}

func (h *Handler) handleFailoverPromote(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var in PromoteInput
	if err := decodeJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "root")
		return
	}
	in.Actor = firstActor(r)
	res, err := h.svc.PromoteManually(r.Context(), in)
	if err != nil {
		_ = h.svc.publishAudit(r.Context(), "audit.cluster.promotion_refused", "root", map[string]interface{}{
			"actor": in.Actor, "force": in.Force, "reason": err.Error(), "severity": "warning", "result": "refused",
		})
		h.writeServiceError(w, err, reqID, "root")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": res, "request_id": reqID})
}
