package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"vecta-kms/pkg/clustercatalog"
	"vecta-kms/pkg/clusterrepl"
	"vecta-kms/pkg/clusterstate"
	pkgconfig "vecta-kms/pkg/config"
	pkgcrypto "vecta-kms/pkg/crypto"
)

// Failover (docs/CLUSTERING.md, slice 4).
//
// Every member heartbeats its primary every two seconds with its forwarding
// credential; the answer carries the cluster (who votes, where to reach
// them, each member's credential hash) and the peer secret that signs
// node-to-node calls. The epoch counts promotions.
//
//   - Manual promotion, at any size: an administrator promotes a member. If
//     the primary answers, it is fenced first and the member waits for its
//     last writes (a switchover); if not, the administrator must say so
//     (force), because the old primary may still be serving clients.
//   - Election, at three or more voters: a member that has not reached the
//     primary for the election timeout asks the others for their vote in the
//     next epoch. A voter grants one vote per epoch, only if it too has lost
//     the primary and the candidate has applied at least as much of the
//     primary's changes. A majority promotes the candidate.
//   - Fencing: a primary of three or more voters holds a lease that a
//     majority's heartbeats renew; when it passes, its services stop making
//     lifecycle writes (pkg/clusterstate). The lease is shorter than the
//     election timeout, so an isolated primary has stopped writing before
//     another can be elected. A primary that learns of a higher epoch fences
//     itself until it rejoins.
//
// A promoted node detaches from the old primary, accepts the members'
// forwarded writes, and gives each member new replication access; members
// re-subscribe to it with a fresh copy.

const (
	failoverTick     = 2 * time.Second
	leaseTTL         = 10 * time.Second
	electionTimeout  = 20 * time.Second
	electionJitter   = 5 * time.Second
	peerClockSkew    = 30 * time.Second
	switchoverWait   = 45 * time.Second
	peerCallTimeout  = 5 * time.Second
	labelResubscribe = "cluster-resubscribe"

	headerPeerNode      = "X-Vecta-Peer-Node"
	headerPeerTime      = "X-Vecta-Peer-Time"
	headerPeerSignature = "X-Vecta-Peer-Signature"
)

// nodeState is cluster_local_state with the failover columns.
type nodeState struct {
	clusterstate.State
	PeerSecret string
}

type peer struct {
	NodeID         string   `json:"node_id"`
	URL            string   `json:"url"`
	Fingerprint    string   `json:"fingerprint"`
	CredentialHash string   `json:"credential_hash,omitempty"`
	Components     []string `json:"components"`
	IsPrimary      bool     `json:"is_primary"`
}

// voter: a node others can reach to ask for its vote.
func (p peer) voter() bool { return p.URL != "" }

type failoverStore interface {
	LoadNode(ctx context.Context) (nodeState, error)
	SaveNode(ctx context.Context, st nodeState) error
	SetLease(ctx context.Context, until time.Time) error
	Peers(ctx context.Context) ([]peer, error)
	UpsertPeer(ctx context.Context, p peer) error
	DeletePeer(ctx context.Context, nodeID string) error
	Vote(ctx context.Context, epoch int64, candidate string) (bool, error)
	// MaxVoteEpoch is the highest epoch this node voted in (0 if none).
	MaxVoteEpoch(ctx context.Context) (int64, error)
	SetMemberCredential(ctx context.Context, nodeID, hash string) error
	MemberCredentialHash(ctx context.Context, nodeID string) (string, error)
	// ActiveMemberCredentials maps each member to its credential hash.
	ActiveMemberCredentials(ctx context.Context) (map[string]string, error)
}

type failoverRepl interface {
	Detach(ctx context.Context, nodeID string) ([]string, error)
	AppliedLSN(ctx context.Context, nodeID string) (string, error)
	ReceivedLSN(ctx context.Context, nodeID string) (string, bool, error)
	CurrentWALLSN(ctx context.Context) (string, error)
	EnsureReplicationRole(ctx context.Context, nodeID, password string, components []string) (string, error)
	Subscribe(ctx context.Context, nodeID, component, conninfo string, opts clusterrepl.SubscribeOptions) error
	DropMemberSlots(ctx context.Context) error
	EnsurePublications(ctx context.Context, components []string) ([]clusterrepl.PublicationStatus, error)
}

type failover struct {
	store failoverStore
	repl  failoverRepl
	// client reaches a peer's cluster-manager, pinned to its certificate.
	client func(url, fingerprint string) *http.Client

	mu            sync.Mutex
	lastContact   time.Time            // member: last answer from the primary
	heartbeats    map[string]time.Time // primary: last heartbeat per member
	electionAfter time.Time
	resubscribe   bool // member: a new primary must be subscribed to
}

// WithFailover attaches the failover machinery.
func (s *Service) WithFailover(store failoverStore, repl failoverRepl) *Service {
	// Until the first heartbeat, count the start as contact: a node that just
	// started does not vote a running primary out.
	s.fo = &failover{store: store, repl: repl, heartbeats: map[string]time.Time{}, lastContact: time.Now(), client: func(url, fp string) *http.Client {
		if strings.HasPrefix(url, "https://") {
			return clusterstate.PinnedHTTPClient(fp, peerCallTimeout)
		}
		return &http.Client{Timeout: peerCallTimeout} // lab only (CLUSTER_JOIN_ALLOW_HTTP)
	}}
	return s
}

func majority(n int) int { return n/2 + 1 }

func (f *failover) jitteredDeadline(now time.Time) time.Time {
	j, err := pkgcrypto.RandomInt(big.NewInt(int64(electionJitter / time.Millisecond)))
	if err != nil {
		return now.Add(electionTimeout + electionJitter)
	}
	return now.Add(electionTimeout + time.Duration(j.Int64())*time.Millisecond)
}

// ---- peer authentication ----

func peerSignature(secret, method, path, ts, node string, body []byte) string {
	msg := strings.Join([]string{method, path, ts, node, hex.EncodeToString(pkgcrypto.SHA256(body))}, "\n")
	return hex.EncodeToString(pkgcrypto.HMACSHA256([]byte(secret), []byte(msg)))
}

func secretFingerprint(secret string) string {
	if secret == "" {
		return ""
	}
	return hex.EncodeToString(pkgcrypto.SHA256([]byte("vecta-peer-secret|" + secret)))[:16]
}

// verifyPeer checks a node-to-node call signed with the peer secret, from a
// node this one knows.
func (s *Service) verifyPeer(ctx context.Context, r *http.Request, body []byte) (string, error) {
	st, err := s.fo.store.LoadNode(ctx)
	if err != nil {
		return "", err
	}
	if st.PeerSecret == "" {
		return "", errors.New("this node has no peer secret yet")
	}
	node := strings.TrimSpace(r.Header.Get(headerPeerNode))
	ts := r.Header.Get(headerPeerTime)
	sec, err := strconv.ParseInt(ts, 10, 64)
	if node == "" || err != nil {
		return "", errors.New("missing peer headers")
	}
	if d := s.now().Sub(time.Unix(sec, 0)); d > peerClockSkew || d < -peerClockSkew {
		return "", errors.New("peer signature outside the clock window")
	}
	want := peerSignature(st.PeerSecret, r.Method, r.URL.Path, ts, node, body)
	if subtle.ConstantTimeCompare([]byte(want), []byte(r.Header.Get(headerPeerSignature))) != 1 {
		return "", errors.New("peer signature does not verify")
	}
	peers, err := s.fo.store.Peers(ctx)
	if err != nil {
		return "", err
	}
	for _, p := range peers {
		if p.NodeID == node {
			return node, nil
		}
	}
	return "", errors.New("unknown peer")
}

// peerCall makes a signed node-to-node call and decodes the JSON answer.
func (s *Service) peerCall(ctx context.Context, st nodeState, p peer, method, path string, in, out any) (int, error) {
	var body []byte
	if in != nil {
		body, _ = json.Marshal(in)
	}
	ctx, cancel := context.WithTimeout(ctx, peerCallTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(p.URL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	ts := strconv.FormatInt(s.now().Unix(), 10)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(headerPeerNode, st.NodeID)
	req.Header.Set(headerPeerTime, ts)
	req.Header.Set(headerPeerSignature, peerSignature(st.PeerSecret, method, path, ts, st.NodeID, body))
	return s.doJSON(req, p.URL, p.Fingerprint, out)
}

func (s *Service) doJSON(req *http.Request, url, fp string, out any) (int, error) {
	resp, err := s.fo.client(url, fp).Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close() //nolint:errcheck
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("%s answered %d: %s", url, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, err
		}
	}
	return resp.StatusCode, nil
}

// ---- primary side ----

// becomePrimary records this node as the primary the first time a member
// joins: its chain node, epoch 1 and the peer secret.
func (s *Service) becomePrimary(ctx context.Context) (nodeState, error) {
	st, err := s.fo.store.LoadNode(ctx)
	if err != nil {
		return st, err
	}
	if st.Role == clusterstate.RolePrimary && st.PeerSecret != "" {
		return st, nil
	}
	if st.Role == clusterstate.RoleFenced {
		return st, newServiceError(409, "node_fenced", "this node was replaced as primary; rejoin it to the cluster first")
	}
	st.NodeID, st.Role, st.PrimaryNodeID = s.bootstrapNodeID, clusterstate.RolePrimary, s.bootstrapNodeID
	st.PrimaryURL, st.PrimaryFingerprint, st.ForwardCredential = "", "", ""
	if st.Epoch < 1 {
		st.Epoch = 1
	}
	if st.PeerSecret == "" {
		raw, err := pkgcrypto.RandomBytes(32)
		if err != nil {
			return st, err
		}
		st.PeerSecret = hex.EncodeToString(raw)
	}
	if err := s.fo.store.SaveNode(ctx, st); err != nil {
		return st, err
	}
	return st, s.fo.store.UpsertPeer(ctx, peer{NodeID: st.NodeID, URL: s.joinCfg.advertiseURL, Fingerprint: s.joinCfg.tlsFingerprint, IsPrimary: true})
}

type heartbeatInput struct {
	Epoch        int64  `json:"epoch"`
	URL          string `json:"url"`
	Fingerprint  string `json:"fingerprint"`
	AppliedLSN   string `json:"applied_lsn"`
	PeerSecretFP string `json:"peer_secret_fp"`
}

type heartbeatResult struct {
	Epoch         int64  `json:"epoch"`
	PrimaryNodeID string `json:"primary_node_id"`
	Peers         []peer `json:"peers"`
	PeerSecret    string `json:"peer_secret,omitempty"`
}

// memberFromCredential authenticates a member by its forwarding credential.
func (s *Service) memberFromCredential(ctx context.Context, r *http.Request) (string, error) {
	node := strings.TrimSpace(r.Header.Get(pkgconfig.HeaderClusterNode))
	want, err := s.fo.store.MemberCredentialHash(ctx, node)
	got := credentialHash(r.Header.Get(pkgconfig.HeaderClusterCredential))
	if node == "" || err != nil || subtle.ConstantTimeCompare([]byte(want), []byte(got)) != 1 {
		return "", errForwardCredential
	}
	return node, nil
}

// Heartbeat runs on the primary for a member.
func (s *Service) Heartbeat(ctx context.Context, member string, in heartbeatInput) (heartbeatResult, error) {
	st, err := s.fo.store.LoadNode(ctx)
	if err != nil {
		return heartbeatResult{}, err
	}
	if st.Role != clusterstate.RolePrimary {
		return heartbeatResult{}, newServiceError(409, "not_primary", "this node is not the primary")
	}
	if in.Epoch > st.Epoch {
		s.fence(ctx, st, in.Epoch, member, "a member reported a newer epoch")
		return heartbeatResult{}, newServiceError(409, "superseded", "a newer primary exists; this node is fenced")
	}
	peers, err := s.fo.store.Peers(ctx)
	if err != nil {
		return heartbeatResult{}, err
	}
	for _, p := range peers {
		if p.NodeID == member && (in.URL != "" && (p.URL != in.URL || p.Fingerprint != in.Fingerprint)) {
			p.URL, p.Fingerprint = in.URL, in.Fingerprint
			if err := s.fo.store.UpsertPeer(ctx, p); err != nil {
				return heartbeatResult{}, err
			}
		}
	}
	s.fo.mu.Lock()
	s.fo.heartbeats[member] = s.now()
	s.fo.mu.Unlock()
	peers, err = s.fo.store.Peers(ctx)
	if err != nil {
		return heartbeatResult{}, err
	}
	out := heartbeatResult{Epoch: st.Epoch, PrimaryNodeID: st.NodeID, Peers: peers}
	if in.PeerSecretFP != secretFingerprint(st.PeerSecret) {
		out.PeerSecret = st.PeerSecret
	}
	return out, nil
}

// renewLease sets the primary's lease from its members' heartbeats: with
// three or more voters, until the majority-th most recent contact (this node
// counting as one) plus leaseTTL; with fewer, no lease is needed.
func (s *Service) renewLease(ctx context.Context, st nodeState) error {
	peers, err := s.fo.store.Peers(ctx)
	if err != nil {
		return err
	}
	voters := 0
	contacts := []time.Time{}
	s.fo.mu.Lock()
	for _, p := range peers {
		if !p.voter() {
			continue
		}
		voters++
		if p.NodeID != st.NodeID {
			if t, ok := s.fo.heartbeats[p.NodeID]; ok {
				contacts = append(contacts, t)
			}
		}
	}
	s.fo.mu.Unlock()
	if voters < 3 {
		if st.WritableUntil.IsZero() {
			return nil
		}
		return s.fo.store.SetLease(ctx, time.Time{})
	}
	need := majority(voters) - 1 // other voters besides this one
	until := time.Unix(1, 0)     // lost: not enough members heard
	if len(contacts) >= need {
		sort.Slice(contacts, func(i, j int) bool { return contacts[i].After(contacts[j]) })
		until = contacts[need-1].Add(leaseTTL)
	}
	if until.Equal(st.WritableUntil) {
		return nil
	}
	return s.fo.store.SetLease(ctx, until)
}

// fence makes this former primary stop: role fenced at the newer epoch.
func (s *Service) fence(ctx context.Context, st nodeState, epoch int64, by, why string) {
	if st.Role != clusterstate.RolePrimary || epoch <= st.Epoch {
		return
	}
	prev := st.Epoch
	st.Role, st.Epoch, st.WritableUntil = clusterstate.RoleFenced, epoch, time.Time{}
	if err := s.fo.store.SaveNode(ctx, st); err != nil {
		return
	}
	_ = s.publishAudit(ctx, "audit.cluster.fenced", "root", map[string]interface{}{
		"node_id": st.NodeID, "epoch": epoch, "previous_epoch": prev, "by_node_id": by, "reason": why,
		"severity": "critical", "result": "success",
		"description": "this node was primary and another node has been promoted: it makes no changes until it rejoins",
	})
}

// ---- member side ----

// heartbeatPrimary runs on a member each tick.
func (s *Service) heartbeatPrimary(ctx context.Context, st nodeState) error {
	applied, _ := s.fo.repl.AppliedLSN(ctx, st.NodeID)
	raw, _ := json.Marshal(heartbeatInput{
		Epoch: st.Epoch, URL: s.joinCfg.advertiseURL, Fingerprint: s.joinCfg.tlsFingerprint,
		AppliedLSN: applied, PeerSecretFP: secretFingerprint(st.PeerSecret),
	})
	ctx2, cancel := context.WithTimeout(ctx, peerCallTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx2, http.MethodPost, strings.TrimRight(st.PrimaryURL, "/")+"/cluster/peer/heartbeat", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(pkgconfig.HeaderClusterNode, st.NodeID)
	req.Header.Set(pkgconfig.HeaderClusterCredential, st.ForwardCredential)
	var out struct {
		Result heartbeatResult `json:"result"`
	}
	if _, err := s.doJSON(req, st.PrimaryURL, st.PrimaryFingerprint, &out); err != nil {
		return err
	}
	res := out.Result
	if res.PrimaryNodeID != st.PrimaryNodeID || res.Epoch < st.Epoch {
		return fmt.Errorf("the node at the primary's address is %s at epoch %d", res.PrimaryNodeID, res.Epoch)
	}
	for _, p := range res.Peers {
		if err := s.fo.store.UpsertPeer(ctx, p); err != nil {
			return err
		}
	}
	if err := s.prunePeers(ctx, res.Peers); err != nil {
		return err
	}
	changed := false
	if res.PeerSecret != "" && res.PeerSecret != st.PeerSecret {
		st.PeerSecret, changed = res.PeerSecret, true
	}
	if res.Epoch > st.Epoch {
		st.Epoch, changed = res.Epoch, true
	}
	if changed {
		if err := s.fo.store.SaveNode(ctx, st); err != nil {
			return err
		}
	}
	s.fo.mu.Lock()
	s.fo.lastContact = s.now()
	s.fo.electionAfter = s.fo.jitteredDeadline(s.now())
	s.fo.mu.Unlock()
	return nil
}

func (s *Service) prunePeers(ctx context.Context, keep []peer) error {
	have, err := s.fo.store.Peers(ctx)
	if err != nil {
		return err
	}
	want := map[string]bool{}
	for _, p := range keep {
		want[p.NodeID] = true
	}
	for _, p := range have {
		if !want[p.NodeID] {
			if err := s.fo.store.DeletePeer(ctx, p.NodeID); err != nil {
				return err
			}
		}
	}
	return nil
}

type peerStatus struct {
	NodeID             string `json:"node_id"`
	Role               string `json:"role"`
	Epoch              int64  `json:"epoch"`
	PrimaryNodeID      string `json:"primary_node_id"`
	PrimaryURL         string `json:"primary_url"`
	PrimaryFP          string `json:"primary_fingerprint"`
	LastContactAgoMS   int64  `json:"last_primary_contact_ago_ms"`
	AppliedLSN         string `json:"applied_lsn,omitempty"`
	WritableUntil      string `json:"writable_until,omitempty"`
	AdvertiseURL       string `json:"url"`
	AdvertiseFP        string `json:"fingerprint"`
	PrimaryContactOK   bool   `json:"primary_contact_ok"`
	ResubscribePending bool   `json:"resubscribe_pending"`
}

func (s *Service) PeerStatus(ctx context.Context) (peerStatus, error) {
	st, err := s.fo.store.LoadNode(ctx)
	if err != nil {
		return peerStatus{}, err
	}
	out := peerStatus{NodeID: st.NodeID, Role: st.Role, Epoch: st.Epoch, PrimaryNodeID: st.PrimaryNodeID,
		PrimaryURL: st.PrimaryURL, PrimaryFP: st.PrimaryFingerprint, AdvertiseURL: s.joinCfg.advertiseURL, AdvertiseFP: s.joinCfg.tlsFingerprint}
	if st.Role == clusterstate.RolePrimary {
		out.PrimaryURL, out.PrimaryFP, out.PrimaryNodeID = s.joinCfg.advertiseURL, s.joinCfg.tlsFingerprint, st.NodeID
		out.PrimaryContactOK = true
	}
	if !st.WritableUntil.IsZero() {
		out.WritableUntil = st.WritableUntil.UTC().Format(time.RFC3339Nano)
	}
	s.fo.mu.Lock()
	if !s.fo.lastContact.IsZero() {
		out.LastContactAgoMS = s.now().Sub(s.fo.lastContact).Milliseconds()
		out.PrimaryContactOK = out.PrimaryContactOK || s.now().Sub(s.fo.lastContact) < electionTimeout
	}
	out.ResubscribePending = s.fo.resubscribe
	s.fo.mu.Unlock()
	if st.Role == clusterstate.RoleFollower {
		out.AppliedLSN, _ = s.fo.repl.AppliedLSN(ctx, st.NodeID)
	}
	return out, nil
}

// followNewer adopts a newer primary reported by a peer, or fences this node
// if it was primary. It reports whether anything changed.
func (s *Service) followNewer(ctx context.Context, st nodeState, ps peerStatus, from string) bool {
	if ps.Epoch <= st.Epoch || ps.Role != clusterstate.RolePrimary || ps.NodeID == st.NodeID {
		return false
	}
	if st.Role == clusterstate.RolePrimary {
		s.fence(ctx, st, ps.Epoch, from, "a peer is primary at a newer epoch")
		return true
	}
	if st.Role != clusterstate.RoleFollower {
		return false
	}
	prev := st.PrimaryNodeID
	st.Epoch, st.PrimaryNodeID, st.PrimaryURL, st.PrimaryFingerprint = ps.Epoch, ps.NodeID, ps.PrimaryURL, ps.PrimaryFP
	if err := s.fo.store.SaveNode(ctx, st); err != nil {
		return false
	}
	s.fo.mu.Lock()
	s.fo.resubscribe = true
	s.fo.lastContact = s.now()
	s.fo.electionAfter = s.fo.jitteredDeadline(s.now())
	s.fo.mu.Unlock()
	_ = s.publishAudit(ctx, "audit.cluster.primary_changed", "root", map[string]interface{}{
		"node_id": st.NodeID, "epoch": ps.Epoch, "primary_node_id": ps.NodeID, "previous_primary_node_id": prev,
		"learned_from": from, "severity": "warning", "result": "success",
	})
	return true
}

// pollPeers asks every peer for its status, following a newer primary.
func (s *Service) pollPeers(ctx context.Context, st nodeState) {
	peers, err := s.fo.store.Peers(ctx)
	if err != nil || st.PeerSecret == "" {
		return
	}
	for _, p := range peers {
		if p.NodeID == st.NodeID || !p.voter() {
			continue
		}
		var ps peerStatus
		if _, err := s.peerCall(ctx, st, p, http.MethodGet, "/cluster/peer/status", nil, &ps); err != nil {
			continue
		}
		if s.followNewer(ctx, st, ps, p.NodeID) {
			return
		}
	}
}

// ---- election ----

type voteRequest struct {
	Epoch      int64  `json:"epoch"`
	Candidate  string `json:"candidate"`
	AppliedLSN string `json:"applied_lsn"`
}

type voteResult struct {
	Granted bool   `json:"granted"`
	Epoch   int64  `json:"epoch"`
	Reason  string `json:"reason,omitempty"`
}

// GrantVote runs on a voter.
func (s *Service) GrantVote(ctx context.Context, from string, in voteRequest) (voteResult, error) {
	st, err := s.fo.store.LoadNode(ctx)
	if err != nil {
		return voteResult{}, err
	}
	refuse := func(reason string) (voteResult, error) {
		_ = s.publishAudit(ctx, "audit.cluster.vote_refused", "root", map[string]interface{}{
			"candidate": in.Candidate, "epoch": in.Epoch, "reason": reason, "severity": "warning", "result": "refused",
		})
		return voteResult{Granted: false, Epoch: st.Epoch, Reason: reason}, nil
	}
	switch {
	case in.Candidate != from:
		return refuse("a node may ask only for itself")
	case in.Epoch <= st.Epoch:
		return refuse("epoch is not newer than this node's")
	case st.Role == clusterstate.RolePrimary:
		return refuse("this node is the primary and running")
	case st.Role != clusterstate.RoleFollower:
		return refuse("this node is not a member")
	}
	s.fo.mu.Lock()
	recent := !s.fo.lastContact.IsZero() && s.now().Sub(s.fo.lastContact) < electionTimeout
	s.fo.mu.Unlock()
	if recent {
		return refuse("this node still reaches the primary")
	}
	mine, _ := s.fo.repl.AppliedLSN(ctx, st.NodeID)
	a, err1 := clusterrepl.ParseLSN(in.AppliedLSN)
	b, err2 := clusterrepl.ParseLSN(mine)
	if err1 != nil || err2 != nil || a < b {
		return refuse("the candidate has applied less of the primary's changes than this node")
	}
	ok, err := s.fo.store.Vote(ctx, in.Epoch, in.Candidate)
	if err != nil {
		return voteResult{}, err
	}
	if !ok {
		return refuse("this node already voted in this epoch")
	}
	// Wait out the next election timeout before standing itself.
	s.fo.mu.Lock()
	s.fo.electionAfter = s.fo.jitteredDeadline(s.now())
	s.fo.mu.Unlock()
	_ = s.publishAudit(ctx, "audit.cluster.vote_granted", "root", map[string]interface{}{
		"candidate": in.Candidate, "epoch": in.Epoch, "candidate_applied_lsn": in.AppliedLSN, "voter_applied_lsn": mine,
		"severity": "warning", "result": "success",
	})
	return voteResult{Granted: true, Epoch: in.Epoch}, nil
}

// nextEpoch is the epoch a promotion of this node would start: past both
// the cluster's epoch and any epoch this node voted in, with this node's own
// vote recorded so it gives none to another candidate there. The node's
// epoch itself changes only when a promotion succeeds: a lost election that
// raised it would fence a running primary at the next heartbeat.
func (s *Service) nextEpoch(ctx context.Context, st nodeState) (int64, error) {
	voted, err := s.fo.store.MaxVoteEpoch(ctx)
	if err != nil {
		return 0, err
	}
	epoch := st.Epoch + 1
	if voted >= epoch {
		epoch = voted + 1
	}
	ok, err := s.fo.store.Vote(ctx, epoch, st.NodeID)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, errors.New("this node already voted in the next epoch")
	}
	return epoch, nil
}

// runElection stands this member for the next epoch.
func (s *Service) runElection(ctx context.Context, st nodeState, peers []peer) {
	epoch, err := s.nextEpoch(ctx, st)
	if err != nil {
		return
	}
	applied, _ := s.fo.repl.AppliedLSN(ctx, st.NodeID)
	voters, granted := 0, []string{st.NodeID}
	for _, p := range peers {
		if !p.voter() {
			continue
		}
		voters++
		if p.NodeID == st.NodeID {
			continue
		}
		var res voteResult
		if _, err := s.peerCall(ctx, st, p, http.MethodPost, "/cluster/peer/vote", voteRequest{Epoch: epoch, Candidate: st.NodeID, AppliedLSN: applied}, &res); err != nil {
			continue
		}
		if res.Granted {
			granted = append(granted, p.NodeID)
		}
	}
	if len(granted) < majority(voters) {
		_ = s.publishAudit(ctx, "audit.cluster.election_lost", "root", map[string]interface{}{
			"epoch": epoch, "votes": granted, "voters": voters, "severity": "warning", "result": "refused",
			"reason": "no majority",
		})
		return
	}
	if _, err := s.promote(ctx, epoch, "election", "", granted); err != nil {
		_ = s.publishAudit(ctx, "audit.cluster.promotion_failed", "root", map[string]interface{}{
			"epoch": epoch, "reason": err.Error(), "severity": "critical", "result": "failure",
		})
	}
}

// ---- promotion ----

type PromoteResult struct {
	NodeID                string   `json:"node_id"`
	Epoch                 int64    `json:"epoch"`
	PreviousPrimaryNodeID string   `json:"previous_primary_node_id"`
	PreviousPrimaryFenced bool     `json:"previous_primary_fenced"`
	CaughtUp              bool     `json:"caught_up"`
	DetachedSubscriptions []string `json:"detached_subscriptions"`
	Announced             []string `json:"announced"`
	Votes                 []string `json:"votes,omitempty"`
	LeaseRequired         bool     `json:"lease_required"`
}

// promote makes this member the primary at epoch.
func (s *Service) promote(ctx context.Context, epoch int64, how, actor string, votes []string) (PromoteResult, error) {
	st, err := s.fo.store.LoadNode(ctx)
	if err != nil {
		return PromoteResult{}, err
	}
	if st.Role != clusterstate.RoleFollower {
		return PromoteResult{}, newServiceError(409, "not_a_member", "only a cluster member can be promoted")
	}
	if s.joinCfg.advertiseURL == "" || s.joinCfg.pgHost == "" {
		return PromoteResult{}, newServiceError(409, "not_promotable", "set CLUSTER_ADVERTISE_URL and CLUSTER_PG_ADVERTISE_HOST on this node so members can reach it as primary")
	}
	out := PromoteResult{NodeID: st.NodeID, Epoch: epoch, PreviousPrimaryNodeID: st.PrimaryNodeID, Votes: votes}
	// Stop applying the old primary's changes; its slots stay on it.
	if out.DetachedSubscriptions, err = s.fo.repl.Detach(ctx, st.NodeID); err != nil {
		return out, err
	}
	// Members subscribe here next: publish every component now rather than
	// at the next minute's refresh.
	if pubs, err := s.fo.repl.EnsurePublications(ctx, clustercatalog.Components()); err != nil {
		return out, err
	} else {
		s.AuditPublicationChanges(ctx, pubs)
	}
	peers, err := s.fo.store.Peers(ctx)
	if err != nil {
		return out, err
	}
	voters := 0
	for _, p := range peers {
		if p.voter() {
			voters++
		}
		// The members' forwarded writes are accepted here from now on.
		if p.NodeID != st.NodeID && p.NodeID != st.PrimaryNodeID && p.CredentialHash != "" {
			if err := s.fo.store.SetMemberCredential(ctx, p.NodeID, p.CredentialHash); err != nil {
				return out, err
			}
		}
		p.IsPrimary = p.NodeID == st.NodeID
		if p.NodeID == st.NodeID {
			p.URL, p.Fingerprint = s.joinCfg.advertiseURL, s.joinCfg.tlsFingerprint
		}
		if err := s.fo.store.UpsertPeer(ctx, p); err != nil {
			return out, err
		}
	}
	prev := st
	st.Role, st.Epoch, st.PrimaryNodeID = clusterstate.RolePrimary, epoch, st.NodeID
	st.PrimaryURL, st.PrimaryFingerprint, st.ForwardCredential = "", "", ""
	st.WritableUntil = time.Time{}
	out.LeaseRequired = voters >= 3
	s.fo.mu.Lock()
	s.fo.heartbeats = map[string]time.Time{}
	if out.LeaseRequired {
		// The votes just granted are contact with those members.
		for _, v := range votes {
			s.fo.heartbeats[v] = s.now()
		}
	}
	s.fo.resubscribe = false
	s.fo.mu.Unlock()
	if err := s.fo.store.SaveNode(ctx, st); err != nil {
		return out, err
	}
	if out.LeaseRequired {
		if err := s.renewLease(ctx, st); err != nil {
			return out, err
		}
	}
	s.recordPromotionInRegistry(ctx, peers, st.NodeID, prev.PrimaryNodeID)
	// Tell every peer; the old primary, if it answers, is fenced.
	for _, p := range peers {
		if p.NodeID == st.NodeID || !p.voter() {
			continue
		}
		var res struct {
			Fenced bool `json:"fenced"`
		}
		if _, err := s.peerCall(ctx, st, p, http.MethodPost, "/cluster/peer/announce", announcement{Epoch: epoch, PrimaryNodeID: st.NodeID, PrimaryURL: s.joinCfg.advertiseURL, PrimaryFP: s.joinCfg.tlsFingerprint}, &res); err == nil {
			out.Announced = append(out.Announced, p.NodeID)
			if p.NodeID == prev.PrimaryNodeID && res.Fenced {
				out.PreviousPrimaryFenced = true
			}
		}
	}
	_ = s.publishAudit(ctx, "audit.cluster.promoted", "root", map[string]interface{}{
		"node_id": st.NodeID, "epoch": epoch, "how": how, "actor": actor, "votes": votes,
		"previous_primary_node_id": prev.PrimaryNodeID, "previous_primary_fenced": out.PreviousPrimaryFenced,
		"detached_subscriptions": out.DetachedSubscriptions, "announced": out.Announced,
		"severity": "critical", "result": "success",
		"description": "this node is now the cluster primary",
	})
	return out, nil
}

// recordPromotionInRegistry keeps the Cluster page's node list (cluster_nodes)
// in step: this node leads, the others follow, the old primary is fenced.
func (s *Service) recordPromotionInRegistry(ctx context.Context, peers []peer, self, previous string) {
	if s.store == nil || s.ensureBootstrap(ctx, "root") != nil {
		return
	}
	for _, p := range peers {
		node, err := s.store.GetNode(ctx, "root", p.NodeID)
		if err != nil {
			node = ClusterNode{ID: p.NodeID, TenantID: "root", Name: p.NodeID, ProfileID: s.bootstrapProfileID, Status: "unknown"}
		}
		node.Endpoint = defaultIfEmpty(p.URL, node.Endpoint)
		node.CertFingerprint = defaultIfEmpty(p.Fingerprint, node.CertFingerprint)
		if len(p.Components) > 0 {
			node.EnabledComponents = p.Components
		}
		node.Role, node.JoinState = "follower", "active"
		switch p.NodeID {
		case self:
			node.Role = "leader"
		case previous:
			node.JoinState = "fenced"
		}
		node.UpdatedAt = s.now()
		_ = s.store.UpsertNode(ctx, node)
	}
}

type announcement struct {
	Epoch         int64  `json:"epoch"`
	PrimaryNodeID string `json:"primary_node_id"`
	PrimaryURL    string `json:"primary_url"`
	PrimaryFP     string `json:"primary_fingerprint"`
}

// Announce runs on a peer told of a new primary.
func (s *Service) Announce(ctx context.Context, from string, a announcement) (bool, error) {
	if a.PrimaryNodeID != from {
		return false, newServiceError(403, "not_the_primary", "a node may announce only itself")
	}
	st, err := s.fo.store.LoadNode(ctx)
	if err != nil {
		return false, err
	}
	wasPrimary := st.Role == clusterstate.RolePrimary
	s.followNewer(ctx, st, peerStatus{NodeID: a.PrimaryNodeID, Role: clusterstate.RolePrimary, Epoch: a.Epoch, PrimaryURL: a.PrimaryURL, PrimaryFP: a.PrimaryFP}, from)
	return wasPrimary && a.Epoch > st.Epoch, nil
}

// Fence runs on the primary when a member is promoted by hand while it
// still answers (a switchover). It returns this node's WAL position, which
// the member waits for so no write is lost.
func (s *Service) Fence(ctx context.Context, from string, epoch int64) (string, error) {
	st, err := s.fo.store.LoadNode(ctx)
	if err != nil {
		return "", err
	}
	if st.Role != clusterstate.RolePrimary || epoch <= st.Epoch {
		return "", newServiceError(409, "not_fenced", "this node is not the primary at an older epoch")
	}
	s.fence(ctx, st, epoch, from, "switchover to "+from)
	return s.fo.repl.CurrentWALLSN(ctx)
}

// PromoteInput is the administrator's request on the node to promote.
type PromoteInput struct {
	Confirm bool   `json:"confirm"`
	Force   bool   `json:"force"`
	Reason  string `json:"reason"`
	Actor   string `json:"-"`
}

// PromoteManually is POST /cluster/failover/promote.
func (s *Service) PromoteManually(ctx context.Context, in PromoteInput) (PromoteResult, error) {
	if s.fo == nil {
		return PromoteResult{}, newServiceError(503, "failover_unavailable", "failover is not configured on this node")
	}
	if !in.Confirm {
		return PromoteResult{}, newServiceError(400, "confirmation_required", "promoting makes this node the primary; set confirm")
	}
	st, err := s.fo.store.LoadNode(ctx)
	if err != nil {
		return PromoteResult{}, err
	}
	if st.Role != clusterstate.RoleFollower {
		return PromoteResult{}, newServiceError(409, "not_a_member", "only a cluster member can be promoted")
	}
	// Checked before the primary is fenced: a refusal after it would leave
	// the cluster with no primary.
	if s.joinCfg.advertiseURL == "" || s.joinCfg.pgHost == "" {
		return PromoteResult{}, newServiceError(409, "not_promotable", "set CLUSTER_ADVERTISE_URL and CLUSTER_PG_ADVERTISE_HOST on this node so members can reach it as primary")
	}
	if st.PeerSecret == "" {
		return PromoteResult{}, newServiceError(409, "not_promotable", "this member has not heard from its primary since it joined; wait for its first heartbeat")
	}
	epoch, err := s.nextEpoch(ctx, st)
	if err != nil {
		return PromoteResult{}, newServiceError(409, "election_in_progress", err.Error())
	}
	caughtUp := false
	old := peer{NodeID: st.PrimaryNodeID, URL: st.PrimaryURL, Fingerprint: st.PrimaryFingerprint}
	var fenced struct {
		WALLSN string `json:"wal_lsn"`
	}
	if _, err := s.peerCall(ctx, st, old, http.MethodPost, "/cluster/peer/fence", map[string]int64{"epoch": epoch}, &fenced); err == nil {
		// Switchover: wait until this node has the old primary's last write.
		target, _ := clusterrepl.ParseLSN(fenced.WALLSN)
		deadline := time.Now().Add(switchoverWait)
		for !caughtUp && time.Now().Before(deadline) {
			lsn, running, err := s.fo.repl.ReceivedLSN(ctx, st.NodeID)
			got, perr := clusterrepl.ParseLSN(lsn)
			if err == nil && perr == nil && running && got >= target {
				caughtUp = true
				break
			}
			select {
			case <-ctx.Done():
				return PromoteResult{}, ctx.Err()
			case <-time.After(500 * time.Millisecond):
			}
		}
	} else if !in.Force {
		return PromoteResult{}, newServiceError(409, "primary_reachable_check_failed",
			"the primary did not answer ("+err.Error()+"). If it is down, promote with force: its writes not yet replicated here are lost, and if it is still serving clients it accepts writes until it learns of this promotion")
	}
	out, err := s.promote(ctx, epoch, "manual", in.Actor, nil)
	out.CaughtUp = caughtUp
	if err == nil {
		_ = s.publishAudit(ctx, "audit.cluster.promoted_manually", "root", map[string]interface{}{
			"node_id": out.NodeID, "epoch": epoch, "actor": in.Actor, "reason": in.Reason, "force": in.Force,
			"switchover": fenced.WALLSN != "", "caught_up": caughtUp, "severity": "critical", "result": "success",
		})
	}
	return out, err
}

// ---- re-subscription ----

type resubscribeInput struct {
	EncapsulationKey string `json:"encapsulation_key"`
}

type resubscribeResult struct {
	Context    string   `json:"context"`
	Sealed     string   `json:"sealed"`
	Components []string `json:"components"`
}

// Resubscribe runs on a new primary for a member: fresh replication access
// for the member's components, sealed to the member.
func (s *Service) Resubscribe(ctx context.Context, member string, in resubscribeInput) (resubscribeResult, error) {
	st, err := s.fo.store.LoadNode(ctx)
	if err != nil {
		return resubscribeResult{}, err
	}
	if st.Role != clusterstate.RolePrimary {
		return resubscribeResult{}, newServiceError(409, "not_primary", "this node is not the primary")
	}
	peers, err := s.fo.store.Peers(ctx)
	if err != nil {
		return resubscribeResult{}, err
	}
	var components []string
	for _, p := range peers {
		if p.NodeID == member {
			components = clustercatalog.WithCore(p.Components)
		}
	}
	if components == nil {
		return resubscribeResult{}, newServiceError(404, "unknown_member", "this primary does not know the member")
	}
	pw, err := pkgcrypto.RandomBytes(32)
	if err != nil {
		return resubscribeResult{}, err
	}
	password := hex.EncodeToString(pw)
	role, err := s.fo.repl.EnsureReplicationRole(ctx, member, password, components)
	if err != nil {
		return resubscribeResult{}, err
	}
	creds, _ := json.Marshal(replicationCreds{Host: s.joinCfg.pgHost, Port: s.joinCfg.pgPort, DB: s.joinCfg.pgDB, User: role, Password: password, SSLMode: s.joinCfg.pgSSLMode})
	key, err := base64.StdEncoding.DecodeString(in.EncapsulationKey)
	if err != nil {
		pkgcrypto.Zeroize(creds)
		return resubscribeResult{}, newServiceError(400, "bad_request", "encapsulation_key must be base64")
	}
	rctx := fmt.Sprintf("cluster-resubscribe|%d|%s", st.Epoch, member)
	sealed, err := pkgcrypto.KEMSeal(key, creds, []byte(rctx), labelResubscribe)
	pkgcrypto.Zeroize(creds)
	if err != nil {
		return resubscribeResult{}, err
	}
	_ = s.publishAudit(ctx, "audit.cluster.member_resubscribe_granted", "root", map[string]interface{}{
		"member_node_id": member, "epoch": st.Epoch, "components": components, "replication_role": role,
		"severity": "warning", "result": "success",
	})
	return resubscribeResult{Context: rctx, Sealed: base64.StdEncoding.EncodeToString(sealed), Components: components}, nil
}

// resubscribeToPrimary runs on a member that follows a new primary: it
// detaches from the old one and copies its components from the new one.
func (s *Service) resubscribeToPrimary(ctx context.Context, st nodeState) error {
	recipient, err := pkgcrypto.NewKEMRecipient()
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(resubscribeInput{EncapsulationKey: base64.StdEncoding.EncodeToString(recipient.EncapsulationKey())})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(st.PrimaryURL, "/")+"/cluster/peer/resubscribe", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(pkgconfig.HeaderClusterNode, st.NodeID)
	req.Header.Set(pkgconfig.HeaderClusterCredential, st.ForwardCredential)
	var out struct {
		Result resubscribeResult `json:"result"`
	}
	if _, err := s.doJSON(req, st.PrimaryURL, st.PrimaryFingerprint, &out); err != nil {
		return err
	}
	sealed, err := base64.StdEncoding.DecodeString(out.Result.Sealed)
	if err != nil {
		return errors.New("the primary sent malformed replication access")
	}
	plain, err := recipient.Open(sealed, []byte(out.Result.Context), labelResubscribe)
	if err != nil {
		return err
	}
	var creds replicationCreds
	err = json.Unmarshal(plain, &creds)
	pkgcrypto.Zeroize(plain)
	if err != nil {
		return err
	}
	detached, err := s.fo.repl.Detach(ctx, st.NodeID)
	if err != nil {
		return err
	}
	subscribed := []string{}
	for _, c := range out.Result.Components {
		if _, ok := clustercatalog.Replicated[c]; !ok {
			continue
		}
		if err := s.fo.repl.Subscribe(ctx, st.NodeID, c, creds.conninfo(), clusterrepl.SubscribeOptions{ResetLocalData: true}); err != nil {
			return fmt.Errorf("subscribe %s: %w", c, err)
		}
		subscribed = append(subscribed, c)
	}
	_ = s.publishAudit(ctx, "audit.cluster.resubscribed", "root", map[string]interface{}{
		"node_id": st.NodeID, "primary_node_id": st.PrimaryNodeID, "epoch": st.Epoch,
		"detached": detached, "subscribed": subscribed, "severity": "warning", "result": "success",
		"description": "this member now copies its components from the new primary",
	})
	return nil
}

// ---- the loop ----

// FailoverTick is one round of the failover loop.
func (s *Service) FailoverTick(ctx context.Context) {
	st, err := s.fo.store.LoadNode(ctx)
	if err != nil {
		return
	}
	switch st.Role {
	case clusterstate.RolePrimary:
		s.pollPeers(ctx, st)
		if st, err = s.fo.store.LoadNode(ctx); err == nil && st.Role == clusterstate.RolePrimary {
			_ = s.renewLease(ctx, st)
		}
	case clusterstate.RoleFollower:
		if st.PrimaryURL == "" {
			return
		}
		s.fo.mu.Lock()
		if s.fo.electionAfter.IsZero() {
			s.fo.electionAfter = s.fo.jitteredDeadline(s.now())
		}
		pending := s.fo.resubscribe
		s.fo.mu.Unlock()
		if pending {
			if err := s.resubscribeToPrimary(ctx, st); err == nil {
				s.fo.mu.Lock()
				s.fo.resubscribe = false
				s.fo.mu.Unlock()
			}
		}
		if err := s.heartbeatPrimary(ctx, st); err == nil {
			return
		}
		s.pollPeers(ctx, st)
		if st, err = s.fo.store.LoadNode(ctx); err != nil || st.Role != clusterstate.RoleFollower {
			return
		}
		s.fo.mu.Lock()
		due := s.now().After(s.fo.electionAfter)
		s.fo.mu.Unlock()
		if !due {
			return
		}
		peers, err := s.fo.store.Peers(ctx)
		if err != nil {
			return
		}
		voters := 0
		for _, p := range peers {
			if p.voter() {
				voters++
			}
		}
		if voters >= 3 && st.PeerSecret != "" {
			s.fo.mu.Lock()
			s.fo.electionAfter = s.fo.jitteredDeadline(s.now())
			s.fo.mu.Unlock()
			s.runElection(ctx, st, peers)
		}
	}
}

// RunFailover runs the loop until ctx ends.
func (s *Service) RunFailover(ctx context.Context) {
	if s.fo == nil {
		return
	}
	for {
		s.FailoverTick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(failoverTick):
		}
	}
}

// FailoverStatus is GET /cluster/failover/status for the Cluster page.
func (s *Service) FailoverStatus(ctx context.Context) (map[string]interface{}, error) {
	if s.fo == nil {
		return map[string]interface{}{"configured": false}, nil
	}
	ps, err := s.PeerStatus(ctx)
	if err != nil {
		return nil, err
	}
	peers, err := s.fo.store.Peers(ctx)
	if err != nil {
		return nil, err
	}
	voters := 0
	list := []map[string]interface{}{}
	s.fo.mu.Lock()
	for _, p := range peers {
		if p.voter() {
			voters++
		}
		item := map[string]interface{}{"node_id": p.NodeID, "url": p.URL, "is_primary": p.IsPrimary, "voter": p.voter()}
		if t, ok := s.fo.heartbeats[p.NodeID]; ok && ps.Role == clusterstate.RolePrimary {
			item["last_heartbeat_ago_ms"] = s.now().Sub(t).Milliseconds()
		}
		list = append(list, item)
	}
	s.fo.mu.Unlock()
	mode := "manual"
	if voters >= 3 {
		mode = "automatic"
	}
	return map[string]interface{}{
		"configured": true, "node": ps, "peers": list, "voters": voters, "majority": majority(voters), "failover_mode": mode,
		"lease_required": voters >= 3, "promotable": s.joinCfg.advertiseURL != "" && s.joinCfg.pgHost != "",
	}, nil
}

// AdoptExistingCluster runs at start. A primary that took members before
// failover existed never recorded its role (nor peers): record them from
// its active member credentials and node registry.
func (s *Service) AdoptExistingCluster(ctx context.Context) error {
	if s.fo == nil {
		return nil
	}
	st, err := s.fo.store.LoadNode(ctx)
	if err != nil || st.Role != "" {
		return err
	}
	creds, err := s.fo.store.ActiveMemberCredentials(ctx)
	if err != nil || len(creds) == 0 {
		return err
	}
	if _, err := s.becomePrimary(ctx); err != nil {
		return err
	}
	for id, hash := range creds {
		p := peer{NodeID: id, CredentialHash: hash}
		if s.store != nil {
			if node, err := s.store.GetNode(ctx, "root", id); err == nil {
				p.URL, p.Fingerprint, p.Components = node.Endpoint, node.CertFingerprint, node.EnabledComponents
			}
		}
		if err := s.fo.store.UpsertPeer(ctx, p); err != nil {
			return err
		}
	}
	_ = s.publishAudit(ctx, "audit.cluster.primary_recorded", "root", map[string]interface{}{
		"node_id": s.bootstrapNodeID, "members": len(creds), "severity": "info", "result": "success",
		"description": "this primary recorded its role and members for failover",
	})
	return nil
}

// refuseUnlessPrimary is checked by the forwarding handler: a member or a
// fenced former primary does not apply other members' writes.
func (s *Service) refuseUnlessPrimary(ctx context.Context) error {
	if s.fo == nil {
		return nil
	}
	st, err := s.fo.store.LoadNode(ctx)
	if err != nil {
		return err
	}
	if st.Role == clusterstate.RoleFollower || st.Role == clusterstate.RoleFenced {
		return newServiceError(409, "not_primary", "this node is not the cluster primary")
	}
	return nil
}
