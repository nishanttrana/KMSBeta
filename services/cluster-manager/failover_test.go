package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"vecta-kms/pkg/clusterrepl"
	"vecta-kms/pkg/clusterstate"
)

// Failover between in-process nodes over real TLS (pinned certificates,
// signed peer calls). The store is in memory and replication is recorded;
// TestFailoverEndToEnd runs the same paths on real Postgres.

type memFailoverStore struct {
	mu    sync.Mutex
	st    nodeState
	peers map[string]peer
	votes map[int64]string
	creds map[string]string
}

func newMemFailoverStore() *memFailoverStore {
	return &memFailoverStore{peers: map[string]peer{}, votes: map[int64]string{}, creds: map[string]string{}}
}

func (m *memFailoverStore) LoadNode(context.Context) (nodeState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.st, nil
}
func (m *memFailoverStore) SaveNode(_ context.Context, st nodeState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.st = st
	return nil
}
func (m *memFailoverStore) SetLease(_ context.Context, t time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.st.WritableUntil = t
	return nil
}
func (m *memFailoverStore) Peers(context.Context) ([]peer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []peer{}
	for _, p := range m.peers {
		out = append(out, p)
	}
	return out, nil
}
func (m *memFailoverStore) UpsertPeer(_ context.Context, p peer) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peers[p.NodeID] = p
	return nil
}
func (m *memFailoverStore) DeletePeer(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.peers, id)
	return nil
}
func (m *memFailoverStore) Vote(_ context.Context, epoch int64, c string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if v, ok := m.votes[epoch]; ok {
		return v == c, nil
	}
	m.votes[epoch] = c
	return true, nil
}
func (m *memFailoverStore) MaxVoteEpoch(context.Context) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var max int64
	for e := range m.votes {
		if e > max {
			max = e
		}
	}
	return max, nil
}
func (m *memFailoverStore) SetMemberCredential(_ context.Context, id, hash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.creds[id] = hash
	return nil
}
func (m *memFailoverStore) MemberCredentialHash(_ context.Context, id string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if h, ok := m.creds[id]; ok {
		return h, nil
	}
	return "", errForwardCredential
}
func (m *memFailoverStore) ActiveMemberCredentials(context.Context) (map[string]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]string{}
	for k, v := range m.creds {
		out[k] = v
	}
	return out, nil
}

type fakeRepl struct {
	mu         sync.Mutex
	applied    string
	received   string
	wal        string
	detached   int
	subscribed []string
	roles      []string
	slots      bool
}

func (f *fakeRepl) Detach(context.Context, string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.detached++
	return []string{"vecta_sub_x_auth"}, nil
}
func (f *fakeRepl) AppliedLSN(context.Context, string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.applied, nil
}
func (f *fakeRepl) ReceivedLSN(context.Context, string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.received, f.received != "", nil
}
func (f *fakeRepl) CurrentWALLSN(context.Context) (string, error) { return f.wal, nil }
func (f *fakeRepl) EnsureReplicationRole(_ context.Context, node, _ string, _ []string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.roles = append(f.roles, node)
	return clusterrepl.ReplicationRoleName(node), nil
}
func (f *fakeRepl) Subscribe(_ context.Context, node, c, conninfo string, o clusterrepl.SubscribeOptions) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !o.ResetLocalData || !strings.Contains(conninfo, "user='vecta_repl_") {
		panic("resubscription must reset and use the new primary's role: " + conninfo)
	}
	f.subscribed = append(f.subscribed, c)
	return nil
}
func (f *fakeRepl) EnsurePublications(context.Context, []string) ([]clusterrepl.PublicationStatus, error) {
	return nil, nil
}

func (f *fakeRepl) DropMemberSlots(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.slots = true
	return nil
}

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *testClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type foNode struct {
	id    string
	svc   *Service
	store *memFailoverStore
	repl  *fakeRepl
	audit *captureAudit
	srv   *httptest.Server
	down  atomic.Bool
	cred  string
}

func (n *foNode) state() nodeState { st, _ := n.store.LoadNode(context.Background()); return st }

// newFoCluster builds a primary and members, with the primary knowing its
// members as a join leaves it; members learn the cluster by heartbeat.
func newFoCluster(t *testing.T, clk *testClock, ids ...string) map[string]*foNode {
	t.Helper()
	nodes := map[string]*foNode{}
	for _, id := range ids {
		n := &foNode{id: id, store: newMemFailoverStore(), repl: &fakeRepl{wal: "0/500"}, audit: &captureAudit{}, cred: "cred-" + id}
		t.Setenv("CLUSTER_NODE_ID", id)
		n.svc = NewService(nil, n.audit).WithFailover(n.store, n.repl)
		n.svc.now = clk.Now
		n.svc.fo.lastContact = clk.Now()
		h := NewHandler(n.svc)
		n.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if n.down.Load() {
				hj, _ := w.(http.Hijacker)
				conn, _, _ := hj.Hijack()
				_ = conn.Close()
				return
			}
			h.ServeHTTP(w, r)
		}))
		t.Cleanup(n.srv.Close)
		sum := sha256.Sum256(n.srv.Certificate().Raw)
		n.svc.joinCfg = joinConfig{advertiseURL: n.srv.URL, tlsFingerprint: hex.EncodeToString(sum[:]), pgHost: id + "-pg", pgPort: "5432", pgDB: "vecta", pgSSLMode: "verify-full"}
		nodes[id] = n
	}
	ctx := context.Background()
	primary := nodes[ids[0]]
	if _, err := primary.svc.becomePrimary(ctx); err != nil {
		t.Fatal(err)
	}
	for _, id := range ids[1:] {
		m := nodes[id]
		_ = primary.store.SetMemberCredential(ctx, id, credentialHash(m.cred))
		_ = primary.store.UpsertPeer(ctx, peer{NodeID: id, URL: m.svc.joinCfg.advertiseURL, Fingerprint: m.svc.joinCfg.tlsFingerprint, CredentialHash: credentialHash(m.cred), Components: []string{"secrets"}})
		_ = m.store.SaveNode(ctx, nodeState{State: clusterstate.State{NodeID: id, Role: clusterstate.RoleFollower, PrimaryNodeID: primary.id,
			PrimaryURL: primary.srv.URL, PrimaryFingerprint: primary.svc.joinCfg.tlsFingerprint, ForwardCredential: m.cred}})
	}
	return nodes
}

func tickAll(nodes map[string]*foNode, ids ...string) {
	for _, id := range ids {
		if !nodes[id].down.Load() {
			nodes[id].svc.FailoverTick(context.Background())
		}
	}
}

func TestThreeNodeElectionFencesTheOldPrimary(t *testing.T) {
	clk := &testClock{t: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
	n := newFoCluster(t, clk, "a", "b", "c")
	a, b, c := n["a"], n["b"], n["c"]
	tickAll(n, "b", "c", "a")
	if b.state().PeerSecret == "" || b.state().Epoch != 1 || len(b.store.peers) != 3 {
		t.Fatalf("member did not learn the cluster: %+v peers %d", b.state(), len(b.store.peers))
	}
	if until := a.state().WritableUntil; !until.Equal(clk.Now().Add(leaseTTL)) {
		t.Fatalf("lease %v, want now+%v", until, leaseTTL)
	}

	// The primary is cut off: its lease runs out before anyone can stand.
	a.down.Store(true)
	clk.Add(leaseTTL + time.Second)
	a.svc.FailoverTick(context.Background()) // it can still tick, but hears nobody
	if ok, _ := a.state().WritesAllowed(clk.Now()); ok {
		t.Fatal("an isolated primary still writes after its lease")
	}
	tickAll(n, "b", "c")
	if b.state().Role != clusterstate.RoleFollower || c.state().Role != clusterstate.RoleFollower {
		t.Fatal("a member stood before the election timeout")
	}

	// B has applied more of A's changes than C, so C can't win; B can.
	b.repl.applied, c.repl.applied = "0/200", "0/100"
	clk.Add(electionTimeout + electionJitter)
	c.svc.FailoverTick(context.Background())
	if c.state().Role != clusterstate.RoleFollower || c.state().Epoch != 1 {
		t.Fatalf("C won without the most data, or a lost election raised its epoch: %+v", c.state())
	}
	if b.audit.count("audit.cluster.vote_refused") != 1 {
		t.Fatal("B's refusal was not audited")
	}
	// C voted for itself in that epoch, so B's first round is refused there
	// too; its next round, an epoch later, wins.
	for i := 0; i < 2 && b.state().Role != clusterstate.RolePrimary; i++ {
		clk.Add(electionTimeout + electionJitter)
		b.svc.FailoverTick(context.Background())
	}
	bs := b.state()
	if bs.Role != clusterstate.RolePrimary || bs.Epoch < 2 || b.repl.detached != 1 {
		t.Fatalf("B not promoted: %+v detached %d", bs, b.repl.detached)
	}
	if b.audit.count("audit.cluster.promoted") != 1 || c.audit.count("audit.cluster.vote_granted") != 1 {
		t.Fatal("promotion or vote not audited")
	}
	if ok, _ := bs.WritesAllowed(clk.Now()); !ok {
		t.Fatal("the new primary has no lease from the votes that elected it")
	}
	// C heard the announcement, re-subscribes to B with B's replication role,
	// and B accepts C's forwarding credential.
	if c.state().PrimaryNodeID != "b" || c.state().Epoch != bs.Epoch {
		t.Fatalf("C does not follow B: %+v", c.state())
	}
	tickAll(n, "c")
	if strings.Join(c.repl.subscribed, ",") != "auth,governance,keycore,policy,secrets" || len(b.repl.roles) != 1 || b.repl.roles[0] != "c" || c.svc.fo.resubscribe {
		t.Fatalf("C did not re-subscribe: subs %v roles %v", c.repl.subscribed, b.repl.roles)
	}
	tickAll(n, "b")
	if ok, _ := b.state().WritesAllowed(clk.Now()); !ok {
		t.Fatal("B lost its lease with C heartbeating")
	}

	// A comes back still believing it is primary: it learns of B and fences.
	a.down.Store(false)
	a.svc.FailoverTick(context.Background())
	as := a.state()
	if as.Role != clusterstate.RoleFenced || as.Epoch != bs.Epoch || a.audit.count("audit.cluster.fenced") != 1 {
		t.Fatalf("old primary not fenced: %+v", as)
	}
	if ok, reason := as.WritesAllowed(clk.Now()); ok || reason != "node_fenced" {
		t.Fatal("a fenced node still writes")
	}
}

// A member cut off from a healthy primary can't take over: the others still
// reach the primary and refuse, and its lost election raises no epoch that
// would fence the primary when it reconnects.
func TestPartitionedMemberCannotDisruptAHealthyPrimary(t *testing.T) {
	clk := &testClock{t: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
	n := newFoCluster(t, clk, "a", "b", "c")
	a, c := n["a"], n["c"]
	tickAll(n, "b", "c", "a")
	realURL := c.state().PrimaryURL
	st := c.state()
	st.PrimaryURL = "https://127.0.0.1:1" // C alone can't reach A
	_ = c.store.SaveNode(context.Background(), st)
	for i := 0; i < 15; i++ {
		clk.Add(failoverTick)
		tickAll(n, "a", "b", "c")
	}
	if c.state().Role != clusterstate.RoleFollower || n["b"].audit.count("audit.cluster.vote_granted") != 0 {
		t.Fatal("a partitioned member won votes while the primary was healthy")
	}
	st = c.state()
	st.PrimaryURL = realURL
	_ = c.store.SaveNode(context.Background(), st)
	tickAll(n, "c", "a")
	if a.state().Role != clusterstate.RolePrimary || c.state().Epoch != 1 {
		t.Fatalf("a lost election disrupted the primary: A %+v C %+v", a.state(), c.state())
	}
}

func TestPeerCallsAndVotesAreChecked(t *testing.T) {
	clk := &testClock{t: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
	n := newFoCluster(t, clk, "a", "b", "c")
	tickAll(n, "b", "c")
	b, c := n["b"], n["c"]
	ctx := context.Background()
	call := func(sign func(*http.Request)) int {
		req, _ := http.NewRequest(http.MethodGet, c.srv.URL+"/cluster/peer/status", nil)
		sign(req)
		resp, err := c.srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close() //nolint:errcheck
		return resp.StatusCode
	}
	secret := c.state().PeerSecret
	signed := func(node, secretUsed string, at time.Time) func(*http.Request) {
		return func(r *http.Request) {
			ts := strconv.FormatInt(at.Unix(), 10)
			r.Header.Set(headerPeerNode, node)
			r.Header.Set(headerPeerTime, ts)
			r.Header.Set(headerPeerSignature, peerSignature(secretUsed, r.Method, r.URL.Path, ts, node, nil))
		}
	}
	if got := call(signed("b", secret, clk.Now())); got != 200 {
		t.Fatalf("a signed call from a peer: %d", got)
	}
	for name, s := range map[string]func(*http.Request){
		"unsigned":     func(*http.Request) {},
		"wrong secret": signed("b", "not-the-secret", clk.Now()),
		"unknown node": signed("z", secret, clk.Now()),
		"stale":        signed("b", secret, clk.Now().Add(-time.Minute)),
	} {
		before := c.audit.count("audit.cluster.peer_refused")
		if got := call(s); got != http.StatusUnauthorized || c.audit.count("audit.cluster.peer_refused") != before+1 {
			t.Fatalf("%s: %d", name, got)
		}
	}
	// C still reaches the primary: no vote.
	if res, _ := c.svc.GrantVote(ctx, "b", voteRequest{Epoch: 2, Candidate: "b"}); res.Granted {
		t.Fatal("a voter in contact with the primary voted")
	}
	clk.Add(electionTimeout + time.Second)
	if res, _ := c.svc.GrantVote(ctx, "a", voteRequest{Epoch: 2, Candidate: "b"}); res.Granted {
		t.Fatal("a vote asked for another node was granted")
	}
	if res, _ := c.svc.GrantVote(ctx, "b", voteRequest{Epoch: 1, Candidate: "b"}); res.Granted {
		t.Fatal("a vote for the current epoch was granted")
	}
	if res, _ := c.svc.GrantVote(ctx, "b", voteRequest{Epoch: 2, Candidate: "b"}); !res.Granted {
		t.Fatalf("a valid vote refused: %+v", res)
	}
	if res, _ := c.svc.GrantVote(ctx, "a", voteRequest{Epoch: 2, Candidate: "a"}); res.Granted {
		t.Fatal("two votes in one epoch")
	}
	_ = b
}

func TestTwoNodeManualPromotion(t *testing.T) {
	ctx := context.Background()
	clk := &testClock{t: time.Now()}

	// Switchover: the primary answers, is fenced first, and the member waits
	// for its last write.
	n := newFoCluster(t, clk, "a", "b")
	a, b := n["a"], n["b"]
	tickAll(n, "b", "a")
	if !a.state().WritableUntil.IsZero() {
		t.Fatal("a two-node primary needs no lease")
	}
	if _, err := b.svc.PromoteManually(ctx, PromoteInput{}); err == nil {
		t.Fatal("promotion without confirm")
	}
	b.svc.joinCfg.pgHost = ""
	if _, err := b.svc.PromoteManually(ctx, PromoteInput{Confirm: true}); err == nil || a.state().Role != clusterstate.RolePrimary {
		t.Fatalf("an unpromotable node was promoted, or fenced the primary first: %v", err)
	}
	b.svc.joinCfg.pgHost = "b-pg"
	b.repl.received = "0/500"
	res, err := b.svc.PromoteManually(ctx, PromoteInput{Confirm: true, Actor: "alice"})
	if err != nil || !res.CaughtUp || b.state().Role != clusterstate.RolePrimary || a.state().Role != clusterstate.RoleFenced {
		t.Fatalf("switchover: %+v %v; A %+v", res, err, a.state())
	}
	if b.audit.count("audit.cluster.promoted_manually") != 1 || a.audit.count("audit.cluster.fenced") != 1 {
		t.Fatal("switchover not audited on both nodes")
	}
	// A fenced node takes no members.
	if _, err := a.svc.becomePrimary(ctx); err == nil {
		t.Fatal("a fenced node became primary again without rejoining")
	}

	// Failover: the primary is down; force is required and said.
	n = newFoCluster(t, clk, "p", "q")
	tickAll(n, "q")
	n["p"].down.Store(true)
	if _, err := n["q"].svc.PromoteManually(ctx, PromoteInput{Confirm: true}); err == nil || !strings.Contains(err.Error(), "force") {
		t.Fatalf("promotion over an unreachable primary without force: %v", err)
	}
	if _, err := n["q"].svc.PromoteManually(ctx, PromoteInput{Confirm: true, Force: true}); err != nil || n["q"].state().Role != clusterstate.RolePrimary {
		t.Fatalf("forced promotion: %v", err)
	}
	// The old primary learns at its next tick that it was replaced.
	n["p"].down.Store(false)
	n["p"].svc.FailoverTick(ctx)
	if n["p"].state().Role != clusterstate.RoleFenced {
		t.Fatal("the old primary did not fence itself")
	}
}

// A primary that took members before failover existed records its role and
// peers at start.
func TestExistingPrimaryIsAdopted(t *testing.T) {
	s := NewService(nil, &captureAudit{})
	store := newMemFailoverStore()
	s.WithFailover(store, &fakeRepl{})
	_ = store.SetMemberCredential(context.Background(), "m1", credentialHash("x"))
	if err := s.AdoptExistingCluster(context.Background()); err != nil {
		t.Fatal(err)
	}
	if store.st.Role != clusterstate.RolePrimary || store.st.PeerSecret == "" || store.peers["m1"].CredentialHash == "" {
		t.Fatalf("not adopted: %+v %+v", store.st, store.peers)
	}
}
