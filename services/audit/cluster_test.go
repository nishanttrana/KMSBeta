package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	pkgaudit "vecta-kms/pkg/audit"
	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/clusterkey"
)

var testAuditKey = []byte("0123456789abcdef0123456789abcdef")

func appendEvents(t *testing.T, s *SQLStore, tenant string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, _, err := s.PersistEventAndAlert(context.Background(), AuditEvent{
			TenantID: tenant, Timestamp: time.Now().UTC(), Service: "key", Action: "audit.key.encrypt",
			ActorID: "u1", ActorType: "human", Result: "success",
		}, Alert{Severity: "LOW", Category: "key", Title: "encrypt", SourceService: "key"}, 60, 5, 10*time.Minute); err != nil {
			t.Fatal(err)
		}
	}
}

const eventCols = `id, tenant_id, sequence, chain_hash, previous_hash, timestamp, service, action, actor_id, actor_type,
	target_type, target_id, method, endpoint, source_ip, user_agent, request_hash, correlation_id, parent_event_id, session_id,
	result, status_code, error_message, duration_ms, fips_compliant, approval_id, risk_score, tags, node_id, details,
	hmac_sig, category_group, chain_node, hmac_key_id`

// replicate copies one node's chain rows into another node's table, as
// logical replication does.
func replicate(t *testing.T, from, to *SQLStore, chain string) {
	t.Helper()
	rows, err := from.db.SQL().Query(`SELECT `+eventCols+` FROM audit_events WHERE chain_node = $1`, chain)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		vals := make([]interface{}, 34)
		ptrs := make([]interface{}, 34)
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		ph := "$1"
		for i := 2; i <= 34; i++ {
			ph += ",$" + itoa(int64(i))
		}
		if _, err := to.db.SQL().Exec(`INSERT INTO audit_events (`+eventCols+`) VALUES (`+ph+`)`, vals...); err != nil {
			t.Fatal(err)
		}
	}
}

func chainAs(s *SQLStore, node string) {
	s.SetChainNode(func(context.Context) string { return node })
}

// Two nodes append their own chains; each verifies both, including HMACs, once
// they share the cluster key. A node never extends another node's chain.
func TestPerNodeChainsReplicateAndVerify(t *testing.T) {
	ctx := context.Background()
	primary, member := newAuditStore(t), newAuditStore(t)
	primary.SetEventSigningKey(testAuditKey)
	member.SetEventSigningKey([]byte("ffffffffffffffffffffffffffffffff")) // member's own key before join

	appendEvents(t, primary, "t1", 2) // standalone history ('' chain)
	appendEvents(t, member, "t1", 2)
	chainAs(primary, "n1")
	chainAs(member, "n2")
	member.SetEventSigningKey(testAuditKey) // cluster key received at join
	appendEvents(t, primary, "t1", 2)
	appendEvents(t, member, "t1", 3)

	replicate(t, member, primary, "n2")
	replicate(t, primary, member, "n1")

	for name, s := range map[string]*SQLStore{"primary": primary, "member": member} {
		if ok, breaks, err := s.VerifyChain(ctx, "t1"); err != nil || !ok {
			t.Fatalf("%s: both chains must verify: %v %v", name, breaks, err)
		}
	}
	// The primary's next event continues its own chain, not the member's.
	appendEvents(t, primary, "t1", 1)
	var seq int64
	_ = primary.db.SQL().QueryRow(`SELECT MAX(sequence) FROM audit_events WHERE chain_node='n1'`).Scan(&seq)
	if seq != 5 {
		t.Fatalf("primary chain must continue at 5 (2 legacy + 3), got %d", seq)
	}
	if ok, breaks, _ := primary.VerifyChain(ctx, "t1"); !ok {
		t.Fatalf("chain after interleaving: %v", breaks)
	}

	// Tampering with a replicated row is detected on the receiving node.
	if _, err := primary.db.SQL().Exec(`UPDATE audit_events SET actor_id='mallory' WHERE chain_node='n2' AND sequence=4`); err != nil {
		t.Fatal(err)
	}
	if ok, _, _ := primary.VerifyChain(ctx, "t1"); ok {
		t.Fatal("a modified replicated event must break verification")
	}
}

func TestHMACVerificationNeedsTheSigningKey(t *testing.T) {
	ctx := context.Background()
	a, b := newAuditStore(t), newAuditStore(t)
	a.SetEventSigningKey(testAuditKey)
	b.SetEventSigningKey([]byte("ffffffffffffffffffffffffffffffff"))
	chainAs(a, "n1")
	chainAs(b, "n2")
	appendEvents(t, a, "t1", 2)
	replicate(t, a, b, "n1")
	ok, breaks, _ := b.VerifyChain(ctx, "t1")
	if ok || len(breaks) == 0 || breaks[0]["reason"] != "hmac_key_unknown" {
		t.Fatalf("a chain signed with a key this node lacks must be flagged: %v", breaks)
	}
	// A forged signature under a known key is a mismatch.
	b.SetEventSigningKey(testAuditKey)
	if _, err := b.db.SQL().Exec(`UPDATE audit_events SET hmac_sig='00' WHERE chain_node='n1' AND sequence=2`); err != nil {
		t.Fatal(err)
	}
	ok, breaks, _ = b.VerifyChain(ctx, "t1")
	if ok || breaks[0]["reason"] != "hmac_mismatch" {
		t.Fatalf("a bad signature must be flagged: %v", breaks)
	}
}

// Relayed events already present by replication are not persisted twice;
// relay-marked events that are not present are persisted (no evasion).
func TestRelayedDuplicatesAreSkippedOnlyWhenPresent(t *testing.T) {
	h, svc, store, _ := newAuditHandler(t, true, false)
	_ = h
	ctx := context.Background()
	chainAs(store, "n1")
	appendEvents(t, store, "t1", 1)
	var id string
	_ = store.db.SQL().QueryRow(`SELECT id FROM audit_events LIMIT 1`).Scan(&id)
	count := func() int {
		var n int
		_ = store.db.SQL().QueryRow(`SELECT COUNT(1) FROM audit_events`).Scan(&n)
		return n
	}
	msg := func(eventID string) []byte {
		b, _ := json.Marshal(pkgaudit.Event{ID: eventID, TenantID: "t1", Service: "key", Action: "audit.key.encrypt", Result: "success", Origin: pkgaudit.OriginClusterRelay, Timestamp: time.Now().UTC().Format(time.RFC3339Nano)})
		return b
	}
	for _, c := range []struct {
		id   string
		want int
	}{{id, 1}, {"evt_not_present", 2}} {
		ev, err := parseIncomingEvent("audit.key.encrypt", msg(c.id))
		if err != nil {
			t.Fatal(err)
		}
		if !svc.isRelayedDuplicate(ctx, ev) {
			if _, _, err := svc.ProcessEvent(ctx, ev); err != nil {
				t.Fatal(err)
			}
		}
		if got := count(); got != c.want {
			t.Fatalf("relay %s: %d events, want %d", c.id, got, c.want)
		}
	}
}

func clusterRequest(t *testing.T, h *Handler, path string, claims *pkgauth.Claims, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	if claims != nil {
		req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims))
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func actionCount(t *testing.T, s *SQLStore, action string) int {
	var n int
	_ = s.db.SQL().QueryRow(`SELECT COUNT(1) FROM audit_events WHERE action=$1`, action).Scan(&n)
	return n
}

// The primary's audit signing key reaches a member sealed, only through the
// cluster-manager identity, and the member then signs with it.
func TestClusterSigningKeyTransfer(t *testing.T) {
	cm := &pkgauth.Claims{Role: "client-service", ClientID: clusterkey.ClusterManager, TenantID: "root", Permissions: []string{"service.internal"}}
	other := &pkgauth.Claims{Role: "client-service", ClientID: "kms-keycore", TenantID: "root", Permissions: []string{"service.internal"}}

	ph, _, pstore, _ := newAuditHandler(t, true, false)
	pstore.SetEventSigningKey(testAuditKey)
	mh, msvc, mstore, _ := newAuditHandler(t, true, false)
	mstore.SetEventSigningKey([]byte("ffffffffffffffffffffffffffffffff"))
	msvc.cluster.keyFile = filepath.Join(t.TempDir(), "cluster-key.b64")

	for _, c := range []*pkgauth.Claims{nil, other} {
		if rr := clusterRequest(t, mh, "/audit/cluster/signing-key/join-key", c, map[string]any{}); rr.Code != http.StatusForbidden {
			t.Fatalf("join key must require cluster-manager: %d", rr.Code)
		}
	}
	if actionCount(t, mstore, "audit.audit.cluster_signing_key_refused") != 2 {
		t.Fatal("refused key operations must be audited")
	}

	rr := clusterRequest(t, mh, "/audit/cluster/signing-key/join-key", cm, map[string]any{})
	var jk struct{ JoinKeyID, EncapsulationKey string }
	_ = json.Unmarshal(rr.Body.Bytes(), &struct {
		ID *string `json:"join_key_id"`
		EK *string `json:"encapsulation_key"`
	}{&jk.JoinKeyID, &jk.EncapsulationKey})
	rr = clusterRequest(t, ph, "/audit/cluster/signing-key/export", cm, map[string]any{"encapsulation_key": jk.EncapsulationKey, "context": "cluster-join|tok|n2", "member_node_id": "n2"})
	var exp struct {
		Sealed string `json:"sealed_key"`
		KeyID  string `json:"key_id"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &exp)
	if rr.Code != http.StatusOK || exp.KeyID != auditKeyID(testAuditKey) {
		t.Fatalf("export: %d %s", rr.Code, rr.Body.String())
	}
	rr = clusterRequest(t, mh, "/audit/cluster/signing-key/import", cm, map[string]any{"join_key_id": jk.JoinKeyID, "sealed_key": exp.Sealed, "context": "cluster-join|tok|n2", "key_id": exp.KeyID})
	if rr.Code != http.StatusOK {
		t.Fatalf("import: %d %s", rr.Code, rr.Body.String())
	}
	if _, id := mstore.keys.current(); id != exp.KeyID {
		t.Fatal("the member must sign with the cluster key after import")
	}
	if _, err := os.Stat(msvc.cluster.keyFile); err != nil {
		t.Fatal("the cluster key must be persisted for restarts")
	}
	fresh := newAuditStore(t)
	if err := loadClusterSigningKey(fresh, msvc.cluster.keyFile); err != nil {
		t.Fatal(err)
	}
	if _, id := fresh.keys.current(); id != exp.KeyID {
		t.Fatal("a restarted member must load the cluster key")
	}
	if actionCount(t, pstore, "audit.audit.cluster_signing_key_exported") != 1 || actionCount(t, mstore, "audit.audit.cluster_signing_key_imported") != 1 {
		t.Fatal("export and import must be audited")
	}
	// The join key is one-use.
	rr = clusterRequest(t, mh, "/audit/cluster/signing-key/import", cm, map[string]any{"join_key_id": jk.JoinKeyID, "sealed_key": exp.Sealed, "context": "cluster-join|tok|n2", "key_id": exp.KeyID})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("a used join key must be refused: %d", rr.Code)
	}
}
