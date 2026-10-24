package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	pkgcache "vecta-kms/pkg/cache"
	"vecta-kms/pkg/metering"
	"vecta-kms/pkg/route/routetest"
)

// installation is one KMS: its own database and master key, behind a TLS
// edge that maps bearer tokens to verified claims and exchanges the peer's
// REST client API key for a token, as auth does.
type installation struct {
	name  string
	svc   *Service
	h     *Handler
	srv   *httptest.Server
	caPEM string
}

func newInstallation(t *testing.T, name string, mek string) *installation {
	t.Helper()
	svc := NewService(newStoreForTest(t), NewKeyCache(pkgcache.NewMemory(time.Minute), time.Minute), &eventRecorder{},
		metering.NewMeter(0, time.Hour), []byte(mek), nil, false)
	h := NewHandler(svc)
	in := &installation{name: name, svc: svc, h: h}
	in.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/svc/auth/auth/client-token" {
			if r.Header.Get("X-API-Key") != "fed-api-key" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "peer-client"})
			return
		}
		var claims *pkgauth.Claims
		switch r.Header.Get("Authorization") {
		case "Bearer admin":
			claims = &pkgauth.Claims{UserID: "admin", TenantID: "t1", Role: "admin", Permissions: []string{"*"}}
			claims.Subject = "admin"
		case "Bearer peer-client":
			// The other installation's REST client: it may only deliver.
			claims = &pkgauth.Claims{ClientID: "fed-client", UserID: "fed-client", TenantID: "t1", Role: "client-service",
				Permissions: []string{permFederationReceive}}
			claims.Subject = "fed-client"
		default:
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/svc/keycore")
		h.ServeHTTP(w, r.WithContext(pkgauth.ContextWithClaims(r.Context(), claims)))
	}))
	t.Cleanup(in.srv.Close)
	in.caPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: in.srv.Certificate().Raw}))
	return in
}

// call is an administrator's request to the installation's keycore.
func (in *installation) call(t *testing.T, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	req := httptest.NewRequest(method, path+sep+"tenant_id=t1", bytes.NewReader(raw))
	rr := httptest.NewRecorder()
	serveAsAdmin(in.h, rr, req)
	out := map[string]any{}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out
}

func (in *installation) identity(t *testing.T) map[string]any {
	t.Helper()
	code, out := in.call(t, http.MethodGet, "/federation/identity", nil)
	if code != http.StatusOK {
		t.Fatalf("%s identity: %d %v", in.name, code, out)
	}
	return out["identity"].(map[string]any)
}

// peer registers other at in and returns the peer's ID.
func (in *installation) peer(t *testing.T, other *installation) string {
	t.Helper()
	code, out := in.call(t, http.MethodPost, "/federation/peers", map[string]any{
		"name": other.name, "url": other.srv.URL, "peer_tenant_id": "t1", "identity": other.identity(t),
		"ca_pem": other.caPEM, "client_id": "fed-client", "api_key": "fed-api-key",
	})
	if code != http.StatusCreated {
		t.Fatalf("%s add peer %s: %d %v", in.name, other.name, code, out)
	}
	return out["peer"].(map[string]any)["id"].(string)
}

func (in *installation) link(t *testing.T, keyID, peerID string) map[string]any {
	t.Helper()
	code, out := in.call(t, http.MethodPost, "/federation/links", map[string]any{"key_id": keyID, "peer_id": peerID})
	if code != http.StatusCreated {
		t.Fatalf("%s link: %d %v", in.name, code, out)
	}
	return out["link"].(map[string]any)
}

func (in *installation) sync(t *testing.T, linkID string) map[string]any {
	t.Helper()
	code, out := in.call(t, http.MethodPost, "/federation/links/"+linkID+"/sync", nil)
	if code != http.StatusOK {
		t.Fatalf("%s sync: %d %v", in.name, code, out)
	}
	return out["link"].(map[string]any)
}

func (in *installation) state(t *testing.T, keyID string) FederationKeyState {
	t.Helper()
	st, err := in.svc.store.GetFederationKeyState(context.Background(), "t1", keyID)
	if err != nil {
		t.Fatalf("%s state of %s: %v", in.name, keyID, err)
	}
	return st
}

func (in *installation) encrypt(t *testing.T, keyID, plain string) CryptoResponse {
	t.Helper()
	out, err := in.svc.Encrypt(adminCtx(), keyID, EncryptRequest{TenantID: "t1", PlaintextB64: b64([]byte(plain))})
	if err != nil {
		t.Fatalf("%s encrypt: %v", in.name, err)
	}
	return out
}

func (in *installation) decrypt(t *testing.T, keyID string, ct CryptoResponse) string {
	t.Helper()
	out, err := in.svc.Decrypt(adminCtx(), keyID, DecryptRequest{TenantID: "t1", CiphertextB64: ct.CipherB64, IVB64: ct.IVB64, Version: ct.Version})
	if err != nil {
		t.Fatalf("%s decrypt v%d: %v", in.name, ct.Version, err)
	}
	plain, _ := base64.StdEncoding.DecodeString(out.PlainB64)
	return string(plain)
}

func (in *installation) rotate(t *testing.T, keyID string) int {
	t.Helper()
	v, err := in.svc.RotateKey(adminCtx(), "t1", keyID, "scheduled", "")
	if err != nil {
		t.Fatalf("%s rotate: %v", in.name, err)
	}
	return v.Version
}

func exportableKey(t *testing.T, in *installation, name string) Key {
	t.Helper()
	key, err := in.svc.CreateKey(adminCtx(), CreateKeyRequest{TenantID: "t1", Name: name, Algorithm: "AES-256", KeyType: "symmetric",
		Purpose: "encrypt", ExportAllowed: true, CreatedBy: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// Two installations: a key replicated from A to B, used on both, rotated
// at A and synced, B promoted when A is lost, A fenced and demoted, and B
// replicating back to A (failback).
func TestFederationReplicatesAndFailsOver(t *testing.T) {
	a := newInstallation(t, "site-a", "0123456789ABCDEF0123456789ABCDEF")
	b := newInstallation(t, "site-b", "FEDCBA9876543210FEDCBA9876543210")
	bAtA, aAtB := a.peer(t, b), b.peer(t, a)

	key := exportableKey(t, a, "payments")
	before := a.encrypt(t, key.ID, "card 4111")
	link := a.link(t, key.ID, bAtA)
	if link["status"] != linkInSync {
		t.Fatalf("first push: %v", link)
	}

	// The replica: same ID, versions and KCV; it decrypts A's ciphertext.
	replica, err := b.svc.GetKey(adminCtx(), "t1", key.ID)
	if err != nil || !bytes.Equal(replica.KCV, key.KCV) || replica.Name != "payments" {
		t.Fatalf("replica at B: %+v %v", replica, err)
	}
	if st := b.state(t, key.ID); st.Role != fedRoleReplica || st.Epoch != 1 || st.SourcePeerID != aAtB {
		t.Fatalf("B's state: %+v", st)
	}
	if got := b.decrypt(t, key.ID, before); got != "card 4111" {
		t.Fatalf("B decrypted %q", got)
	}
	// And B serves new operations; A reads them.
	if got := a.decrypt(t, key.ID, b.encrypt(t, key.ID, "from b")); got != "from b" {
		t.Fatalf("A decrypted %q", got)
	}

	// A replica's lifecycle is the primary's.
	if _, err := b.svc.RotateKey(adminCtx(), "t1", key.ID, "x", ""); !errors.Is(err, errFederatedReplica) {
		t.Fatalf("rotating a replica: %v", err)
	}
	if code, out := b.call(t, http.MethodPost, "/keys/"+key.ID+"/rotate", map[string]any{"reason": "x"}); code != http.StatusConflict || !strings.Contains(out["error"].(map[string]any)["code"].(string), "federated_replica") {
		t.Fatalf("rotate route on a replica: %d %v", code, out)
	}
	if code, _ := b.call(t, http.MethodPatch, "/keys/"+key.ID, map[string]any{"name": "renamed"}); code != http.StatusConflict {
		t.Fatalf("patch on a replica: %d", code)
	}

	// A rotates; the next push brings version 2.
	if v := a.rotate(t, key.ID); v != 2 {
		t.Fatalf("rotated to %d", v)
	}
	if l := a.sync(t, link["id"].(string)); l["status"] != linkInSync {
		t.Fatalf("sync after rotation: %v", l)
	}
	v2 := a.encrypt(t, key.ID, "version 2")
	if v2.Version != 2 || b.decrypt(t, key.ID, v2) != "version 2" || b.decrypt(t, key.ID, before) != "card 4111" {
		t.Fatal("B doesn't hold both versions")
	}

	// A is lost: B takes over.
	if code, out := b.call(t, http.MethodPost, "/federation/keys/"+key.ID+"/promote", map[string]any{"reason": "short"}); code != http.StatusBadRequest {
		t.Fatalf("promote without a reason: %d %v", code, out)
	}
	if code, out := b.call(t, http.MethodPost, "/federation/keys/"+key.ID+"/promote", map[string]any{"reason": "site A is down: failover"}); code != http.StatusOK {
		t.Fatalf("promote: %d %v", code, out)
	}
	if st := b.state(t, key.ID); st.Role != fedRolePrimary || st.Epoch != 2 {
		t.Fatalf("B after promotion: %+v", st)
	}
	if v := b.rotate(t, key.ID); v != 3 {
		t.Fatalf("B rotated to %d", v)
	}

	// A comes back and pushes: B refuses with a signed statement, and A
	// demotes itself (it keeps serving; it can't change).
	if l := a.sync(t, link["id"].(string)); l["status"] != linkSuperseded {
		t.Fatalf("A's push after the failover: %v", l)
	}
	if st := a.state(t, key.ID); st.Role != fedRoleDemoted || st.Epoch != 2 {
		t.Fatalf("A after the fence: %+v", st)
	}
	if _, err := a.svc.RotateKey(adminCtx(), "t1", key.ID, "x", ""); !errors.Is(err, errFederatedReplica) {
		t.Fatalf("A rotated a demoted key: %v", err)
	}
	if got := a.decrypt(t, key.ID, v2); got != "version 2" {
		t.Fatalf("demoted A decrypted %q", got)
	}

	// Failback: B replicates to A, which becomes B's replica with version 3.
	back := b.link(t, key.ID, aAtB)
	if back["status"] != linkInSync {
		t.Fatalf("failback push: %v", back)
	}
	if st := a.state(t, key.ID); st.Role != fedRoleReplica || st.Epoch != 2 || st.SourcePeerID != bAtA {
		t.Fatalf("A after failback: %+v", st)
	}
	if got := a.decrypt(t, key.ID, b.encrypt(t, key.ID, "version 3")); got != "version 3" {
		t.Fatalf("A decrypted %q", got)
	}
}

// A split brain never costs material: both sides rotate apart, and the push
// that would replace a differing version is refused (version_conflict).
func TestFederationSplitBrainKeepsBothVersions(t *testing.T) {
	a := newInstallation(t, "site-a", "0123456789ABCDEF0123456789ABCDEF")
	b := newInstallation(t, "site-b", "FEDCBA9876543210FEDCBA9876543210")
	bAtA, aAtB := a.peer(t, b), b.peer(t, a)
	key := exportableKey(t, a, "orders")
	a.link(t, key.ID, bAtA)
	if code, _ := b.call(t, http.MethodPost, "/federation/keys/"+key.ID+"/promote", map[string]any{"reason": "network partition"}); code != http.StatusOK {
		t.Fatal("promote")
	}
	a.rotate(t, key.ID) // A doesn't know it was replaced
	b.rotate(t, key.ID)
	onA := a.encrypt(t, key.ID, "written at A")
	back := b.link(t, key.ID, aAtB)
	if back["status"] != linkConflict || !strings.Contains(back["last_error"].(string), "version_conflict") {
		t.Fatalf("pushing a different version 2: %v", back)
	}
	if got := a.decrypt(t, key.ID, onA); got != "written at A" {
		t.Fatalf("A lost its version 2: %q", got)
	}
}

// Pushes that must never apply: a forged signature, a key that exists and
// isn't federated, a key that may not be exported, a stale push.
func TestFederationRefusesWhatItMustNotApply(t *testing.T) {
	a := newInstallation(t, "site-a", "0123456789ABCDEF0123456789ABCDEF")
	b := newInstallation(t, "site-b", "FEDCBA9876543210FEDCBA9876543210")
	bAtA := a.peer(t, b)
	b.peer(t, a)
	ctx := context.Background()
	key := exportableKey(t, a, "k")
	peer, _ := a.svc.store.GetFederationPeer(ctx, "t1", bAtA)
	id, _ := a.svc.federationIdentity(ctx, "t1")
	vers, _ := a.svc.store.ListVersions(ctx, "t1", key.ID)
	st, _ := a.svc.primaryState(ctx, key)
	signed, err := a.svc.buildBundle(ctx, id, key, vers, st, peer)
	if err != nil {
		t.Fatal(err)
	}
	reason := func(err error) string {
		var fr *federationRefusal
		if errors.As(err, &fr) {
			return fr.Reason
		}
		return "not refused: " + errFmt(err)
	}
	forged := signed
	forged.Payload = bytes.Replace(append([]byte{}, signed.Payload...), []byte(`"name":"k"`), []byte(`"name":"x"`), 1)
	if _, err := b.svc.ReceiveFederatedKey(ctx, "t1", forged); reason(err) != "bad_signature" {
		t.Fatalf("forged bundle: %s", reason(err))
	}
	if _, err := b.svc.ReceiveFederatedKey(ctx, "t2", signed); reason(err) != "tenant_mismatch" {
		t.Fatalf("other tenant: %s", reason(err))
	}
	if _, err := b.svc.ReceiveFederatedKey(ctx, "t1", signed); err != nil {
		t.Fatalf("the real bundle: %v", err)
	}
	if _, err := b.svc.ReceiveFederatedKey(ctx, "t1", signed); reason(err) != "stale_bundle" {
		t.Fatalf("replayed bundle: %s", reason(err))
	}
	// A local key with the same ID is never overwritten.
	local := exportableKey(t, b, "local")
	key.ID = local.ID
	collide, _ := a.svc.buildBundle(ctx, id, key, vers, st, peer)
	if _, err := b.svc.ReceiveFederatedKey(ctx, "t1", collide); reason(err) != "key_exists" {
		t.Fatalf("a local key with the same ID: %s", reason(err))
	}
	// Replicating needs export permission on the key.
	locked, err := a.svc.CreateKey(adminCtx(), CreateKeyRequest{TenantID: "t1", Name: "locked", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt", CreatedBy: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	if code, out := a.call(t, http.MethodPost, "/federation/links", map[string]any{"key_id": locked.ID, "peer_id": bAtA}); code != http.StatusConflict || out["error"].(map[string]any)["code"] != "key_not_exportable" {
		t.Fatalf("non-exportable key: %d %v", code, out)
	}
	// A peer's own identity, a wrong fingerprint, and plain HTTP are refused.
	bad := map[string]any{"name": "self", "url": a.srv.URL, "peer_tenant_id": "t1", "identity": a.identity(t), "client_id": "c", "api_key": "k"}
	if code, _ := a.call(t, http.MethodPost, "/federation/peers", bad); code != http.StatusBadRequest {
		t.Fatalf("own identity as a peer: %d", code)
	}
	other := b.identity(t)
	other["fingerprint"] = strings.Repeat("0", 64)
	bad["identity"], bad["name"] = other, "typo"
	if code, _ := a.call(t, http.MethodPost, "/federation/peers", bad); code != http.StatusBadRequest {
		t.Fatalf("wrong fingerprint: %d", code)
	}
	bad["identity"], bad["url"] = b.identity(t), strings.Replace(b.srv.URL, "https", "http", 1)
	if code, _ := a.call(t, http.MethodPost, "/federation/peers", bad); code != http.StatusBadRequest {
		t.Fatalf("http peer: %d", code)
	}
}

func errFmt(err error) string {
	if err == nil {
		return "nil"
	}
	return err.Error()
}

// The sync loop pushes a link whose key changed, and only then.
func TestFederationSyncLoopPushesChanges(t *testing.T) {
	a := newInstallation(t, "site-a", "0123456789ABCDEF0123456789ABCDEF")
	b := newInstallation(t, "site-b", "FEDCBA9876543210FEDCBA9876543210")
	bAtA := a.peer(t, b)
	b.peer(t, a)
	key := exportableKey(t, a, "k")
	a.link(t, key.ID, bAtA)
	a.rotate(t, key.ID)
	a.svc.syncDueLinks(context.Background())
	if vers, _ := b.svc.store.ListVersions(context.Background(), "t1", key.ID); len(vers) != 2 {
		t.Fatalf("B holds %d versions after the loop", len(vers))
	}
}

func TestFederationRefusalsAudited(t *testing.T) {
	h, _ := newHandlerForTest(t)
	rec := &routetest.Recorder{}
	routetest.RefusalsAudited(t, h.federationRouter(rec), rec)
}
