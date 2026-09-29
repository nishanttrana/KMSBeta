package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/delegation"
)

// Keycore gives no public key (409, e.g. a key with no public half): the key
// is created with an empty cache and the public key request is refused with
// 424 public_key_unavailable and audited as refused. Until 6.12.0-beta ekm returned, stored and audited as a success
// "EKM-PUBLIC-" + a hash of tenant and key ID.
func TestTDEPublicKeyUnavailableRefuses(t *testing.T) {
	svc, store, keycore, pub := newEKMService(t)
	keycore.noPublicKey = true
	ctx := context.Background()

	key, err := svc.CreateTDEKey(ctx, CreateTDEKeyRequest{TenantID: "tenant-pk", Name: "pk"})
	if err != nil {
		t.Fatal(err)
	}
	if key.PublicKey != "" {
		t.Fatalf("created key public key = %q, want empty", key.PublicKey)
	}

	_, err = svc.GetTDEPublicKey(ctx, "tenant-pk", key.ID)
	var se serviceError
	if !errors.As(err, &se) || se.HTTPStatus != http.StatusFailedDependency || se.Code != "public_key_unavailable" {
		t.Fatalf("err = %v, want 424 public_key_unavailable", err)
	}
	ev := pub.Last("audit.ekm.tde_key_accessed")
	if ev["result"] != "refused" || ev["reason"] != "public_key_unavailable" || ev["operation"] != "public" || ev["key_id"] != key.ID {
		t.Fatalf("audit = %v, want refused public_key_unavailable", ev)
	}
	stored, err := store.GetTDEKey(ctx, "tenant-pk", key.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.PublicKey != "" {
		t.Fatalf("stored public key = %q, want empty", stored.PublicKey)
	}
	logs, err := store.ListKeyAccessByTenant(ctx, "tenant-pk", time.Time{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	failed := false
	for _, l := range logs {
		if l.KeyID == key.ID && l.Operation == "public" {
			if l.Status != "failed" {
				t.Fatalf("key access log = %+v, want failed", l)
			}
			failed = true
		}
	}
	if !failed {
		t.Fatalf("no failed public key access logged: %+v", logs)
	}
}

func TestTDEPublicKeyUnavailableHTTP424(t *testing.T) {
	h, svc, keycore, pub := newEKMHandler(t)
	keycore.noPublicKey = true
	key, err := svc.CreateTDEKey(context.Background(), CreateTDEKeyRequest{TenantID: "tenant-h1", Name: "pk"})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, authed(httptest.NewRequest(http.MethodGet, "/ekm/tde/keys/"+key.ID+"/public?tenant_id=tenant-h1", nil)))
	if rr.Code != http.StatusFailedDependency || !strings.Contains(rr.Body.String(), "public_key_unavailable") {
		t.Fatalf("status=%d body=%s, want 424 public_key_unavailable", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "EKM-PUBLIC-") {
		t.Fatalf("response carries an invented public key: %s", rr.Body.String())
	}
	if ev := pub.Last("audit.ekm.tde_key_accessed"); ev["result"] != "refused" {
		t.Fatalf("audit = %v, want refused", ev)
	}
}

// With a public key from keycore the request succeeds and is audited as one.
func TestTDEPublicKeyFromKeycore(t *testing.T) {
	svc, _, _, pub := newEKMService(t)
	ctx := context.Background()
	key, err := svc.CreateTDEKey(ctx, CreateTDEKeyRequest{TenantID: "tenant-pk", Name: "pk"})
	if err != nil {
		t.Fatal(err)
	}
	out, err := svc.GetTDEPublicKey(ctx, "tenant-pk", key.ID)
	if err != nil {
		t.Fatal(err)
	}
	if out.Format != "pem" || !strings.Contains(out.PublicKey, "BEGIN PUBLIC KEY") {
		t.Fatalf("public key = %+v, want keycore's PEM", out)
	}
	if ev := pub.Last("audit.ekm.tde_key_accessed"); ev["result"] != "success" {
		t.Fatalf("audit = %v, want success", ev)
	}
}

// Migration 007 clears stored "EKM-PUBLIC-" values and leaves real keys.
func TestMigrationClearsInventedPublicKeys(t *testing.T) {
	svc, store, _, _ := newEKMService(t)
	ctx := context.Background()
	for _, k := range []TDEKeyRecord{
		{TenantID: "t", ID: "fake", KeyCoreKeyID: "fake", Name: "f", Algorithm: "RSA-3072", Status: "active", CurrentVersion: "v1", PublicKey: "EKM-PUBLIC-0123456789abcdef0123456789abcdef", PublicKeyFormat: "opaque"},
		{TenantID: "t", ID: "real", KeyCoreKeyID: "real", Name: "r", Algorithm: "RSA-3072", Status: "active", CurrentVersion: "v1", PublicKey: "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----", PublicKeyFormat: "pem"},
	} {
		if err := store.CreateTDEKey(ctx, k); err != nil {
			t.Fatal(err)
		}
	}
	sqlText, err := os.ReadFile(filepath.Join("migrations", "007_clear_invented_public_keys.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.SQL().ExecContext(ctx, string(sqlText)); err != nil {
		t.Fatal(err)
	}
	fake, _ := store.GetTDEKey(ctx, "t", "fake")
	real, _ := store.GetTDEKey(ctx, "t", "real")
	if fake.PublicKey != "" || fake.PublicKeyFormat != "" {
		t.Fatalf("invented key not cleared: %+v", fake)
	}
	if !strings.HasPrefix(real.PublicKey, "-----BEGIN") || real.PublicKeyFormat != "pem" {
		t.Fatalf("real key changed: %+v", real)
	}
	// The cleared key now asks keycore, which does not know it: refused.
	if _, err := svc.GetTDEPublicKey(ctx, "t", "fake"); err == nil {
		t.Fatal("cleared key served a public key")
	}
}

func TestAgentStatusCarriesAssignedKeyAlgorithm(t *testing.T) {
	svc, _, _, _ := newEKMService(t)
	ctx := context.Background()
	agent, _, err := svc.RegisterAgent(ctx, RegisterAgentRequest{TenantID: "tenant-st", AgentID: "agent-st", DBEngine: "mssql"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.RegisterDatabase(ctx, RegisterDatabaseRequest{
		TenantID: "tenant-st", DatabaseID: "db-st", AgentID: agent.ID, Name: "st", Engine: "mssql", TDEEnabled: true, DatabaseName: "ST",
	}); err != nil {
		t.Fatal(err)
	}
	st, err := svc.GetAgentStatus(ctx, "tenant-st", agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if st.Agent.AssignedKeyID == "" || st.AssignedKeyAlgorithm != DefaultTDEAlgorithm {
		raw, _ := json.Marshal(st)
		t.Fatalf("status = %s, want assigned key algorithm %s", raw, DefaultTDEAlgorithm)
	}
}

// Every read asks keycore: after a rotation the new version's key is served,
// never the cached copy of the old one.
func TestTDEPublicKeyFollowsRotation(t *testing.T) {
	svc, store, _, _ := newEKMService(t)
	ctx := context.Background()
	key, err := svc.CreateTDEKey(ctx, CreateTDEKeyRequest{TenantID: "tenant-rot", Name: "rot"})
	if err != nil {
		t.Fatal(err)
	}
	v1, err := svc.GetTDEPublicKey(ctx, "tenant-rot", key.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RotateTDEKey(ctx, key.ID, RotateTDEKeyRequest{TenantID: "tenant-rot"}); err != nil {
		t.Fatal(err)
	}
	stored, _ := store.GetTDEKey(ctx, "tenant-rot", key.ID)
	v2, err := svc.GetTDEPublicKey(ctx, "tenant-rot", key.ID)
	if err != nil {
		t.Fatal(err)
	}
	if v2.KeyVersion != "v2" || v2.PublicKey == v1.PublicKey || stored.PublicKey != strings.TrimSpace(v2.PublicKey) {
		t.Fatalf("after rotation: v1=%+v v2=%+v cached=%q", v1, v2, stored.PublicKey)
	}
}

// Keycore's refusal of the user ekm acts for is passed on with its status
// and reason, and audited as refused; nothing cached is served instead.
func TestTDEPublicKeyKeycoreRefusalPassedOn(t *testing.T) {
	svc, _, keycore, pub := newEKMService(t)
	ctx := context.Background()
	key, err := svc.CreateTDEKey(ctx, CreateTDEKeyRequest{TenantID: "tenant-rf", Name: "rf"})
	if err != nil {
		t.Fatal(err)
	}
	if key.PublicKey == "" {
		t.Fatal("creation did not cache keycore's public key")
	}
	for _, refusal := range []*keycoreError{
		{Status: http.StatusNotFound, Code: "not_found", Msg: "key not found"},
		{Status: http.StatusForbidden, Code: "delegation_refused", Msg: "delegation_token_invalid"},
	} {
		keycore.refuse = refusal
		_, err := svc.GetTDEPublicKey(ctx, "tenant-rf", key.ID)
		var se serviceError
		if !errors.As(err, &se) || se.HTTPStatus != refusal.Status || se.Code != refusal.Code {
			t.Fatalf("err = %v, want %d %s", err, refusal.Status, refusal.Code)
		}
		if ev := pub.Last("audit.ekm.tde_key_accessed"); ev["result"] != "refused" || ev["reason"] != refusal.Code {
			t.Fatalf("audit = %v, want refused %s", ev, refusal.Code)
		}
	}
}

// The request's verified token reaches the keycore call, so keycore decides
// for the user (pkg/delegation), not for ekm.
func TestTDEPublicKeyReadCarriesTheUsersToken(t *testing.T) {
	h, svc, keycore, _ := newEKMHandler(t)
	key, err := svc.CreateTDEKey(context.Background(), CreateTDEKeyRequest{TenantID: "tenant-h1", Name: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, authed(httptest.NewRequest(http.MethodGet, "/ekm/tde/keys/"+key.ID+"/public?tenant_id=tenant-h1", nil)))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "BEGIN PUBLIC KEY") {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if keycore.publicKeyToken != "jwt:tenant-h1:admin" {
		t.Fatalf("keycore call carried token %q, want the caller's", keycore.publicKeyToken)
	}
}

// The HTTP client reads keycore's real response and forwards the user's
// token with usage "read"; a refusal keeps keycore's status and reason.
func TestHTTPKeyCoreClientPublicKey(t *testing.T) {
	const pemKey = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"
	var gotToken, gotUsage, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken, gotUsage, gotPath = r.Header.Get(delegation.HeaderToken), r.Header.Get(delegation.HeaderUsage), r.URL.RequestURI()
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/denied/") {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":{"code":"delegation_refused","message":"delegation_token_invalid"}}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"key_id": "k1", "version": 3, "algorithm": "RSA-3072", "format": "spki-pem", "public_key_pem": pemKey})
	}))
	defer srv.Close()
	c := NewHTTPKeyCoreClient(srv.URL, time.Second)
	user := &pkgauth.Claims{UserID: "alice", TenantID: "t1", Role: "operator"}
	ctx := pkgauth.ContextWithVerifiedToken(pkgauth.ContextWithClaims(context.Background(), user), "alice-token")

	pk, err := c.PublicKey(ctx, "t1", "k1")
	if err != nil {
		t.Fatal(err)
	}
	if pk.Version != 3 || pk.Algorithm != "RSA-3072" || pk.PublicKeyPEM != pemKey || gotPath != "/keys/k1/public-key?tenant_id=t1" {
		t.Fatalf("pk=%+v path=%s", pk, gotPath)
	}
	if gotToken != "alice-token" || gotUsage != "read" {
		t.Fatalf("forwarded token=%q usage=%q", gotToken, gotUsage)
	}
	_, err = c.PublicKey(ctx, "t1", "denied/k2")
	var kerr *keycoreError
	if !errors.As(err, &kerr) || kerr.Status != http.StatusForbidden || kerr.Code != "delegation_refused" {
		t.Fatalf("err = %v, want keycore's 403 delegation_refused", err)
	}
}
