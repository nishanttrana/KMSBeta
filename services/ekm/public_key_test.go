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
)

// Keycore gives no public key: the key is created with an empty cache and the
// public key request is refused with 424 public_key_unavailable and audited
// as refused. Until 6.12.0-beta ekm returned, stored and audited as a success
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
