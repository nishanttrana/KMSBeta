package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	pkgkeyaccess "vecta-kms/pkg/keyaccess"
)

func lastEventData(subjects []string, payloads [][]byte, subject string) map[string]interface{} {
	for i := len(subjects) - 1; i >= 0; i-- {
		if subjects[i] == subject {
			var ev struct {
				Data map[string]interface{} `json:"data"`
			}
			_ = json.Unmarshal(payloads[i], &ev)
			return ev.Data
		}
	}
	return nil
}

// unreachableKeyAccess is the real HTTP client pointed at a closed server.
func unreachableKeyAccess(t *testing.T) pkgkeyaccess.Gate {
	t.Helper()
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	return pkgkeyaccess.Deployed(pkgkeyaccess.NewHTTPClient(url, time.Second))
}

func newEKMKeyForGate(t *testing.T, svc *Service) (string, string) {
	t.Helper()
	ctx := context.Background()
	agent, _, err := svc.RegisterAgent(ctx, RegisterAgentRequest{TenantID: "tenant-ka", AgentID: "agent-ka", DBEngine: "mssql"}, "")
	if err != nil {
		t.Fatal(err)
	}
	dbi, _, err := svc.RegisterDatabase(ctx, RegisterDatabaseRequest{
		TenantID: "tenant-ka", DatabaseID: "db-ka", AgentID: agent.ID, Name: "ka", Engine: "mssql", TDEEnabled: true, DatabaseName: "KA",
	})
	if err != nil {
		t.Fatal(err)
	}
	return dbi.KeyID, dbi.ID
}

// Key access deployed but unreachable: every TDE key operation is refused
// with 424 key_access_unavailable and audited as refused. Until 6.10.0-beta
// the error was turned into an allow.
func TestEKMKeyAccessUnavailableRefuses(t *testing.T) {
	svc, _, _, pub := newEKMService(t)
	ctx := context.Background()
	keyID, dbID := newEKMKeyForGate(t, svc)
	svc.SetKeyAccess(unreachableKeyAccess(t))

	plain := base64.StdEncoding.EncodeToString([]byte("0123456789ABCDEF0123456789ABCDEF"))
	_, wrapErr := svc.WrapDEK(ctx, keyID, WrapDEKRequest{TenantID: "tenant-ka", PlaintextB64: plain, DatabaseID: dbID})
	_, unwrapErr := svc.UnwrapDEK(ctx, keyID, UnwrapDEKRequest{TenantID: "tenant-ka", CiphertextB64: plain, DatabaseID: dbID})
	_, rotateErr := svc.RotateTDEKey(ctx, keyID, RotateTDEKeyRequest{TenantID: "tenant-ka"})
	for op, err := range map[string]error{"wrap": wrapErr, "unwrap": unwrapErr, "rotate": rotateErr} {
		if httpStatusForErr(err) != http.StatusFailedDependency {
			t.Fatalf("%s: %v (status %d), want 424 key_access_unavailable", op, err, httpStatusForErr(err))
		}
	}
	if n := pub.Count("audit.ekm.key_access_denied"); n != 3 {
		t.Fatalf("%d key_access_denied events, want 3", n)
	}
	ev := pub.Last("audit.ekm.key_access_denied")
	if ev["result"] != "refused" || ev["reason"] != pkgkeyaccess.ReasonUnavailable || ev["operation"] != "rotate" {
		t.Fatalf("refusal event %+v", ev)
	}
	if pub.Count("audit.ekm.tde_key_accessed") != 0 || pub.Count("audit.ekm.tde_key_rotated") != 0 {
		t.Fatal("an operation ran while key access was unavailable")
	}
}

// Key access not deployed: the operation runs and records why no
// justification was checked.
func TestEKMKeyAccessNotDeployedAllows(t *testing.T) {
	svc, _, _, pub := newEKMService(t)
	ctx := context.Background()
	keyID, dbID := newEKMKeyForGate(t, svc)
	svc.SetKeyAccess(pkgkeyaccess.NotDeployed())

	plain := base64.StdEncoding.EncodeToString([]byte("0123456789ABCDEF0123456789ABCDEF"))
	if _, err := svc.WrapDEK(ctx, keyID, WrapDEKRequest{TenantID: "tenant-ka", PlaintextB64: plain, DatabaseID: dbID}); err != nil {
		t.Fatal(err)
	}
	ev := pub.Last("audit.ekm.tde_key_accessed")
	if ev["key_access_reason"] != pkgkeyaccess.ReasonNotDeployed {
		t.Fatalf("wrap event %+v, want key_access_reason %s", ev, pkgkeyaccess.ReasonNotDeployed)
	}
	if pub.Count("audit.ekm.key_access_denied") != 0 {
		t.Fatal("not-deployed allow audited as a refusal")
	}
}

// A deny decision on unwrap and rotate is audited too (before 6.10.0-beta
// only wrap's was).
func TestEKMKeyAccessDenyAudited(t *testing.T) {
	svc, _, _, pub := newEKMService(t)
	ctx := context.Background()
	keyID, _ := newEKMKeyForGate(t, svc)
	deny := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"action": "deny", "reason": "justification_required"}})
	}))
	defer deny.Close()
	svc.SetKeyAccess(pkgkeyaccess.Deployed(pkgkeyaccess.NewHTTPClient(deny.URL, time.Second)))

	if _, err := svc.RotateTDEKey(ctx, keyID, RotateTDEKeyRequest{TenantID: "tenant-ka"}); httpStatusForErr(err) != http.StatusForbidden {
		t.Fatalf("rotate: %v, want 403", err)
	}
	ev := pub.Last("audit.ekm.key_access_denied")
	if ev["result"] != "refused" || ev["reason"] != "justification_required" {
		t.Fatalf("deny event %+v", ev)
	}
}
