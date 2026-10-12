package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/clientip"
	"vecta-kms/pkg/tenantcheck"
)

type quorumOnDestroy struct{}

func (quorumOnDestroy) Controls(context.Context, string) (GovernancePostureControls, error) {
	return GovernancePostureControls{ForceQuorumDestructiveOps: true}, nil
}

// Who asked for a key to be destroyed is the verified caller, at the address
// the edge saw. Governance keeps the *recorded* requester from approving, so
// until 11.8.0-beta a caller who named somebody else in the body could then
// approve their own destruction. Only a platform service may name the person
// it acts for.
func TestKeyDestroyRequesterIsTheVerifiedCaller(t *testing.T) {
	t.Setenv("INTERNAL_SERVICE_TENANT", "root")
	h, svc, _ := newActorTestHandler(t)
	key := ownedKey(t, svc)

	var mu sync.Mutex
	var asked []map[string]any
	governance := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"items":[]}`))
			return
		}
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		mu.Lock()
		asked = append(asked, body)
		mu.Unlock()
		_, _ = w.Write([]byte(`{"request":{"id":"apr_1"}}`))
	}))
	defer governance.Close()
	svc.SetGovernanceApprovalClient(newGovernanceApprovalClient(governance.URL, 5*time.Second))
	svc.SetGovernancePostureControlsProvider(quorumOnDestroy{})

	destroy := func(claims *pkgauth.Claims) map[string]any {
		t.Helper()
		body, _ := json.Marshal(map[string]any{
			"mode": "scheduled", "destroy_after_days": 7, "confirm_name": key.Name, "justification": "retired",
			"requester_id": "alice", "requester_email": "alice@corp.example", "requester_ip": "10.9.9.9",
			"checks": map[string]bool{"no_active_workloads": true, "backup_completed": true, "irreversible_ack": true},
		})
		req := httptest.NewRequest(http.MethodPost, "/keys/"+key.ID+"/destroy?tenant_id=t1", bytes.NewReader(body))
		req.RemoteAddr = "172.18.0.9:41000"
		req.Header.Set(clientip.Header, "10.9.9.9, 198.51.100.7") // what the caller wrote, then what the edge saw
		req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusAccepted {
			t.Fatalf("destroy as %s: %d %s", claims.Subject, w.Code, w.Body)
		}
		mu.Lock()
		defer mu.Unlock()
		return asked[len(asked)-1]
	}

	// A user naming someone else is still the requester, from where the edge saw them.
	got := destroy(&pkgauth.Claims{UserID: "mallory", Subject: "mallory@corp.example", TenantID: "t1", Role: "admin", Permissions: []string{"*"}})
	if got["requester_id"] != "mallory" || got["requester_email"] != "mallory@corp.example" || got["requester_ip"] != "198.51.100.7" {
		t.Fatalf("a user's destroy request was recorded as somebody else's: %v", got)
	}

	// A platform service acts for a person and may say who.
	got = destroy(&pkgauth.Claims{ClientID: "kms-compliance", Subject: "kms-compliance", TenantID: "root", Role: "client-service", Permissions: []string{tenantcheck.ServicePermission}})
	if got["requester_id"] != "alice" || got["requester_email"] != "alice@corp.example" || got["requester_ip"] != "10.9.9.9" {
		t.Fatalf("a platform service must be able to name the person it acts for: %v", got)
	}

	// A client that only looks like a service is a caller like any other.
	got = destroy(&pkgauth.Claims{ClientID: "kms-lookalike", Subject: "kms-lookalike", TenantID: "t1", Role: "client-service", Permissions: []string{"*"}})
	if got["requester_id"] == "alice" || got["requester_email"] == "alice@corp.example" || got["requester_ip"] != "198.51.100.7" {
		t.Fatalf("a tenant's own client named the requester: %v", got)
	}
}
