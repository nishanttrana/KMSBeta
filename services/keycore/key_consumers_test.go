package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route/routetest"
)

// Consumers come from the usage trail: grouped by actor and interface,
// limited to the retained window, never another key's usage. The read is
// audited as audit.key.key_consumers_read.
func TestKeyConsumersFromUsageTrail(t *testing.T) {
	h, svc := newHandlerForTest(t)
	ctx := context.Background()
	key, err := svc.CreateKey(ctx, CreateKeyRequest{
		TenantID: "t1", Name: "orders", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt", Owner: "ops", CreatedBy: "tester",
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for i, e := range []KeyUsageEvent{
		{KeyID: key.ID, Operation: "encrypt", ActorID: "alice", Interface: "rest", OccurredAt: now.Add(-2 * time.Hour)},
		{KeyID: key.ID, Operation: "encrypt", ActorID: "alice", Interface: "rest", OccurredAt: now.Add(-time.Hour)},
		{KeyID: key.ID, Operation: "decrypt", ActorID: "alice", Interface: "rest", OccurredAt: now.Add(-30 * time.Minute)},
		{KeyID: key.ID, Operation: "decrypt", ActorID: "billing-svc", Interface: "kmip", OccurredAt: now.Add(-3 * time.Hour)},
		{KeyID: key.ID, Operation: "encrypt", ActorID: "ghost", Interface: "rest", OccurredAt: now.Add(-usageRetention - 24*time.Hour)},
		{KeyID: "other-key", Operation: "encrypt", ActorID: "mallory", Interface: "rest", OccurredAt: now},
	} {
		e.ID, e.TenantID = newID("kue")+string(rune('a'+i)), "t1"
		if err := svc.store.InsertKeyUsageEvent(ctx, e); err != nil {
			t.Fatal(err)
		}
	}

	rec := &routetest.Recorder{}
	router := h.keyConsumersRouter(rec)
	get := func(id string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/keys/"+id+"/consumers?tenant_id=t1", nil)
		req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), &pkgauth.Claims{UserID: "u1", TenantID: "t1", Permissions: []string{"key.usage.read"}}))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	w := get(key.ID)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var body struct {
		Consumers KeyConsumers `json:"consumers"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	got := body.Consumers
	if len(got.Consumers) != 2 || !got.NodeLocal || got.WindowDays != 30 {
		t.Fatalf("consumers: %+v", got)
	}
	alice := got.Consumers[0]
	if alice.ActorID != "alice" || alice.Interface != "rest" || alice.Total != 3 || alice.Operations["encrypt"] != 2 || alice.Operations["decrypt"] != 1 {
		t.Fatalf("alice: %+v", alice)
	}
	if !alice.FirstSeen.Equal(now.Add(-2*time.Hour).Truncate(time.Microsecond)) || !alice.LastSeen.Equal(now.Add(-30*time.Minute).Truncate(time.Microsecond)) {
		t.Fatalf("alice seen %s .. %s", alice.FirstSeen, alice.LastSeen)
	}
	if billing := got.Consumers[1]; billing.ActorID != "billing-svc" || billing.Total != 1 {
		t.Fatalf("billing-svc: %+v", billing)
	}
	imp := got.Impact
	if imp.ActiveCallers != 2 || len(imp.Interfaces) != 2 || imp.Interfaces[0] != "kmip" || imp.VersionsByStatus["active"] != 1 || imp.CurrentVersion != 1 || imp.LastUsedAt == nil {
		t.Fatalf("impact: %+v", imp)
	}
	if ev := rec.Last(t); ev.Action != "key_consumers_read" || ev.Event.TargetID != key.ID || ev.Event.Result != "success" || ev.Event.Details["consumers"] != 2 {
		t.Fatalf("audited %+v", ev)
	}

	if w := get("no-such-key"); w.Code != http.StatusNotFound {
		t.Fatalf("unknown key: status %d", w.Code)
	}
	if ev := rec.Last(t); ev.Event.Result != "failure" {
		t.Fatalf("unknown key audited %+v", ev)
	}
}

func TestKeyConsumersRefusalsAudited(t *testing.T) {
	h, _ := newHandlerForTest(t)
	rec := &routetest.Recorder{}
	routetest.RefusalsAudited(t, h.keyConsumersRouter(rec), rec)
}
