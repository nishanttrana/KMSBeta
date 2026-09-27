package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"vecta-kms/pkg/route/routetest"
)

const threatSubject = "audit.keycore.threat_signal_raised"

// seedUsage inserts a usage event at a specific time for detection tests.
func seedUsage(t *testing.T, s *Service, tenantID, keyID, actorID string, at time.Time) {
	t.Helper()
	if err := s.store.InsertKeyUsageEvent(context.Background(), KeyUsageEvent{
		ID:         newID("kue"),
		TenantID:   tenantID,
		KeyID:      keyID,
		Operation:  "encrypt",
		ActorID:    actorID,
		OccurredAt: at,
	}); err != nil {
		t.Fatalf("seed usage: %v", err)
	}
}

// sweep runs one scheduled tick, as the sweeper does every minute.
func sweep(svc *Service) { NewThreatSweeper(svc).Tick(context.Background()) }

// raised returns the details of every threat_signal_raised event, by type.
func raised(t *testing.T, pub *captureKeycorePublisher) map[string][]map[string]any {
	t.Helper()
	pub.mu.Lock()
	defer pub.mu.Unlock()
	out := map[string][]map[string]any{}
	for i, s := range pub.subjects {
		if s != threatSubject {
			continue
		}
		var ev struct {
			TenantID string         `json:"tenant_id"`
			Details  map[string]any `json:"details"`
		}
		if err := json.Unmarshal(pub.payloads[i], &ev); err != nil {
			t.Fatal(err)
		}
		ev.Details["tenant_id"] = ev.TenantID
		typ, _ := ev.Details["signal_type"].(string)
		out[typ] = append(out[typ], ev.Details)
	}
	return out
}

// Each detection is emitted as an audit event carrying what posture and
// reporting need: type, key, actor, severity and description.
func TestThreatDetectsNewActor(t *testing.T) {
	svc, pub := newCaptureService(t)
	now := time.Now().UTC()
	for i := 0; i < newActorHistoryMin+2; i++ {
		seedUsage(t, svc, "t1", "key-A", "alice", now.Add(-time.Duration(i+1)*time.Minute))
	}
	seedUsage(t, svc, "t1", "key-A", "mallory", now.Add(-30*time.Second))

	sweep(svc)

	got := raised(t, pub)["new_actor"]
	if len(got) != 1 {
		t.Fatalf("new_actor events: %v", raised(t, pub))
	}
	d := got[0]
	if d["actor_id"] != "mallory" || d["key_id"] != "key-A" || d["severity"] != "high" || d["tenant_id"] != "t1" || d["signal_id"] == "" || d["description"] == "" {
		t.Fatalf("unexpected event: %v", d)
	}
}

func TestThreatNoNewActorSignalForKnownActor(t *testing.T) {
	svc, pub := newCaptureService(t)
	now := time.Now().UTC()
	for i := 0; i < newActorHistoryMin+5; i++ {
		seedUsage(t, svc, "t1", "key-A", "alice", now.Add(-time.Duration(i+1)*time.Minute))
	}
	sweep(svc)
	if n := pub.count(threatSubject); n != 0 {
		t.Fatalf("known actor raised %d signals: %v", n, raised(t, pub))
	}
}

func TestThreatDetectsVolumeSpike(t *testing.T) {
	svc, pub := newCaptureService(t)
	now := time.Now().UTC()
	for d := 1; d <= 6; d++ {
		base := now.Add(-time.Duration(d) * 24 * time.Hour)
		for i := 0; i < 3; i++ {
			seedUsage(t, svc, "t1", "key-B", "svc", base.Add(time.Duration(i)*time.Minute))
		}
	}
	for i := 0; i < volumeSpikeMinOps+40; i++ {
		seedUsage(t, svc, "t1", "key-B", "svc", now.Add(-time.Duration(i)*time.Second))
	}

	sweep(svc)

	got := raised(t, pub)["volume_spike"]
	if len(got) != 1 || got[0]["key_id"] != "key-B" || got[0]["severity"] != "high" {
		t.Fatalf("volume_spike events: %v", got)
	}
}

func TestThreatDetectsDormantActivity(t *testing.T) {
	svc, pub := newCaptureService(t)
	now := time.Now().UTC()
	seedUsage(t, svc, "t1", "key-C", "svc", now.Add(-dormantThreshold-threatSweepWindow-48*time.Hour))
	seedUsage(t, svc, "t1", "key-C", "svc", now.Add(-2*time.Minute))

	sweep(svc)

	got := raised(t, pub)["dormant_key_activity"]
	if len(got) != 1 || got[0]["severity"] != "medium" {
		t.Fatalf("dormant events: %v", got)
	}
}

// The sweep runs every minute; the same condition is raised once.
func TestThreatSignalDedupe(t *testing.T) {
	svc, pub := newCaptureService(t)
	now := time.Now().UTC()
	for i := 0; i < newActorHistoryMin+2; i++ {
		seedUsage(t, svc, "t1", "key-A", "alice", now.Add(-time.Duration(i+1)*time.Minute))
	}
	seedUsage(t, svc, "t1", "key-A", "mallory", now.Add(-30*time.Second))

	sweep(svc)
	sweep(svc)

	if n := pub.count(threatSubject); n != 1 {
		t.Fatalf("expected one deduplicated signal, got %d", n)
	}
}

// Each tenant with usage is swept under its own tenant; one tenant's traffic
// never raises a signal in another.
func TestThreatSweepCoversEveryTenantSeparately(t *testing.T) {
	svc, pub := newCaptureService(t)
	now := time.Now().UTC()
	for _, tenant := range []string{"t1", "t2"} {
		for i := 0; i < newActorHistoryMin+2; i++ {
			seedUsage(t, svc, tenant, "key-"+tenant, "alice", now.Add(-time.Duration(i+1)*time.Minute))
		}
	}
	seedUsage(t, svc, "t2", "key-t2", "mallory", now.Add(-30*time.Second))

	sweep(svc)

	got := raised(t, pub)["new_actor"]
	if len(got) != 1 || got[0]["tenant_id"] != "t2" || got[0]["key_id"] != "key-t2" {
		t.Fatalf("expected one t2 signal, got %v", got)
	}
}

// A probe of a canary through the real key API returns not-found, records
// the trip, and raises a critical signal plus the canary_tripped event.
func TestCanaryProbeThroughKeyAPITrips(t *testing.T) {
	svc, pub := newCaptureService(t)
	ctx := contextWithAccessActor(context.Background(), AccessActor{
		UserID: "mallory", Authenticated: true, SourceIP: "10.0.0.9",
	})
	if err := svc.store.CreateCanaryKey(ctx, CanaryKey{ID: "key_decoy1", TenantID: "t1", Name: "prod-master", Active: true}); err != nil {
		t.Fatalf("create canary: %v", err)
	}
	if _, err := svc.GetKey(ctx, "t1", "key_decoy1"); err == nil {
		t.Fatal("expected not-found when resolving a canary key id")
	}
	got := raised(t, pub)["canary_tripped"]
	if len(got) != 1 || got[0]["severity"] != "critical" || got[0]["actor_id"] != "mallory" || got[0]["key_id"] != "key_decoy1" {
		t.Fatalf("canary signal: %v", got)
	}
	if d := pub.details(t, "audit.keycore.canary_tripped"); d["canary_id"] != "key_decoy1" || d["actor_ip"] != "10.0.0.9" {
		t.Fatalf("canary_tripped event: %v", d)
	}
	k, err := svc.store.GetCanaryKey(ctx, "t1", "key_decoy1")
	if err != nil || k.TripCount != 1 || k.LastTripped == nil {
		t.Fatalf("trip not recorded: %+v %v", k, err)
	}
}

// A deactivated canary no longer trips.
func TestDeactivatedCanaryDoesNotTrip(t *testing.T) {
	svc, pub := newCaptureService(t)
	ctx := context.Background()
	if err := svc.store.CreateCanaryKey(ctx, CanaryKey{ID: "key_decoy2", TenantID: "t1", Name: "old", Active: true}); err != nil {
		t.Fatal(err)
	}
	if err := svc.store.DeactivateCanaryKey(ctx, "t1", "key_decoy2"); err != nil {
		t.Fatal(err)
	}
	_, _ = svc.GetKey(ctx, "t1", "key_decoy2")
	if pub.count("audit.keycore.canary_tripped") != 0 || pub.count(threatSubject) != 0 {
		t.Fatal("deactivated canary tripped")
	}
}

func canaryCall(t *testing.T, h *Handler, method, path, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	rr := httptest.NewRecorder()
	serveAsAdmin(h, rr, httptest.NewRequest(method, path, strings.NewReader(body)))
	out := map[string]any{}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr, out
}

// Canary routes run on the kernel: create, list, trips and deactivate each
// emit their own event; a canary ID is minted like a real key ID.
func TestCanaryRoutesAudited(t *testing.T) {
	h, _ := newHandlerForTest(t)
	rec := &routetest.Recorder{}
	h.kernelAudit = rec

	rr, out := canaryCall(t, h, http.MethodPost, "/canary/keys", `{"name":"payments-master"}`)
	item, _ := out["item"].(map[string]any)
	id, _ := item["id"].(string)
	if rr.Code != http.StatusCreated || !strings.HasPrefix(id, "key_") || item["active"] != true {
		t.Fatalf("create: %d %s", rr.Code, rr.Body)
	}
	if e := rec.Last(t); e.Action != "canary_key_created" || e.Event.Result != "success" || e.Event.TargetID != id || e.Event.Details["name"] != "payments-master" {
		t.Fatalf("create event %+v", e)
	}
	if rr, _ := canaryCall(t, h, http.MethodPost, "/canary/keys", `{"name":" "}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("empty name accepted: %d", rr.Code)
	}

	rr, out = canaryCall(t, h, http.MethodGet, "/canary/keys", "")
	if items, _ := out["items"].([]any); rr.Code != http.StatusOK || len(items) != 1 {
		t.Fatalf("list: %d %s", rr.Code, rr.Body)
	}
	if e := rec.Last(t); e.Action != "canary_keys_listed" {
		t.Fatalf("list event %+v", e)
	}

	if rr, _ := canaryCall(t, h, http.MethodGet, "/canary/keys/"+id+"/trips", ""); rr.Code != http.StatusOK {
		t.Fatalf("trips: %d %s", rr.Code, rr.Body)
	}
	if e := rec.Last(t); e.Action != "canary_trips_listed" || e.Event.TargetID != id {
		t.Fatalf("trips event %+v", e)
	}

	if rr, _ := canaryCall(t, h, http.MethodDelete, "/canary/keys/"+id, ""); rr.Code != http.StatusOK {
		t.Fatalf("deactivate: %d %s", rr.Code, rr.Body)
	}
	if e := rec.Last(t); e.Action != "canary_key_deactivated" || e.Event.Result != "success" || e.Event.TargetID != id {
		t.Fatalf("deactivate event %+v", e)
	}
	if rr, _ := canaryCall(t, h, http.MethodDelete, "/canary/keys/key_missing", ""); rr.Code != http.StatusNotFound {
		t.Fatalf("missing canary: %d", rr.Code)
	}
}

func TestCanaryRoutesRefusalsAudited(t *testing.T) {
	h, _, _ := newActorTestHandler(t)
	rec := &routetest.Recorder{}
	routetest.RefusalsAudited(t, h.canaryRouter(rec), rec)
}
