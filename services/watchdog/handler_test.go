package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
)

func newTestRouter(rec *routetest.Recorder) *route.Router {
	now := time.Now().UTC()
	return newRouter(
		func() []ServiceState {
			return []ServiceState{{Service: "policy", LastSeen: now, State: "ready", Healthy: true}, {Service: "keycore", LastSeen: now, State: "ready", Healthy: true}}
		},
		func() []Incident {
			return []Incident{{ID: "inc-1", Service: "audit", Reason: "silent", Timestamp: now}}
		},
		rec, nil,
	)
}

func TestWatchdogRoutesRefusalsAudited(t *testing.T) {
	rec := &routetest.Recorder{}
	routetest.RefusalsAudited(t, newTestRouter(rec), rec)
}

// A health.read holder gets the list, sorted, and the read is audited under
// its specific action.
func TestWatchdogReadsAudited(t *testing.T) {
	rec := &routetest.Recorder{}
	r := newTestRouter(rec)
	admin := &pkgauth.Claims{UserID: "u-1", TenantID: "root", Role: "admin", Permissions: []string{permHealthRead}}
	for pattern, action := range map[string]string{
		"GET /watchdog/heartbeats": "heartbeats_listed",
		"GET /watchdog/incidents":  "incidents_listed",
	} {
		rec.Reset()
		w := httptest.NewRecorder()
		r.ServeHTTP(w, routetest.Request(pattern, admin, ""))
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status %d: %s", pattern, w.Code, w.Body.String())
		}
		got := rec.Last(t)
		if got.Action != action || got.Event.Result != route.ResultSuccess || got.Event.ActorID != "u-1" {
			t.Fatalf("%s: audited %s result=%s actor=%s", pattern, got.Action, got.Event.Result, got.Event.ActorID)
		}
		var body struct {
			Items []map[string]any `json:"items"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || len(body.Items) == 0 {
			t.Fatalf("%s: body %s", pattern, w.Body.String())
		}
		if pattern == "GET /watchdog/heartbeats" && body.Items[0]["service"] != "keycore" {
			t.Fatalf("heartbeats not sorted: %v", body.Items)
		}
	}
}
