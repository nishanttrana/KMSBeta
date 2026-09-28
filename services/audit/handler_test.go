package main

import (
	"bytes"
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

type mockPublisher struct {
	fail bool
}

func (m mockPublisher) Publish(_ context.Context, _ string, _ []byte) error {
	if m.fail {
		return errors.New("nats unavailable")
	}
	return nil
}

func newAuditHandler(t *testing.T, failClosed bool, publisherFail bool) (*Handler, *Service, *SQLStore, string) {
	t.Helper()
	store := newAuditStore(t)
	walPath := filepath.Join(t.TempDir(), "audit-wal.log")
	svc := NewService(store, AuditConfig{
		FailClosed:   failClosed,
		WALPath:      walPath,
		WALMaxSizeMB: 8,
		WALHMACKey:   []byte("0123456789abcdef0123456789abcdef"),
	}, NewWALBuffer(walPath, 8, []byte("0123456789abcdef0123456789abcdef")), mockPublisher{fail: publisherFail})
	return NewHandler(svc, store), svc, store, walPath
}

func TestPublishFailClosedReturns503(t *testing.T) {
	h, _, _, _ := newAuditHandler(t, true, true)
	body := map[string]interface{}{
		"subject": "audit.auth.login",
		"event": map[string]interface{}{
			"tenant_id": "t1",
			"action":    "audit.auth.login",
			"service":   "auth",
			"actor_id":  "u1",
			"result":    "success",
		},
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/audit/publish", bytes.NewReader(raw))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestPublishBuffersWhenFailClosedFalse(t *testing.T) {
	h, _, _, walPath := newAuditHandler(t, false, true)
	body := map[string]interface{}{
		"subject": "audit.auth.login",
		"event": map[string]interface{}{
			"tenant_id": "t1",
			"action":    "audit.auth.login",
			"service":   "auth",
			"actor_id":  "u1",
			"result":    "success",
		},
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/audit/publish", bytes.NewReader(raw))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if st, err := os.Stat(walPath); err != nil || st.Size() == 0 {
		t.Fatalf("expected wal file with data, err=%v", err)
	}
}

// Audit keeps no alert store (2.16.0-beta): alerts, their triage, stats and
// stream live in reporting (the Alert Center). Every former audit alert
// route is gone, and ingest still chains the event without writing an alert.
func TestAuditAlertStoreRemoved(t *testing.T) {
	h, svc, store, _ := newAuditHandler(t, true, false)
	for _, rt := range []struct{ method, path string }{
		{http.MethodGet, "/alerts"}, {http.MethodGet, "/alerts/a1"},
		{http.MethodPut, "/alerts/a1/acknowledge"}, {http.MethodPut, "/alerts/a1/resolve"}, {http.MethodPut, "/alerts/a1/suppress"},
		{http.MethodGet, "/alerts/stats"}, {http.MethodGet, "/alerts/stream"}, {http.MethodGet, "/audit/stats"},
		{http.MethodGet, "/alerts/rules"}, {http.MethodPost, "/alerts/rules"}, {http.MethodPost, "/alerts/test-rule"},
		{http.MethodGet, "/alerts/channels"}, {http.MethodPost, "/alerts/channels/test"},
	} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(rt.method, rt.path+"?tenant_id=t1", strings.NewReader(`{"actor":"secops"}`)))
		if rr.Code != http.StatusNotFound && rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s %s still served: %d", rt.method, rt.path, rr.Code)
		}
	}
	ev, err := svc.ProcessEvent(context.Background(), AuditEvent{
		TenantID: "t1", Timestamp: time.Now().UTC(), Service: "auth", Action: "audit.auth.login_failed",
		ActorID: "u1", ActorType: "human", SourceIP: "1.1.1.1", Result: "failure",
	})
	if err != nil || ev.ChainHash == "" {
		t.Fatalf("event: %+v %v", ev, err)
	}
	got, err := store.GetEvent(context.Background(), "t1", ev.ID)
	if err != nil || got.Action != "audit.auth.login_failed" || got.RiskScore == 0 {
		t.Fatalf("persisted event %+v %v", got, err)
	}
}
