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
		FailClosed:          failClosed,
		WALPath:             walPath,
		WALMaxSizeMB:        8,
		WALHMACKey:          []byte("0123456789abcdef0123456789abcdef"),
		DedupWindowSeconds:  60,
		EscalationThreshold: 5,
		EscalationMinutes:   10,
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

func TestAlertLifecycleEndpoints(t *testing.T) {
	h, svc, store, _ := newAuditHandler(t, true, false)
	_, alert, err := svc.ProcessEvent(context.Background(), AuditEvent{
		TenantID:  "t1",
		Timestamp: time.Now().UTC(),
		Service:   "auth",
		Action:    "audit.auth.login_failed",
		ActorID:   "u1",
		ActorType: "human",
		SourceIP:  "1.1.1.1",
		Result:    "failure",
	})
	if err != nil {
		t.Fatal(err)
	}

	ackReq := httptest.NewRequest(http.MethodPut, "/alerts/"+alert.ID+"/acknowledge?tenant_id=t1", bytes.NewReader([]byte(`{"actor":"secops","note":"investigating"}`)))
	ackRR := httptest.NewRecorder()
	h.ServeHTTP(ackRR, ackReq)
	if ackRR.Code != http.StatusOK {
		t.Fatalf("ack status=%d body=%s", ackRR.Code, ackRR.Body.String())
	}
	got, err := store.GetAlert(context.Background(), "t1", alert.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "acknowledged" {
		t.Fatalf("status=%s", got.Status)
	}
}

// An alert records only where it really goes (the dashboard): no email, SMS,
// paging, SIEM or webhook marked "queued" that nothing sends, and the
// in-memory channel settings that nothing read are gone.
func TestAlertRecordsOnlyRealDispatch(t *testing.T) {
	h, svc, store, _ := newAuditHandler(t, true, false)
	_, alert, err := svc.ProcessEvent(context.Background(), AuditEvent{
		TenantID: "t1", Timestamp: time.Now().UTC(), Service: "auth", Action: "audit.auth.login_failed",
		ActorID: "u1", ActorType: "human", SourceIP: "1.1.1.1", Result: "failure",
	})
	if err != nil || alert.ID == "" {
		t.Fatalf("alert: %+v %v", alert, err)
	}
	got, err := store.GetAlert(context.Background(), "t1", alert.ID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got.DispatchedChannels, ",") != "dashboard" || len(got.DispatchStatus) != 1 || got.DispatchStatus["dashboard"] != "recorded" {
		t.Fatalf("dispatch %v %v", got.DispatchedChannels, got.DispatchStatus)
	}
	for _, sev := range []string{"CRITICAL", "HIGH", "LOW", ""} {
		if p := dispatchPlan(sev); strings.Join(p.Channels, ",") != "dashboard" {
			t.Fatalf("%s: %v", sev, p.Channels)
		}
	}
	for _, rt := range []struct{ method, path string }{{http.MethodGet, "/alerts/channels"}, {http.MethodPut, "/alerts/channels"}, {http.MethodPost, "/alerts/channels/test"}} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(rt.method, rt.path+"?tenant_id=t1", strings.NewReader(`{}`)))
		if rr.Code != http.StatusNotFound && rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s %s still served: %d", rt.method, rt.path, rr.Code)
		}
	}
}

// Audit's own alert-rule routes are gone (2.14.0-beta): rules live in
// reporting. An alert still records with audit's default severity and title.
func TestAuditAlertRuleRoutesRemoved(t *testing.T) {
	h, svc, store, _ := newAuditHandler(t, true, false)
	for _, rt := range []struct{ method, path string }{
		{http.MethodGet, "/alerts/rules"}, {http.MethodPost, "/alerts/rules"},
		{http.MethodPut, "/alerts/rules/r1"}, {http.MethodDelete, "/alerts/rules/r1"},
	} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(rt.method, rt.path+"?tenant_id=t1", strings.NewReader(`{"condition":"event.action == 'audit.auth.login_failed'","severity":"CRITICAL"}`)))
		if rr.Code != http.StatusNotFound && rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s %s still served: %d", rt.method, rt.path, rr.Code)
		}
	}
	_, alert, err := svc.ProcessEvent(context.Background(), AuditEvent{
		TenantID: "t1", Timestamp: time.Now().UTC(), Service: "auth", Action: "audit.auth.login_failed",
		ActorID: "u1", ActorType: "human", SourceIP: "1.1.1.1", Result: "failure",
	})
	if err != nil || alert.ID == "" {
		t.Fatalf("alert: %+v %v", alert, err)
	}
	got, err := store.GetAlert(context.Background(), "t1", alert.ID)
	if err != nil || got.Title != defaultAlertTitle("audit.auth.login_failed", "") {
		t.Fatalf("alert %+v %v", got, err)
	}
}
