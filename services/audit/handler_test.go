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
