package auditmw

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type publishedEvent struct {
	subject string
	payload []byte
}

type fakePublisher struct {
	ch chan publishedEvent
}

func (f *fakePublisher) Publish(_ context.Context, subject string, payload []byte) error {
	select {
	case f.ch <- publishedEvent{subject: subject, payload: payload}:
	default:
	}
	return nil
}

func TestWrapSkipsHTTPRequestAuditByDefault(t *testing.T) {
	t.Setenv("AUDIT_CAPTURE_HTTP_REQUESTS", "")

	pub := &fakePublisher{ch: make(chan publishedEvent, 1)}
	h := Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), pub, "reporting")

	req := httptest.NewRequest(http.MethodGet, "/healthz?tenant_id=root", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	select {
	case evt := <-pub.ch:
		t.Fatalf("unexpected published event: %s", evt.subject)
	case <-time.After(120 * time.Millisecond):
	}
}

func TestWrapPublishesHTTPRequestAuditWhenEnabled(t *testing.T) {
	t.Setenv("AUDIT_CAPTURE_HTTP_REQUESTS", "true")

	pub := &fakePublisher{ch: make(chan publishedEvent, 1)}
	h := Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}), pub, "policy")

	req := httptest.NewRequest(http.MethodPost, "/policies?tenant_id=root&token=secret", nil)
	req.RemoteAddr = "172.18.0.20:43122"
	req.Header.Set("User-Agent", "auditmw-test")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	var evt publishedEvent
	select {
	case evt = <-pub.ch:
	case <-time.After(2 * time.Second):
		t.Fatal("expected published event")
	}

	if evt.subject != "audit.policy.http_request" {
		t.Fatalf("unexpected subject %q", evt.subject)
	}

	var payload map[string]any
	if err := json.Unmarshal(evt.payload, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if got := payload["action"]; got != "audit.policy.http_request" {
		t.Fatalf("unexpected action %v", got)
	}
	if got := payload["tenant_id"]; got != "root" {
		t.Fatalf("unexpected tenant_id %v", got)
	}
	if got := payload["endpoint"]; got != "/policies" {
		t.Fatalf("unexpected endpoint %v", got)
	}
	if got := payload["query"]; got != "tenant_id=root&token=***" {
		t.Fatalf("unexpected query %v", got)
	}
}
