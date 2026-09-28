package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The client calls compliance's resolve and import routes for the tenant
// and maps a refusal to connError.
func TestComplianceConnectionsClient(t *testing.T) {
	type call struct{ path, tenant, body string }
	var calls []call
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		calls = append(calls, call{r.URL.Path, r.Header.Get("X-Tenant-ID"), string(b)})
		switch r.URL.Path {
		case "/compliance/connections/c1/resolve":
			_, _ = w.Write([]byte(`{"data":{"id":"c1","type":"datadog","fields":{"url":"https://x","api_key":"k"}}}`))
		case "/compliance/connections/import":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"id":"pbconn_audit_wh1"}}`))
		default:
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":{"code":"refused","message":"a jira connection can't be used for stream"}}`))
		}
	}))
	defer srv.Close()
	c := complianceConnections{base: srv.URL, http: srv.Client()}
	conn, err := c.Resolve(context.Background(), "t1", "c1")
	if err != nil || conn.Type != "datadog" || conn.Fields["api_key"] != "k" {
		t.Fatalf("resolve %+v %v", conn, err)
	}
	id, err := c.Import(context.Background(), "t1", connImport{SourceID: "wh1", Type: "webhook", Fields: map[string]string{"url": "https://x"}, Exposed: true})
	if err != nil || id != "pbconn_audit_wh1" {
		t.Fatalf("import %s %v", id, err)
	}
	var body map[string]any
	_ = json.Unmarshal([]byte(calls[1].body), &body)
	if calls[0].tenant != "t1" || body["exposed"] != true || body["source_id"] != "wh1" || body["tenant_id"] != "t1" {
		t.Fatalf("calls %+v", calls)
	}
	_, err = c.Resolve(context.Background(), "t1", "jira")
	if ce, ok := err.(connError); !ok || ce.Status != http.StatusConflict || !strings.Contains(ce.Error(), "jira") {
		t.Fatalf("refusal %v", err)
	}
}

// Opened connections are reused for the TTL, then resolved again, so a
// change in compliance reaches deliveries.
func TestConnCacheExpires(t *testing.T) {
	src := &testConns{conns: map[string]streamConnection{}}
	src.add("c1", "webhook", map[string]string{"url": "https://a.example.com"})
	cache := newConnCache(src)
	get := func() string {
		conn, _, err := cache.get(context.Background(), "t1", "c1", http.DefaultClient)
		if err != nil {
			t.Fatal(err)
		}
		return conn.Fields["url"]
	}
	get()
	src.add("c1", "webhook", map[string]string{"url": "https://b.example.com"})
	if get() != "https://a.example.com" {
		t.Fatal("not cached")
	}
	cache.ttl = time.Nanosecond
	if get() != "https://b.example.com" {
		t.Fatal("stale after the TTL")
	}
}

// A transport error names the host, never the URL: a Slack or Teams URL is
// a credential and the error lands in the delivery log and audit.
func TestDeliveryErrorsDoNotQuoteURL(t *testing.T) {
	d := NewWebhookDispatcher()
	d.validate = func(string) error { return nil }
	d.retry.MaxAttempts = 1
	_, _, err := d.Deliver(context.Background(), Webhook{ID: "w", URL: "https://127.0.0.1:1/services/T0/B0/sekret"}, "a", "e", []byte("{}"))
	if err == nil || strings.Contains(err.Error(), "sekret") {
		t.Fatalf("error %v", err)
	}
}
