package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/route/routetest"
)

type received struct {
	body    []byte
	headers http.Header
}

// webhookRig wires a fanout whose dispatcher reaches a local TLS server
// (the production SSRF guard refuses loopback, as it should).
func webhookRig(t *testing.T) (*Handler, *Service, *SQLStore, *httptest.Server, func() []received) {
	t.Helper()
	h, svc, store, _ := newAuditHandler(t, true, false)
	var mu sync.Mutex
	var got []received
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, received{b, r.Header.Clone()})
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	f := newWebhookFanout(store, func(ctx context.Context, ev AuditEvent) { _, _, _ = svc.ProcessEvent(ctx, ev) }, log.Default())
	f.disp.client = srv.Client()
	f.disp.validate = func(u string) error {
		if !strings.HasPrefix(u, "https://") {
			return validateWebhookURL(u)
		}
		return nil
	}
	f.primary = func(context.Context) bool { return true }
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	f.Start(ctx)
	svc.SetWebhookFanout(f)
	return h, svc, store, srv, func() []received { mu.Lock(); defer mu.Unlock(); return append([]received(nil), got...) }
}

func webhookReq(t *testing.T, h *Handler, method, path string, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var r io.Reader = http.NoBody
	if body != nil {
		raw, _ := json.Marshal(body)
		r = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, r)
	claims := &pkgauth.Claims{UserID: "admin", TenantID: "t1", Role: "admin", Permissions: []string{"*"}}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims)))
	out := map[string]any{}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr, out
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for delivery")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// An ingested audit event that matches a subscription is delivered, signed,
// in the webhook's format; a non-matching one is not; each delivery is
// recorded and audited, and the delivery audit is never itself delivered.
func TestWebhookDeliversMatchingAuditEvents(t *testing.T) {
	h, svc, store, srv, got := webhookRig(t)
	secret := "0123456789abcdef-secret"
	rr, out := webhookReq(t, h, http.MethodPost, "/webhooks", map[string]any{
		"name": "splunk", "url": srv.URL + "/services/collector", "format": "splunk_hec",
		"events": []string{"audit.key.*", "audit.audit.*"}, "secret": secret,
		"headers": map[string]string{"Authorization": "Splunk hec-token-value"},
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rr.Code, rr.Body)
	}
	id := out["webhook"].(map[string]any)["id"].(string)

	ctx := context.Background()
	for _, action := range []string{"audit.key.rotate", "audit.secrets.read"} {
		if _, _, err := svc.ProcessEvent(ctx, AuditEvent{TenantID: "t1", Service: "key", Action: action, ActorID: "u1", ActorType: "user", Result: "success", Timestamp: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, func() bool { return len(got()) >= 1 })
	time.Sleep(200 * time.Millisecond) // anything else would have arrived by now
	deliveries := got()
	if len(deliveries) != 1 {
		t.Fatalf("delivered %d requests, want 1 (audit.key.rotate only; webhook_created predates the webhook, delivery audits are never delivered)", len(deliveries))
	}
	d := deliveries[0]
	var hec map[string]any
	if err := json.Unmarshal(d.body, &hec); err != nil || hec["sourcetype"] != "vecta:audit" || hec["event"].(map[string]any)["action"] != "audit.key.rotate" {
		t.Fatalf("splunk payload %s", d.body)
	}
	if want := "sha256=" + hex.EncodeToString(pkgcrypto.HMACSHA256([]byte(secret), d.body)); d.headers.Get("X-KMS-Signature") != want {
		t.Fatal("signature does not verify")
	}
	if d.headers.Get("Authorization") != "Splunk hec-token-value" || d.headers.Get("X-KMS-Event-ID") == "" {
		t.Fatalf("headers %v", d.headers)
	}
	waitFor(t, func() bool { return actionCount(t, store, "audit.audit.webhook_delivered") == 1 })
	items, _ := store.ListDeliveries(ctx, "t1", id, 10)
	if len(items) != 1 || items[0].Status != "success" || items[0].HTTPStatus != 200 {
		t.Fatalf("deliveries %+v", items)
	}
}

// The API never returns the signing secret or header values; an empty header
// value on update keeps the stored one; plain http is refused and audited.
func TestWebhookSecretsAreWriteOnly(t *testing.T) {
	h, _, store, srv, _ := webhookRig(t)
	_, out := webhookReq(t, h, http.MethodPost, "/webhooks", map[string]any{
		"name": "dd", "url": srv.URL, "format": "datadog", "events": []string{"*"},
		"secret": "0123456789abcdef", "headers": map[string]string{"DD-API-KEY": "dd-secret-key"},
	})
	id := out["webhook"].(map[string]any)["id"].(string)
	rr, _ := webhookReq(t, h, http.MethodGet, "/webhooks", nil)
	if strings.Contains(rr.Body.String(), "0123456789abcdef") || strings.Contains(rr.Body.String(), "dd-secret-key") {
		t.Fatalf("list leaked a secret: %s", rr.Body)
	}
	if !strings.Contains(rr.Body.String(), `"has_secret":true`) {
		t.Fatalf("has_secret missing: %s", rr.Body)
	}
	if rr, _ := webhookReq(t, h, http.MethodPatch, "/webhooks/"+id, map[string]any{"headers": map[string]string{"DD-API-KEY": ""}, "name": "dd2"}); rr.Code != http.StatusOK {
		t.Fatalf("update: %d %s", rr.Code, rr.Body)
	}
	wh, _ := store.GetWebhook(context.Background(), "t1", id)
	if wh.Headers["DD-API-KEY"] != "dd-secret-key" || wh.Secret != "0123456789abcdef" {
		t.Fatal("update lost a write-only value")
	}
	rr, _ = webhookReq(t, h, http.MethodPost, "/webhooks", map[string]any{"name": "plain", "url": "http://example.com/hook", "events": []string{"*"}})
	if rr.Code != http.StatusBadRequest || actionCount(t, store, "audit.audit.webhook_created") != 2 {
		t.Fatalf("plain http: %d", rr.Code)
	}
	var result string
	_ = store.db.SQL().QueryRow(`SELECT result FROM audit_events WHERE action='audit.audit.webhook_created' ORDER BY sequence DESC LIMIT 1`).Scan(&result)
	if result != "refused" {
		t.Fatalf("http refusal audited as %q", result)
	}
	for _, bad := range []map[string]any{
		{"name": "f", "url": srv.URL, "format": "pagerduty", "events": []string{"*"}},
		{"name": "e", "url": srv.URL, "events": []string{"key.created"}},
		{"name": "s", "url": srv.URL, "events": []string{"*"}, "secret": "short"},
		{"name": "r", "url": srv.URL, "events": []string{"*"}, "headers": map[string]string{"X-KMS-Signature": "x"}},
	} {
		if rr, _ := webhookReq(t, h, http.MethodPost, "/webhooks", bad); rr.Code != http.StatusBadRequest {
			t.Fatalf("%v accepted: %d", bad, rr.Code)
		}
	}
}

func TestWebhookRoutesRefusalsAudited(t *testing.T) {
	h, _, _, _ := newAuditHandler(t, true, false)
	rec := &routetest.Recorder{}
	routetest.RefusalsAudited(t, h.webhookRouter(rec), rec)
}

// On a cluster member the delivery is made and recorded in the node-local
// webhook_deliveries, but the replicated webhooks row is left to the primary.
func TestWebhookDeliveryOnMemberLeavesReplicatedRowAlone(t *testing.T) {
	h, svc, store, srv, got := webhookRig(t)
	_, out := webhookReq(t, h, http.MethodPost, "/webhooks", map[string]any{"name": "m", "url": srv.URL, "events": []string{"audit.key.*"}})
	id := out["webhook"].(map[string]any)["id"].(string)
	svc.webhooks.primary = func(context.Context) bool { return false }
	if _, _, err := svc.ProcessEvent(context.Background(), AuditEvent{TenantID: "t1", Service: "key", Action: "audit.key.create", ActorID: "u1", Result: "success", Timestamp: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return len(got()) == 1 })
	waitFor(t, func() bool {
		items, _ := store.ListDeliveries(context.Background(), "t1", id, 10)
		return len(items) == 1
	})
	wh, _ := store.GetWebhook(context.Background(), "t1", id)
	if wh.LastDeliveryAt != nil || wh.LastDeliveryStatus != "" {
		t.Fatalf("member wrote the replicated webhook row: %+v", wh)
	}
}
