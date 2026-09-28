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
	"vecta-kms/pkg/mek/mektest"
	"vecta-kms/pkg/route/routetest"
)

type received struct {
	body    []byte
	headers http.Header
}

// testConns stands in for compliance's connection endpoints (resolve and
// import), which have their own tests in services/compliance.
type testConns struct {
	mu      sync.Mutex
	conns   map[string]streamConnection
	imports []connImport
	down    bool
}

func (c *testConns) add(id, typ string, fields map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.conns[id] = streamConnection{ID: id, Name: id, Type: typ, Endpoint: "127.0.0.1", Fields: fields}
}

func (c *testConns) Resolve(_ context.Context, tenantID, id string) (streamConnection, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.down {
		return streamConnection{}, connError{Status: http.StatusServiceUnavailable, Msg: "compliance unavailable"}
	}
	conn, ok := c.conns[id]
	if !ok || tenantID != "t1" {
		return streamConnection{}, connError{Status: http.StatusNotFound, Code: "not_found"}
	}
	if conn.Type == "jira" {
		return streamConnection{}, connError{Status: http.StatusConflict, Code: "refused", Msg: "a jira connection can't be used for stream"}
	}
	return conn, nil
}

func (c *testConns) Import(_ context.Context, _ string, in connImport) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.down {
		return "", connError{Status: http.StatusServiceUnavailable}
	}
	c.imports = append(c.imports, in)
	return "pbconn_audit_" + in.SourceID, nil
}

// webhookRig wires a fanout whose dispatcher reaches a local TLS server
// (the production SSRF guard refuses loopback, as it should).
func webhookRig(t *testing.T) (*Handler, *Service, *SQLStore, *httptest.Server, func() []received) {
	h, svc, store, srv, got, _ := streamRig(t)
	return h, svc, store, srv, got
}

func streamRig(t *testing.T) (*Handler, *Service, *SQLStore, *httptest.Server, func() []received, *testConns) {
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
	mektest.ApplySchema(t, store.db.SQL(), "audit")
	svc.creds.set(mektest.Open(t, store.db.SQL(), "audit", mektest.NewKeycore(t)))
	conns := &testConns{conns: map[string]streamConnection{}}
	f := newWebhookFanout(store, svc.creds, conns, func(ctx context.Context, ev AuditEvent) { _, _ = svc.ProcessEvent(ctx, ev) }, log.Default())
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
	return h, svc, store, srv, func() []received { mu.Lock(); defer mu.Unlock(); return append([]received(nil), got...) }, conns
}

// legacyStream stores a stream the way an earlier release did: its own URL
// and format, credentials sealed under the audit master key.
func legacyStream(t *testing.T, svc *Service, store *SQLStore, wh Webhook) Webhook {
	t.Helper()
	wh.TenantID, wh.Enabled = "t1", true
	if wh.ID == "" {
		wh.ID = newID("wh")
	}
	if wh.Events == nil {
		wh.Events = []string{"*"}
	}
	if err := svc.creds.Seal(&wh); err != nil {
		t.Fatal(err)
	}
	out, err := store.CreateWebhook(context.Background(), wh)
	if err != nil {
		t.Fatal(err)
	}
	svc.webhooks.Invalidate("t1")
	return out
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

func createStream(t *testing.T, h *Handler, body map[string]any) string {
	t.Helper()
	rr, out := webhookReq(t, h, http.MethodPost, "/webhooks", body)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create stream: %d %s", rr.Code, rr.Body)
	}
	return out["webhook"].(map[string]any)["id"].(string)
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

func ingest(t *testing.T, svc *Service, action string) {
	t.Helper()
	if _, err := svc.ProcessEvent(context.Background(), AuditEvent{TenantID: "t1", Service: "key", Action: action, ActorID: "u1", ActorType: "user", Result: "success", Timestamp: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
}

// A matching event is delivered through the stream's SIEM connection
// (pkg/siem Splunk HEC); a non-matching one is not; each delivery is
// recorded and audited, and the delivery audit is never itself delivered.
func TestStreamDeliversThroughSIEMConnection(t *testing.T) {
	h, svc, store, srv, got, conns := streamRig(t)
	conns.add("pbconn_splunk", "splunk_hec", map[string]string{"url": srv.URL, "token": "hec-token-value"})
	id := createStream(t, h, map[string]any{"name": "splunk", "connection_id": "pbconn_splunk", "events": []string{"audit.key.*", "audit.audit.*"}})
	ingest(t, svc, "audit.key.rotate")
	ingest(t, svc, "audit.secrets.read")
	waitFor(t, func() bool { return len(got()) >= 1 })
	time.Sleep(200 * time.Millisecond) // anything else would have arrived by now
	deliveries := got()
	if len(deliveries) != 1 {
		t.Fatalf("delivered %d requests, want 1 (audit.key.rotate only)", len(deliveries))
	}
	d := deliveries[0]
	var hec map[string]any
	if err := json.Unmarshal(d.body, &hec); err != nil || hec["sourcetype"] != "vecta:audit" || hec["event"].(map[string]any)["action"] != "audit.key.rotate" {
		t.Fatalf("splunk payload %s", d.body)
	}
	if d.headers.Get("Authorization") != "Splunk hec-token-value" {
		t.Fatalf("headers %v", d.headers)
	}
	waitFor(t, func() bool { return actionCount(t, store, "audit.audit.webhook_delivered") == 1 })
	items, _ := store.ListDeliveries(context.Background(), "t1", id, 10)
	if len(items) != 1 || items[0].Status != "success" || items[0].HTTPStatus != 200 {
		t.Fatalf("deliveries %+v", items)
	}
	// The stream row holds no credential: only the connection it names.
	wh, _ := store.GetWebhook(context.Background(), "t1", id)
	if wh.URL != "" || wh.Sealed != nil || wh.ConnectionType != "splunk_hec" || wh.Legacy {
		t.Fatalf("stream row %+v", wh)
	}
}

// A webhook connection signs the body with its signing secret and sends its
// header values; a Teams connection gets an Adaptive Card.
func TestStreamWebhookAndTeamsConnections(t *testing.T) {
	h, svc, _, srv, got, conns := streamRig(t)
	secret := "0123456789abcdef-secret"
	conns.add("pbconn_hook", "webhook", map[string]string{"url": srv.URL + "/hook", "signing_secret": secret, "headers": `{"X-Api-Key":"k1","X-KMS-Signature":"forged"}`})
	conns.add("pbconn_teams", "teams", map[string]string{"webhook_url": srv.URL + "/teams"})
	createStream(t, h, map[string]any{"name": "hook", "connection_id": "pbconn_hook", "events": []string{"audit.key.rotate"}})
	createStream(t, h, map[string]any{"name": "teams", "connection_id": "pbconn_teams", "events": []string{"audit.key.rotate"}})
	ingest(t, svc, "audit.key.rotate")
	waitFor(t, func() bool { return len(got()) == 2 })
	for _, d := range got() {
		if strings.Contains(string(d.body), "AdaptiveCard") {
			continue
		}
		if d.headers.Get("X-KMS-Signature") != "sha256="+hex.EncodeToString(pkgcrypto.HMACSHA256([]byte(secret), d.body)) || d.headers.Get("X-Api-Key") != "k1" {
			t.Fatalf("webhook delivery %v %s", d.headers, d.body)
		}
		return
	}
	t.Fatal("no webhook delivery")
}

// The API takes a connection, never a URL or credential; an unknown or
// non-stream connection is refused; compliance being unreachable is a 503.
func TestStreamAPIRequiresConnection(t *testing.T) {
	h, _, store, srv, _, conns := streamRig(t)
	conns.add("pbconn_jira", "jira", map[string]string{"base_url": srv.URL})
	for _, bad := range []map[string]any{
		{"name": "inline", "url": srv.URL, "events": []string{"*"}},
		{"name": "secret", "connection_id": "x", "secret": "0123456789abcdef", "events": []string{"*"}},
		{"name": "none", "events": []string{"*"}},
		{"name": "missing", "connection_id": "pbconn_nope", "events": []string{"*"}},
		{"name": "events", "connection_id": "pbconn_jira", "events": []string{"key.created"}},
	} {
		if rr, _ := webhookReq(t, h, http.MethodPost, "/webhooks", bad); rr.Code != http.StatusBadRequest {
			t.Fatalf("%v accepted: %d %s", bad, rr.Code, rr.Body)
		}
	}
	if rr, _ := webhookReq(t, h, http.MethodPost, "/webhooks", map[string]any{"name": "jira", "connection_id": "pbconn_jira", "events": []string{"*"}}); rr.Code != http.StatusBadRequest {
		t.Fatalf("jira stream accepted: %d", rr.Code)
	}
	var result, reason string
	_ = store.db.SQL().QueryRow(`SELECT result, details FROM audit_events WHERE action='audit.audit.webhook_created' ORDER BY sequence DESC LIMIT 1`).Scan(&result, &reason)
	if result != "refused" || !strings.Contains(reason, "connection_not_streamable") {
		t.Fatalf("non-stream connection refusal audited as %q %s", result, reason)
	}
	conns.down = true
	if rr, _ := webhookReq(t, h, http.MethodPost, "/webhooks", map[string]any{"name": "down", "connection_id": "pbconn_other", "events": []string{"*"}}); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("compliance down: %d", rr.Code)
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
	h, svc, store, srv, got, conns := streamRig(t)
	conns.add("pbconn_hook", "webhook", map[string]string{"url": srv.URL})
	id := createStream(t, h, map[string]any{"name": "m", "connection_id": "pbconn_hook", "events": []string{"audit.key.*"}})
	svc.webhooks.primary = func(context.Context) bool { return false }
	ingest(t, svc, "audit.key.create")
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

// Each stream management call is recorded under its own action.
func TestWebhookManagementAudited(t *testing.T) {
	h, _, store, srv, got, conns := streamRig(t)
	conns.add("pbconn_hook", "webhook", map[string]string{"url": srv.URL})
	id := createStream(t, h, map[string]any{"name": "ops", "connection_id": "pbconn_hook", "events": []string{"audit.key.*"}})
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/webhooks"},
		{http.MethodPatch, "/webhooks/" + id},
		{http.MethodPost, "/webhooks/" + id + "/test"},
		{http.MethodGet, "/webhooks/" + id + "/deliveries"},
		{http.MethodDelete, "/webhooks/" + id},
	} {
		var body any
		if c.method == http.MethodPatch {
			body = map[string]any{"name": "ops-2"}
		}
		if rr, _ := webhookReq(t, h, c.method, c.path, body); rr.Code >= 300 {
			t.Fatalf("%s %s: %d %s", c.method, c.path, rr.Code, rr.Body)
		}
	}
	if len(got()) != 1 {
		t.Fatalf("the test call must deliver once, got %d", len(got()))
	}
	for _, action := range []string{"webhook_created", "webhooks_listed", "webhook_updated", "webhook_tested", "webhook_deliveries_listed", "webhook_deleted"} {
		if n := actionCount(t, store, "audit.audit."+action); n != 1 {
			t.Fatalf("audit.audit.%s recorded %d times, want 1", action, n)
		}
	}
}

// A legacy stream keeps delivering with its own sealed credentials until it
// is migrated.
func TestLegacyStreamDeliversUntilMigrated(t *testing.T) {
	_, svc, _, srv, got, _ := streamRig(t)
	legacyStream(t, svc, svc.store.(*SQLStore), Webhook{Name: "old", URL: srv.URL, Format: "splunk_hec", Headers: map[string]string{"Authorization": "Splunk old-token"}})
	ingest(t, svc, "audit.key.rotate")
	waitFor(t, func() bool { return len(got()) == 1 })
	if got()[0].headers.Get("Authorization") != "Splunk old-token" {
		t.Fatalf("legacy delivery %v", got()[0].headers)
	}
}

// Legacy streams move into connections of the type their format spoke, with
// their exposure carried over; one that doesn't map keeps delivering and is
// reported once; a member leaves the replicated rows alone.
func TestLegacyStreamsMigrateIntoConnections(t *testing.T) {
	_, svc, store, _, _, conns := streamRig(t)
	ctx := context.Background()
	legacyStream(t, svc, store, Webhook{ID: "wh_json", Name: "json", URL: "https://hooks.example.com/a", Format: "json", Secret: "0123456789abcdef-sign", Headers: map[string]string{"X-Api-Key": "k"}})
	legacyStream(t, svc, store, Webhook{ID: "wh_splunk", Name: "splunk", URL: "https://splunk.example.com:8088/services/collector", Format: "splunk_hec", Headers: map[string]string{"Authorization": "Splunk tok"}})
	legacyStream(t, svc, store, Webhook{ID: "wh_dd", Name: "dd", URL: "https://http-intake.logs.datadoghq.com/api/v2/logs", Format: "datadog", Headers: map[string]string{"X-Other": "v"}})
	if _, err := store.db.SQL().Exec(`INSERT INTO webhooks (id, tenant_id, name, url, format, events_json, secret, headers_json)
		VALUES ('wh_plain', 't1', 'plain', 'https://hooks.slack.com/services/T/B/x', 'slack', '["*"]', '', '{}')`); err != nil {
		t.Fatal(err)
	}
	k, _ := svc.creds.current()
	if err := k.RecordExposure(ctx, "t1", webhookCredsItemType, "wh_splunk", "plaintext_storage"); err != nil {
		t.Fatal(err)
	}
	var events []AuditEvent
	audit := func(_ context.Context, ev AuditEvent) { events = append(events, ev) }
	m := &streamMigrator{reported: map[string]bool{}}
	if n, _ := svc.migrateLegacyStreams(ctx, k, conns, m, func(context.Context) bool { return false }, audit); n != 0 || len(conns.imports) != 0 {
		t.Fatal("a member migrated replicated rows")
	}
	n, err := svc.migrateLegacyStreams(ctx, k, conns, m, func(context.Context) bool { return true }, audit)
	if err != nil || n != 3 {
		t.Fatalf("migrated %d: %v", n, err)
	}
	byID := map[string]connImport{}
	for _, in := range conns.imports {
		byID[in.SourceID] = in
	}
	if in := byID["wh_json"]; in.Type != "webhook" || in.Fields["signing_secret"] != "0123456789abcdef-sign" || in.Fields["headers"] != `{"X-Api-Key":"k"}` || in.Exposed {
		t.Fatalf("json import %+v", in)
	}
	if in := byID["wh_splunk"]; in.Type != "splunk_hec" || in.Fields["token"] != "tok" || !in.Exposed {
		t.Fatalf("splunk import %+v", in)
	}
	if in := byID["wh_plain"]; in.Type != "slack" || in.Fields["webhook_url"] != "https://hooks.slack.com/services/T/B/x" {
		t.Fatalf("slack import %+v", in)
	}
	for _, id := range []string{"wh_json", "wh_splunk", "wh_plain"} {
		wh, _ := store.GetWebhook(ctx, "t1", id)
		if wh.ConnectionID != "pbconn_audit_"+id || wh.URL != "" || wh.Sealed != nil || wh.Legacy {
			t.Fatalf("%s after migration %+v", id, wh)
		}
	}
	if e, _ := k.Exposures(ctx, "t1", true); len(e) != 0 {
		t.Fatalf("exposure left in the audit register after moving: %+v", e)
	}
	dd, _ := store.GetWebhook(ctx, "t1", "wh_dd")
	if !dd.Legacy || dd.Sealed == nil {
		t.Fatalf("unmappable stream changed: %+v", dd)
	}
	refused := 0
	for _, ev := range events {
		if ev.Action == "audit.audit.webhook_migration_refused" && ev.TargetID == "wh_dd" && ev.Details["reason"] == "no_datadog_api_key_header" {
			refused++
		}
	}
	if refused != 1 {
		t.Fatalf("refusal reported %d times: %+v", refused, events)
	}
	_, _ = svc.migrateLegacyStreams(ctx, k, conns, m, func(context.Context) bool { return true }, audit)
	for _, ev := range events[len(events)-1:] {
		if ev.Action == "audit.audit.webhook_migration_refused" {
			t.Fatal("refusal reported again on the next sweep")
		}
	}
}

// Compliance unreachable: nothing is changed and the sweep reports it.
func TestLegacyStreamMigrationRetriesWhenComplianceDown(t *testing.T) {
	_, svc, store, _, _, conns := streamRig(t)
	legacyStream(t, svc, store, Webhook{ID: "wh_json", Name: "json", URL: "https://hooks.example.com/a", Format: "json"})
	conns.down = true
	k, _ := svc.creds.current()
	if _, err := svc.migrateLegacyStreams(context.Background(), k, conns, &streamMigrator{reported: map[string]bool{}}, func(context.Context) bool { return true }, nil); err == nil {
		t.Fatal("the sweep must report a stream it couldn't move")
	}
	if wh, _ := store.GetWebhook(context.Background(), "t1", "wh_json"); !wh.Legacy || wh.URL == "" {
		t.Fatalf("stream changed without a connection: %+v", wh)
	}
}

// Re-pointing a legacy stream at a connection drops its own credentials and
// retires their exposure.
func TestLegacyStreamRepointedAtConnection(t *testing.T) {
	h, svc, store, srv, _, conns := streamRig(t)
	legacyStream(t, svc, store, Webhook{ID: "wh_old", Name: "old", URL: srv.URL, Format: "json", Secret: "0123456789abcdef"})
	k, _ := svc.creds.current()
	_ = k.RecordExposure(context.Background(), "t1", webhookCredsItemType, "wh_old", "plaintext_storage")
	conns.add("pbconn_new", "webhook", map[string]string{"url": srv.URL})
	if rr, _ := webhookReq(t, h, http.MethodPatch, "/webhooks/wh_old", map[string]any{"secret": "0123456789abcdef-new"}); rr.Code != http.StatusBadRequest {
		t.Fatalf("inline secret accepted on update: %d", rr.Code)
	}
	if rr, _ := webhookReq(t, h, http.MethodPatch, "/webhooks/wh_old", map[string]any{"connection_id": "pbconn_new"}); rr.Code != http.StatusOK {
		t.Fatalf("re-point: %d %s", rr.Code, rr.Body)
	}
	wh, _ := store.GetWebhook(context.Background(), "t1", "wh_old")
	if wh.ConnectionID != "pbconn_new" || wh.Sealed != nil || wh.URL != "" || wh.HasSecret {
		t.Fatalf("after re-point %+v", wh)
	}
	if e, _ := k.Exposures(context.Background(), "t1", true); len(e) != 0 {
		t.Fatalf("exposure not retired: %+v", e)
	}
}
