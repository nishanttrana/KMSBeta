package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/ssrfguard"
)

func svcClaims(clientID string) *pkgauth.Claims {
	return &pkgauth.Claims{Role: "client-service", ClientID: clientID, TenantID: "root", Permissions: []string{"service.internal"}}
}

// Only the audit and governance service identities may open a connection;
// a user (even an admin), another platform service and an external client
// are refused, and each refusal is audited.
func TestConnectionResolveRestrictedToAuditAndGovernance(t *testing.T) {
	hs := newPlaybookHarness(t)
	id := hs.conn(t, "splunk_hec", map[string]string{"url": "https://1.1.1.1", "token": "hec-secret"})
	path := "/compliance/connections/" + id + "/resolve?tenant_id=t1"
	for _, who := range []*pkgauth.Claims{pbAdmin, pbClient, svcClaims("kms-keycore")} {
		w := hs.do(t, http.MethodPost, path, who, map[string]any{})
		if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "hec-secret") {
			t.Fatalf("%s: %d %s", who.ClientID+who.UserID, w.Code, w.Body.String())
		}
		wantRefused(t, lastEvent(t, hs.rec, "connection_resolved"), reasonConnectionCaller)
	}
	w := hs.do(t, http.MethodPost, path, svcClaims("kms-audit"), map[string]any{})
	var out struct {
		Data resolvedConnection `json:"data"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Data.Fields["token"] != "hec-secret" || out.Data.Type != "splunk_hec" {
		t.Fatalf("audit resolve: %d %s", w.Code, w.Body.String())
	}
	ev := lastEvent(t, hs.rec, "connection_resolved")
	if ev.Event.Result != route.ResultSuccess || ev.Event.Details["caller"] != "kms-audit" || ev.Event.TargetID != id {
		t.Fatalf("resolve audit %+v", ev.Event)
	}
	if raw, _ := json.Marshal(ev.Event); strings.Contains(string(raw), "hec-secret") {
		t.Fatal("credential in the audit event")
	}
	// Governance sends approval notices to Slack or Teams only.
	if w := hs.do(t, http.MethodPost, path, svcClaims("kms-governance"), map[string]any{}); w.Code != http.StatusConflict {
		t.Fatalf("governance opened a SIEM connection: %d", w.Code)
	}
	wantRefused(t, lastEvent(t, hs.rec, "connection_resolved"), reasonConnectionUse)
	// A ticketing connection can't carry the event stream.
	jira := hs.conn(t, "jira", map[string]string{"base_url": "https://1.1.1.1", "api_token": "x"})
	if w := hs.do(t, http.MethodPost, "/compliance/connections/"+jira+"/resolve?tenant_id=t1", svcClaims("kms-audit"), map[string]any{}); w.Code != http.StatusConflict {
		t.Fatalf("jira as stream: %d", w.Code)
	}
	// Tenancy: another tenant's connection is not found.
	if w := hs.do(t, http.MethodPost, "/compliance/connections/"+id+"/resolve?tenant_id=t2", svcClaims("kms-audit"), map[string]any{}); w.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant resolve: %d", w.Code)
	}
}

// Import seals the credentials, keeps the exposure register entry, derives
// its ID from the source so a retried migration doesn't duplicate, and is
// refused to other callers.
func TestConnectionImportIdempotentWithExposure(t *testing.T) {
	hs := newPlaybookHarness(t)
	body := map[string]any{"tenant_id": "t1", "source_id": "wh_abc", "name": "Splunk (migrated)", "type": "splunk_hec",
		"fields": map[string]string{"url": "https://1.1.1.1/services/collector", "token": "legacy-token"}, "exposed": true}
	if w := hs.do(t, http.MethodPost, "/compliance/connections/import", pbAdmin, body); w.Code != http.StatusForbidden {
		t.Fatalf("user import: %d", w.Code)
	}
	wantRefused(t, lastEvent(t, hs.rec, "connection_imported"), reasonConnectionCaller)
	w := hs.do(t, http.MethodPost, "/compliance/connections/import", svcClaims("kms-audit"), body)
	if w.Code != http.StatusCreated || strings.Contains(w.Body.String(), "legacy-token") {
		t.Fatalf("import: %d %s", w.Code, w.Body.String())
	}
	const id = "pbconn_audit_wh_abc"
	stored, err := hs.store.GetConnection(context.Background(), "t1", id)
	if err != nil {
		t.Fatal(err)
	}
	if opened, err := hs.vault.Open(stored); err != nil || opened.Fields["token"] != "legacy-token" {
		t.Fatalf("sealed import %v", err)
	}
	k, _ := hs.vault.current()
	exp, _ := k.Exposures(context.Background(), "t1", true)
	if len(exp) != 1 || exp[0].ItemID != id || exp[0].ItemType != connectionItemType {
		t.Fatalf("exposure %+v", exp)
	}
	if w := hs.do(t, http.MethodPost, "/compliance/connections/import", svcClaims("kms-audit"), body); w.Code != http.StatusOK {
		t.Fatalf("re-import: %d", w.Code)
	}
	if ev := lastEvent(t, hs.rec, "connection_imported"); ev.Event.Details["already_imported"] != true {
		t.Fatalf("re-import audit %+v", ev.Event.Details)
	}
	conns, _ := hs.store.ListConnections(context.Background(), "t1")
	if len(conns) != 1 {
		t.Fatalf("%d connections after a retried import", len(conns))
	}
	body["type"], body["source_id"] = "splunk_hec", "slack_url"
	if w := hs.do(t, http.MethodPost, "/compliance/connections/import", svcClaims("kms-governance"), body); w.Code != http.StatusConflict {
		t.Fatalf("governance imported a SIEM connection: %d", w.Code)
	}
}

// SIEM connections are validated by building the destination: plain http,
// private addresses and malformed Sentinel identifiers are refused.
func TestSIEMConnectionValidation(t *testing.T) {
	hs := newPlaybookHarness(t)
	for _, c := range []map[string]any{
		{"type": "splunk_hec", "fields": map[string]string{"url": "http://1.1.1.1", "token": "t"}},
		{"type": "elastic", "fields": map[string]string{"url": "https://10.0.0.5:9200", "api_key": "k"}},
		{"type": "syslog", "fields": map[string]string{"address": "127.0.0.1:6514"}},
		{"type": "syslog", "fields": map[string]string{"address": "no-port"}},
		{"type": "sentinel", "fields": map[string]string{"dce_url": "https://1.1.1.1", "dcr_immutable_id": "dcr-x", "stream_name": "Custom-A", "azure_tenant_id": "t", "client_id": "c", "client_secret": "s"}},
		{"type": "webhook", "fields": map[string]string{"url": "https://1.1.1.1", "signing_secret": "short"}},
	} {
		c["name"] = "x"
		if w := hs.do(t, http.MethodPost, "/compliance/playbooks/connections", pbAdmin, c); w.Code != http.StatusBadRequest {
			t.Fatalf("%v accepted: %d", c, w.Code)
		}
	}
	w := hs.do(t, http.MethodPost, "/compliance/playbooks/connections", pbAdmin, map[string]any{"name": "qradar", "type": "syslog", "fields": map[string]string{"address": "1.1.1.1:6514"}})
	if w.Code != http.StatusCreated || !strings.Contains(w.Body.String(), `"endpoint":"1.1.1.1"`) {
		t.Fatalf("syslog connection: %d %s", w.Code, w.Body.String())
	}
}

// send_siem_alert posts the run's alert through a SIEM connection; the
// connection test sends a real, labelled event the same way.
func TestSendSIEMAlertDeliversRunContext(t *testing.T) {
	hs := newPlaybookHarness(t)
	got := make(chan []byte, 4)
	auth := make(chan string, 4)
	ext := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- b
		auth <- r.Header.Get("Authorization")
	}))
	defer ext.Close()
	hs.exec.outbound = ext.Client()
	id := hs.conn(t, "splunk_hec", map[string]string{"url": ext.URL, "token": "hec-tok"})
	rc := RunContext{TenantID: "t1", RunID: "pbrun_9", PlaybookID: "pb1", PlaybookName: "canary response", Actor: "u-admin",
		Event: RunEvent{Subject: "audit.dataprotect.canary_tripped", TargetType: "canary", TargetID: "cn1"}}
	if _, err := hs.exec.executeAction(context.Background(), "send_siem_alert", map[string]string{"connection_id": id, "severity": "critical"}, rc); err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	if err := json.Unmarshal(<-got, &p); err != nil {
		t.Fatal(err)
	}
	rec := p["event"].(map[string]any)
	if <-auth != "Splunk hec-tok" || rec["severity"] != "critical" || rec["run_id"] != "pbrun_9" || rec["trigger_event"].(map[string]any)["target_id"] != "cn1" ||
		!strings.Contains(rec["title"].(string), "canary_tripped") {
		t.Fatalf("alert %v", p)
	}
	// A Slack connection doesn't fit a SIEM action.
	slack := hs.conn(t, "slack", map[string]string{"webhook_url": ext.URL})
	if _, err := hs.exec.executeAction(context.Background(), "send_siem_alert", map[string]string{"connection_id": slack}, rc); err == nil {
		t.Fatal("SIEM alert sent through a Slack connection")
	}
	if w := hs.do(t, http.MethodPost, "/compliance/playbooks", pbAdmin, playbookBody("canary_tripped", true, act("send_siem_alert", map[string]string{"connection_id": slack}))); w.Code != http.StatusBadRequest {
		t.Fatalf("playbook saved with a Slack connection for a SIEM alert: %d", w.Code)
	}
	if w := hs.do(t, http.MethodPost, "/compliance/playbooks/connections/"+id+"/test", pbAdmin, nil); w.Code != http.StatusOK {
		t.Fatalf("SIEM connection test: %d %s", w.Code, w.Body.String())
	}
	_ = json.Unmarshal(<-got, &p)
	if p["event"].(map[string]any)["test"] != true {
		t.Fatalf("test event %v", p)
	}
}

// A webhook connection's signing secret signs every body it sends.
func TestWebhookConnectionSignsBody(t *testing.T) {
	hs := newPlaybookHarness(t)
	type req struct {
		body []byte
		sig  string
	}
	got := make(chan req, 1)
	ext := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- req{b, r.Header.Get("X-KMS-Signature")}
	}))
	defer ext.Close()
	hs.exec.outbound = ext.Client()
	secret := "0123456789abcdef-signing"
	id := hs.conn(t, "webhook", map[string]string{"url": ext.URL, "signing_secret": secret})
	if _, err := hs.exec.executeAction(context.Background(), "send_webhook", map[string]string{"connection_id": id, "body": `{"a":1}`}, RunContext{TenantID: "t1"}); err != nil {
		t.Fatal(err)
	}
	r := <-got
	if r.sig != "sha256="+hex.EncodeToString(pkgcrypto.HMACSHA256([]byte(secret), r.body)) {
		t.Fatalf("signature %q for %s", r.sig, r.body)
	}
}

type fakeUsage struct {
	users []string
	err   error
}

func (f fakeUsage) Users(context.Context, string, string) ([]string, error) { return f.users, f.err }

// A connection an event stream or governance uses can't be deleted, and
// when its use can't be checked the delete is refused rather than risked.
func TestConnectionDeleteChecksStreamsAndGovernance(t *testing.T) {
	hs := newPlaybookHarness(t)
	id := hs.conn(t, "datadog", map[string]string{"url": "https://1.1.1.1/api/v2/logs", "api_key": "k"})
	hs.h.usage = fakeUsage{users: []string{"event stream SOC"}}
	if w := hs.do(t, http.MethodDelete, "/compliance/playbooks/connections/"+id, pbAdmin, nil); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "event stream SOC") {
		t.Fatalf("delete in use by a stream: %d %s", w.Code, w.Body.String())
	}
	wantRefused(t, lastEvent(t, hs.rec, "connection_deleted"), "connection_in_use")
	hs.h.usage = fakeUsage{err: errors.New("audit unreachable")}
	if w := hs.do(t, http.MethodDelete, "/compliance/playbooks/connections/"+id, pbAdmin, nil); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("delete with usage unknown: %d", w.Code)
	}
	wantRefused(t, lastEvent(t, hs.rec, "connection_deleted"), "connection_usage_unverified")
	hs.h.usage = fakeUsage{}
	if w := hs.do(t, http.MethodDelete, "/compliance/playbooks/connections/"+id, pbAdmin, nil); w.Code != http.StatusOK {
		t.Fatalf("delete unused: %d", w.Code)
	}
}

// platformUsage reads the audit streams and governance settings as the
// compliance service and names the users it finds.
func TestPlatformUsageFindsStreamsAndGovernance(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/webhooks":
			_, _ = w.Write([]byte(`{"items":[{"id":"wh1","name":"SOC","connection_id":"c1"},{"id":"wh2","name":"other","connection_id":"c2"}]}`))
		case "/governance/settings":
			_, _ = w.Write([]byte(`{"settings":{"slack_connection_id":"c1"}}`))
		case "/audit/anchor":
			_, _ = w.Write([]byte(`{"anchor":{"enabled":true,"connection_id":"c1"}}`))
		}
	}))
	defer srv.Close()
	users, err := platformUsage{auditURL: srv.URL, governanceURL: srv.URL, http: srv.Client()}.Users(context.Background(), "root", "c1")
	if err != nil || strings.Join(users, "|") != "event stream SOC|governance approval notices|audit checkpoint anchoring" {
		t.Fatalf("users %v %v", users, err)
	}
	// Other tenants have no governance settings to check.
	if users, err := (platformUsage{auditURL: srv.URL, governanceURL: srv.URL, http: srv.Client()}).Users(context.Background(), "t1", "c1"); err != nil || len(users) != 1 {
		t.Fatalf("t1 users %v %v", users, err)
	}
}

// A time-stamp authority credential is opened by the audit service alone,
// and its real test is the one Audit runs when anchoring is turned on.
func TestTimestampConnectionIsAuditsAlone(t *testing.T) {
	hs := newPlaybookHarness(t)
	tsa := hs.conn(t, "tsa", map[string]string{"url": "https://1.1.1.1/tsr", "username": "u", "password": "tsa-secret"})
	resolve := func(who *pkgauth.Claims) (int, string) {
		w := hs.do(t, http.MethodPost, "/compliance/connections/"+tsa+"/resolve?tenant_id=t1", who, map[string]any{})
		return w.Code, w.Body.String()
	}
	if code, body := resolve(svcClaims("kms-audit")); code != http.StatusOK || !strings.Contains(body, `"password":"tsa-secret"`) {
		t.Fatalf("audit resolve: %d %s", code, body)
	}
	for _, who := range []string{"kms-governance", "kms-discovery"} {
		if code, body := resolve(svcClaims(who)); code != http.StatusConflict || strings.Contains(body, "tsa-secret") {
			t.Fatalf("%s opened a tsa connection: %d %s", who, code, body)
		}
		wantRefused(t, lastEvent(t, hs.rec, "connection_resolved"), reasonConnectionUse)
	}
	if w := hs.do(t, http.MethodPost, "/compliance/playbooks/connections/"+tsa+"/test", pbAdmin, map[string]any{}); w.Code != http.StatusConflict {
		t.Fatalf("tsa connection test: %d %s", w.Code, w.Body.String())
	}
	wantRefused(t, lastEvent(t, hs.rec, "connection_tested"), "connection_test_elsewhere")
	for _, bad := range []map[string]string{
		{"url": "https://1.1.1.1/tsr", "username": "u"},
		{"url": "https://1.1.1.1/tsr", "trust_pem": "not a certificate"},
	} {
		if w := hs.do(t, http.MethodPost, "/compliance/playbooks/connections", pbAdmin, map[string]any{"name": "tsa", "type": "tsa", "fields": bad}); w.Code != http.StatusBadRequest {
			t.Fatalf("tsa fields %v: %d %s", bad, w.Code, w.Body.String())
		}
	}
}

// A git connection holds a repository access token. Only discovery may open
// one, discovery may open no other type, it is tested from the repository
// that uses it, and it can't be deleted while a repository reads with it.
func TestGitConnectionIsDiscoverysAlone(t *testing.T) {
	hs := newPlaybookHarness(t)
	git := hs.conn(t, "git", map[string]string{"git_url": "https://1.1.1.1", "token": "ghp-secret"})
	slack := hs.conn(t, "slack", map[string]string{"webhook_url": "https://1.1.1.1/x"})
	resolve := func(id string, who *pkgauth.Claims) (int, string) {
		w := hs.do(t, http.MethodPost, "/compliance/connections/"+id+"/resolve?tenant_id=t1", who, map[string]any{})
		return w.Code, w.Body.String()
	}
	// Created through the API: the token is required, the host is shown,
	// and no value comes back.
	if w := hs.do(t, http.MethodPost, "/compliance/playbooks/connections", pbAdmin, map[string]any{"name": "gh", "type": "git", "fields": map[string]string{"git_url": "https://1.1.1.1"}}); w.Code != http.StatusBadRequest {
		t.Fatalf("git connection without a token: %d %s", w.Code, w.Body.String())
	}
	w := hs.do(t, http.MethodPost, "/compliance/playbooks/connections", pbAdmin, map[string]any{"name": "gh", "type": "git", "fields": map[string]string{"git_url": "https://1.1.1.1", "token": "api-made-secret"}})
	if w.Code != http.StatusCreated || !strings.Contains(w.Body.String(), `"endpoint":"1.1.1.1"`) || strings.Contains(w.Body.String(), "api-made-secret") {
		t.Fatalf("create git connection: %d %s", w.Code, w.Body.String())
	}
	if code, body := resolve(git, svcClaims("kms-discovery")); code != http.StatusOK || !strings.Contains(body, `"token":"ghp-secret"`) {
		t.Fatalf("discovery resolve: %d %s", code, body)
	}
	if ev := lastEvent(t, hs.rec, "connection_resolved"); ev.Event.Details["caller"] != "kms-discovery" || ev.Event.Details["use"] != "scan_source" {
		t.Fatalf("resolve audit %+v", ev.Event.Details)
	}
	for _, who := range []string{"kms-audit", "kms-governance"} {
		if code, body := resolve(git, svcClaims(who)); code != http.StatusConflict || strings.Contains(body, "ghp-secret") {
			t.Fatalf("%s opened a git connection: %d %s", who, code, body)
		}
		wantRefused(t, lastEvent(t, hs.rec, "connection_resolved"), reasonConnectionUse)
	}
	if code, _ := resolve(slack, svcClaims("kms-discovery")); code != http.StatusConflict {
		t.Fatalf("discovery opened a Slack connection: %d", code)
	}
	wantRefused(t, lastEvent(t, hs.rec, "connection_resolved"), reasonConnectionUse)

	if w := hs.do(t, http.MethodPost, "/compliance/playbooks/connections/"+git+"/test", pbAdmin, map[string]any{}); w.Code != http.StatusConflict {
		t.Fatalf("git connection test: %d %s", w.Code, w.Body.String())
	}
	wantRefused(t, lastEvent(t, hs.rec, "connection_tested"), "connection_test_elsewhere")

	hs.h.usage = fakeUsage{}
	asked := ""
	hs.h.sourceUsage = func(_ context.Context, tenant, id string) ([]string, error) {
		asked = tenant + "/" + id
		return []string{"repository https://github.com/acme/app"}, nil
	}
	if w := hs.do(t, http.MethodDelete, "/compliance/playbooks/connections/"+git, pbAdmin, nil); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "github.com/acme/app") || asked != "t1/"+git {
		t.Fatalf("delete in use by a repository: %d %s (asked %q)", w.Code, w.Body.String(), asked)
	}
	wantRefused(t, lastEvent(t, hs.rec, "connection_deleted"), "connection_in_use")
	hs.h.sourceUsage = func(context.Context, string, string) ([]string, error) {
		return nil, errors.New("discovery unreachable")
	}
	if w := hs.do(t, http.MethodDelete, "/compliance/playbooks/connections/"+git, pbAdmin, nil); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("delete with repositories unknown: %d", w.Code)
	}
	wantRefused(t, lastEvent(t, hs.rec, "connection_deleted"), "connection_usage_unverified")
	// Discovery is not asked about other types.
	if w := hs.do(t, http.MethodDelete, "/compliance/playbooks/connections/"+slack, pbAdmin, nil); w.Code != http.StatusOK {
		t.Fatalf("delete a Slack connection with discovery down: %d %s", w.Code, w.Body.String())
	}
	hs.h.sourceUsage = func(context.Context, string, string) ([]string, error) { return nil, nil }
	if w := hs.do(t, http.MethodDelete, "/compliance/playbooks/connections/"+git, pbAdmin, nil); w.Code != http.StatusOK {
		t.Fatalf("delete unused git connection: %d %s", w.Code, w.Body.String())
	}
}

// platformUsage reads discovery's repositories and buckets as the
// compliance service.
func TestPlatformUsageFindsRepositoriesAndBuckets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Query().Get("tenant_id") != "t1":
			http.NotFound(w, r)
		case r.URL.Path == "/discovery/repositories":
			_, _ = w.Write([]byte(`{"items":[{"url":"https://github.com/acme/app","connection_id":"c1"},{"url":"https://github.com/acme/public","connection_id":""}]}`))
		case r.URL.Path == "/discovery/buckets":
			_, _ = w.Write([]byte(`{"items":[{"endpoint":"https://s3.eu-west-1.amazonaws.com","bucket":"acme-artifacts","connection_id":"c2"},{"endpoint":"https://acme.blob.core.windows.net","bucket":"public","connection_id":""}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	usage := platformUsage{discoveryURL: srv.URL, http: srv.Client()}
	for id, want := range map[string]string{"c1": "repository https://github.com/acme/app", "c2": "bucket https://s3.eu-west-1.amazonaws.com/acme-artifacts", "c3": ""} {
		users, err := usage.Sources(context.Background(), "t1", id)
		if err != nil || strings.Join(users, "|") != want {
			t.Fatalf("%s: users %v %v, want %q", id, users, err, want)
		}
	}
	if _, err := usage.Sources(context.Background(), "t2", "c1"); err == nil {
		t.Fatal("usage that could not be read was reported as none")
	}
}

// An s3 or azure_blob connection holds a bucket credential. Like a git
// connection it is discovery's alone, is tested on a bucket that uses it,
// and can't be deleted while a bucket reads with it. A secret key too short
// to sign with and a SAS token that isn't one are refused.
func TestStorageConnectionsAreDiscoverysAlone(t *testing.T) {
	// The Amazon endpoint below is a name. Left to real DNS, this test failed
	// whenever the resolver did (seen as one red CI job in twelve).
	defer ssrfguard.SetResolverForTests(map[string][]string{"s3.eu-west-1.amazonaws.com": {"52.218.0.10"}})()
	hs := newPlaybookHarness(t)
	create := func(typ string, fields map[string]string) *httptest.ResponseRecorder {
		return hs.do(t, http.MethodPost, "/compliance/playbooks/connections", pbAdmin, map[string]any{"name": typ, "type": typ, "fields": fields})
	}
	for name, w := range map[string]*httptest.ResponseRecorder{
		"s3 without a secret key": create("s3", map[string]string{"endpoint_url": "https://1.1.1.1", "access_key_id": "AKIDEXAMPLE"}),
		"s3 with a short secret":  create("s3", map[string]string{"endpoint_url": "https://1.1.1.1", "access_key_id": "AKIDEXAMPLE", "secret_access_key": "tooshort"}),
		"azure without a SAS":     create("azure_blob", map[string]string{"account_url": "https://1.1.1.1"}),
		"azure with a bare key":   create("azure_blob", map[string]string{"account_url": "https://1.1.1.1", "sas_token": "bm90LWEtc2FzLXRva2Vu"}),
		"s3 over http":            create("s3", map[string]string{"endpoint_url": "http://1.1.1.1", "access_key_id": "AKIDEXAMPLE", "secret_access_key": "long-enough-secret"}),
		"s3 on a platform host":   create("s3", map[string]string{"endpoint_url": "https://keycore:8010", "access_key_id": "AKIDEXAMPLE", "secret_access_key": "long-enough-secret"}),
	} {
		if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "long-enough-secret") {
			t.Fatalf("%s: %d %s", name, w.Code, w.Body.String())
		}
	}
	// 7.39.0-beta: one Azure credential, each well formed; a role only on
	// Amazon endpoints; a Google connection holds a real service account key.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p8, _ := x509.MarshalPKCS8PrivateKey(key)
	saJSON := func(pemText string) string {
		raw, _ := json.Marshal(map[string]string{"type": "service_account", "client_email": "scan@acme.iam.gserviceaccount.com", "private_key": pemText})
		return string(raw)
	}
	goodSA := saJSON(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p8})))
	accountKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 64))
	const sas = "sv=2022-11-02&sp=rl&sig=c2FzLXNpZ25hdHVyZQ%3D%3D"
	aws := map[string]string{"endpoint_url": "https://s3.eu-west-1.amazonaws.com", "access_key_id": "AKIDEXAMPLE", "secret_access_key": "long-enough-secret"}
	with := func(base map[string]string, kv ...string) map[string]string {
		out := map[string]string{}
		for k, v := range base {
			out[k] = v
		}
		for i := 0; i < len(kv); i += 2 {
			out[kv[i]] = kv[i+1]
		}
		return out
	}
	az := map[string]string{"account_url": "https://1.1.1.1"}
	for name, w := range map[string]*httptest.ResponseRecorder{
		"a role that is not an ARN":      create("s3", with(aws, "role_arn", "scanner-role")),
		"a role on a non-Amazon service": create("s3", map[string]string{"endpoint_url": "https://1.1.1.1", "access_key_id": "AKIDEXAMPLE", "secret_access_key": "long-enough-secret", "role_arn": "arn:aws:iam::123456789012:role/scanner"}),
		"an external ID without a role":  create("s3", with(aws, "external_id", "x")),
		"azure with two credentials":     create("azure_blob", with(az, "sas_token", sas, "account_key", accountKey)),
		"azure with half an application": create("azure_blob", with(az, "azure_tenant_id", "acme.onmicrosoft.com", "client_id", "app")),
		"azure with a short account key": create("azure_blob", with(az, "account_key", "c2hvcnQ=")),
		"azure account name without key": create("azure_blob", with(az, "sas_token", sas, "account_name", "acme")),
		"gcs without a key file":         create("gcs", map[string]string{"gcs_url": "https://1.1.1.1"}),
		"gcs with a user key file":       create("gcs", map[string]string{"gcs_url": "https://1.1.1.1", "service_account_json": `{"type":"authorized_user","client_email":"a@b"}`}),
		"gcs with no private key":        create("gcs", map[string]string{"gcs_url": "https://1.1.1.1", "service_account_json": saJSON("not a key")}),
	} {
		if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "long-enough-secret") || strings.Contains(w.Body.String(), accountKey) {
			t.Fatalf("%s: %d %s", name, w.Code, w.Body.String())
		}
	}
	for name, w := range map[string]*httptest.ResponseRecorder{
		"s3 with a role":         create("s3", with(aws, "role_arn", "arn:aws:iam::123456789012:role/kms/scanner", "external_id", "vecta")),
		"azure with Entra ID":    create("azure_blob", with(az, "azure_tenant_id", "acme.onmicrosoft.com", "client_id", "app-id", "client_secret", "entra-client-secret")),
		"azure with account key": create("azure_blob", with(az, "account_key", accountKey, "account_name", "acme")),
		"gcs":                    create("gcs", map[string]string{"gcs_url": "https://1.1.1.1", "service_account_json": goodSA}),
	} {
		if w.Code != http.StatusCreated || strings.Contains(w.Body.String(), "entra-client-secret") || strings.Contains(w.Body.String(), accountKey) || strings.Contains(w.Body.String(), "PRIVATE KEY") || strings.Contains(w.Body.String(), "long-enough-secret") {
			t.Fatalf("%s: %d %s", name, w.Code, w.Body.String())
		}
	}

	ids := map[string]string{}
	for typ, fields := range map[string]map[string]string{
		"s3":         {"endpoint_url": "https://1.1.1.1", "access_key_id": "AKIDEXAMPLE", "secret_access_key": "s3-secret-access-key"},
		"gcs":        {"gcs_url": "https://1.1.1.1", "service_account_json": goodSA},
		"azure_blob": {"account_url": "https://1.1.1.1", "sas_token": "?sv=2022-11-02&sp=rl&sig=c2FzLXNpZ25hdHVyZQ%3D%3D"},
	} {
		w := create(typ, fields)
		var out struct{ Data Connection }
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		if w.Code != http.StatusCreated || out.Data.Endpoint != "1.1.1.1" || strings.Contains(w.Body.String(), "s3-secret-access-key") || strings.Contains(w.Body.String(), "c2FzLXNpZ25hdHVyZQ") {
			t.Fatalf("create %s: %d %s", typ, w.Code, w.Body.String())
		}
		ids[typ] = out.Data.ID
	}
	resolve := func(id string, who *pkgauth.Claims) (int, string) {
		w := hs.do(t, http.MethodPost, "/compliance/connections/"+id+"/resolve?tenant_id=t1", who, map[string]any{})
		return w.Code, w.Body.String()
	}
	for typ, secret := range map[string]string{"s3": `"secret_access_key":"s3-secret-access-key"`, "azure_blob": `sig=c2FzLXNpZ25hdHVyZQ%3D%3D`, "gcs": `scan@acme.iam.gserviceaccount.com`} {
		id := ids[typ]
		if code, body := resolve(id, svcClaims("kms-discovery")); code != http.StatusOK || !strings.Contains(body, secret) {
			t.Fatalf("discovery resolve %s: %d %s", typ, code, body)
		}
		if ev := lastEvent(t, hs.rec, "connection_resolved"); ev.Event.Details["caller"] != "kms-discovery" || ev.Event.Details["use"] != "scan_source" || ev.Event.Details["type"] != typ {
			t.Fatalf("resolve audit %+v", ev.Event.Details)
		}
		for _, who := range []string{"kms-audit", "kms-governance"} {
			if code, body := resolve(id, svcClaims(who)); code != http.StatusConflict || strings.Contains(body, "c2FzLXNpZ25hdHVyZQ") || strings.Contains(body, "s3-secret-access-key") {
				t.Fatalf("%s opened a %s connection: %d %s", who, typ, code, body)
			}
			wantRefused(t, lastEvent(t, hs.rec, "connection_resolved"), reasonConnectionUse)
		}
		if w := hs.do(t, http.MethodPost, "/compliance/playbooks/connections/"+id+"/test", pbAdmin, map[string]any{}); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "Object storage") {
			t.Fatalf("%s connection test: %d %s", typ, w.Code, w.Body.String())
		}
		wantRefused(t, lastEvent(t, hs.rec, "connection_tested"), "connection_test_elsewhere")

		hs.h.usage = fakeUsage{}
		hs.h.sourceUsage = func(context.Context, string, string) ([]string, error) {
			return []string{"bucket https://1.1.1.1/acme-artifacts"}, nil
		}
		if w := hs.do(t, http.MethodDelete, "/compliance/playbooks/connections/"+id, pbAdmin, nil); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "acme-artifacts") {
			t.Fatalf("delete %s in use by a bucket: %d %s", typ, w.Code, w.Body.String())
		}
		wantRefused(t, lastEvent(t, hs.rec, "connection_deleted"), "connection_in_use")
		hs.h.sourceUsage = func(context.Context, string, string) ([]string, error) { return nil, nil }
		if w := hs.do(t, http.MethodDelete, "/compliance/playbooks/connections/"+id, pbAdmin, nil); w.Code != http.StatusOK {
			t.Fatalf("delete unused %s connection: %d %s", typ, w.Code, w.Body.String())
		}
	}
}
