package siem

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

type hit struct {
	path, query string
	header      http.Header
	body        []byte
}

func receiver(t *testing.T, answer func(w http.ResponseWriter, r *http.Request)) (*httptest.Server, *[]hit) {
	t.Helper()
	var hits []hit
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		hits = append(hits, hit{r.URL.Path, r.URL.RawQuery, r.Header.Clone(), b})
		if answer != nil {
			answer(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func sample() Event {
	return Event{ID: "evt_1", Timestamp: time.Unix(1790000000, 0), TenantID: "t1", Service: "keycore", Action: "audit.key.rotate",
		ActorID: "alice", TargetType: "key", TargetID: "k1", Result: "success", Severity: "warning", SourceIP: "203.0.113.9", NodeID: "node-1",
		Record: map[string]any{"id": "evt_1", "action": "audit.key.rotate"}}
}

func send(t *testing.T, kind string, fields map[string]string, client *http.Client) (int, error) {
	t.Helper()
	d, err := New(kind, fields, Options{Client: client})
	if err != nil {
		t.Fatalf("New(%s): %v", kind, err)
	}
	return d.Send(context.Background(), []Event{sample()})
}

func TestSplunkHECSendsEnvelopeWithToken(t *testing.T) {
	srv, hits := receiver(t, nil)
	if _, err := send(t, "splunk_hec", map[string]string{"url": srv.URL, "token": "hec-tok", "index": "sec"}, srv.Client()); err != nil {
		t.Fatal(err)
	}
	h := (*hits)[0]
	if h.path != "/services/collector/event" || h.header.Get("Authorization") != "Splunk hec-tok" {
		t.Fatalf("path %s auth %q", h.path, h.header.Get("Authorization"))
	}
	var p map[string]any
	if json.Unmarshal(h.body, &p) != nil || p["sourcetype"] != "vecta:audit" || p["index"] != "sec" || p["event"].(map[string]any)["action"] != "audit.key.rotate" {
		t.Fatalf("payload %s", h.body)
	}
}

func TestDatadogSendsLogsWithAPIKey(t *testing.T) {
	srv, hits := receiver(t, nil)
	if _, err := send(t, "datadog", map[string]string{"url": srv.URL + "/api/v2/logs", "api_key": "dd-key"}, srv.Client()); err != nil {
		t.Fatal(err)
	}
	h := (*hits)[0]
	var p []map[string]any
	if h.header.Get("DD-API-KEY") != "dd-key" || json.Unmarshal(h.body, &p) != nil || p[0]["status"] != "warning" || !strings.Contains(p[0]["ddtags"].(string), "action:audit.key.rotate") {
		t.Fatalf("datadog %v %s", h.header, h.body)
	}
}

// A bulk answer of 200 with a rejected document is a failed delivery.
func TestElasticChecksBulkItemErrors(t *testing.T) {
	srv, hits := receiver(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"errors":true,"items":[{"index":{"status":400,"error":{"type":"mapper_parsing_exception"}}}]}`))
	})
	_, err := send(t, "elastic", map[string]string{"url": srv.URL, "api_key": "ek"}, srv.Client())
	if err == nil || !strings.Contains(err.Error(), "mapper_parsing_exception") {
		t.Fatalf("err = %v, want the rejected document reported", err)
	}
	h := (*hits)[0]
	lines := strings.Split(strings.TrimSpace(string(h.body)), "\n")
	if h.path != "/_bulk" || h.header.Get("Authorization") != "ApiKey ek" || len(lines) != 2 || !strings.Contains(lines[0], `"_id":"evt_1"`) {
		t.Fatalf("bulk %s %v %s", h.path, h.header, h.body)
	}
}

func TestElasticAcceptsCleanBulk(t *testing.T) {
	srv, _ := receiver(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"errors":false,"items":[]}`)) })
	if _, err := send(t, "elastic", map[string]string{"url": srv.URL, "api_key": "ek"}, srv.Client()); err != nil {
		t.Fatal(err)
	}
}

// Sentinel gets an Entra token with the client credentials, then posts rows
// to the DCR stream with it; the token is reused while valid.
func TestSentinelLogsIngestion(t *testing.T) {
	var tokenCalls int
	srv, hits := receiver(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
			tokenCalls++
			_, _ = w.Write([]byte(`{"access_token":"entra-tok","expires_in":3600}`))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	defer func(old string) { azureLogin = old }(azureLogin)
	azureLogin = srv.URL
	dcr := "dcr-" + strings.Repeat("a1", 16)
	d, err := New("sentinel", map[string]string{"dce_url": srv.URL, "dcr_immutable_id": dcr, "stream_name": "Custom-VectaKMSAudit_CL",
		"azure_tenant_id": "contoso.onmicrosoft.com", "client_id": "app", "client_secret": "s3cret"}, Options{Client: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if st, err := d.Send(context.Background(), []Event{sample()}); err != nil || st != http.StatusNoContent {
			t.Fatalf("send: %d %v", st, err)
		}
	}
	if tokenCalls != 1 {
		t.Fatalf("token fetched %d times, want 1 (cached)", tokenCalls)
	}
	tok, ingest := (*hits)[0], (*hits)[1]
	if tok.path != "/contoso.onmicrosoft.com/oauth2/v2.0/token" || !strings.Contains(string(tok.body), "client_secret=s3cret") || !strings.Contains(string(tok.body), "scope=https%3A%2F%2Fmonitor.azure.com%2F%2F.default") {
		t.Fatalf("token request %s %s", tok.path, tok.body)
	}
	var rows []map[string]any
	if ingest.path != "/dataCollectionRules/"+dcr+"/streams/Custom-VectaKMSAudit_CL" || ingest.query != "api-version=2023-01-01" ||
		ingest.header.Get("Authorization") != "Bearer entra-tok" || json.Unmarshal(ingest.body, &rows) != nil || rows[0]["Action"] != "audit.key.rotate" {
		t.Fatalf("ingest %s?%s %v %s", ingest.path, ingest.query, ingest.header, ingest.body)
	}
}

func TestSentinelRefusesMalformedIdentifiers(t *testing.T) {
	_, err := New("sentinel", map[string]string{"dce_url": "https://x.ingest.monitor.azure.com", "dcr_immutable_id": "../../x", "stream_name": "Custom-A",
		"azure_tenant_id": "t", "client_id": "c", "client_secret": "s"}, Options{Client: http.DefaultClient})
	if err == nil {
		t.Fatal("a path-traversing DCR id was accepted")
	}
}

func TestHTTPKindsRequireHTTPS(t *testing.T) {
	for _, kind := range []string{"splunk_hec", "datadog", "elastic"} {
		if _, err := New(kind, map[string]string{"url": "http://siem.example.com", "token": "t", "api_key": "k"}, Options{Client: http.DefaultClient}); err == nil {
			t.Fatalf("%s accepted plain http", kind)
		}
	}
}

// Syslog: RFC 5425 frames over TLS 1.3, each an RFC 5424 message carrying
// CEF, verified against the collector's CA.
func TestSyslogTLSDeliversCEFFrames(t *testing.T) {
	// httptest's certificate (for example.com) stands in for the collector's.
	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	leaf := srv.Certificate()
	pair := srv.TLS.Certificates[0]
	srv.Close()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		var msgs []string
		for i := 0; i < 2; i++ {
			n, err := r.ReadString(' ')
			if err != nil {
				break
			}
			size, _ := strconv.Atoi(strings.TrimSpace(n))
			buf := make([]byte, size)
			if _, err := io.ReadFull(r, buf); err != nil {
				break
			}
			msgs = append(msgs, string(buf))
		}
		got <- msgs
	}()
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))
	d, err := New("syslog", map[string]string{"address": "collector.example.com:6514", "ca_pem": caPEM, "server_name": "example.com"}, Options{
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, ln.Addr().String())
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	second := sample()
	second.Action, second.Result, second.Severity = "audit.auth.login", "refused", ""
	if _, err := d.Send(context.Background(), []Event{sample(), second}); err != nil {
		t.Fatal(err)
	}
	msgs := <-got
	if len(msgs) != 2 {
		t.Fatalf("frames %q", msgs)
	}
	if !strings.HasPrefix(msgs[0], "<84>1 ") || !strings.Contains(msgs[0], "CEF:0|Vecta|KMS||audit.key.rotate|audit.key.rotate|5|") ||
		!strings.Contains(msgs[0], "src=203.0.113.9") || !strings.Contains(msgs[0], "cs1=t1") {
		t.Fatalf("frame %q", msgs[0])
	}
	if !strings.Contains(msgs[1], "outcome=refused") {
		t.Fatalf("frame %q", msgs[1])
	}
}

// A collector whose certificate isn't signed by the configured CA is refused.
func TestSyslogRefusesUntrustedCollector(t *testing.T) {
	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	pair := srv.TLS.Certificates[0]
	srv.Close()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			_ = c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()
	d, _ := New("syslog", map[string]string{"address": "collector.example.com:6514"}, Options{
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, ln.Addr().String())
		},
	})
	if _, err := d.Send(context.Background(), []Event{sample()}); err == nil || !strings.Contains(err.Error(), "handshake") {
		t.Fatalf("err = %v, want a TLS handshake refusal", err)
	}
}

func TestCEFEscaping(t *testing.T) {
	e := sample()
	e.Action, e.ActorID = "a|b", "x=y\nz"
	s := CEF(e)
	if !strings.Contains(s, `|a\|b|a\|b|`) || !strings.Contains(s, `suser=x\=y\nz`) {
		t.Fatalf("cef %q", s)
	}
}

func TestSpecsCoverEveryKind(t *testing.T) {
	for _, s := range Specs {
		if _, ok := SpecFor(s.Kind); !ok || s.URLField == "" {
			t.Fatalf("spec %+v", s)
		}
	}
	if ValidationURL("syslog", map[string]string{"address": "siem.example.com:6514"}) != "https://siem.example.com:6514" {
		t.Fatal("syslog validation URL")
	}
}
