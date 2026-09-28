// Package siem delivers audit events to the SIEM platforms a tenant connects:
// Splunk (HTTP Event Collector), Datadog Logs, Elasticsearch, Microsoft
// Sentinel (Azure Monitor Logs Ingestion API) and any collector that takes
// CEF over syslog (QRadar, ArcSight, and others).
//
// A Destination is built from a connection's opened fields. The fields live
// only in compliance's sealed connections (docs/SECURITY/CONNECTIONS.md);
// callers open them just for the delivery. Every destination speaks TLS: the
// HTTP kinds go through the caller's client (ssrfguard.NewHTTPSClient in
// production: HTTPS at TLS 1.3, no private addresses, no redirects), and
// syslog is RFC 5425 over TLS 1.3 through the same address guard.
package siem

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"strings"
	"time"
)

// Event is one audit event as a SIEM receives it. Record is the full event
// the audit service holds; it is sent as the body's event document, so a
// receiver sees the same fields the audit log does.
type Event struct {
	ID         string
	Timestamp  time.Time
	TenantID   string
	Service    string
	Action     string
	ActorID    string
	TargetType string
	TargetID   string
	Result     string
	Severity   string // info, low, warning, high, critical
	SourceIP   string
	NodeID     string
	Record     any
}

func (e Event) record() any {
	if e.Record != nil {
		return e.Record
	}
	return map[string]any{
		"id": e.ID, "timestamp": e.Timestamp.UTC().Format(time.RFC3339Nano), "tenant_id": e.TenantID,
		"service": e.Service, "action": e.Action, "actor_id": e.ActorID, "target_type": e.TargetType,
		"target_id": e.TargetID, "result": e.Result, "severity": e.Severity, "source_ip": e.SourceIP,
	}
}

// Destination sends a batch of events in one request (one TLS session for
// syslog). It returns the receiver's HTTP status (0 for syslog or when no
// answer came) and an error unless the receiver accepted every event.
type Destination interface {
	Send(ctx context.Context, events []Event) (int, error)
}

// Spec describes one destination kind's connection fields.
type Spec struct {
	Kind     string   `json:"type"`
	Label    string   `json:"label"`
	Required []string `json:"fields"`
	Optional []string `json:"optional,omitempty"`
	// URLField holds the endpoint the platform calls; its host is shown and
	// it must pass the outbound address checks.
	URLField string `json:"url_field"`
	// Secrets are the credential fields (entered masked).
	Secrets []string `json:"secrets"`
}

// Specs lists every destination kind New builds.
var Specs = []Spec{
	{Kind: "splunk_hec", Label: "Splunk HTTP Event Collector", Required: []string{"url", "token"}, Optional: []string{"index", "sourcetype"}, URLField: "url", Secrets: []string{"token"}},
	{Kind: "datadog", Label: "Datadog Logs", Required: []string{"url", "api_key"}, URLField: "url", Secrets: []string{"api_key"}},
	{Kind: "elastic", Label: "Elasticsearch", Required: []string{"url", "api_key"}, Optional: []string{"index"}, URLField: "url", Secrets: []string{"api_key"}},
	{Kind: "sentinel", Label: "Microsoft Sentinel (Logs Ingestion API)", Required: []string{"dce_url", "dcr_immutable_id", "stream_name", "azure_tenant_id", "client_id", "client_secret"}, URLField: "dce_url", Secrets: []string{"client_secret"}},
	{Kind: "syslog", Label: "Syslog over TLS, CEF (QRadar, ArcSight)", Required: []string{"address"}, Optional: []string{"ca_pem", "server_name"}, URLField: "address", Secrets: []string{}},
}

// SpecFor returns the spec of kind.
func SpecFor(kind string) (Spec, bool) {
	for _, s := range Specs {
		if s.Kind == kind {
			return s, true
		}
	}
	return Spec{}, false
}

// Options carries what a destination needs from its caller.
type Options struct {
	// Client makes the HTTPS calls. Production passes
	// ssrfguard.NewHTTPSClient; tests pass a client that trusts their server.
	Client *http.Client
	// Dial opens the syslog TCP connection; nil means ssrfguard.DialContext.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// New builds the destination for kind from a connection's opened fields.
func New(kind string, fields map[string]string, opt Options) (Destination, error) {
	spec, ok := SpecFor(kind)
	if !ok {
		return nil, fmt.Errorf("%q is not a SIEM destination", kind)
	}
	f := make(map[string]string, len(fields))
	for k, v := range fields {
		f[k] = strings.TrimSpace(v)
	}
	for _, k := range spec.Required {
		if f[k] == "" {
			return nil, fmt.Errorf("%s is required", k)
		}
	}
	if kind == "syslog" {
		return newSyslog(f, opt)
	}
	if opt.Client == nil {
		return nil, errors.New("no HTTPS client")
	}
	u, err := httpsURL(f[spec.URLField])
	if err != nil {
		return nil, fmt.Errorf("%s: %w", spec.URLField, err)
	}
	switch kind {
	case "splunk_hec":
		return newSplunk(u, f, opt.Client), nil
	case "datadog":
		return &datadog{url: u.String(), apiKey: f["api_key"], client: opt.Client}, nil
	case "elastic":
		return newElastic(u, f, opt.Client), nil
	case "sentinel":
		return newSentinel(u, f, opt.Client)
	}
	return nil, fmt.Errorf("%q is not a SIEM destination", kind)
}

// ValidationURL is the address the outbound checks apply to: the endpoint
// URL, or https://host:port for a syslog address (the same resolver and
// address rules apply to both).
func ValidationURL(kind string, fields map[string]string) string {
	spec, _ := SpecFor(kind)
	v := strings.TrimSpace(fields[spec.URLField])
	if kind == "syslog" && v != "" {
		return "https://" + v
	}
	return v
}

func httpsURL(raw string) (*neturl.URL, error) {
	u, err := neturl.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return nil, errors.New("must be an https URL")
	}
	return u, nil
}

// post sends body and returns the status and (bounded) answer. Errors name
// the host only: an endpoint URL can itself carry a credential.
func post(ctx context.Context, client *http.Client, url, contentType string, body []byte, headers map[string]string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, nil, errors.New("invalid request")
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "VectaKMS-SIEM/1")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		var ue *neturl.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return 0, nil, fmt.Errorf("%s: %v", req.URL.Hostname(), err)
	}
	defer resp.Body.Close() //nolint:errcheck
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, raw, fmt.Errorf("%s answered HTTP %d", req.URL.Hostname(), resp.StatusCode)
	}
	return resp.StatusCode, raw, nil
}
