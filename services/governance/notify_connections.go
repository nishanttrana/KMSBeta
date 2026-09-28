package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"strings"
	"time"

	"vecta-kms/pkg/servicetoken"
)

// Approval notices go to Slack or Teams through compliance connections, the
// platform's one store of outbound credentials (docs/SECURITY/CONNECTIONS.md).
// Governance keeps only the connection ID; each notice opens it through
// compliance (POST /compliance/connections/{id}/resolve, callable only by the
// kms-audit and kms-governance identities, audited as connection_resolved).
// Before 2.10.0-beta the incoming-webhook URLs, which are credentials, were
// stored here in plaintext; migrateNotifyURLs moves them into connections.

// notifyConnections opens and imports connections.
type notifyConnections interface {
	// Resolve returns the connection's type and webhook URL.
	Resolve(ctx context.Context, tenantID, id string) (string, string, error)
	Import(ctx context.Context, tenantID, sourceID, typ, webhookURL string) (string, error)
}

// WithNotifyConnections wires the compliance connection client.
func WithNotifyConnections(c notifyConnections) ServiceOption {
	return func(s *Service) { s.conns = c }
}

// complianceConnections calls compliance as kms-governance over internal
// mTLS (http.DefaultTransport is svctls's router).
type complianceConnections struct {
	base string
	http *http.Client
}

func newComplianceConnections(base string) complianceConnections {
	return complianceConnections{base: strings.TrimRight(base, "/"), http: &http.Client{Timeout: 10 * time.Second}}
}

func (c complianceConnections) call(ctx context.Context, tenantID, path string, body, out interface{}) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", tenantID)
	servicetoken.Authorize(ctx, req)
	resp, err := c.http.Do(req)
	if err != nil {
		var ue *neturl.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("compliance unreachable: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	ans, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		var e struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(ans, &e)
		return fmt.Errorf("compliance HTTP %d: %s", resp.StatusCode, e.Error.Message)
	}
	return json.Unmarshal(ans, out)
}

func (c complianceConnections) Resolve(ctx context.Context, tenantID, id string) (string, string, error) {
	var out struct {
		Data struct {
			Type   string            `json:"type"`
			Fields map[string]string `json:"fields"`
		} `json:"data"`
	}
	if err := c.call(ctx, tenantID, "/compliance/connections/"+neturl.PathEscape(id)+"/resolve", map[string]string{"tenant_id": tenantID}, &out); err != nil {
		return "", "", err
	}
	return out.Data.Type, out.Data.Fields["webhook_url"], nil
}

func (c complianceConnections) Import(ctx context.Context, tenantID, sourceID, typ, webhookURL string) (string, error) {
	var out struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	body := map[string]interface{}{
		"tenant_id": tenantID, "source_id": sourceID, "type": typ, "exposed": true,
		"name":   strings.ToUpper(typ[:1]) + typ[1:] + " approval notices (migrated)",
		"fields": map[string]string{"webhook_url": webhookURL},
	}
	if err := c.call(ctx, tenantID, "/compliance/connections/import", body, &out); err != nil {
		return "", err
	}
	if out.Data.ID == "" {
		return "", errors.New("compliance returned no connection id")
	}
	return out.Data.ID, nil
}

// notifyURL opens the channel's connection and returns its webhook URL,
// held in memory for this notice only. A setting an earlier release stored
// as a plaintext URL is used until the migration moves it.
func (s *Service) notifyURL(ctx context.Context, settings GovernanceSettings, channel string) (string, error) {
	connID, legacy := settings.SlackConnectionID, settings.SlackWebhookURL
	if channel == webhookChannelTeams {
		connID, legacy = settings.TeamsConnectionID, settings.TeamsWebhookURL
	}
	if connID == "" {
		if legacy != "" {
			return legacy, nil
		}
		return "", fmt.Errorf("no %s connection is configured", channel)
	}
	if s.conns == nil {
		return "", errors.New("connections are not wired")
	}
	typ, url, err := s.conns.Resolve(ctx, settings.TenantID, connID)
	if err != nil {
		return "", fmt.Errorf("%s connection %s: %w", channel, connID, err)
	}
	if typ != channel || url == "" {
		return "", fmt.Errorf("connection %s is %s, not %s", connID, typ, channel)
	}
	return url, nil
}

// migrateNotifyURLs moves plaintext Slack and Teams URLs into connections
// (recorded as exposed: database copies made before still hold them), then
// points the settings at them and clears the URL. Primary only.
func (s *Service) migrateNotifyURLs(ctx context.Context, primary func(context.Context) bool) (int, error) {
	if !primary(ctx) || s.conns == nil {
		return 0, nil
	}
	rows, err := s.store.ListLegacyNotifyURLs(ctx)
	if err != nil {
		return 0, err
	}
	moved := 0
	var failed []string
	for _, g := range rows {
		var ids []string
		for _, ch := range []struct{ name, url string }{{webhookChannelSlack, g.SlackWebhookURL}, {webhookChannelTeams, g.TeamsWebhookURL}} {
			if ch.url == "" {
				continue
			}
			id, err := s.conns.Import(ctx, g.TenantID, "governance_"+ch.name, ch.name, ch.url)
			if err == nil {
				err = s.store.SetNotifyConnection(ctx, g.TenantID, ch.name, id)
			}
			if err != nil {
				failed = append(failed, g.TenantID+"/"+ch.name)
				continue
			}
			ids = append(ids, id)
			moved++
		}
		if len(ids) > 0 {
			_ = s.publishAudit(ctx, "audit.governance.notify_connections_migrated", g.TenantID, map[string]interface{}{
				"connection_ids": ids, "severity": "warning",
				"exposure": "stored in plaintext by an earlier release; rotate these Slack/Teams webhook URLs",
			})
		}
	}
	if len(failed) > 0 {
		return moved, errors.New("notification URLs not moved yet (compliance unavailable?), retrying: " + strings.Join(failed, ", "))
	}
	return moved, nil
}

// migrateNotifyURLsLoop runs the migration now and every interval, which
// also catches rows a restore brings back.
func (s *Service) migrateNotifyURLsLoop(ctx context.Context, primary func(context.Context) bool, interval time.Duration, logf func(string, ...interface{})) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if n, err := s.migrateNotifyURLs(ctx, primary); err != nil {
			logf("approval notices: %v", err)
		} else if n > 0 {
			logf("approval notices: moved %d plaintext webhook URL(s) into compliance connections", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
