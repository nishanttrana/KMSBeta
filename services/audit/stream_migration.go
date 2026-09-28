package main

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"vecta-kms/pkg/mek"
)

// Before 2.10.0-beta an event stream ("webhook") kept its own URL, format,
// signing secret and header credentials, sealed under the audit master key.
// migrateLegacyStreams moves each into a compliance connection of the type
// its format spoke, points the stream at it, and clears the stream's copy.
// An open exposure register entry (credentials once stored in plaintext)
// moves with them. Primary only: the webhooks table is replicated.
//
// A stream whose credentials don't map onto a connection type (a Splunk
// stream with no "Authorization: Splunk <token>" header, extra headers on a
// SIEM format) keeps delivering as before and is reported once per process
// as webhook_migration_refused, for an operator to re-point by hand.

// legacyConnection maps a legacy stream (credentials opened) onto a
// connection type and its fields.
func legacyConnection(wh Webhook) (string, map[string]string, string) {
	headers := map[string]string{}
	for k, v := range wh.Headers {
		if v != "" {
			headers[http.CanonicalHeaderKey(k)] = v
		}
	}
	take := func(name string) string {
		v := headers[name]
		delete(headers, name)
		return v
	}
	switch wh.Format {
	case "", "json":
		fields := map[string]string{"url": wh.URL}
		if len(headers) > 0 {
			fields["headers"] = string(mustJSON(headers))
		}
		if wh.Secret != "" {
			fields["signing_secret"] = wh.Secret
		}
		return "webhook", fields, ""
	case "slack":
		return "slack", map[string]string{"webhook_url": wh.URL}, ""
	case "splunk_hec":
		auth := take("Authorization")
		token := strings.TrimSpace(strings.TrimPrefix(auth, "Splunk "))
		if token == "" || token == auth {
			return "", nil, "no_splunk_token_header"
		}
		if len(headers) > 0 {
			return "", nil, "unmapped_headers"
		}
		return "splunk_hec", map[string]string{"url": wh.URL, "token": token}, ""
	case "datadog":
		key := take("Dd-Api-Key")
		if key == "" {
			return "", nil, "no_datadog_api_key_header"
		}
		if len(headers) > 0 {
			return "", nil, "unmapped_headers"
		}
		return "datadog", map[string]string{"url": wh.URL, "api_key": key}, ""
	}
	return "", nil, "unknown_format"
}

// streamMigrator remembers which refusals it already reported.
type streamMigrator struct {
	mu       sync.Mutex
	reported map[string]bool
}

func (s *Service) migrateLegacyStreams(ctx context.Context, k *mek.Keyring, src connectionSource, m *streamMigrator, primary func(context.Context) bool, audit func(context.Context, AuditEvent)) (int, error) {
	if !primary(ctx) || src == nil {
		return 0, nil
	}
	rows, err := s.store.ListLegacyWebhooks(ctx)
	if err != nil {
		return 0, err
	}
	moved := map[string][]string{}
	var failed []string
	for _, stored := range rows {
		wh, err := s.creds.Open(stored)
		if err != nil {
			failed = append(failed, stored.ID)
			continue
		}
		typ, fields, reason := legacyConnection(wh)
		if reason != "" {
			m.mu.Lock()
			first := !m.reported[wh.ID]
			m.reported[wh.ID] = true
			m.mu.Unlock()
			if first && audit != nil {
				audit(ctx, AuditEvent{
					TenantID: wh.TenantID, Service: "audit", Action: webhookSelfPrefix + "migration_refused",
					ActorID: "audit-webhooks", ActorType: "service", TargetType: "webhook", TargetID: wh.ID, Result: "refused",
					Timestamp: time.Now().UTC(),
					Details: map[string]interface{}{"severity": "warning", "reason": reason, "format": wh.Format,
						"remedy": "create a connection for this stream under Playbooks → Connections and select it on the stream"},
				})
			}
			continue
		}
		// Unknown exposure is not "not exposed": retry rather than drop it.
		open, err := k.Exposures(ctx, wh.TenantID, true)
		if err != nil {
			failed = append(failed, wh.ID)
			continue
		}
		// A row still in plaintext (the seal job runs alongside) is exposed
		// whether or not the register has it yet.
		exposed := stored.Sealed == nil && hasCredentials(stored.Secret, stored.Headers)
		for _, e := range open {
			exposed = exposed || (e.ItemType == webhookCredsItemType && e.ItemID == wh.ID)
		}
		connID, err := src.Import(ctx, wh.TenantID, connImport{SourceID: wh.ID, Name: wh.Name + " (migrated stream)", Type: typ, Fields: fields, Exposed: exposed})
		if err != nil {
			failed = append(failed, wh.ID)
			continue
		}
		next := stored
		next.ConnectionID, next.ConnectionType = connID, typ
		next.URL, next.Format, next.Secret, next.Headers, next.Sealed, next.HasSecret = "", "", "", map[string]string{}, nil, false
		if _, err := s.store.UpdateWebhook(ctx, wh.TenantID, wh.ID, next); err != nil {
			failed = append(failed, wh.ID)
			continue
		}
		if exposed {
			// The register entry now follows the connection in compliance.
			k.Retire(ctx, wh.TenantID, webhookCredsItemType, wh.ID, "moved_to_connection")
		}
		moved[wh.TenantID] = append(moved[wh.TenantID], wh.ID)
	}
	tenants := make([]string, 0, len(moved))
	for t := range moved {
		tenants = append(tenants, t)
	}
	sort.Strings(tenants)
	total := 0
	for _, t := range tenants {
		total += len(moved[t])
		if audit != nil {
			audit(ctx, AuditEvent{
				TenantID: t, Service: "audit", Action: webhookSelfPrefix + "migrated",
				ActorID: "audit-webhooks", ActorType: "service", TargetType: "webhook", Result: "success", Timestamp: time.Now().UTC(),
				Details: map[string]interface{}{"severity": "info", "count": len(moved[t]), "webhook_ids": moved[t],
					"note": "stream credentials moved into compliance connections; the streams now name them"},
			})
		}
	}
	if len(failed) > 0 {
		return total, errors.New("some legacy streams could not be moved yet (compliance or the master key unavailable); retrying: " + strings.Join(failed, ", "))
	}
	return total, nil
}

// migrateLegacyStreamsLoop runs the migration now and every interval,
// which also catches rows a restore brings back.
func (s *Service) migrateLegacyStreamsLoop(ctx context.Context, k *mek.Keyring, src connectionSource, primary func(context.Context) bool, audit func(context.Context, AuditEvent), interval time.Duration, logf func(string, ...interface{})) {
	m := &streamMigrator{reported: map[string]bool{}}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if n, err := s.migrateLegacyStreams(ctx, k, src, m, primary, audit); err != nil {
			logf("event streams: %v", err)
		} else if n > 0 {
			logf("event streams: moved %d legacy stream(s) into compliance connections", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
