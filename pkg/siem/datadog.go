package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DatadogExporter sends audit events to Datadog Logs API.
type DatadogExporter struct {
	apiKey     string
	site       string // e.g., "datadoghq.com", "datadoghq.eu", "us5.datadoghq.com"
	httpClient *http.Client
	service    string
	source     string
}

// NewDatadogExporter creates a Datadog logs destination.
func NewDatadogExporter(apiKey, site string, client *http.Client) *DatadogExporter {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if site == "" {
		site = "datadoghq.com"
	}
	return &DatadogExporter{
		apiKey:     apiKey,
		site:       site,
		httpClient: client,
		service:    "vecta-kms",
		source:     "kms-audit",
	}
}

func (d *DatadogExporter) Name() string { return "datadog" }

// datadogLogEntry represents a single log entry in the Datadog Logs API format.
type datadogLogEntry struct {
	Ddsource string            `json:"ddsource"`
	Ddtags   string            `json:"ddtags"`
	Hostname string            `json:"hostname"`
	Message  string            `json:"message"`
	Service  string            `json:"service"`
	Status   string            `json:"status"`
	Attrs    map[string]string `json:"attributes,omitempty"`
}

// Send posts events to the Datadog Logs HTTP intake endpoint.
func (d *DatadogExporter) Send(ctx context.Context, events []AuditEvent) error {
	if len(events) == 0 {
		return nil
	}

	entries := make([]datadogLogEntry, 0, len(events))
	for _, evt := range events {
		status := "info"
		switch {
		case evt.Severity >= 8:
			status = "critical"
		case evt.Severity >= 6:
			status = "error"
		case evt.Severity >= 4:
			status = "warning"
		}

		msg, _ := json.Marshal(evt)

		entry := datadogLogEntry{
			Ddsource: d.source,
			Ddtags:   fmt.Sprintf("tenant:%s,key:%s,action:%s", evt.TenantID, evt.KeyID, evt.Action),
			Hostname: "vecta-kms",
			Message:  string(msg),
			Service:  d.service,
			Status:   status,
			Attrs: map[string]string{
				"tenant_id": evt.TenantID,
				"key_id":    evt.KeyID,
				"actor":     evt.Actor,
				"action":    evt.Action,
				"outcome":   evt.Outcome,
			},
		}
		entries = append(entries, entry)
	}

	body, err := json.Marshal(entries)
	if err != nil {
		return fmt.Errorf("datadog: marshal: %w", err)
	}

	url := fmt.Sprintf("https://http-intake.logs.%s/api/v2/logs", d.site)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("datadog: create request: %w", err)
	}
	req.Header.Set("DD-API-KEY", d.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("datadog: post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("datadog: unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}
