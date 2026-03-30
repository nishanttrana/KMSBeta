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

// SplunkHEC sends audit events to Splunk via the HTTP Event Collector.
type SplunkHEC struct {
	hecURL     string
	token      string
	index      string
	sourcetype string
	httpClient *http.Client
}

// NewSplunkHEC creates a Splunk HEC destination.
func NewSplunkHEC(hecURL, token, index, sourcetype string, client *http.Client) *SplunkHEC {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if sourcetype == "" {
		sourcetype = "vecta:kms:audit"
	}
	return &SplunkHEC{
		hecURL:     hecURL,
		token:      token,
		index:      index,
		sourcetype: sourcetype,
		httpClient: client,
	}
}

func (s *SplunkHEC) Name() string { return "splunk_hec" }

// splunkPayload is a single HEC event envelope.
type splunkPayload struct {
	Event      interface{} `json:"event"`
	Index      string      `json:"index,omitempty"`
	Sourcetype string      `json:"sourcetype,omitempty"`
	Time       float64     `json:"time"`
}

// Send posts events to Splunk HEC using newline-delimited JSON for batching.
func (s *SplunkHEC) Send(ctx context.Context, events []AuditEvent) error {
	if len(events) == 0 {
		return nil
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)

	for _, evt := range events {
		payload := splunkPayload{
			Event:      evt,
			Index:      s.index,
			Sourcetype: s.sourcetype,
			Time:       float64(evt.Timestamp.Unix()) + float64(evt.Timestamp.Nanosecond())/1e9,
		}
		if err := enc.Encode(payload); err != nil {
			return fmt.Errorf("splunk_hec: marshal event %s: %w", evt.ID, err)
		}
	}

	url := s.hecURL + "/services/collector/event"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &buf)
	if err != nil {
		return fmt.Errorf("splunk_hec: create request: %w", err)
	}
	req.Header.Set("Authorization", "Splunk "+s.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("splunk_hec: post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("splunk_hec: unexpected status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
