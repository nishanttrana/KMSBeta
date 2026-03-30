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

// ElasticExporter sends audit events to Elasticsearch using the Bulk API.
type ElasticExporter struct {
	esURL      string
	apiKey     string
	index      string
	httpClient *http.Client
}

// NewElasticExporter creates an Elasticsearch destination.
func NewElasticExporter(esURL, apiKey, index string, client *http.Client) *ElasticExporter {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if index == "" {
		index = "vecta-kms-audit"
	}
	return &ElasticExporter{
		esURL:      esURL,
		apiKey:     apiKey,
		index:      index,
		httpClient: client,
	}
}

func (e *ElasticExporter) Name() string { return "elasticsearch" }

// bulkActionMeta is the action/metadata line in NDJSON bulk format.
type bulkActionMeta struct {
	Index bulkIndexMeta `json:"index"`
}

type bulkIndexMeta struct {
	Index string `json:"_index"`
	ID    string `json:"_id,omitempty"`
}

// Send posts events to Elasticsearch using the _bulk endpoint with NDJSON format.
func (e *ElasticExporter) Send(ctx context.Context, events []AuditEvent) error {
	if len(events) == 0 {
		return nil
	}

	var buf bytes.Buffer

	for _, evt := range events {
		// Action line
		meta := bulkActionMeta{
			Index: bulkIndexMeta{Index: e.index, ID: evt.ID},
		}
		metaJSON, err := json.Marshal(meta)
		if err != nil {
			return fmt.Errorf("elasticsearch: marshal meta: %w", err)
		}
		buf.Write(metaJSON)
		buf.WriteByte('\n')

		// Document line
		docJSON, err := json.Marshal(evt)
		if err != nil {
			return fmt.Errorf("elasticsearch: marshal event %s: %w", evt.ID, err)
		}
		buf.Write(docJSON)
		buf.WriteByte('\n')
	}

	url := fmt.Sprintf("%s/%s/_bulk", e.esURL, e.index)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &buf)
	if err != nil {
		return fmt.Errorf("elasticsearch: create request: %w", err)
	}
	req.Header.Set("Authorization", "ApiKey "+e.apiKey)
	req.Header.Set("Content-Type", "application/x-ndjson")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("elasticsearch: post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("elasticsearch: unexpected status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
