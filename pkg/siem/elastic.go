package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	neturl "net/url"
	"strings"
)

// elastic indexes events with the Bulk API. The event ID is the document
// ID, so a redelivered event overwrites itself instead of duplicating.
type elastic struct {
	url, apiKey, index string
	client             *http.Client
}

func newElastic(u *neturl.URL, f map[string]string, client *http.Client) *elastic {
	u.Path = strings.TrimRight(u.Path, "/") + "/_bulk"
	idx := f["index"]
	if idx == "" {
		idx = "vecta-kms-audit"
	}
	return &elastic{url: u.String(), apiKey: f["api_key"], index: idx, client: client}
}

// Send posts the batch. Bulk answers 200 even when documents are rejected,
// so the answer's errors flag is checked: a rejected document is a failure.
func (e *elastic) Send(ctx context.Context, events []Event) (int, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, ev := range events {
		if err := enc.Encode(map[string]any{"index": map[string]string{"_index": e.index, "_id": ev.ID}}); err != nil {
			return 0, err
		}
		if err := enc.Encode(ev.record()); err != nil {
			return 0, err
		}
	}
	status, raw, err := post(ctx, e.client, e.url, "application/x-ndjson", buf.Bytes(), map[string]string{"Authorization": "ApiKey " + e.apiKey})
	if err != nil {
		return status, err
	}
	var ans struct {
		Errors bool `json:"errors"`
		Items  []map[string]struct {
			Status int `json:"status"`
			Error  struct {
				Type string `json:"type"`
			} `json:"error"`
		} `json:"items"`
	}
	if json.Unmarshal(raw, &ans) != nil {
		return status, fmt.Errorf("elasticsearch: unreadable bulk answer")
	}
	if ans.Errors {
		for _, item := range ans.Items {
			for _, r := range item {
				if r.Status >= 300 {
					return status, fmt.Errorf("elasticsearch rejected a document: HTTP %d %s", r.Status, r.Error.Type)
				}
			}
		}
		return status, fmt.Errorf("elasticsearch rejected a document")
	}
	return status, nil
}
