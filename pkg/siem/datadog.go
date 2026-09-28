package siem

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type datadog struct {
	url, apiKey string
	client      *http.Client
}

// Send posts the batch to the Logs intake (…/api/v2/logs). The message is
// the full event; tags carry tenant, action and result for faceting.
func (d *datadog) Send(ctx context.Context, events []Event) (int, error) {
	entries := make([]map[string]any, 0, len(events))
	for _, e := range events {
		msg, err := json.Marshal(e.record())
		if err != nil {
			return 0, err
		}
		entries = append(entries, map[string]any{
			"ddsource": "vecta-kms", "service": e.Service, "hostname": e.NodeID, "status": ddStatus(e.Severity, e.Result),
			"ddtags":  fmt.Sprintf("tenant:%s,action:%s,result:%s", e.TenantID, e.Action, e.Result),
			"message": string(msg),
		})
	}
	body, err := json.Marshal(entries)
	if err != nil {
		return 0, err
	}
	status, _, err := post(ctx, d.client, d.url, "application/json", body, map[string]string{"DD-API-KEY": d.apiKey})
	return status, err
}

func ddStatus(severity, result string) string {
	switch cefSeverity(severity, result) {
	case 10:
		return "critical"
	case 8:
		return "error"
	case 5:
		return "warning"
	}
	return "info"
}
