package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	neturl "net/url"
)

// splunk sends to the HTTP Event Collector. Several events go in one
// request as concatenated JSON objects, which HEC accepts.
type splunk struct {
	url, token, index, sourcetype string
	client                        *http.Client
}

// newSplunk takes the collector URL as given; a bare host (no path) gets
// the standard /services/collector/event endpoint.
func newSplunk(u *neturl.URL, f map[string]string, client *http.Client) *splunk {
	if u.Path == "" || u.Path == "/" {
		u.Path = "/services/collector/event"
	}
	st := f["sourcetype"]
	if st == "" {
		st = "vecta:audit" // what audit streams have always sent
	}
	return &splunk{url: u.String(), token: f["token"], index: f["index"], sourcetype: st, client: client}
}

func (s *splunk) Send(ctx context.Context, events []Event) (int, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, e := range events {
		p := map[string]any{
			"time": float64(e.Timestamp.UnixMilli()) / 1000, "host": e.NodeID, "source": "vecta-kms",
			"sourcetype": s.sourcetype, "event": e.record(),
		}
		if s.index != "" {
			p["index"] = s.index
		}
		if err := enc.Encode(p); err != nil {
			return 0, err
		}
	}
	status, _, err := post(ctx, s.client, s.url, "application/json", buf.Bytes(), map[string]string{"Authorization": "Splunk " + s.token})
	return status, err
}
