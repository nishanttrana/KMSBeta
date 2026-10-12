package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/clientip"
)

type capturedEvents struct{ payloads [][]byte }

func (c *capturedEvents) Publish(_ context.Context, _ string, payload []byte) error {
	c.payloads = append(c.payloads, payload)
	return nil
}

// A backup event names the verified caller at the address the edge saw. It
// named whatever X-Actor said, at the edge proxy's own address (11.8.0-beta).
func TestBackupAuditNamesTheVerifiedCallerAndTheirAddress(t *testing.T) {
	events := &capturedEvents{}
	svc := NewBackupService(nil, events)
	req := httptest.NewRequest(http.MethodPost, "/backup/policies", nil)
	req.RemoteAddr = "172.18.0.9:41000"
	req.Header.Set("X-Actor", "ceo")
	req.Header.Set("X-Username", "ceo")
	req.Header.Set(clientip.Header, "203.0.113.9, 198.51.100.7")
	req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), &pkgauth.Claims{UserID: "usr_mallory", TenantID: "t1"}))
	svc.audit(req, "audit.backup.policy_created", "t1", map[string]interface{}{})
	if len(events.payloads) != 1 {
		t.Fatalf("events: %d", len(events.payloads))
	}
	var evt struct {
		Data map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(events.payloads[0], &evt); err != nil {
		t.Fatal(err)
	}
	if evt.Data["actor"] != "usr_mallory" || evt.Data["source_ip"] != "198.51.100.7" {
		t.Fatalf("the event must name the verified caller and the address the edge saw: %v", evt.Data)
	}
}
