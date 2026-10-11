package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	pkgkeyaccess "vecta-kms/pkg/keyaccess"
)

func lastEventData(subjects []string, payloads [][]byte, subject string) map[string]interface{} {
	for i := len(subjects) - 1; i >= 0; i-- {
		if subjects[i] == subject {
			var ev struct {
				Data map[string]interface{} `json:"data"`
			}
			_ = json.Unmarshal(payloads[i], &ev)
			return ev.Data
		}
	}
	return nil
}

// unreachableKeyAccess is the real HTTP client pointed at a closed server.
func unreachableKeyAccess(t *testing.T) pkgkeyaccess.Gate {
	t.Helper()
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	return pkgkeyaccess.Deployed(pkgkeyaccess.NewHTTPClient(url, time.Second))
}

// Key access deployed but unreachable: a sync of cloud keys is refused with
// 424 key_access_unavailable and audited as refused (6.10.0-beta; before,
// the error was turned into an allow). BYOK operations: TestBYOKKeyAccessUnavailableRefuses.
func TestCloudSyncKeyAccessUnavailableRefuses(t *testing.T) {
	svc, _, _, pub := newCloudService(t)
	svc.SetKeyAccess(unreachableKeyAccess(t))
	_, err := svc.SyncCloudKeys(context.Background(), SyncCloudKeysRequest{TenantID: "tenant-ka", Provider: ProviderAWS})
	if httpStatusForErr(err) != http.StatusFailedDependency || serviceCode(err, "") != pkgkeyaccess.ReasonUnavailable {
		t.Fatalf("%v, want 424 key_access_unavailable", err)
	}
	if ev := pub.Last("audit.cloud.key_access_denied"); ev["result"] != "refused" || ev["reason"] != pkgkeyaccess.ReasonUnavailable || ev["operation"] != "sync" {
		t.Fatalf("refusal event %+v", ev)
	}
}
