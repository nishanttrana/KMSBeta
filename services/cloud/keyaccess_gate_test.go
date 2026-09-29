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

func newCloudBindingForGate(t *testing.T) (*Service, *nopCloudPublisher, CloudAccount, CloudKeyBinding) {
	t.Helper()
	svc, _, keycore, pub := newCloudService(t)
	ctx := context.Background()
	keycore.Seed("tenant-ka", "key-ka", "AES-256")
	account, err := svc.RegisterAccount(ctx, RegisterCloudAccountRequest{
		TenantID: "tenant-ka", Provider: ProviderAWS, Name: "aws-ka", DefaultRegion: "us-east-1",
		CredentialsJSON: `{"access_key":"abc","secret":"xyz"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := svc.ImportKeyToCloud(ctx, ImportKeyToCloudRequest{TenantID: "tenant-ka", KeyID: "key-ka", AccountID: account.ID})
	if err != nil {
		t.Fatal(err)
	}
	return svc, pub, account, binding
}

// Key access deployed but unreachable: import, rotate and sync are refused
// with 424 key_access_unavailable and audited as refused. Until 6.10.0-beta
// the error was turned into an allow.
func TestCloudKeyAccessUnavailableRefuses(t *testing.T) {
	svc, pub, account, binding := newCloudBindingForGate(t)
	ctx := context.Background()
	imported, rotated := pub.Count("audit.cloud.key_imported"), pub.Count("audit.cloud.key_rotated")
	svc.SetKeyAccess(unreachableKeyAccess(t))

	_, importErr := svc.ImportKeyToCloud(ctx, ImportKeyToCloudRequest{TenantID: "tenant-ka", KeyID: "key-ka", AccountID: account.ID})
	_, _, rotateErr := svc.RotateCloudKey(ctx, RotateCloudKeyRequest{TenantID: "tenant-ka", BindingID: binding.ID})
	_, syncErr := svc.SyncCloudKeys(ctx, SyncCloudKeysRequest{TenantID: "tenant-ka", Provider: ProviderAWS})
	for op, err := range map[string]error{"import": importErr, "rotate": rotateErr, "sync": syncErr} {
		if httpStatusForErr(err) != http.StatusFailedDependency || serviceCode(err, "") != pkgkeyaccess.ReasonUnavailable {
			t.Fatalf("%s: %v, want 424 key_access_unavailable", op, err)
		}
	}
	if n := pub.Count("audit.cloud.key_access_denied"); n != 3 {
		t.Fatalf("%d key_access_denied events, want 3", n)
	}
	ev := pub.Last("audit.cloud.key_access_denied")
	if ev["result"] != "refused" || ev["reason"] != pkgkeyaccess.ReasonUnavailable || ev["operation"] != "sync" {
		t.Fatalf("refusal event %+v", ev)
	}
	if pub.Count("audit.cloud.key_imported") != imported || pub.Count("audit.cloud.key_rotated") != rotated {
		t.Fatal("an operation ran while key access was unavailable")
	}
}

// Key access not deployed: the operation runs and records why no
// justification was checked.
func TestCloudKeyAccessNotDeployedAllows(t *testing.T) {
	_, pub, _, binding := newCloudBindingForGate(t)
	if binding.ID == "" {
		t.Fatal("import did not run")
	}
	ev := pub.Last("audit.cloud.key_imported")
	if ev["key_access_reason"] != pkgkeyaccess.ReasonNotDeployed {
		t.Fatalf("import event %+v, want key_access_reason %s", ev, pkgkeyaccess.ReasonNotDeployed)
	}
	if pub.Count("audit.cloud.key_access_denied") != 0 {
		t.Fatal("not-deployed allow audited as a refusal")
	}
}
