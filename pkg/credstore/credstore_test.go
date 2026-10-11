package credstore

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
)

func TestClientMapsTheStoresAnswers(t *testing.T) {
	var gotPath, gotTenant string
	var gotBody map[string]interface{}
	status, body := http.StatusOK, `{"data":{"id":"pbconn_1","type":"aws","fields":{"secret_access_key":"s3cr3t"},"private_ranges":["10.2.0.0/16"]}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotTenant = r.URL.RequestURI(), r.Header.Get("X-Tenant-ID")
		gotBody = nil
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	c, ctx := New(srv.URL+"/"), context.Background()

	cred, err := c.Resolve(ctx, "t1", "pbconn_1")
	if err != nil || cred.Fields["secret_access_key"] != "s3cr3t" || cred.PrivateRanges[0] != "10.2.0.0/16" {
		t.Fatalf("resolve: %v %+v", err, cred)
	}
	if gotPath != "/compliance/connections/pbconn_1/resolve?tenant_id=t1" || gotTenant != "t1" {
		t.Fatalf("resolve request: %s (%s)", gotPath, gotTenant)
	}
	if err := c.ReportTest(ctx, "t1", "pbconn_1", errors.New("AccessDenied")); err != nil || gotBody["ok"] != false || gotBody["error"] != "AccessDenied" {
		t.Fatalf("report: %v %v", err, gotBody)
	}
	if id, err := c.Import(ctx, "t1", "ca_1", "prod (migrated)", "aws", map[string]string{"access_key_id": "A"}, true); err != nil || id != "pbconn_1" || gotBody["exposed"] != true || gotBody["source_id"] != "ca_1" {
		t.Fatalf("import: %v %q %v", err, id, gotBody)
	}

	status, body = http.StatusNotFound, `{"error":{"code":"not_found"}}`
	if _, err := c.Resolve(ctx, "t1", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("404: %v", err)
	}
	status, body = http.StatusConflict, `{"error":{"code":"connection_use_unsupported","message":"a pkcs11_hsm connection can't be used for cloud_account"}}`
	if _, err := c.Resolve(ctx, "t1", "x"); !errors.Is(err, ErrWrongType) {
		t.Fatalf("wrong type: %v", err)
	}
	status, body = http.StatusServiceUnavailable, `{"error":{"code":"connections_unavailable","message":"master key not open"}}`
	if _, err := c.Resolve(ctx, "t1", "x"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("503: %v", err)
	}
	// An unreachable store never puts the URL (or anything else) in the error.
	srv.Close()
	if _, err := c.Resolve(ctx, "t1", "pbconn_secret_id"); !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "pbconn_secret_id") {
		t.Fatalf("unreachable: %v", err)
	}
	// A deployment without the store says so; it doesn't pretend to be down.
	var none *Client
	if _, err := none.Resolve(ctx, "t1", "x"); !errors.Is(err, ErrNotDeployed) {
		t.Fatalf("nil client: %v", err)
	}
}

func TestMayAttachNeedsTheUsePermission(t *testing.T) {
	with := func(c *pkgauth.Claims) context.Context { return pkgauth.ContextWithClaims(context.Background(), c) }
	if MayAttach(context.Background()) {
		t.Fatal("an unauthenticated caller may attach")
	}
	if MayAttach(with(&pkgauth.Claims{UserID: "u", TenantID: "t1", Permissions: []string{"cloud.write", "compliance.playbook.write"}})) {
		t.Fatal("managing playbooks is not the use permission")
	}
	for _, perms := range [][]string{{PermissionUse}, {"compliance.*"}, {"*"}} {
		if !MayAttach(with(&pkgauth.Claims{UserID: "u", TenantID: "t1", Permissions: perms})) {
			t.Fatalf("%v may not attach", perms)
		}
	}
}
