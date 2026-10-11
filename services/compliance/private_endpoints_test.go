package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route"
)

var (
	rootAdmin = &pkgauth.Claims{UserID: "u-root", TenantID: "root", Role: "admin", Permissions: []string{"*"}}
	// A root-tenant operator with playbook rights but not the approval.
	rootOperator = &pkgauth.Claims{UserID: "u-ops", TenantID: "root", Permissions: []string{"compliance.playbook.read", "compliance.playbook.write", "kms.write"}}
)

func TestNormalizePrivateRange(t *testing.T) {
	for in, want := range map[string]string{
		"10.4.0.20":       "10.4.0.20/32",
		" 10.4.0.77/24 ":  "10.4.0.0/24",
		"172.20.0.0/16":   "172.20.0.0/16",
		"192.168.10.0/24": "192.168.10.0/24",
		"100.64.3.0/24":   "100.64.3.0/24",
		"fd12:3456::/48":  "fd12:3456::/48",
		"fd12:3456::9":    "fd12:3456::9/128",
	} {
		if got, err := normalizePrivateRange(in); err != nil || got.String() != want {
			t.Errorf("%q = %v, %v; want %s", in, got, err, want)
		}
	}
	for _, in := range []string{
		"", "minio.corp.example", "10.0.0.0/8", "10.4.0.0/15", "0.0.0.0/0", // not a range, or too wide
		"8.8.8.8", "93.184.216.0/24", // public: needs no approval
		"127.0.0.1", "169.254.169.254", "169.254.0.0/16", "::1", "fe80::1", "224.0.0.1", // never approvable
		"172.32.0.0/16", "192.169.0.0/24", "fc00::/7", "::ffff:10.4.0.20",
	} {
		if got, err := normalizePrivateRange(in); err == nil {
			t.Errorf("%q approved as %v", in, got)
		}
	}
}

// Only a root administrator approves or withdraws a range; every refusal
// is audited; a tenant sees the ranges approved for it and no one else's.
func TestPrivateEndpointRoutes(t *testing.T) {
	hs := newPlaybookHarness(t)
	add := func(who *pkgauth.Claims, body map[string]any) *httptest.ResponseRecorder {
		tenant := "t1"
		if who.TenantID == "root" {
			tenant = "root"
		}
		body["tenant_id"] = tenant
		return hs.do(t, http.MethodPost, "/compliance/private-endpoints?tenant_id="+tenant, who, body)
	}
	// A tenant's own administrator can't widen where its credentials go.
	if w := add(pbAdmin, map[string]any{"for_tenant": "t1", "cidr": "10.4.0.0/24"}); w.Code != http.StatusForbidden {
		t.Fatalf("tenant admin approved a range: %d %s", w.Code, w.Body.String())
	}
	wantRefused(t, lastEvent(t, hs.rec, "private_endpoint_added"), reasonPlatformTenant)
	// Nor a root-tenant operator without the approval permission, nor a service.
	if w := add(rootOperator, map[string]any{"for_tenant": "t1", "cidr": "10.4.0.0/24"}); w.Code != http.StatusForbidden {
		t.Fatalf("root operator approved a range: %d %s", w.Code, w.Body.String())
	}
	wantRefused(t, lastEvent(t, hs.rec, "private_endpoint_added"), route.ReasonPermissionDenied)
	svc := svcClaims("kms-discovery")
	if w := hs.do(t, http.MethodPost, "/compliance/private-endpoints?tenant_id=t1", svc, map[string]any{"tenant_id": "t1", "for_tenant": "t1", "cidr": "10.4.0.0/24"}); w.Code != http.StatusForbidden {
		t.Fatalf("a service approved a range: %d %s", w.Code, w.Body.String())
	}
	wantRefused(t, lastEvent(t, hs.rec, "private_endpoint_added"), reasonPlatformTenant)

	for cidr, why := range map[string]string{"8.8.8.8": "public", "127.0.0.1": "loopback", "169.254.169.254": "metadata", "10.0.0.0/8": "too wide", "minio.corp": "a name"} {
		if w := add(rootAdmin, map[string]any{"for_tenant": "t1", "cidr": cidr}); w.Code != http.StatusBadRequest {
			t.Fatalf("%s (%s): %d %s", cidr, why, w.Code, w.Body.String())
		}
		wantRefused(t, lastEvent(t, hs.rec, "private_endpoint_added"), reasonInvalidPrivateEndpoint)
	}
	if w := add(rootAdmin, map[string]any{"cidr": "10.4.0.0/24"}); w.Code != http.StatusBadRequest {
		t.Fatalf("no tenant named: %d", w.Code)
	}

	w := add(rootAdmin, map[string]any{"for_tenant": "t1", "cidr": "10.4.0.77/24", "note": "MinIO, data centre A"})
	var created struct{ Data PrivateEndpoint }
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	if w.Code != http.StatusCreated || created.Data.CIDR != "10.4.0.0/24" || created.Data.TenantID != "t1" || created.Data.CreatedBy != "u-root" {
		t.Fatalf("approve: %d %s", w.Code, w.Body.String())
	}
	if ev := lastEvent(t, hs.rec, "private_endpoint_added"); ev.Event.Result != route.ResultSuccess || ev.Event.Details["for_tenant"] != "t1" || ev.Event.Details["cidr"] != "10.4.0.0/24" {
		t.Fatalf("approval audited as %+v", ev.Event)
	}
	if w := add(rootAdmin, map[string]any{"for_tenant": "t1", "cidr": "10.4.0.0/24"}); w.Code != http.StatusConflict {
		t.Fatalf("duplicate: %d", w.Code)
	}
	wantRefused(t, lastEvent(t, hs.rec, "private_endpoint_added"), "private_endpoint_exists")
	if w := add(rootAdmin, map[string]any{"for_tenant": "t2", "cidr": "192.168.7.0/24"}); w.Code != http.StatusCreated {
		t.Fatalf("approve for t2: %d", w.Code)
	}

	list := func(who *pkgauth.Claims) (string, bool) {
		w := hs.do(t, http.MethodGet, "/compliance/private-endpoints?tenant_id="+who.TenantID, who, nil)
		var out struct {
			Data       []PrivateEndpoint
			CanApprove bool `json:"can_approve"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		var cidrs []string
		for _, e := range out.Data {
			cidrs = append(cidrs, e.TenantID+"="+e.CIDR)
		}
		return strings.Join(cidrs, ","), out.CanApprove
	}
	if got, can := list(pbAdmin); got != "t1=10.4.0.0/24" || can {
		t.Fatalf("t1 sees %q (can approve %v)", got, can)
	}
	if got, can := list(rootAdmin); got != "t1=10.4.0.0/24,t2=192.168.7.0/24" || !can {
		t.Fatalf("root sees %q (can approve %v)", got, can)
	}
	if _, can := list(rootOperator); can {
		t.Fatal("a root operator is told it can approve")
	}

	del := "/compliance/private-endpoints/" + created.Data.ID
	if w := hs.do(t, http.MethodDelete, del+"?tenant_id=t1", pbAdmin, nil); w.Code != http.StatusForbidden {
		t.Fatalf("tenant admin withdrew an approval: %d", w.Code)
	}
	wantRefused(t, lastEvent(t, hs.rec, "private_endpoint_removed"), reasonPlatformTenant)
	if w := hs.do(t, http.MethodDelete, del+"?tenant_id=root", rootAdmin, nil); w.Code != http.StatusOK {
		t.Fatalf("withdraw: %d %s", w.Code, w.Body.String())
	}
	if ev := lastEvent(t, hs.rec, "private_endpoint_removed"); ev.Event.Result != route.ResultSuccess || ev.Event.Details["cidr"] != "10.4.0.0/24" || ev.Event.Details["for_tenant"] != "t1" {
		t.Fatalf("withdrawal audited as %+v", ev.Event)
	}
	if w := hs.do(t, http.MethodDelete, del+"?tenant_id=root", rootAdmin, nil); w.Code != http.StatusNotFound {
		t.Fatalf("second withdrawal: %d", w.Code)
	}
}

// A source connection may name a private address only inside a range
// approved for its tenant; notification connections never; and discovery
// is handed the tenant's ranges with the opened connection.
func TestSourceConnectionOnAnApprovedPrivateAddress(t *testing.T) {
	hs := newPlaybookHarness(t)
	old := lookupHost
	defer func() { lookupHost = old }()
	lookupHost = func(_ context.Context, host string) ([]netip.Addr, error) {
		switch host {
		case "minio.corp.example":
			return []netip.Addr{netip.MustParseAddr("10.4.0.20")}, nil
		case "split.corp.example": // one address inside the range, one outside
			return []netip.Addr{netip.MustParseAddr("10.4.0.21"), netip.MustParseAddr("10.9.9.9")}, nil
		}
		return nil, errors.New("no such host")
	}
	create := func(who *pkgauth.Claims, typ string, fields map[string]string) *httptest.ResponseRecorder {
		return hs.do(t, http.MethodPost, "/compliance/playbooks/connections?tenant_id="+who.TenantID, who, map[string]any{"name": typ, "type": typ, "fields": fields})
	}
	s3 := func(url string) map[string]string {
		return map[string]string{"endpoint_url": url, "access_key_id": "AKIDEXAMPLE", "secret_access_key": "long-enough-secret"}
	}
	git := map[string]string{"git_url": "https://10.4.0.30", "token": "glpat-private"}

	// Before any approval: refused, and told how it can be allowed.
	w := create(pbAdmin, "s3", s3("https://10.4.0.20:9000"))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "root administrator can approve") {
		t.Fatalf("private s3 endpoint before approval: %d %s", w.Code, w.Body.String())
	}
	wantRefused(t, lastEvent(t, hs.rec, "connection_created"), reasonURLBlocked)

	if w := hs.do(t, http.MethodPost, "/compliance/private-endpoints?tenant_id=root", rootAdmin, map[string]any{"tenant_id": "root", "for_tenant": "t1", "cidr": "10.4.0.0/24"}); w.Code != http.StatusCreated {
		t.Fatalf("approve: %d %s", w.Code, w.Body.String())
	}
	ids := map[string]string{}
	for name, fields := range map[string]map[string]string{"by address": s3("https://10.4.0.20:9000"), "by name": s3("https://minio.corp.example"), "git": git} {
		typ := "s3"
		if name == "git" {
			typ = "git"
		}
		w := create(pbAdmin, typ, fields)
		var out struct{ Data Connection }
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		if w.Code != http.StatusCreated || strings.Contains(w.Body.String(), "long-enough-secret") || strings.Contains(w.Body.String(), "glpat-private") {
			t.Fatalf("%s after approval: %d %s", name, w.Code, w.Body.String())
		}
		if ev := lastEvent(t, hs.rec, "connection_created"); ev.Event.Details["private_endpoint"] != true {
			t.Fatalf("%s: the audit event does not say the endpoint is private: %+v", name, ev.Event.Details)
		}
		ids[name] = out.Data.ID
	}
	for name, w := range map[string]*httptest.ResponseRecorder{
		"outside the range":              create(pbAdmin, "s3", s3("https://10.4.1.20")),
		"a name with an address outside": create(pbAdmin, "s3", s3("https://split.corp.example")),
		"another tenant":                 create(&pkgauth.Claims{UserID: "u2", TenantID: "t2", Permissions: []string{"*"}}, "s3", s3("https://10.4.0.20")),
		"loopback":                       create(pbAdmin, "s3", s3("https://127.0.0.1")),
		"metadata":                       create(pbAdmin, "s3", s3("https://169.254.169.254")),
		"a platform service":             create(pbAdmin, "s3", s3("https://keycore:8010")),
		"not https":                      create(pbAdmin, "s3", s3("http://10.4.0.20")),
		// Notification types follow the same approval
		// (TestNotifyTicketingAndSIEMOnAnApprovedPrivateRange): outside it, refused.
		"a webhook": create(pbAdmin, "webhook", map[string]string{"url": "https://10.4.1.20/hook"}),
		"slack":     create(pbAdmin, "slack", map[string]string{"webhook_url": "https://10.9.9.9/x"}),
	} {
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d %s", name, w.Code, w.Body.String())
		}
	}

	// Discovery gets the tenant's approved ranges with the connection.
	resolve := func(id string) (int, resolvedConnection) {
		w := hs.do(t, http.MethodPost, "/compliance/connections/"+id+"/resolve?tenant_id=t1", svcClaims("kms-discovery"), map[string]any{})
		var out struct{ Data resolvedConnection }
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out.Data
	}
	if code, c := resolve(ids["by address"]); code != http.StatusOK || strings.Join(c.PrivateRanges, ",") != "10.4.0.0/24" || c.Fields["secret_access_key"] != "long-enough-secret" {
		t.Fatalf("resolve: %d %+v", code, c.PrivateRanges)
	}
	if ev := lastEvent(t, hs.rec, "connection_resolved"); ev.Event.Details["private_ranges"] != 1 {
		t.Fatalf("resolve audit %+v", ev.Event.Details)
	}
	// Withdrawn: the connection stays, and discovery is told nothing is approved.
	list, _ := hs.store.ListPrivateEndpoints(context.Background(), "t1")
	if w := hs.do(t, http.MethodDelete, "/compliance/private-endpoints/"+list[0].ID+"?tenant_id=root", rootAdmin, nil); w.Code != http.StatusOK {
		t.Fatalf("withdraw: %d", w.Code)
	}
	if code, c := resolve(ids["git"]); code != http.StatusOK || c.PrivateRanges == nil || len(c.PrivateRanges) != 0 {
		t.Fatalf("resolve after withdrawal: %d %+v", code, c.PrivateRanges)
	}
	// A stream connection carries no ranges.
	slack := hs.conn(t, "slack", map[string]string{"webhook_url": "https://1.1.1.1/x"})
	w = hs.do(t, http.MethodPost, "/compliance/connections/"+slack+"/resolve?tenant_id=t1", svcClaims("kms-audit"), map[string]any{})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"private_ranges":[]`) {
		t.Fatalf("slack resolve: %d %s", w.Code, w.Body.String())
	}
}
