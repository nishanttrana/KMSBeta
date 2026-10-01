package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
)

func TestDiscoveryRoutesRefusalsAudited(t *testing.T) {
	svc, _, _ := newDiscoveryService(t)
	rec := &routetest.Recorder{}
	routetest.RefusalsAudited(t, NewHandler(svc, rec, nil).router, rec)
}

func serveAs(h http.Handler, claims *pkgauth.Claims, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims)))
	return rr
}

// Before 7.9.0-beta discovery verified no token: a scan or a classification
// ran for whatever tenant the body named.
func TestDiscoveryWritesNeedPermissionAndOwnTenant(t *testing.T) {
	svc, _, _ := newDiscoveryService(t)
	rec := &routetest.Recorder{}
	h := NewHandler(svc, rec, nil)

	readonly := &pkgauth.Claims{UserID: "ro", TenantID: "t1", Permissions: []string{"discovery.read"}}
	for _, c := range []struct{ method, path, body string }{
		{http.MethodPost, "/discovery/scan", `{"tenant_id":"t1","scan_types":["certs"]}`},
		{http.MethodPut, "/discovery/assets/a1/classify", `{"tenant_id":"t1","status":"reviewed"}`},
	} {
		rec.Reset()
		if rr := serveAs(h, readonly, c.method, c.path, c.body); rr.Code != http.StatusForbidden {
			t.Fatalf("%s %s as discovery.read: %d %s", c.method, c.path, rr.Code, rr.Body)
		}
		if ev := rec.Last(t); ev.Action != map[string]string{http.MethodPost: "scan_start", http.MethodPut: "asset_review"}[c.method] ||
			ev.Event.Result != route.ResultRefused || ev.Event.Details["reason"] != route.ReasonPermissionDenied {
			t.Fatalf("%s %s audited as %s %+v", c.method, c.path, ev.Action, ev.Event.Details)
		}
	}

	writer := &pkgauth.Claims{UserID: "w", TenantID: "t1", Permissions: []string{"discovery.write"}}
	rec.Reset()
	if rr := serveAs(h, writer, http.MethodPost, "/discovery/scan", `{"tenant_id":"t2","scan_types":["certs"]}`); rr.Code != http.StatusForbidden {
		t.Fatalf("scan for another tenant: %d %s", rr.Code, rr.Body)
	}
	if ev := rec.Last(t); ev.Event.Result != route.ResultRefused || ev.Event.Details["reason"] != route.ReasonTenantMismatch {
		t.Fatalf("cross-tenant scan audited as %+v", ev.Event.Details)
	}
	if scans, _ := svc.ListScans(context.Background(), "t2", 10, 0); len(scans) != 0 {
		t.Fatalf("a refused scan ran for t2: %+v", scans)
	}
}

// A classification is a catalogue fact; relabelling it is refused and audited.
func TestDiscoveryRelabelRefusedAndAudited(t *testing.T) {
	svc, _, _ := newDiscoveryService(t)
	ctx := context.Background()
	scan, err := svc.StartScan(ctx, ScanRequest{TenantID: "t1", ScanTypes: []string{"certs"}})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	finishScan(t, svc, scan)
	assets, err := svc.ListAssets(ctx, "t1", 10, 0, "", "", "quantum_vulnerable")
	if err != nil || len(assets) == 0 {
		t.Fatalf("no quantum-vulnerable asset to relabel: %v", err)
	}
	rec := &routetest.Recorder{}
	h := NewHandler(svc, rec, nil)
	writer := &pkgauth.Claims{UserID: "w", TenantID: "t1", Permissions: []string{"discovery.write"}}
	rr := serveAs(h, writer, http.MethodPut, "/discovery/assets/"+assets[0].ID+"/classify", `{"classification":"strong"}`)
	if rr.Code != http.StatusConflict {
		t.Fatalf("relabel: %d %s", rr.Code, rr.Body)
	}
	if ev := rec.Last(t); ev.Action != "asset_review" || ev.Event.Result != route.ResultRefused || ev.Event.Details["reason"] != "classification_is_catalogue" {
		t.Fatalf("relabel audited as %s %+v", ev.Action, ev.Event.Details)
	}
	if got, _ := svc.GetAsset(ctx, "t1", assets[0].ID); got.Classification != "quantum_vulnerable" {
		t.Fatalf("classification changed to %q", got.Classification)
	}
}
