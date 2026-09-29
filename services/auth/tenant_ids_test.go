package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"vecta-kms/pkg/route/routetest"
)

func TestTenantIDsRoutesRefusalsAudited(t *testing.T) {
	d := newDelegatedHarness(t)
	routetest.RefusalsAudited(t, d.h.tenantIDsRouter(), d.rec)
}

// Only the reporting service identity lists tenant IDs; another platform
// service is refused and audited.
func TestTenantIDsOnlyForReporting(t *testing.T) {
	d := newDelegatedHarness(t)
	if err := d.store.CreateTenant(context.Background(), Tenant{ID: "t9", Name: "t9", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	get := func(client string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/internal/tenant-ids", nil)
		req.Header.Set("Authorization", "Bearer "+d.token(t, client))
		w := httptest.NewRecorder()
		d.h.ServeHTTP(w, req)
		return w
	}
	if w := get("kms-posture"); w.Code != http.StatusForbidden {
		t.Fatalf("other service: %d", w.Code)
	}
	wantAuthRefusal(t, d.last(t), "tenant_ids_listed", reasonServiceIdentityRequired)
	w := get(tenantIDsCaller)
	var out struct{ Items []string }
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	found := false
	for _, id := range out.Items {
		found = found || id == "t9"
	}
	if w.Code != http.StatusOK || !found {
		t.Fatalf("reporting: %d %s", w.Code, w.Body)
	}
	if e := d.last(t); e.Action != "tenant_ids_listed" || e.Event.Result != "success" {
		t.Fatalf("event %+v", e)
	}
}
