package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"vecta-kms/pkg/route/routetest"
)

func TestSubjectsRoutesRefusalsAudited(t *testing.T) {
	d := newDelegatedHarness(t)
	routetest.RefusalsAudited(t, d.h.subjectsRouter(), d.rec)
}

// Only the secrets service may ask, and it learns whether a user, role or
// client exists in the tenant it names.
func TestSubjectsCheck(t *testing.T) {
	d := newDelegatedHarness(t)
	body := `{"tenant_id":"t1","subjects":[{"type":"user","id":"u-ops"},{"type":"user","id":"u-nobody"},
		{"type":"role","id":"ops"},{"type":"role","id":"tenant-admin"},{"type":"role","id":"no-such-role"},{"type":"client","id":"reg_missing"}]}`
	post := func(client, payload string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/internal/subjects/check", strings.NewReader(payload))
		req.Header.Set("Authorization", "Bearer "+d.token(t, client))
		w := httptest.NewRecorder()
		d.h.ServeHTTP(w, req)
		return w
	}
	if w := post("kms-posture", body); w.Code != http.StatusForbidden {
		t.Fatalf("other service: %d", w.Code)
	}
	wantAuthRefusal(t, d.last(t), "subjects_checked", reasonServiceIdentityRequired)

	w := post(subjectsCaller, body)
	if w.Code != http.StatusOK {
		t.Fatalf("secrets: %d %s", w.Code, w.Body)
	}
	got := w.Body.String()
	for _, want := range []string{
		`{"type":"user","id":"u-ops","exists":true,"label":"ops"}`,
		`{"type":"user","id":"u-nobody","exists":false}`,
		`{"type":"role","id":"ops","exists":true}`,
		`{"type":"role","id":"tenant-admin","exists":true}`, // held by a user, not a row in the role table
		`{"type":"role","id":"no-such-role","exists":false}`,
		`{"type":"client","id":"reg_missing","exists":false}`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %s in %s", want, got)
		}
	}
	if strings.Contains(got, "example.com") {
		t.Fatalf("the check returned more than existence and a name: %s", got)
	}
	if w := post(subjectsCaller, `{"tenant_id":"t1","subjects":[{"type":"group","id":"g"}]}`); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown type: %d", w.Code)
	}
	// Another tenant's user is not found in this one.
	if w := post(subjectsCaller, `{"tenant_id":"t2","subjects":[{"type":"user","id":"u-ops"}]}`); !strings.Contains(w.Body.String(), `"exists":false`) {
		t.Fatalf("cross-tenant: %s", w.Body)
	}
}
