package main

import (
	"net/http"
	"strings"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
)

func TestKeyOpsRoutesRefusalsAudited(t *testing.T) {
	h, _, _ := newActorTestHandler(t)
	rec := &routetest.Recorder{}
	routetest.RefusalsAudited(t, h.keyOpsRouter(rec), rec)
}

// Before 4.0.0-beta any verified token could report a compromise (which
// suspends the key) or rotate any key through an orchestration run.
func TestKeyOpsNeedTheirPermission(t *testing.T) {
	h, svc, _ := newActorTestHandler(t)
	rec := &routetest.Recorder{}
	h.kernelAudit = rec
	key := ownedKey(t, svc)
	readonly := &pkgauth.Claims{UserID: "ro-user", TenantID: "t1", Role: "readonly", Permissions: []string{"auth.self.read"}}
	calls := []struct{ path, body string }{
		{"/compromise/events", `{"key_id":"` + key.ID + `","severity":"critical","status":"open"}`},
		{"/enterprise/orchestration/runs", `{"key_ids":["` + key.ID + `"],"execute_rotation":true}`},
		{"/ceremony", `{}`},
		{"/keys/" + key.ID + "/attest", `{}`},
		{"/keys/" + key.ID + "/destruction-check", ``},
	}
	for _, c := range calls {
		rec.Reset()
		if w := callKeycore(h, http.MethodPost, c.path, c.body, readonly); w.Code != http.StatusForbidden {
			t.Fatalf("POST %s as readonly: %d %s", c.path, w.Code, w.Body)
		}
		if ev := rec.Last(t); ev.Event.Result != route.ResultRefused || ev.Event.Details["reason"] != route.ReasonPermissionDenied {
			t.Fatalf("POST %s audited as %s %+v", c.path, ev.Action, ev.Event.Details)
		}
	}
	got, _ := svc.GetKey(t.Context(), "t1", key.ID)
	if got.CurrentVersion != key.CurrentVersion || !strings.EqualFold(got.Status, key.Status) {
		t.Fatalf("refused calls changed the key: %+v", got)
	}
}

// The fingerprint check returns the key's actual KCV, so it answers for a
// hidden key exactly as for a missing one.
func TestFingerprintCheckRespectsVisibility(t *testing.T) {
	h, svc, _ := newActorTestHandler(t)
	keys := visibilityFixture(t, svc)
	alice := &pkgauth.Claims{UserID: "alice", TenantID: "t1", Role: "operator", Permissions: []string{"key.enterprise.write"}}
	hidden := callKeycore(h, http.MethodPost, "/enterprise/verification/fingerprint", `{"key_id":"`+keys["k2"].ID+`","fingerprint":"00"}`, alice)
	missing := callKeycore(h, http.MethodPost, "/enterprise/verification/fingerprint", `{"key_id":"key_does_not_exist","fingerprint":"00"}`, alice)
	if hidden.Code != missing.Code || errCode(hidden) != errCode(missing) || strings.Contains(hidden.Body.String(), "actual_kcv") {
		t.Fatalf("hidden %d %s vs missing %d %s", hidden.Code, hidden.Body, missing.Code, missing.Body)
	}
	own := callKeycore(h, http.MethodPost, "/enterprise/verification/fingerprint", `{"key_id":"`+keys["k1"].ID+`","fingerprint":"00"}`, alice)
	if own.Code != http.StatusOK {
		t.Fatalf("own key: %d %s", own.Code, own.Body)
	}
}
