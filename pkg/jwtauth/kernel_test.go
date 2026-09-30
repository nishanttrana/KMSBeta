package jwtauth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
)

// A request without a valid token is refused by the kernel and audited under
// the route's own action, on Public routes too for a bad token; before
// 7.10.0-beta the middleware answered 401 and no specific event was emitted.
func TestKernelWrapperAuditsTokenRefusals(t *testing.T) {
	rec := &routetest.Recorder{}
	rt := route.New("probe", rec, nil)
	rt.Handle("GET /things", route.Spec{Action: "things_list", Permission: "probe.read"}, func(c *route.Call) { c.JSON(http.StatusOK, nil) })
	rt.Handle("POST /exchange", route.Spec{Action: "exchange", Public: true, Tenancy: route.PlatformScoped}, func(c *route.Call) { c.JSON(http.StatusOK, nil) })
	parser := func(raw string) (*pkgauth.Claims, error) {
		if raw == "good" {
			return &pkgauth.Claims{UserID: "u", TenantID: "t1", Permissions: []string{"probe.read"}}, nil
		}
		return nil, errors.New("bad signature")
	}
	h := wrapKernel(parser, rt)
	for _, c := range []struct {
		method, path, auth string
		status             int
		action, reason     string
	}{
		{http.MethodGet, "/things", "", http.StatusUnauthorized, "things_list", route.ReasonUnauthenticated},
		{http.MethodGet, "/things", "Bearer forged", http.StatusUnauthorized, "things_list", route.ReasonInvalidToken},
		{http.MethodPost, "/exchange", "Bearer forged", http.StatusUnauthorized, "exchange", route.ReasonInvalidToken},
		{http.MethodGet, "/things", "Bearer good", http.StatusOK, "things_list", ""},
	} {
		rec.Reset()
		req := httptest.NewRequest(c.method, c.path, nil)
		if c.auth != "" {
			req.Header.Set("Authorization", c.auth)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != c.status {
			t.Fatalf("%s %s %q: status %d, want %d", c.method, c.path, c.auth, rr.Code, c.status)
		}
		ev := rec.Last(t)
		if ev.Action != c.action || (c.reason != "" && (ev.Event.Result != route.ResultRefused || ev.Event.Details["reason"] != c.reason)) {
			t.Fatalf("%s %s %q: audited %s %s %+v", c.method, c.path, c.auth, ev.Action, ev.Event.Result, ev.Event.Details)
		}
	}
}
