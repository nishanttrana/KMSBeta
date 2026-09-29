package jwtauth

import (
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
)

// Only a tokenless request to a Public route skips the JWT layer; a
// tokenless request anywhere else, and a bad token on a Public route, are
// refused before the handler runs.
func TestMustWrapRouterAdmitsOnlyPublicRoutesWithoutToken(t *testing.T) {
	t.Setenv("TEST_JWT_PUBLIC_KEY_PEM", makeTestKey(t))
	rt := route.New("demo", &routetest.Recorder{}, nil)
	rt.Handle("POST /open", route.Spec{Action: "open", Public: true, Tenancy: route.PlatformScoped}, func(c *route.Call) {
		c.JSON(http.StatusOK, nil)
	})
	rt.Handle("GET /closed", route.Spec{Action: "closed", Permission: route.Authenticated, Tenancy: route.PlatformScoped}, func(c *route.Call) {
		c.JSON(http.StatusOK, nil)
	})
	h := MustWrapRouter("TEST", "iss", "aud", rt, log.Default())
	cases := []struct {
		method, path, authz string
		want                int
	}{
		{"POST", "/open", "", http.StatusOK},
		{"POST", "/open", "Bearer not-a-jwt", http.StatusUnauthorized},
		{"GET", "/closed", "", http.StatusUnauthorized},
		{"GET", "/open", "", http.StatusUnauthorized},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		if tc.authz != "" {
			req.Header.Set("Authorization", tc.authz)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != tc.want {
			t.Errorf("%s %s authz=%q: status %d, want %d", tc.method, tc.path, tc.authz, w.Code, tc.want)
		}
	}
}
