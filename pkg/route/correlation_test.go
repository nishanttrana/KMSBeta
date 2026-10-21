package route_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/correlation"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
	"vecta-kms/pkg/servicetoken"
)

// withClaims stands in for the JWT middleware in front of a service.
func withClaims(h http.Handler, c *pkgauth.Claims) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(pkgauth.ContextWithClaims(r.Context(), c)))
	})
}

// One request that crosses two services is one correlation: service A's
// handler calls service B the way every internal client does
// (servicetoken.Authorize), and both events carry A's correlation ID.
func TestCorrelationFollowsTheRequestToTheNextService(t *testing.T) {
	recB := &routetest.Recorder{}
	b := route.New("b", recB, nil)
	b.Handle("GET /b", route.Spec{Action: "b.read", Permission: route.Authenticated, Tenancy: route.PlatformScoped}, func(c *route.Call) {
		c.JSON(http.StatusOK, nil)
	})
	srvB := httptest.NewServer(withClaims(b, &pkgauth.Claims{ClientID: "svc-a", TenantID: "root", Role: "service"}))
	defer srvB.Close()

	recA := &routetest.Recorder{}
	a := route.New("a", recA, nil)
	var inHandler string
	a.Handle("GET /a", route.Spec{Action: "a.read", Permission: route.Authenticated, Tenancy: route.PlatformScoped}, func(c *route.Call) {
		inHandler = correlation.From(c.R.Context())
		req, _ := http.NewRequestWithContext(c.R.Context(), http.MethodGet, srvB.URL+"/b", nil)
		servicetoken.Authorize(c.R.Context(), req)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			c.Error(http.StatusBadGateway, "b_unreachable", err.Error())
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		c.JSON(http.StatusOK, nil)
	})

	user := &pkgauth.Claims{UserID: "u1", TenantID: "t1", Role: "operator", Permissions: []string{"*"}, SessionID: "sess_1"}
	call := func(header string) (routetest.Recorded, routetest.Recorded) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/a", nil)
		if header != "" {
			req.Header.Set(correlation.Header, header)
		}
		req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), user))
		w := httptest.NewRecorder()
		a.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status %d: %s", w.Code, w.Body)
		}
		return recA.Last(t), recB.Last(t)
	}

	// No correlation from the caller: the first service's request ID is it.
	evA, evB := call("")
	if evA.Event.CorrelationID == "" || evA.Event.CorrelationID != inHandler {
		t.Fatalf("A's event correlation %q, handler saw %q", evA.Event.CorrelationID, inHandler)
	}
	if evB.Event.CorrelationID != evA.Event.CorrelationID {
		t.Fatalf("B's event correlation %q, want A's %q", evB.Event.CorrelationID, evA.Event.CorrelationID)
	}
	if evA.Event.SessionID != "sess_1" {
		t.Fatalf("A's event session %q, want the token's sid", evA.Event.SessionID)
	}

	// A correlation set by a calling platform service is kept downstream.
	evA, evB = call("corr_upstream")
	if evA.Event.CorrelationID != "corr_upstream" || evB.Event.CorrelationID != "corr_upstream" {
		t.Fatalf("correlation not carried: A %q, B %q", evA.Event.CorrelationID, evB.Event.CorrelationID)
	}
}
