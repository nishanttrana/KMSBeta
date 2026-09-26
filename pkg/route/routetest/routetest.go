// Package routetest proves a service's routes meet the kernel contract. A
// service test is one call: routetest.RefusalsAudited(t, router, rec).
package routetest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	pkgaudit "vecta-kms/pkg/audit"
	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route"
)

// Recorder is an in-memory route.Emitter.
type Recorder struct {
	mu     sync.Mutex
	events []Recorded
}

// Recorded is one emitted event and the action it was emitted under.
type Recorded struct {
	Action string
	Event  pkgaudit.Event
}

func (r *Recorder) Emit(_ context.Context, action string, evt pkgaudit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, Recorded{Action: action, Event: evt})
	return nil
}

// Events returns a copy of everything recorded.
func (r *Recorder) Events() []Recorded {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Recorded(nil), r.events...)
}

// Reset forgets recorded events.
func (r *Recorder) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = nil
}

// Last returns the most recent event, failing the test if there is none.
func (r *Recorder) Last(t testing.TB) Recorded {
	t.Helper()
	ev := r.Events()
	if len(ev) == 0 {
		t.Fatal("no audit event was emitted")
	}
	return ev[len(ev)-1]
}

var wildcard = regexp.MustCompile(`\{[^}]+\}`)

// Request builds a request for a registered pattern, filling wildcards.
func Request(pattern string, claims *pkgauth.Claims, query string) *http.Request {
	method, path, _ := strings.Cut(pattern, " ")
	path = wildcard.ReplaceAllString(path, "probe")
	if query != "" {
		path += "?" + query
	}
	req := httptest.NewRequest(method, path, http.NoBody)
	if claims != nil {
		req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims))
	}
	return req
}

// RefusalsAudited proves, for every non-public route, that the kernel
// refuses an unauthenticated caller, a caller without the permission, and a
// caller naming another tenant, and that each refusal is audited under the
// route's own action with result "refused" and its reason.
func RefusalsAudited(t *testing.T, router *route.Router, rec *Recorder) {
	t.Helper()
	routes := router.Routes()
	if len(routes) == 0 {
		t.Fatal("router has no routes")
	}
	for _, rt := range routes {
		if rt.Spec.Public {
			continue
		}
		t.Run(rt.Pattern, func(t *testing.T) {
			expect := func(req *http.Request, status int, reason string) {
				t.Helper()
				rec.Reset()
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)
				if w.Code != status {
					t.Fatalf("%s: status %d, want %d (%s)", reason, w.Code, status, w.Body.String())
				}
				ev := rec.Events()
				if len(ev) != 1 {
					t.Fatalf("%s: %d audit events, want exactly 1", reason, len(ev))
				}
				got := ev[0]
				if got.Action != rt.Spec.Action || got.Event.Result != route.ResultRefused || got.Event.Details["reason"] != reason {
					t.Fatalf("%s: audited %s result=%s reason=%v, want %s refused %s",
						reason, got.Action, got.Event.Result, got.Event.Details["reason"], rt.Spec.Action, reason)
				}
			}
			expect(Request(rt.Pattern, nil, "tenant_id=t-probe"), http.StatusUnauthorized, route.ReasonUnauthenticated)
			if rt.Spec.Permission != route.Authenticated {
				none := &pkgauth.Claims{UserID: "u-probe", TenantID: "t-probe", Role: "probe"}
				expect(Request(rt.Pattern, none, "tenant_id=t-probe"), http.StatusForbidden, route.ReasonPermissionDenied)
			}
			if rt.Spec.Tenancy == route.TenantScoped {
				all := &pkgauth.Claims{UserID: "u-probe", TenantID: "t-probe", Role: "admin", Permissions: []string{"*"}}
				expect(Request(rt.Pattern, all, "tenant_id=t-other"), http.StatusForbidden, route.ReasonTenantMismatch)
			}
		})
	}
}
