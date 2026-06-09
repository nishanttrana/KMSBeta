package securityheaders

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWrapSetsAllSecurityHeaders(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := Wrap(inner)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	expected := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Content-Security-Policy":   "default-src 'self'; frame-ancestors 'none'",
		"Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
		"Cache-Control":             "no-store, no-cache, must-revalidate",
		"Referrer-Policy":           "no-referrer",
		"Permissions-Policy":        "camera=(), microphone=(), geolocation=(), payment=()",
	}
	for header, want := range expected {
		got := rr.Header().Get(header)
		if got != want {
			t.Errorf("header %s = %q; want %q", header, got, want)
		}
	}

	if rr.Header().Get("X-Request-ID") == "" {
		t.Error("X-Request-ID should be generated when not provided")
	}
}

func TestWrapPreservesClientRequestID(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := Wrap(inner)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Request-ID", "client-id-123")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if got := rr.Header().Get("X-Request-ID"); got != "client-id-123" {
		t.Errorf("X-Request-ID = %q; want %q", got, "client-id-123")
	}
}
