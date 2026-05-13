package internalauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// touched records whether the gated handler executed.
func newGatedHandler() (http.HandlerFunc, *bool) {
	called := false
	h := func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}
	return RequireToken(h), &called
}

func TestRequireToken_FailsClosedWhenUnconfigured(t *testing.T) {
	t.Setenv(EnvVar, "")
	h, called := newGatedHandler()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set(HeaderName, "anything")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when token unconfigured, got %d", rec.Code)
	}
	if *called {
		t.Fatalf("handler should not have run when token unconfigured")
	}
}

func TestRequireToken_RejectsMissingHeader(t *testing.T) {
	t.Setenv(EnvVar, "expected-token")
	h, called := newGatedHandler()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when header missing, got %d", rec.Code)
	}
	if *called {
		t.Fatalf("handler should not have run on missing token")
	}
}

func TestRequireToken_RejectsWrongToken(t *testing.T) {
	t.Setenv(EnvVar, "expected-token")
	h, called := newGatedHandler()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set(HeaderName, "wrong-token")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on wrong token, got %d", rec.Code)
	}
	if *called {
		t.Fatalf("handler should not have run on wrong token")
	}
}

func TestRequireToken_AcceptsMatchingHeader(t *testing.T) {
	t.Setenv(EnvVar, "expected-token")
	h, called := newGatedHandler()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set(HeaderName, "expected-token")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on matching token, got %d", rec.Code)
	}
	if !*called {
		t.Fatalf("handler should have run on matching token")
	}
}

func TestRequireToken_AcceptsBearerAuthorization(t *testing.T) {
	t.Setenv(EnvVar, "expected-token")
	h, called := newGatedHandler()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer expected-token")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on Bearer token, got %d", rec.Code)
	}
	if !*called {
		t.Fatalf("handler should have run on Bearer token")
	}
}

func TestAddTokenHeader_NoopWhenUnset(t *testing.T) {
	t.Setenv(EnvVar, "")
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	AddTokenHeader(req)
	if got := req.Header.Get(HeaderName); got != "" {
		t.Fatalf("AddTokenHeader should be a no-op when env is empty; got %q", got)
	}
}

func TestAddTokenHeader_SetsHeader(t *testing.T) {
	t.Setenv(EnvVar, "set-token")
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	AddTokenHeader(req)
	if got := req.Header.Get(HeaderName); got != "set-token" {
		t.Fatalf("AddTokenHeader should set header from env; got %q", got)
	}
}
