package hsmconnector

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// The connector's credential client asks compliance for one credential of
// one tenant, maps its answers, and confines the library exactly as a
// profile's. It needs no HSM.
func TestCredentialsClientAsksComplianceAndConfinesTheLibrary(t *testing.T) {
	root := t.TempDir()
	lib := filepath.Join(root, "t1", "libvendor.so")
	if err := os.MkdirAll(filepath.Dir(lib), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lib, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HSM_LIBRARY_ROOTS", root)
	var path, tenant string
	status, body := http.StatusOK, `{"data":{"type":"pkcs11_hsm","fields":{"library_path":"`+lib+`","token_label":"prod","pin":"123456","vendor":"thales"}}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, tenant = r.URL.RequestURI(), r.Header.Get("X-Tenant-ID")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	ctx := context.Background()
	fresh := func() *Credentials { return &Credentials{BaseURL: srv.URL, HTTP: srv.Client()} }

	cfg, err := fresh().LoadConnection(ctx, "t1", "pbconn_luna")
	if err != nil || cfg.PIN != "123456" || cfg.TokenLabel != "prod" || cfg.Provider != "thales" || cfg.ConnectionID != "pbconn_luna" || cfg.TenantID != "t1" {
		t.Fatalf("load: %+v %v", cfg, err)
	}
	if path != "/compliance/connections/pbconn_luna/resolve?tenant_id=t1" || tenant != "t1" {
		t.Fatalf("request: %s (%s)", path, tenant)
	}
	// A library outside the provider workspace is refused, credential or not.
	outside := filepath.Join(t.TempDir(), "libevil.so")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	body = `{"data":{"type":"pkcs11_hsm","fields":{"library_path":"` + outside + `","token_label":"prod","pin":"123456"}}}`
	if _, err := fresh().LoadConnection(ctx, "t1", "pbconn_evil"); !errors.Is(err, errLibraryRefused) {
		t.Fatalf("library outside the workspace: %v", err)
	}
	body = `{"data":{"type":"aws","fields":{}}}`
	if _, err := fresh().LoadConnection(ctx, "t1", "pbconn_aws"); !errors.Is(err, ErrConnectionNotFound) {
		t.Fatalf("a non-HSM credential: %v", err)
	}
	for _, code := range []int{http.StatusNotFound, http.StatusConflict} {
		status, body = code, `{"error":{"code":"x"}}`
		if _, err := fresh().LoadConnection(ctx, "t1", "pbconn_x"); !errors.Is(err, ErrConnectionNotFound) {
			t.Fatalf("HTTP %d: %v", code, err)
		}
	}
	// An outage is reported as one and is not cached; a definite answer is.
	status = http.StatusServiceUnavailable
	c := fresh()
	if _, err := c.LoadConnection(ctx, "t1", "pbconn_luna"); !errors.Is(err, errConnectionsUnavailable) {
		t.Fatalf("store down: %v", err)
	}
	status, body = http.StatusOK, `{"data":{"type":"pkcs11_hsm","fields":{"library_path":"`+lib+`","slot_id":"3","pin":"123456"}}}`
	if cfg, err := c.LoadConnection(ctx, "t1", "pbconn_luna"); err != nil || cfg.SlotID != "3" {
		t.Fatalf("after the outage: %+v %v", cfg, err)
	}
	status = http.StatusServiceUnavailable
	if _, err := c.LoadConnection(ctx, "t1", "pbconn_luna"); err != nil {
		t.Fatalf("a resolved credential was not cached for its 15 seconds: %v", err)
	}
	srv.Close()
	if _, err := fresh().LoadConnection(ctx, "t1", "pbconn_luna"); !errors.Is(err, errConnectionsUnavailable) {
		t.Fatalf("unreachable store: %v", err)
	}
}
