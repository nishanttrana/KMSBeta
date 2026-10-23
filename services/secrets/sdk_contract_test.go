package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nishanttrana/KMSBeta/sdk/go/vecta"

	pkgauth "vecta-kms/pkg/auth"
)

// The Go SDK's secret read against the secrets service's real route: a REST
// client with the default permissions (kms.read, kms.write) reads a value.
func TestGoSDKReadsASecret(t *testing.T) {
	h, _, _ := newSecretsHandler(t)
	rr := serveAs(h, tenantAdmin("t1"), httptest.NewRequest(http.MethodPost, "/secrets",
		strings.NewReader(`{"tenant_id":"t1","name":"db-password","secret_type":"password","value":"hunter2"}`)))
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rr.Code, rr.Body)
	}
	var created struct {
		Secret Secret `json:"secret"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &created)
	client := &pkgauth.Claims{ClientID: "release-pipeline", UserID: "release-pipeline", TenantID: "t1", Role: "client-service", Permissions: []string{"kms.read", "kms.write"}}
	client.Subject = "release-pipeline"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer client-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/svc/secrets")
		authedHandler{h, client}.ServeHTTP(w, r)
	}))
	defer srv.Close()
	c, err := vecta.New(vecta.Config{BaseURL: srv.URL, TenantID: "t1", Token: "client-token",
		CAPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})})
	if err != nil {
		t.Fatal(err)
	}
	v, err := c.GetSecretValue(context.Background(), created.Secret.ID)
	if err != nil || v.Value != "hunter2" || v.Version < 1 {
		t.Fatalf("value: %+v %v", v, err)
	}
	if _, err := c.GetSecretValue(context.Background(), "sec_missing"); !vecta.IsNotFound(err) {
		t.Fatalf("a missing secret: %v", err)
	}
}
