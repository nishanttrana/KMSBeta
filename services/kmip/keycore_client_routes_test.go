package main

import (
	"context"
	"encoding/csv"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// Every request the keycore client makes names a route keycore registers.
// Until 12.3.0-beta the client had five methods nothing called, four of them
// to routes keycore never had (POST /keys/keypair, POST /keys/{id}/hmac,
// POST /keys/{id}/hmac/verify, GET /keys/{id}/export). The route list is
// docs/generated/backend-routes.csv, which `make conformance` keeps current.
func TestKeycoreClientCallsRegisteredRoutes(t *testing.T) {
	registered := map[string]bool{}
	fh, err := os.Open("../../docs/generated/backend-routes.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close() //nolint:errcheck
	rows, err := csv.NewReader(fh).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows[1:] {
		if row[0] == "keycore" {
			registered[row[1]+" "+row[3]] = true // method, normalized_path
		}
	}
	if len(registered) < 50 {
		t.Fatalf("only %d keycore routes in the route list", len(registered))
	}

	var (
		mu    sync.Mutex
		calls []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.Method+" "+strings.ReplaceAll(r.URL.Path, "/key-1", "/{param}"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"key_id":"key-1","key":{"id":"key-1","name":"k"}}`))
	}))
	defer srv.Close()

	var client KeyCoreClient = NewHTTPKeyCoreClient(srv.URL, 2*time.Second)
	ctx := context.Background()
	exercised := map[string]bool{}
	run := func(method string, fn func()) { exercised[method] = true; fn() }
	run("CreateKey", func() { _, _ = client.CreateKey(ctx, "t1", CreateRequest{}) })
	run("ImportKey", func() { _, _ = client.ImportKey(ctx, "t1", RegisterRequest{}) })
	run("GetKey", func() { _, _ = client.GetKey(ctx, "t1", "key-1") })
	run("RotateKey", func() { _, _ = client.RotateKey(ctx, "t1", "key-1", "kmip rekey") })
	run("SetKeyStatus", func() {
		for _, status := range []string{"active", "disabled", "deactivated", "destroyed"} {
			_ = client.SetKeyStatus(ctx, "t1", "key-1", status)
		}
	})
	run("Encrypt", func() { _, _ = client.Encrypt(ctx, "t1", "key-1", "aGk=", "", "") })
	run("Decrypt", func() { _, _ = client.Decrypt(ctx, "t1", "key-1", "aGk=", "") })
	run("Sign", func() { _, _ = client.Sign(ctx, "t1", "key-1", "aGk=", "") })
	run("Verify", func() { _, _ = client.Verify(ctx, "t1", "key-1", "aGk=", "aGk=", "") })

	// A method added to the client is exercised here, or this fails.
	iface := reflect.TypeOf((*KeyCoreClient)(nil)).Elem()
	for i := 0; i < iface.NumMethod(); i++ {
		if name := iface.Method(i).Name; !exercised[name] {
			t.Errorf("KeyCoreClient.%s is not exercised by this test", name)
		}
	}
	if len(calls) < 12 {
		t.Fatalf("only %d requests were made: %v", len(calls), calls)
	}
	for _, call := range calls {
		if !registered[call] {
			t.Errorf("the client calls %s, which keycore does not register", call)
		}
	}
}
