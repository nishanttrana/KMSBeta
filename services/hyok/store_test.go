package main

import (
	"context"
	"testing"
)

func TestStoreEndpointConfigLifecycle(t *testing.T) {
	_, store, _, _, _, _ := newHYOKService(t)
	ctx := context.Background()

	cfg := EndpointConfig{
		TenantID:           "tenant-1",
		Protocol:           ProtocolGeneric,
		Enabled:            true,
		AuthMode:           AuthModeMTLS,
		PolicyID:           "pol-1",
		GovernanceRequired: true,
		MetadataJSON:       `{"owner":"secops"}`,
	}
	if err := store.UpsertEndpoint(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetEndpoint(ctx, "tenant-1", ProtocolGeneric)
	if err != nil {
		t.Fatal(err)
	}
	if got.AuthMode != AuthModeMTLS || !got.GovernanceRequired {
		t.Fatalf("unexpected endpoint %+v", got)
	}
	items, err := store.ListEndpoints(ctx, "tenant-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 endpoint got %d", len(items))
	}
	if err := store.DeleteEndpoint(ctx, "tenant-1", ProtocolGeneric); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetEndpoint(ctx, "tenant-1", ProtocolGeneric); err == nil {
		t.Fatalf("expected endpoint to be deleted")
	}
}

func TestStoreRequestLogLifecycle(t *testing.T) {
	_, store, _, _, _, _ := newHYOKService(t)
	ctx := context.Background()

	req := ProxyRequestLog{
		ID:             "hreq-1",
		TenantID:       "tenant-2",
		Protocol:       ProtocolDKE,
		Operation:      "decrypt",
		KeyID:          "key-1",
		Endpoint:       "/hyok/dke/v1/keys/key-1/decrypt",
		AuthMode:       "mtls",
		AuthSubject:    "tenant-2:cloud-service",
		RequesterID:    "svc-hyok",
		RequesterEmail: "hyok@example.com",
		Status:         "started",
		RequestJSON:    `{"ciphertext":"abc"}`,
	}
	if err := store.CreateRequestLog(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteRequestLog(ctx, "tenant-2", "hreq-1", "success", `{"plaintext":"xyz"}`, "", "", "ALLOW"); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetRequestLog(ctx, "tenant-2", "hreq-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "success" || got.PolicyDecision != "ALLOW" {
		t.Fatalf("unexpected request log %+v", got)
	}
	items, err := store.ListRequestLogs(ctx, "tenant-2", ProtocolDKE, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 request log got %d", len(items))
	}
}
