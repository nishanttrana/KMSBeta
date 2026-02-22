package main

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"testing"
)

func TestServiceProcessCryptoSuccess(t *testing.T) {
	svc, _, keycore, _, _, pub := newHYOKService(t)
	ctx := context.Background()
	keycore.Seed("tenant-1", "key-1", "AES-256")
	identity := AuthIdentity{Mode: "mtls", Subject: "tenant-1:cloud"}

	wrapResp, err := svc.ProcessCrypto(ctx, "tenant-1", ProtocolGeneric, "wrap", "key-1", "/hyok/generic/v1/keys/key-1/wrap", identity, ProxyCryptoRequest{
		PlaintextB64: "aGVsbG8=",
		IVB64:        "aXYxMjM0NTY3ODkw",
	})
	if err != nil {
		t.Fatal(err)
	}
	if wrapResp.Status != "ok" || wrapResp.CiphertextB64 == "" {
		t.Fatalf("unexpected wrap response %+v", wrapResp)
	}
	unwrapResp, err := svc.ProcessCrypto(ctx, "tenant-1", ProtocolGeneric, "unwrap", "key-1", "/hyok/generic/v1/keys/key-1/unwrap", identity, ProxyCryptoRequest{
		CiphertextB64: wrapResp.CiphertextB64,
		IVB64:         wrapResp.IVB64,
	})
	if err != nil {
		t.Fatal(err)
	}
	if unwrapResp.PlaintextB64 != "aGVsbG8=" {
		t.Fatalf("unexpected unwrap response %+v", unwrapResp)
	}
	if pub.Count("audit.hyok.wrap_request") == 0 || pub.Count("audit.hyok.unwrap_request") == 0 {
		t.Fatalf("expected wrap/unwrap audit events")
	}
}

func TestServicePolicyDenied(t *testing.T) {
	svc, store, keycore, policy, _, pub := newHYOKService(t)
	ctx := context.Background()
	keycore.Seed("tenant-2", "key-2", "AES-256")
	policy.decision = "DENY"
	policy.reason = "blocked by policy"

	_, err := svc.ProcessCrypto(ctx, "tenant-2", ProtocolGeneric, "decrypt", "key-2", "/hyok/generic/v1/keys/key-2/decrypt", AuthIdentity{Mode: "mtls", Subject: "tenant-2:cloud"}, ProxyCryptoRequest{
		CiphertextB64: "enc:aGVsbG8=",
		IVB64:         "aXYxMjM0NTY3ODkw",
	})
	if err == nil {
		t.Fatalf("expected policy deny error")
	}
	var svcErr serviceError
	if !errors.As(err, &svcErr) {
		t.Fatalf("expected serviceError got %T", err)
	}
	if svcErr.HTTPStatus != http.StatusForbidden {
		t.Fatalf("unexpected status: %+v", svcErr)
	}
	if pub.Count("audit.hyok.request_denied") == 0 {
		t.Fatalf("expected request_denied event")
	}
	items, err := store.ListRequestLogs(ctx, "tenant-2", ProtocolGeneric, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) == 0 || items[0].Status != "denied" {
		t.Fatalf("expected denied request log %+v", items)
	}
}

func TestServiceGovernancePendingApproval(t *testing.T) {
	svc, store, keycore, _, governance, _ := newHYOKService(t)
	ctx := context.Background()
	keycore.Seed("tenant-3", "key-3", "AES-256")
	governance.id = "apr-123"

	if _, err := svc.ConfigureEndpoint(ctx, EndpointConfig{
		TenantID:           "tenant-3",
		Protocol:           ProtocolGeneric,
		Enabled:            true,
		AuthMode:           AuthModeMTLSOrJWT,
		GovernanceRequired: true,
	}); err != nil {
		t.Fatal(err)
	}
	resp, err := svc.ProcessCrypto(ctx, "tenant-3", ProtocolGeneric, "wrap", "key-3", "/hyok/generic/v1/keys/key-3/wrap", AuthIdentity{Mode: "mtls", Subject: "tenant-3:cloud", RemoteIP: "127.0.0.1"}, ProxyCryptoRequest{
		PlaintextB64: "aGVsbG8=",
		RequesterID:  "svc-hyok",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != "pending_approval" || resp.ApprovalRequestID != "apr-123" {
		t.Fatalf("unexpected pending response %+v", resp)
	}
	items, err := store.ListRequestLogs(ctx, "tenant-3", ProtocolGeneric, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) == 0 || items[0].Status != "pending_approval" {
		t.Fatalf("expected pending request log %+v", items)
	}
}

func TestServiceGetDKEPublicKey(t *testing.T) {
	svc, _, keycore, _, _, pub := newHYOKService(t)
	ctx := context.Background()
	keycore.Seed("tenant-4", "key-4", "AES-256")
	resp, err := svc.GetDKEPublicKey(ctx, "tenant-4", "key-4", "/hyok/dke/v1/keys/key-4/publickey", AuthIdentity{Mode: "mtls", Subject: "tenant-4:cloud"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.KeyID != "key-4" || resp.PublicKey == "" {
		t.Fatalf("unexpected response %+v", resp)
	}
	if pub.Count("audit.hyok.dke_request") == 0 {
		t.Fatalf("expected dke_request audit event")
	}
}

func TestServiceMicrosoftDKEAdapter(t *testing.T) {
	svc, _, keycore, _, _, _ := newHYOKService(t)
	ctx := context.Background()
	keycore.Seed("tenant-ms", "rsa-1", "RSA-2048")

	keyDoc, err := svc.GetMicrosoftDKEKey(ctx, "tenant-ms", "rsa-1", "/api/v1/keys/rsa-1", "localhost", AuthIdentity{Mode: "mtls", Subject: "tenant-ms:cloud"})
	if err != nil {
		t.Fatal(err)
	}
	if keyDoc.KTY != "RSA" || keyDoc.N == "" || keyDoc.E == "" {
		t.Fatalf("unexpected key doc %+v", keyDoc)
	}

	resp, err := svc.ProcessMicrosoftDKEDecrypt(ctx, "tenant-ms", "rsa-1", "/api/v1/keys/rsa-1/decrypt", "localhost", AuthIdentity{Mode: "mtls", Subject: "tenant-ms:cloud"}, MicrosoftDKEDecryptRequest{
		Alg:   "RSA-OAEP-256",
		KID:   "rsa-1",
		Value: base64.RawURLEncoding.EncodeToString([]byte("wrap:aGVsbG8=")),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Value != "aGVsbG8" {
		t.Fatalf("unexpected decrypt response %+v", resp)
	}
}

func TestServiceMicrosoftDKEAdapterMetadataHostEnforcement(t *testing.T) {
	svc, _, keycore, _, _, _ := newHYOKService(t)
	ctx := context.Background()
	keycore.Seed("tenant-ms", "rsa-2", "RSA-2048")
	_, err := svc.ConfigureEndpoint(ctx, EndpointConfig{
		TenantID:     "tenant-ms",
		Protocol:     ProtocolDKE,
		Enabled:      true,
		AuthMode:     AuthModeMTLSOrJWT,
		MetadataJSON: `{"key_uri_hostname":"keys.example.com"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.GetMicrosoftDKEKey(ctx, "tenant-ms", "rsa-2", "/api/v1/keys/rsa-2", "localhost", AuthIdentity{Mode: "mtls", Subject: "tenant-ms:cloud"})
	if err == nil {
		t.Fatalf("expected host validation error")
	}
	var svcErr serviceError
	if !errors.As(err, &svcErr) {
		t.Fatalf("expected serviceError got %T", err)
	}
	if svcErr.HTTPStatus != http.StatusUnauthorized {
		t.Fatalf("unexpected status=%d msg=%s", svcErr.HTTPStatus, svcErr.Message)
	}
}
