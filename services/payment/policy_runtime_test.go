package main

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
)

func TestPaymentPolicyStrictModeNormalization(t *testing.T) {
	svc, _, _, _ := newPaymentService(t)
	ctx := context.Background()

	out, err := svc.UpdatePaymentPolicy(ctx, PaymentPolicy{
		TenantID:                  "tenant-strict",
		StrictPCIDSS40:            true,
		RequireKBPKForTR31:        false,
		AllowInlineKeyMaterial:    true,
		RequireISO20022LAUContext: false,
		RequireKeyIDForOperations: false,
		RequireJWTOnTCP:           false,
		BlockWildcardPAN:          false,
	})
	if err != nil {
		t.Fatalf("update policy: %v", err)
	}
	if !out.StrictPCIDSS40 {
		t.Fatalf("expected strict_pci_dss_4_0=true")
	}
	if !out.RequireKBPKForTR31 {
		t.Fatalf("strict mode must enforce require_kbpk_for_tr31")
	}
	if out.AllowInlineKeyMaterial {
		t.Fatalf("strict mode must disable inline key material")
	}
	if !out.RequireISO20022LAUContext {
		t.Fatalf("strict mode must enforce require_iso20022_lau_context")
	}
	if !out.RequireKeyIDForOperations {
		t.Fatalf("strict mode must enforce require_key_id_for_operations")
	}
	if !out.RequireJWTOnTCP {
		t.Fatalf("strict mode must enforce require_jwt_on_tcp")
	}
	if !out.BlockWildcardPAN {
		t.Fatalf("strict mode must enforce block_wildcard_pan")
	}
}

func TestPaymentPolicyBlocksInlineKeyMaterialWhenKeyIDRequired(t *testing.T) {
	svc, _, _, _ := newPaymentService(t)
	ctx := context.Background()

	_, err := svc.UpdatePaymentPolicy(ctx, PaymentPolicy{
		TenantID:                  "tenant-inline",
		RequireKeyIDForOperations: true,
		AllowInlineKeyMaterial:    false,
	})
	if err != nil {
		t.Fatalf("update policy: %v", err)
	}

	rawKey := []byte("123456789012345678901234")
	rawKeyB64 := base64.StdEncoding.EncodeToString(rawKey)
	_, err = svc.TranslatePIN(ctx, TranslatePINRequest{
		TenantID:        "tenant-inline",
		SourceFormat:    "ISO-0",
		TargetFormat:    "ISO-1",
		PINBlock:        "0000000000000000",
		PAN:             "4111111111111111",
		SourceZPKKeyB64: rawKeyB64,
		TargetZPKKeyB64: rawKeyB64,
		SourceZPKKeyID:  "",
		TargetZPKKeyID:  "",
	})
	if err == nil {
		t.Fatalf("expected policy_violation for inline key material")
	}
	var svcErr serviceError
	if !errors.As(err, &svcErr) {
		t.Fatalf("expected serviceError, got: %v", err)
	}
	if svcErr.Code != "policy_violation" {
		t.Fatalf("expected policy_violation, got: %s (%s)", svcErr.Code, svcErr.Message)
	}
}

func TestPaymentPolicyBlocksDisallowedPINFormat(t *testing.T) {
	svc, _, _, _ := newPaymentService(t)
	ctx := context.Background()

	_, err := svc.UpdatePaymentPolicy(ctx, PaymentPolicy{
		TenantID:               "tenant-pin-format",
		AllowedPINBlockFormats: []string{"ISO-0"},
	})
	if err != nil {
		t.Fatalf("update policy: %v", err)
	}

	_, err = svc.TranslatePIN(ctx, TranslatePINRequest{
		TenantID:       "tenant-pin-format",
		SourceFormat:   "ISO-0",
		TargetFormat:   "ISO-1",
		PINBlock:       "0000000000000000",
		PAN:            "4111111111111111",
		SourceZPKKeyID: "zpk-src",
		TargetZPKKeyID: "zpk-tgt",
	})
	if err == nil {
		t.Fatalf("expected policy_violation for disallowed pin format")
	}
	var svcErr serviceError
	if !errors.As(err, &svcErr) {
		t.Fatalf("expected serviceError, got: %v", err)
	}
	if svcErr.Code != "policy_violation" {
		t.Fatalf("expected policy_violation, got: %s (%s)", svcErr.Code, svcErr.Message)
	}
}

func TestPaymentPolicyBlocksTCPWhenDisabled(t *testing.T) {
	svc, _, _, _ := newPaymentService(t)
	ctx := context.Background()

	_, err := svc.UpdatePaymentPolicy(ctx, PaymentPolicy{
		TenantID:             "tenant-tcp",
		AllowTCPInterface:    false,
		AllowedTCPOperations: []string{"pin.translate"},
	})
	if err != nil {
		t.Fatalf("update policy: %v", err)
	}

	tcpCtx := withPaymentChannel(ctx, paymentChannelTCP)
	_, err = svc.enforceOperationPolicy(tcpCtx, "tenant-tcp", "pin.translate")
	if err == nil {
		t.Fatalf("expected policy_violation for disabled tcp")
	}
	var svcErr serviceError
	if !errors.As(err, &svcErr) {
		t.Fatalf("expected serviceError, got: %v", err)
	}
	if svcErr.Code != "policy_violation" {
		t.Fatalf("expected policy_violation, got: %s (%s)", svcErr.Code, svcErr.Message)
	}
}
