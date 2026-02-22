package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestServicePaymentKeyLifecycle(t *testing.T) {
	svc, _, _, pub := newPaymentService(t)
	ctx := context.Background()

	created, err := svc.RegisterPaymentKey(ctx, RegisterPaymentKeyRequest{
		TenantID:      "tenant-a",
		KeyID:         "kc-1",
		PaymentType:   "ZMK",
		UsageCode:     "K0",
		ModeOfUse:     "B",
		Exportability: "E",
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID == "" || created.KCVHex == "" {
		t.Fatalf("unexpected created key: %+v", created)
	}

	got, err := svc.GetPaymentKey(ctx, "tenant-a", created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.KeyID != "kc-1" {
		t.Fatalf("unexpected key: %+v", got)
	}

	updated, err := svc.UpdatePaymentKey(ctx, created.ID, UpdatePaymentKeyRequest{
		TenantID:      "tenant-a",
		PaymentType:   "TPK",
		UsageCode:     "P0",
		ModeOfUse:     "E",
		Exportability: "N",
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.PaymentType != "TPK" || updated.ModeOfUse != "E" {
		t.Fatalf("unexpected updated key: %+v", updated)
	}

	rot, err := svc.RotatePaymentKey(ctx, created.ID, RotatePaymentKeyRequest{
		TenantID: "tenant-a",
		Reason:   "test-rotation",
	})
	if err != nil {
		t.Fatal(err)
	}
	if rot.VersionID == "" {
		t.Fatalf("missing version id: %+v", rot)
	}
	if pub.Count("audit.payment.key_rotated") == 0 {
		t.Fatal("expected rotation audit event")
	}
}

func TestServiceTR31PINAndMACFlows(t *testing.T) {
	svc, _, keycore, _ := newPaymentService(t)
	ctx := context.Background()

	keycore.materials["tenant-b:kc-2"] = []byte("1234567890ABCDEF")
	kbpkB64 := base64.StdEncoding.EncodeToString([]byte("0123456789ABCDEF0123456789ABCDEF"))
	createResp, err := svc.CreateTR31(ctx, CreateTR31Request{
		TenantID:    "tenant-b",
		KeyID:       "kc-2",
		TR31Version: "D",
		Algorithm:   "AES",
		UsageCode:   "D0",
		KBPKKeyB64:  kbpkB64,
	})
	if err != nil {
		t.Fatal(err)
	}
	if createResp.KeyBlock == "" || !strings.HasPrefix(createResp.KeyBlock, "D") || strings.Contains(createResp.KeyBlock, "|") {
		t.Fatalf("unexpected tr31 create response: %+v", createResp)
	}

	validateResp, err := svc.ValidateTR31(ctx, ValidateTR31Request{
		TenantID:    "tenant-b",
		KeyBlock:    createResp.KeyBlock,
		KBPKKeyB64:  kbpkB64,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !validateResp.Valid {
		t.Fatalf("expected valid tr31 block: %+v", validateResp)
	}

	parseResp, err := svc.ParseTR31(ctx, ParseTR31Request{
		TenantID:    "tenant-b",
		KeyBlock:    createResp.KeyBlock,
		KBPKKeyB64:  kbpkB64,
		ImportToKMS: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if parseResp.ImportedKeyID == "" {
		t.Fatalf("expected imported key id: %+v", parseResp)
	}

	translated, err := svc.TranslateTR31(ctx, TranslateTR31Request{
		TenantID:           "tenant-b",
		SourceFormat:       TR31FormatD,
		TargetFormat:       TR31FormatAESKWP,
		SourceBlock:        createResp.KeyBlock,
		SourceKBPKKeyB64:   kbpkB64,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(translated.ResultBlock, "AESKWP|") {
		t.Fatalf("unexpected translation block: %+v", translated)
	}

	sourcePINKey := []byte("1234567890ABCDEF")
	targetPINKey := []byte("FEDCBA0987654321")
	keycore.materials["tenant-b:zpk-src"] = append([]byte{}, sourcePINKey...)
	keycore.materials["tenant-b:zpk-dst"] = append([]byte{}, targetPINKey...)
	pan := "4111111111111111"
	clearISO0, err := buildPINClearBlock("ISO-0", "1234", pan)
	if err != nil {
		t.Fatal(err)
	}
	sourceTDES, err := normalizeTDESKey(sourcePINKey)
	if err != nil {
		t.Fatal(err)
	}
	sourcePINBlock, err := tdesECBEncrypt(sourceTDES, clearISO0)
	if err != nil {
		t.Fatal(err)
	}
	pinTranslated, err := svc.TranslatePIN(ctx, TranslatePINRequest{
		TenantID:       "tenant-b",
		SourceFormat:   "ISO-0",
		TargetFormat:   "ISO-1",
		PINBlock:       strings.ToUpper(hex.EncodeToString(sourcePINBlock)),
		PAN:            pan,
		SourceZPKKeyID: "zpk-src",
		TargetZPKKeyID: "zpk-dst",
	})
	if err != nil {
		t.Fatal(err)
	}
	targetTDES, err := normalizeTDESKey(targetPINKey)
	if err != nil {
		t.Fatal(err)
	}
	targetBlockRaw, err := hex.DecodeString(pinTranslated)
	if err != nil {
		t.Fatal(err)
	}
	targetClear, err := tdesECBDecrypt(targetTDES, targetBlockRaw)
	if err != nil {
		t.Fatal(err)
	}
	decodedPIN, err := decodePINFromClearBlock("ISO-1", targetClear, pan)
	if err != nil {
		t.Fatal(err)
	}
	if decodedPIN != "1234" {
		t.Fatalf("translated pin mismatch got=%s", decodedPIN)
	}

	pvv, err := svc.GeneratePVV(ctx, PVVGenerateRequest{
		TenantID:  "tenant-b",
		PVKKeyB64: base64.StdEncoding.EncodeToString([]byte("1234567890ABCDEF")),
		PIN:       "1234",
		PAN:       "4111111111111111",
		PVKI:      "1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(pvv) != 4 {
		t.Fatalf("unexpected pvv: %s", pvv)
	}

	ok, err := svc.VerifyPVV(ctx, PVVVerifyRequest{
		TenantID:  "tenant-b",
		PVKKeyB64: base64.StdEncoding.EncodeToString([]byte("1234567890ABCDEF")),
		PIN:       "1234",
		PAN:       "4111111111111111",
		PVKI:      "1",
		PVV:       pvv,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected pvv verification true")
	}

	macB64, err := svc.ComputeMAC(ctx, MACRequest{
		TenantID: "tenant-b",
		KeyB64:   base64.StdEncoding.EncodeToString([]byte("12345678ABCDEFGH")),
		DataB64:  base64.StdEncoding.EncodeToString([]byte("hello-payment")),
		Type:     "retail",
	})
	if err != nil {
		t.Fatal(err)
	}
	verifyMAC, err := svc.VerifyMAC(ctx, VerifyMACRequest{
		TenantID: "tenant-b",
		KeyB64:   base64.StdEncoding.EncodeToString([]byte("12345678ABCDEFGH")),
		DataB64:  base64.StdEncoding.EncodeToString([]byte("hello-payment")),
		MACB64:   macB64,
		Type:     "retail",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !verifyMAC {
		t.Fatal("expected mac verification true")
	}
}

func TestServiceISOAndLAUFlows(t *testing.T) {
	svc, _, _, _ := newPaymentService(t)
	ctx := context.Background()
	xml := "<Document><Msg>ok</Msg></Document>"

	signed, err := svc.ISO20022Sign(ctx, ISO20022SignRequest{
		TenantID: "tenant-c",
		KeyID:    "iso-key-1",
		XML:      xml,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(signed["signature_b64"]) == "" {
		t.Fatalf("missing signature response: %+v", signed)
	}

	verified, err := svc.ISO20022Verify(ctx, ISO20022VerifyRequest{
		TenantID:     "tenant-c",
		KeyID:        "iso-key-1",
		XML:          xml,
		SignatureB64: signed["signature_b64"],
	})
	if err != nil {
		t.Fatal(err)
	}
	if !verified {
		t.Fatal("expected xml verification true")
	}

	enc, err := svc.ISO20022Encrypt(ctx, ISO20022EncryptRequest{
		TenantID: "tenant-c",
		KeyID:    "iso-key-1",
		XML:      xml,
	})
	if err != nil {
		t.Fatal(err)
	}
	dec, err := svc.ISO20022Decrypt(ctx, ISO20022DecryptRequest{
		TenantID:      "tenant-c",
		KeyID:         "iso-key-1",
		CiphertextB64: enc["ciphertext"],
		IVB64:         enc["iv"],
	})
	if err != nil {
		t.Fatal(err)
	}
	if dec != xml {
		t.Fatalf("decrypt mismatch got=%s want=%s", dec, xml)
	}

	lau, err := svc.GenerateLAU(ctx, LAUGenerateRequest{
		TenantID:  "tenant-c",
		LAUKeyB64: base64.StdEncoding.EncodeToString([]byte("lau-secret-123456")),
		Message:   "pacs.008 payload",
		Context:   "swift",
	})
	if err != nil {
		t.Fatal(err)
	}
	lauOK, err := svc.VerifyLAU(ctx, LAUVerifyRequest{
		TenantID:  "tenant-c",
		LAUKeyB64: base64.StdEncoding.EncodeToString([]byte("lau-secret-123456")),
		Message:   "pacs.008 payload",
		Context:   "swift",
		LAUB64:    lau,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !lauOK {
		t.Fatal("expected lau verification true")
	}
}
