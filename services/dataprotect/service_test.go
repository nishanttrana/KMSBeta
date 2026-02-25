package main

import (
	"context"
	"strings"
	"testing"
)

func TestServiceTokenizationFlow(t *testing.T) {
	svc, _, pub := newDataProtectService(t)
	ctx := context.Background()
	tenantID := "tenant-svc-1"

	vault, err := svc.CreateTokenVault(ctx, tenantID, TokenVault{
		Name:      "card-vault",
		TokenType: "credit_card",
		Format:    "deterministic",
		KeyID:     "key-1",
	})
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}

	items, err := svc.Tokenize(ctx, TokenizeRequest{
		TenantID: tenantID,
		VaultID:  vault.ID,
		Values:   []string{"4111111111111111", "4111111111111111"},
	})
	if err != nil {
		t.Fatalf("tokenize: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 tokenized items got %d", len(items))
	}
	token := firstString(items[0]["token"])
	if token == "" {
		t.Fatalf("missing token in response: %+v", items[0])
	}
	if pub.Count("audit.dataprotect.tokenized") == 0 {
		t.Fatalf("expected tokenized audit event")
	}

	detok, err := svc.Detokenize(ctx, DetokenizeRequest{TenantID: tenantID, Tokens: []string{token}})
	if err != nil {
		t.Fatalf("detokenize: %v", err)
	}
	if len(detok) != 1 || firstString(detok[0]["value"]) != "4111111111111111" {
		t.Fatalf("unexpected detokenize result: %+v", detok)
	}
}

func TestServiceFPEMaskRedactAndAppCrypto(t *testing.T) {
	svc, _, _ := newDataProtectService(t)
	ctx := context.Background()
	tenantID := "tenant-svc-2"

	enc, err := svc.FPEEncrypt(ctx, FPERequest{
		TenantID:  tenantID,
		KeyID:     "key-1",
		Algorithm: "FF1",
		Radix:     10,
		Tweak:     "abcd",
		Plaintext: "1234567890",
	})
	if err != nil {
		t.Fatalf("fpe encrypt: %v", err)
	}
	ciphertext := firstString(enc["ciphertext"])
	if ciphertext == "" {
		t.Fatalf("missing ciphertext")
	}
	dec, err := svc.FPEDecrypt(ctx, FPERequest{
		TenantID:   tenantID,
		KeyID:      "key-1",
		Algorithm:  "FF1",
		Radix:      10,
		Tweak:      "abcd",
		Ciphertext: ciphertext,
	})
	if err != nil {
		t.Fatalf("fpe decrypt: %v", err)
	}
	if firstString(dec["plaintext"]) != "1234567890" {
		t.Fatalf("unexpected plaintext: %+v", dec)
	}

	maskPolicy, err := svc.CreateMaskingPolicy(ctx, tenantID, MaskingPolicy{
		Name:         "mask-ssn",
		TargetType:   "field",
		FieldPath:    "$.customer.ssn",
		MaskPattern:  "full",
		RolesPartial: []string{"analyst"},
		Consistent:   true,
	})
	if err != nil {
		t.Fatalf("create masking policy: %v", err)
	}
	masked, err := svc.ApplyMask(ctx, MaskRequest{
		TenantID: tenantID,
		PolicyID: maskPolicy.ID,
		Role:     "analyst",
		Data: map[string]interface{}{
			"customer": map[string]interface{}{"ssn": "123-45-6789"},
		},
	})
	if err != nil {
		t.Fatalf("apply mask: %v", err)
	}
	ssn, _ := getPathValue(masked, "$.customer.ssn")
	if strings.TrimSpace(firstString(ssn)) == "123-45-6789" {
		t.Fatalf("value was not masked: %+v", masked)
	}

	redPolicy, err := svc.CreateRedactionPolicy(ctx, tenantID, RedactionPolicy{
		Name: "redact-pii",
		Patterns: []RedactionPattern{
			{Type: "regex", Pattern: `\b\d{3}-\d{2}-\d{4}\b`, Label: "SSN"},
		},
		Action:      "replace_placeholder",
		Placeholder: "[REDACTED]",
		Scope:       "all",
		AppliesTo:   []string{"*"},
	})
	if err != nil {
		t.Fatalf("create redaction policy: %v", err)
	}
	redacted, err := svc.Redact(ctx, RedactRequest{
		TenantID: tenantID,
		PolicyID: redPolicy.ID,
		Content:  "customer ssn is 123-45-6789",
	})
	if err != nil {
		t.Fatalf("redact: %v", err)
	}
	if !strings.Contains(firstString(redacted["content"]), "[REDACTED]") {
		t.Fatalf("expected redaction marker in content: %+v", redacted)
	}

	encryptedDoc, err := svc.EncryptFields(ctx, AppFieldRequest{
		TenantID:   tenantID,
		DocumentID: "doc-1",
		KeyID:      "key-1",
		Algorithm:  "AES-GCM",
		Document: map[string]interface{}{
			"email": "alice@example.com",
		},
		Fields: []string{"$.email"},
	})
	if err != nil {
		t.Fatalf("encrypt fields: %v", err)
	}
	doc, _ := encryptedDoc["document"].(map[string]interface{})
	field, _ := getPathValue(doc, "$.email")
	if _, ok := field.(map[string]interface{}); !ok {
		t.Fatalf("expected encrypted field object, got: %#v", field)
	}

	decryptedDoc, err := svc.DecryptFields(ctx, AppFieldRequest{
		TenantID:   tenantID,
		DocumentID: "doc-1",
		KeyID:      "key-1",
		Document:   doc,
		Fields:     []string{"$.email"},
	})
	if err != nil {
		t.Fatalf("decrypt fields: %v", err)
	}
	plainDoc, _ := decryptedDoc["document"].(map[string]interface{})
	email, _ := getPathValue(plainDoc, "$.email")
	if firstString(email) != "alice@example.com" {
		t.Fatalf("unexpected decrypted email: %#v", email)
	}

	envEnc, err := svc.EnvelopeEncrypt(ctx, EnvelopeRequest{
		TenantID:  tenantID,
		KeyID:     "key-1",
		Algorithm: "AES-GCM",
		Plaintext: "hello envelope",
	})
	if err != nil {
		t.Fatalf("envelope encrypt: %v", err)
	}
	envDec, err := svc.EnvelopeDecrypt(ctx, EnvelopeRequest{
		TenantID:     tenantID,
		KeyID:        "key-1",
		Algorithm:    "AES-GCM",
		Ciphertext:   firstString(envEnc["ciphertext"]),
		IV:           firstString(envEnc["iv"]),
		WrappedDEK:   firstString(envEnc["wrapped_dek"]),
		WrappedDEKIV: firstString(envEnc["wrapped_dek_iv"]),
	})
	if err != nil {
		t.Fatalf("envelope decrypt: %v", err)
	}
	if firstString(envDec["plaintext"]) != "hello envelope" {
		t.Fatalf("unexpected envelope plaintext: %+v", envDec)
	}

	se, err := svc.SearchableEncrypt(ctx, SearchableRequest{
		TenantID:  tenantID,
		KeyID:     "key-2",
		Plaintext: "alice@example.com",
	})
	if err != nil {
		t.Fatalf("searchable encrypt: %v", err)
	}
	sd, err := svc.SearchableDecrypt(ctx, SearchableRequest{
		TenantID:   tenantID,
		KeyID:      "key-2",
		Ciphertext: firstString(se["ciphertext"]),
	})
	if err != nil {
		t.Fatalf("searchable decrypt: %v", err)
	}
	if firstString(sd["plaintext"]) != "alice@example.com" {
		t.Fatalf("unexpected searchable plaintext: %+v", sd)
	}
}

func TestServiceVaultlessTokenizationDeterministic(t *testing.T) {
	svc, _, _ := newDataProtectService(t)
	ctx := context.Background()
	tenantID := "tenant-svc-vaultless"

	items, err := svc.Tokenize(ctx, TokenizeRequest{
		TenantID:  tenantID,
		Mode:      "vaultless",
		KeyID:     "key-1",
		TokenType: "credit_card",
		Format:    "deterministic",
		Values:    []string{"4111111111111111", "4111111111111111"},
		TTLHours:  24,
	})
	if err != nil {
		t.Fatalf("vaultless tokenize: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 vaultless tokenized items, got %d", len(items))
	}
	t1 := firstString(items[0]["token"])
	t2 := firstString(items[1]["token"])
	if t1 == "" || t2 == "" {
		t.Fatalf("expected vaultless tokens in response: %+v", items)
	}
	if t1 != t2 {
		t.Fatalf("expected deterministic vaultless tokens to match, got %q and %q", t1, t2)
	}
	if ignored, _ := items[0]["ttl_ignored"].(bool); !ignored {
		t.Fatalf("expected ttl_ignored=true in vaultless mode")
	}
}

func TestServiceRejectsAsymmetricTokenVaultKey(t *testing.T) {
	svc, _, _ := newDataProtectService(t)
	ctx := context.Background()
	tenantID := "tenant-svc-key-validation"

	_, err := svc.CreateTokenVault(ctx, tenantID, TokenVault{
		Name:      "bad-vault",
		TokenType: "credit_card",
		Format:    "format_preserving",
		KeyID:     "key-rsa",
	})
	if err == nil {
		t.Fatalf("expected asymmetric key validation error")
	}
}

func TestServiceTokenizationPolicyEnforcement(t *testing.T) {
	svc, _, _ := newDataProtectService(t)
	ctx := context.Background()
	tenantID := "tenant-svc-policy-token"

	_, err := svc.UpdateDataProtectionPolicy(ctx, DataProtectionPolicy{
		TenantID: tenantID,
		TokenizationModePolicy: map[string][]string{
			"credit_card": []string{"vault"},
		},
		MaxCustomRegexLength: 8,
	})
	if err != nil {
		t.Fatalf("update policy: %v", err)
	}

	_, err = svc.Tokenize(ctx, TokenizeRequest{
		TenantID:  tenantID,
		Mode:      "vaultless",
		KeyID:     "key-1",
		TokenType: "credit_card",
		Format:    "deterministic",
		Values:    []string{"4111111111111111"},
	})
	if err == nil {
		t.Fatalf("expected vaultless policy denial for credit_card")
	}

	_, err = svc.Tokenize(ctx, TokenizeRequest{
		TenantID:    tenantID,
		Mode:        "vaultless",
		KeyID:       "key-1",
		TokenType:   "custom",
		Format:      "deterministic",
		CustomRegex: "(very-long-regex)",
		Values:      []string{"abc"},
	})
	if err == nil {
		t.Fatalf("expected custom regex policy rejection")
	}
}

func TestServiceDetokenizePolicyEnforcement(t *testing.T) {
	svc, _, _ := newDataProtectService(t)
	ctx := context.Background()
	tenantID := "tenant-svc-policy-detok"

	vault, err := svc.CreateTokenVault(ctx, tenantID, TokenVault{
		Name:      "card-vault",
		TokenType: "credit_card",
		Format:    "deterministic",
		KeyID:     "key-1",
	})
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	tok, err := svc.Tokenize(ctx, TokenizeRequest{
		TenantID: tenantID,
		VaultID:  vault.ID,
		Values:   []string{"4111111111111111"},
	})
	if err != nil {
		t.Fatalf("tokenize: %v", err)
	}
	token := firstString(tok[0]["token"])
	if token == "" {
		t.Fatalf("missing token")
	}

	_, err = svc.UpdateDataProtectionPolicy(ctx, DataProtectionPolicy{
		TenantID:                       tenantID,
		AllowBulkDetokenize:            false,
		DetokenizeAllowedPurposes:      []string{"support"},
		RequireDetokenizeJustification: true,
	})
	if err != nil {
		t.Fatalf("update policy: %v", err)
	}

	_, err = svc.Detokenize(ctx, DetokenizeRequest{
		TenantID: tenantID,
		Tokens:   []string{token},
		Purpose:  "support",
	})
	if err == nil {
		t.Fatalf("expected missing justification rejection")
	}

	_, err = svc.Detokenize(ctx, DetokenizeRequest{
		TenantID:      tenantID,
		Tokens:        []string{token},
		Purpose:       "support",
		Justification: "ticket-1234",
	})
	if err != nil {
		t.Fatalf("detokenize with allowed purpose/justification: %v", err)
	}
}
