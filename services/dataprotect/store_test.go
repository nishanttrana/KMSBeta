package main

import (
	"context"
	"testing"
	"time"
)

func TestStoreFlows(t *testing.T) {
	_, store, _ := newDataProtectService(t)
	ctx := context.Background()
	tenantID := "tenant-store"

	vault := TokenVault{
		ID:        "vault1",
		TenantID:  tenantID,
		Name:      "card-vault",
		TokenType: "credit_card",
		Format:    "deterministic",
		KeyID:     "key-1",
	}
	if err := store.CreateTokenVault(ctx, vault); err != nil {
		t.Fatalf("create vault: %v", err)
	}
	gotVault, err := store.GetTokenVault(ctx, tenantID, vault.ID)
	if err != nil {
		t.Fatalf("get vault: %v", err)
	}
	if gotVault.Name != vault.Name {
		t.Fatalf("unexpected vault: %+v", gotVault)
	}

	token := TokenRecord{
		ID:           "tok1",
		TenantID:     tenantID,
		VaultID:      vault.ID,
		Token:        "tok_abc",
		OriginalEnc:  []byte("enc"),
		OriginalHash: "h1",
		FormatMetadata: map[string]interface{}{
			"x": "y",
		},
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
	if err := store.CreateToken(ctx, token); err != nil {
		t.Fatalf("create token: %v", err)
	}
	gotToken, err := store.GetTokenByValue(ctx, tenantID, token.Token)
	if err != nil {
		t.Fatalf("get token by value: %v", err)
	}
	if gotToken.OriginalHash != token.OriginalHash {
		t.Fatalf("unexpected token: %+v", gotToken)
	}
	if _, err := store.GetTokenByHash(ctx, tenantID, vault.ID, token.OriginalHash); err != nil {
		t.Fatalf("get token by hash: %v", err)
	}

	maskPolicy := MaskingPolicy{
		ID:          "mask1",
		TenantID:    tenantID,
		Name:        "ssn",
		TargetType:  "field",
		FieldPath:   "$.ssn",
		MaskPattern: "partial_last4",
		RolesFull:   []string{"admin"},
		Consistent:  true,
	}
	if err := store.CreateMaskingPolicy(ctx, maskPolicy); err != nil {
		t.Fatalf("create masking policy: %v", err)
	}
	maskPolicy.Name = "ssn-updated"
	if err := store.UpdateMaskingPolicy(ctx, maskPolicy); err != nil {
		t.Fatalf("update masking policy: %v", err)
	}
	items, err := store.ListMaskingPolicies(ctx, tenantID)
	if err != nil {
		t.Fatalf("list masking policies: %v", err)
	}
	if len(items) != 1 || items[0].Name != "ssn-updated" {
		t.Fatalf("unexpected masking policies: %+v", items)
	}

	redPolicy := RedactionPolicy{
		ID:          "red1",
		TenantID:    tenantID,
		Name:        "pii",
		Patterns:    []RedactionPattern{{Type: "regex", Pattern: `\\d{3}-\\d{2}-\\d{4}`, Label: "SSN"}},
		Scope:       "all",
		Action:      "replace_placeholder",
		Placeholder: "[REDACTED]",
		AppliesTo:   []string{"*"},
	}
	if err := store.CreateRedactionPolicy(ctx, redPolicy); err != nil {
		t.Fatalf("create redaction policy: %v", err)
	}
	redItems, err := store.ListRedactionPolicies(ctx, tenantID)
	if err != nil {
		t.Fatalf("list redaction policy: %v", err)
	}
	if len(redItems) != 1 {
		t.Fatalf("unexpected redaction policy count: %d", len(redItems))
	}

	meta := FLEMetadata{
		ID:         "fle1",
		TenantID:   tenantID,
		DocumentID: "doc1",
		FieldPath:  "$.email",
		KeyID:      "key-1",
		KeyVersion: 1,
		Algorithm:  "AES-GCM",
		IV:         []byte("iv"),
		Searchable: false,
	}
	if err := store.CreateFLEMetadata(ctx, meta); err != nil {
		t.Fatalf("create fle metadata: %v", err)
	}
	metas, err := store.ListFLEMetadataByDocument(ctx, tenantID, "doc1")
	if err != nil {
		t.Fatalf("list fle metadata: %v", err)
	}
	if len(metas) != 1 {
		t.Fatalf("unexpected metadata count: %d", len(metas))
	}

	if err := store.DeleteMaskingPolicy(ctx, tenantID, maskPolicy.ID); err != nil {
		t.Fatalf("delete masking policy: %v", err)
	}
	if err := store.DeleteTokenVault(ctx, tenantID, vault.ID); err != nil {
		t.Fatalf("delete token vault: %v", err)
	}
}
