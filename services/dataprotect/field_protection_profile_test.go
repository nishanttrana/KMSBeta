package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFieldProtectionProfileServiceResolveFlow(t *testing.T) {
	svc, _, _ := newDataProtectService(t)
	ctx := context.Background()
	tenantID := "tenant-field-profile-service"

	vault, err := svc.CreateTokenVault(ctx, tenantID, TokenVault{
		Name:      "card-vault",
		TokenType: "credit_card",
		Format:    "deterministic",
		KeyID:     "key-1",
	})
	if err != nil {
		t.Fatalf("CreateTokenVault: %v", err)
	}

	item, err := svc.UpsertFieldProtectionProfile(ctx, FieldProtectionProfile{
		TenantID: tenantID,
		Name:     "payments-profile",
		AppID:    "payments-api",
		Status:   "active",
		Rules: []FieldProtectionRule{
			{
				RuleID:              "email_rule",
				JSONPath:            "$.customer.email",
				WriteAction:         "encrypt",
				ReadAction:          "decrypt",
				Algorithm:           "AES-GCM",
				KeyID:               "key-1",
				AllowedDecryptRoles: []string{"admin"},
				MaskedRoles:         []string{"analyst"},
			},
			{
				RuleID:       "pan_rule",
				TableName:    "payments",
				ColumnName:   "pan_token",
				WriteAction:  "tokenize",
				ReadAction:   "token_only",
				TokenVaultID: vault.ID,
			},
		},
	})
	if err != nil {
		t.Fatalf("UpsertFieldProtectionProfile: %v", err)
	}
	if strings.TrimSpace(item.ProfileID) == "" || strings.TrimSpace(item.PolicyHash) == "" {
		t.Fatalf("expected profile_id and policy_hash: %+v", item)
	}

	list, err := svc.ListFieldProtectionProfiles(ctx, tenantID, "payments-api", "", "active", 10, 0)
	if err != nil {
		t.Fatalf("ListFieldProtectionProfiles: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 profile, got %d", len(list))
	}

	adminBundle, err := svc.ResolveFieldProtectionPolicyBundle(ctx, FieldProtectionResolveRequest{
		TenantID: tenantID,
		AppID:    "payments-api",
		Role:     "admin",
	})
	if err != nil {
		t.Fatalf("ResolveFieldProtectionPolicyBundle(admin): %v", err)
	}
	if strings.TrimSpace(adminBundle.ETag) == "" || adminBundle.CacheTTLSeconds <= 0 {
		t.Fatalf("invalid bundle metadata: %+v", adminBundle)
	}
	adminEmailRule := findResolvedRuleByID(adminBundle.Rules, "email_rule")
	if adminEmailRule == nil || !strings.EqualFold(strings.TrimSpace(adminEmailRule.ReadAction), "decrypt") {
		t.Fatalf("expected admin read_action=decrypt, got: %+v", adminEmailRule)
	}

	analystBundle, err := svc.ResolveFieldProtectionPolicyBundle(ctx, FieldProtectionResolveRequest{
		TenantID: tenantID,
		AppID:    "payments-api",
		Role:     "analyst",
	})
	if err != nil {
		t.Fatalf("ResolveFieldProtectionPolicyBundle(analyst): %v", err)
	}
	analystEmailRule := findResolvedRuleByID(analystBundle.Rules, "email_rule")
	if analystEmailRule == nil || !strings.EqualFold(strings.TrimSpace(analystEmailRule.ReadAction), "mask") {
		t.Fatalf("expected analyst read_action=mask, got: %+v", analystEmailRule)
	}
}

func TestFieldProtectionResolveWrapperAuthRequired(t *testing.T) {
	svc, _, _ := newDataProtectService(t)
	ctx := context.Background()
	tenantID := "tenant-field-profile-auth"
	wrapperID := "wrapper-profile-auth-1"
	appID := "app-profile-auth-1"

	reg, _ := registerWrapperForAuthTest(t, svc, tenantID, wrapperID, appID, "aabbccdd0011")
	if strings.TrimSpace(reg.AuthProfile.Token) == "" {
		t.Fatal("expected wrapper auth token")
	}

	if _, err := svc.UpsertFieldProtectionProfile(ctx, FieldProtectionProfile{
		TenantID:  tenantID,
		Name:      "wrapper-bound-profile",
		AppID:     appID,
		WrapperID: wrapperID,
		Status:    "active",
		Rules: []FieldProtectionRule{
			{
				RuleID:      "wrapper_email_rule",
				JSONPath:    "$.email",
				WriteAction: "encrypt",
				ReadAction:  "decrypt",
				KeyID:       "key-1",
			},
		},
	}); err != nil {
		t.Fatalf("UpsertFieldProtectionProfile: %v", err)
	}

	_, err := svc.ResolveFieldProtectionPolicyBundle(ctx, FieldProtectionResolveRequest{
		TenantID:  tenantID,
		AppID:     appID,
		WrapperID: wrapperID,
	})
	expectServiceErrCode(t, err, "auth_required")

	bundle, err := svc.ResolveFieldProtectionPolicyBundle(ctx, FieldProtectionResolveRequest{
		TenantID:     tenantID,
		AppID:        appID,
		WrapperID:    wrapperID,
		AuthToken:    reg.AuthProfile.Token,
		ClientCertFP: reg.Wrapper.CertFingerprint,
	})
	if err != nil {
		t.Fatalf("ResolveFieldProtectionPolicyBundle(authenticated): %v", err)
	}
	if len(bundle.Rules) == 0 {
		t.Fatalf("expected resolved rules, got empty bundle: %+v", bundle)
	}
}

func TestFieldProtectionResolveHandlerETagCaching(t *testing.T) {
	h, _, _ := newDataProtectHandler(t)
	tenantID := "tenant-field-profile-handler"
	appID := "orders-api"

	createReq := httptest.NewRequest(http.MethodPost, "/field-protection/profiles?tenant_id="+tenantID, strings.NewReader(`{
		"tenant_id":"`+tenantID+`",
		"name":"orders-profile",
		"app_id":"`+appID+`",
		"status":"active",
		"rules":[{"rule_id":"order_email","json_path":"$.email","write_action":"encrypt","read_action":"decrypt","key_id":"key-1"}]
	}`))
	createReq.Header.Set("Content-Type", "application/json")
	createRR := httptest.NewRecorder()
	h.ServeHTTP(createRR, createReq)
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create field profile status=%d body=%s", createRR.Code, createRR.Body.String())
	}

	resolveReq := httptest.NewRequest(http.MethodGet, "/field-protection/resolve?tenant_id="+tenantID+"&app_id="+appID+"&role=admin", nil)
	resolveRR := httptest.NewRecorder()
	h.ServeHTTP(resolveRR, resolveReq)
	if resolveRR.Code != http.StatusOK {
		t.Fatalf("resolve status=%d body=%s", resolveRR.Code, resolveRR.Body.String())
	}
	etag := strings.TrimSpace(resolveRR.Header().Get("ETag"))
	if etag == "" {
		t.Fatalf("expected ETag header")
	}
	if cacheControl := strings.TrimSpace(resolveRR.Header().Get("Cache-Control")); cacheControl == "" {
		t.Fatalf("expected Cache-Control header")
	}

	resolve304Req := httptest.NewRequest(http.MethodGet, "/field-protection/resolve?tenant_id="+tenantID+"&app_id="+appID+"&role=admin", nil)
	resolve304Req.Header.Set("If-None-Match", etag)
	resolve304RR := httptest.NewRecorder()
	h.ServeHTTP(resolve304RR, resolve304Req)
	if resolve304RR.Code != http.StatusNotModified {
		t.Fatalf("resolve with If-None-Match status=%d body=%s", resolve304RR.Code, resolve304RR.Body.String())
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(resolveRR.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode resolve payload: %v", err)
	}
	if _, ok := payload["bundle"]; !ok {
		t.Fatalf("expected bundle in response: %+v", payload)
	}
}

func findResolvedRuleByID(items []FieldProtectionResolvedRule, ruleID string) *FieldProtectionResolvedRule {
	for i := range items {
		if strings.EqualFold(strings.TrimSpace(items[i].RuleID), strings.TrimSpace(ruleID)) {
			return &items[i]
		}
	}
	return nil
}
