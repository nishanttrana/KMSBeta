package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base32"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"vecta-kms/pkg/metering"
)

type mockPublisher struct {
	subjects []string
}

func (m *mockPublisher) Publish(_ context.Context, subject string, _ []byte) error {
	m.subjects = append(m.subjects, subject)
	return nil
}

func newTestHandler(t *testing.T) (*Handler, *AuthLogic, *SQLStore, *mockPublisher) {
	t.Helper()
	store := newTestStore(t)
	if err := store.CreateTenant(context.Background(), Tenant{ID: "t1", Name: "Tenant", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateTenantRole(context.Background(), TenantRole{
		TenantID: "t1", RoleName: "tenant-admin", Permissions: []string{"*"},
	}); err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	logic := NewAuthLogic(key, "test-issuer", "test-aud")
	pub := &mockPublisher{}
	h := NewHandler(store, logic, pub, metering.NewMeter(0, time.Hour), nil)
	return h, logic, store, pub
}

func TestHandlerRegisterActivateFlow(t *testing.T) {
	h, logic, _, pub := newTestHandler(t)

	regBody := map[string]any{
		"tenant_id":      "t1",
		"client_name":    "svc-a",
		"client_type":    "service",
		"contact_email":  "ops@example.com",
		"requested_role": "app-service",
	}
	body, _ := json.Marshal(regBody)
	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("register status=%d body=%s", rr.Code, rr.Body.String())
	}
	var regResp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &regResp)
	regID, _ := regResp["registration_id"].(string)
	if regID == "" {
		t.Fatal("registration_id missing")
	}

	token, _, err := logic.IssueJWT("t1", "tenant-admin", []string{"*"}, "admin-1", false)
	if err != nil {
		t.Fatal(err)
	}
	actBody := []byte(`{"tenant_id":"t1","governance_enabled":true}`)
	actReq := httptest.NewRequest(http.MethodPost, "/auth/register/"+regID+"/activate", bytes.NewReader(actBody))
	actReq.Header.Set("Authorization", "Bearer "+token)
	actRR := httptest.NewRecorder()
	h.ServeHTTP(actRR, actReq)
	if actRR.Code != http.StatusOK {
		t.Fatalf("activate status=%d body=%s", actRR.Code, actRR.Body.String())
	}
	if len(pub.subjects) < 2 {
		t.Fatalf("expected >=2 audit events, got %v", pub.subjects)
	}
}

func TestHandlerRegisterRejectsUnknownTenant(t *testing.T) {
	h, _, _, _ := newTestHandler(t)
	body := []byte(`{
		"tenant_id":"missing-tenant",
		"client_name":"svc-a",
		"client_type":"service",
		"contact_email":"ops@example.com",
		"requested_role":"app-service"
	}`)
	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request, got %d body=%s", rr.Code, rr.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	errObj, _ := out["error"].(map[string]any)
	if code, _ := errObj["code"].(string); code != "bad_request" {
		t.Fatalf("expected bad_request code, got %v body=%s", code, rr.Body.String())
	}
}

func TestHandlerLoginWithTOTP(t *testing.T) {
	h, _, store, _ := newTestHandler(t)
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := HashPassword("P@ssw0rd!")
	if err := store.CreateUser(context.Background(), User{
		ID:         "u1",
		TenantID:   "t1",
		Username:   "alice",
		Email:      "alice@example.com",
		Password:   hash,
		TOTPSecret: []byte(secret),
		Role:       "tenant-admin",
		Status:     "active",
	}); err != nil {
		t.Fatal(err)
	}
	stored, err := store.GetUserByUsername(context.Background(), "t1", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(stored.Password, "P@ssw0rd!") {
		t.Fatalf("password verification failed for stored hash: %q", string(stored.Password))
	}
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	code := hotpCode(decoded, time.Now().UTC().Unix()/30)
	loginBody := map[string]any{
		"tenant_id": "t1",
		"username":  "alice",
		"password":  "P@ssw0rd!",
		"totp_code": code,
	}
	raw, _ := json.Marshal(loginBody)
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(raw))
	req.RemoteAddr = "127.0.0.1:12345"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("login status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["access_token"] == "" {
		t.Fatal("missing access token")
	}
}

func TestHandlerEnforcesPasswordChange(t *testing.T) {
	h, _, store, _ := newTestHandler(t)
	hash, _ := HashPassword("TempPass@2026")
	if err := store.CreateUser(context.Background(), User{
		ID:                 "u2",
		TenantID:           "t1",
		Username:           "admin",
		Email:              "admin@example.com",
		Password:           hash,
		Role:               "tenant-admin",
		Status:             "active",
		MustChangePassword: true,
	}); err != nil {
		t.Fatal(err)
	}

	loginBody := map[string]any{
		"tenant_id": "t1",
		"username":  "admin",
		"password":  "TempPass@2026",
	}
	raw, _ := json.Marshal(loginBody)
	loginReq := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(raw))
	loginReq.RemoteAddr = "127.0.0.1:12345"
	loginRR := httptest.NewRecorder()
	h.ServeHTTP(loginRR, loginReq)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login status=%d body=%s", loginRR.Code, loginRR.Body.String())
	}

	var loginResp map[string]any
	_ = json.Unmarshal(loginRR.Body.Bytes(), &loginResp)
	token, _ := loginResp["access_token"].(string)
	mustChange, _ := loginResp["must_change_password"].(bool)
	if token == "" || !mustChange {
		t.Fatalf("unexpected login response: %v", loginResp)
	}

	meReq := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	meReq.Header.Set("Authorization", "Bearer "+token)
	meRR := httptest.NewRecorder()
	h.ServeHTTP(meRR, meReq)
	if meRR.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden before password change, got %d body=%s", meRR.Code, meRR.Body.String())
	}

	changeBody := map[string]any{
		"current_password": "TempPass@2026",
		"new_password":     "NewStrongPass@2026",
	}
	changeRaw, _ := json.Marshal(changeBody)
	changeReq := httptest.NewRequest(http.MethodPost, "/auth/change-password", bytes.NewReader(changeRaw))
	changeReq.Header.Set("Authorization", "Bearer "+token)
	changeReq.RemoteAddr = "127.0.0.1:12345"
	changeRR := httptest.NewRecorder()
	h.ServeHTTP(changeRR, changeReq)
	if changeRR.Code != http.StatusOK {
		t.Fatalf("change-password status=%d body=%s", changeRR.Code, changeRR.Body.String())
	}

	var changeResp map[string]any
	_ = json.Unmarshal(changeRR.Body.Bytes(), &changeResp)
	newToken, _ := changeResp["access_token"].(string)
	if newToken == "" {
		t.Fatalf("missing new access token: %v", changeResp)
	}

	meReq2 := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	meReq2.Header.Set("Authorization", "Bearer "+newToken)
	meRR2 := httptest.NewRecorder()
	h.ServeHTTP(meRR2, meReq2)
	if meRR2.Code != http.StatusOK {
		t.Fatalf("expected success after password change, got %d body=%s", meRR2.Code, meRR2.Body.String())
	}
}

func TestHandlerRejectsDisabledUserLogin(t *testing.T) {
	h, _, store, _ := newTestHandler(t)
	hash, _ := HashPassword("Disabled@2026")
	if err := store.CreateUser(context.Background(), User{
		ID:       "u-disabled",
		TenantID: "t1",
		Username: "disabled-user",
		Email:    "disabled@example.com",
		Password: hash,
		Role:     "tenant-admin",
		Status:   "inactive",
	}); err != nil {
		t.Fatal(err)
	}

	loginBody := map[string]any{
		"tenant_id": "t1",
		"username":  "disabled-user",
		"password":  "Disabled@2026",
	}
	raw, _ := json.Marshal(loginBody)
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(raw))
	req.RemoteAddr = "127.0.0.1:12345"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized for inactive user, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandlerUserCreateHonorsPasswordPolicy(t *testing.T) {
	h, logic, _, _ := newTestHandler(t)
	adminToken, _, err := logic.IssueJWT("t1", "tenant-admin", []string{"*"}, "admin-1", false)
	if err != nil {
		t.Fatal(err)
	}

	policyReq := map[string]any{
		"min_length":            16,
		"require_special":       true,
		"require_digit":         true,
		"min_unique_chars":      8,
		"deny_username":         true,
		"deny_email_local_part": true,
	}
	policyRaw, _ := json.Marshal(policyReq)
	putReq := httptest.NewRequest(http.MethodPut, "/auth/password-policy", bytes.NewReader(policyRaw))
	putReq.Header.Set("Authorization", "Bearer "+adminToken)
	putRR := httptest.NewRecorder()
	h.ServeHTTP(putRR, putReq)
	if putRR.Code != http.StatusOK {
		t.Fatalf("update policy status=%d body=%s", putRR.Code, putRR.Body.String())
	}

	weakUser := map[string]any{
		"username": "weak",
		"email":    "weak@example.com",
		"password": "weakpass",
		"role":     "readonly",
		"status":   "active",
	}
	weakRaw, _ := json.Marshal(weakUser)
	weakReq := httptest.NewRequest(http.MethodPost, "/auth/users", bytes.NewReader(weakRaw))
	weakReq.Header.Set("Authorization", "Bearer "+adminToken)
	weakRR := httptest.NewRecorder()
	h.ServeHTTP(weakRR, weakReq)
	if weakRR.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request for weak password, got %d body=%s", weakRR.Code, weakRR.Body.String())
	}

	strongUser := map[string]any{
		"username": "strong",
		"email":    "strong@example.com",
		"password": "UsrAlphaSecure@2026!X",
		"role":     "readonly",
		"status":   "active",
	}
	strongRaw, _ := json.Marshal(strongUser)
	strongReq := httptest.NewRequest(http.MethodPost, "/auth/users", bytes.NewReader(strongRaw))
	strongReq.Header.Set("Authorization", "Bearer "+adminToken)
	strongRR := httptest.NewRecorder()
	h.ServeHTTP(strongRR, strongReq)
	if strongRR.Code != http.StatusCreated {
		t.Fatalf("expected created for strong password, got %d body=%s", strongRR.Code, strongRR.Body.String())
	}
}

func TestHandlerCLIResetRequiresAdmin(t *testing.T) {
	h, logic, store, _ := newTestHandler(t)
	cliHash, _ := HashPassword("CliPass@2026!")
	if err := store.CreateUser(context.Background(), User{
		ID:       "u-cli",
		TenantID: "t1",
		Username: "cli-user",
		Email:    "cli@example.com",
		Password: cliHash,
		Role:     "cli-user",
		Status:   "active",
	}); err != nil {
		t.Fatal(err)
	}

	nonAdminToken, _, err := logic.IssueJWT("t1", "readonly", []string{"auth.user.write"}, "user-1", false)
	if err != nil {
		t.Fatal(err)
	}
	resetBody := map[string]any{
		"new_password":         "ResetPwd@2026!Y",
		"must_change_password": false,
	}
	resetRaw, _ := json.Marshal(resetBody)
	forbiddenReq := httptest.NewRequest(http.MethodPost, "/auth/users/u-cli/reset-password", bytes.NewReader(resetRaw))
	forbiddenReq.Header.Set("Authorization", "Bearer "+nonAdminToken)
	forbiddenRR := httptest.NewRecorder()
	h.ServeHTTP(forbiddenRR, forbiddenReq)
	if forbiddenRR.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden for non-admin reset, got %d body=%s", forbiddenRR.Code, forbiddenRR.Body.String())
	}

	adminToken, _, err := logic.IssueJWT("t1", "admin", []string{"*"}, "admin-1", false)
	if err != nil {
		t.Fatal(err)
	}
	allowedReq := httptest.NewRequest(http.MethodPost, "/auth/users/u-cli/reset-password", bytes.NewReader(resetRaw))
	allowedReq.Header.Set("Authorization", "Bearer "+adminToken)
	allowedRR := httptest.NewRecorder()
	h.ServeHTTP(allowedRR, allowedReq)
	if allowedRR.Code != http.StatusOK {
		t.Fatalf("expected success for admin reset, got %d body=%s", allowedRR.Code, allowedRR.Body.String())
	}
}

func TestHandlerDeleteTenantPurgesTenantData(t *testing.T) {
	h, logic, store, pub := newTestHandler(t)
	if err := store.CreateTenant(context.Background(), Tenant{ID: "t-delete", Name: "Delete Tenant", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateTenantRole(context.Background(), TenantRole{
		TenantID: "t-delete", RoleName: "tenant-admin", Permissions: []string{"*"},
	}); err != nil {
		t.Fatal(err)
	}
	pwd, _ := HashPassword("TempStrong@2026")
	if err := store.CreateUser(context.Background(), User{
		ID: "u-del", TenantID: "t-delete", Username: "to-delete", Email: "to-delete@example.com",
		Password: pwd, Role: "tenant-admin", Status: "active",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.SQL().ExecContext(context.Background(), `
INSERT INTO approval_requests (id, tenant_id, action, target_type, target_id, status)
VALUES ('apr-disable','t-delete','tenant.disable','tenant','t-delete','approved')
`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.SQL().ExecContext(context.Background(), `
INSERT INTO approval_requests (id, tenant_id, action, target_type, target_id, status)
VALUES ('apr-delete','t-delete','tenant.delete','tenant','t-delete','approved')
`); err != nil {
		t.Fatal(err)
	}

	superToken, _, err := logic.IssueJWT("t1", "super-admin", []string{"*"}, "root-admin", false)
	if err != nil {
		t.Fatal(err)
	}
	disableBody := []byte(`{"governance_approval_id":"apr-disable"}`)
	disableReq := httptest.NewRequest(http.MethodPost, "/tenants/t-delete/disable", bytes.NewReader(disableBody))
	disableReq.Header.Set("Authorization", "Bearer "+superToken)
	disableRR := httptest.NewRecorder()
	h.ServeHTTP(disableRR, disableReq)
	if disableRR.Code != http.StatusOK {
		t.Fatalf("disable tenant status=%d body=%s", disableRR.Code, disableRR.Body.String())
	}

	reqBody := []byte(`{"confirm_tenant_id":"t-delete","force":true,"governance_approval_id":"apr-delete"}`)
	req := httptest.NewRequest(http.MethodDelete, "/tenants/t-delete", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+superToken)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("delete tenant status=%d body=%s", rr.Code, rr.Body.String())
	}
	if len(pub.subjects) == 0 || pub.subjects[len(pub.subjects)-1] != "audit.auth.tenant_deleted" {
		t.Fatalf("expected tenant_deleted audit event, subjects=%v", pub.subjects)
	}
	_, err = store.GetTenant(context.Background(), "t-delete")
	if !errors.Is(err, errNotFound) {
		t.Fatalf("expected tenant deleted, err=%v", err)
	}
}

func TestHandlerDisableTenantBlockedByActiveSessions(t *testing.T) {
	h, logic, store, _ := newTestHandler(t)
	if err := store.CreateTenant(context.Background(), Tenant{ID: "t-disable", Name: "Disable Tenant", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	hash, _ := HashPassword("Disable@2026")
	if err := store.CreateUser(context.Background(), User{
		ID:       "u-disable",
		TenantID: "t-disable",
		Username: "disable-user",
		Email:    "disable-user@example.com",
		Password: hash,
		Role:     "tenant-admin",
		Status:   "active",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateSession(context.Background(), Session{
		ID:        "sess-disable",
		TenantID:  "t-disable",
		UserID:    "u-disable",
		TokenHash: []byte("token-hash"),
		ExpiresAt: time.Now().Add(30 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.SQL().ExecContext(context.Background(), `
INSERT INTO approval_requests (id, tenant_id, action, target_type, target_id, status)
VALUES ('apr-disable-block','t-disable','tenant.disable','tenant','t-disable','approved')
`); err != nil {
		t.Fatal(err)
	}

	superToken, _, err := logic.IssueJWT("t1", "super-admin", []string{"*"}, "root-admin", false)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"governance_approval_id":"apr-disable-block"}`)
	req := httptest.NewRequest(http.MethodPost, "/tenants/t-disable/disable", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+superToken)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("expected conflict for active sessions, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandlerLoginIncludesGroupRolePermissions(t *testing.T) {
	h, logic, store, _ := newTestHandler(t)

	if err := store.CreateTenantRole(context.Background(), TenantRole{
		TenantID: "t1", RoleName: "readonly", Permissions: []string{"auth.user.read"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateTenantRole(context.Background(), TenantRole{
		TenantID: "t1", RoleName: "audit", Permissions: []string{"audit.read"},
	}); err != nil {
		t.Fatal(err)
	}
	hash, _ := HashPassword("ReadOnly@2026")
	if err := store.CreateUser(context.Background(), User{
		ID:       "u-readonly",
		TenantID: "t1",
		Username: "reader",
		Email:    "reader@example.com",
		Password: hash,
		Role:     "readonly",
		Status:   "active",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.SQL().ExecContext(context.Background(), `
INSERT INTO key_access_group_members (tenant_id, group_id, user_id)
VALUES ('t1','grp-audit','u-readonly')
`); err != nil {
		t.Fatal(err)
	}

	adminToken, _, err := logic.IssueJWT("t1", "tenant-admin", []string{"*"}, "admin-1", false)
	if err != nil {
		t.Fatal(err)
	}
	assignBody := []byte(`{"role_name":"audit"}`)
	assignReq := httptest.NewRequest(http.MethodPut, "/auth/groups/grp-audit/role", bytes.NewReader(assignBody))
	assignReq.Header.Set("Authorization", "Bearer "+adminToken)
	assignRR := httptest.NewRecorder()
	h.ServeHTTP(assignRR, assignReq)
	if assignRR.Code != http.StatusOK {
		t.Fatalf("assign group role status=%d body=%s", assignRR.Code, assignRR.Body.String())
	}

	loginBody := []byte(`{"tenant_id":"t1","username":"reader","password":"ReadOnly@2026"}`)
	loginReq := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(loginBody))
	loginReq.RemoteAddr = "127.0.0.1:12345"
	loginRR := httptest.NewRecorder()
	h.ServeHTTP(loginRR, loginReq)
	if loginRR.Code != http.StatusOK {
		t.Fatalf("login status=%d body=%s", loginRR.Code, loginRR.Body.String())
	}

	var out map[string]any
	_ = json.Unmarshal(loginRR.Body.Bytes(), &out)
	token, _ := out["access_token"].(string)
	if token == "" {
		t.Fatalf("missing token in login response: %v", out)
	}
	claims, err := logic.ParseJWT(token)
	if err != nil {
		t.Fatalf("parse jwt: %v", err)
	}
	if !hasPermission(claims.Permissions, "auth.user.read") {
		t.Fatalf("expected primary role permission in claims, got %+v", claims.Permissions)
	}
	if !hasPermission(claims.Permissions, "audit.read") {
		t.Fatalf("expected inherited group role permission in claims, got %+v", claims.Permissions)
	}
}
