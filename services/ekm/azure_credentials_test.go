package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/credstore"
)

// azureCreds is the credential store as the ekm service sees it.
type azureCreds struct {
	mu       sync.Mutex
	creds    map[string]credstore.Credential
	exposed  map[string]bool
	reported map[string]string
}

func newAzureCreds() *azureCreds {
	return &azureCreds{exposed: map[string]bool{}, reported: map[string]string{}, creds: map[string]credstore.Credential{
		"cred-azure": {ID: "cred-azure", Type: "azure", Fields: map[string]string{"tenant_id": "entra-tenant", "client_id": "app-1", "client_secret": "from-the-store"}},
		"cred-aws":   {ID: "cred-aws", Type: "aws", Fields: map[string]string{"access_key_id": "AKIA"}},
	}}
}

func (c *azureCreds) Resolve(_ context.Context, _, id string) (credstore.Credential, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cred, ok := c.creds[id]
	if !ok {
		return credstore.Credential{}, credstore.ErrNotFound
	}
	return cred, nil
}

func (c *azureCreds) Import(_ context.Context, _, sourceID, name, typ string, fields map[string]string, exposed bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	id := "pbconn_ekm_" + sourceID
	c.creds[id], c.exposed[id] = credstore.Credential{ID: id, Name: name, Type: typ, Fields: fields}, exposed
	return id, nil
}

func (c *azureCreds) ReportTest(_ context.Context, _, id string, err error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reported[id] = ""
	if err != nil {
		c.reported[id] = err.Error()
	}
	return nil
}

func azureSchema(t *testing.T, store *SQLStore) {
	t.Helper()
	if _, err := store.db.SQL().Exec(`CREATE TABLE ekm_azure_configs (
		tenant_id TEXT NOT NULL, id TEXT NOT NULL, azure_tenant_id TEXT NOT NULL, subscription_id TEXT NOT NULL DEFAULT '',
		resource_group TEXT NOT NULL DEFAULT '', vault_name TEXT NOT NULL, vault_url TEXT NOT NULL,
		managed_hsm_name TEXT NOT NULL DEFAULT '', managed_hsm_url TEXT NOT NULL DEFAULT '', client_id TEXT NOT NULL DEFAULT '',
		client_secret TEXT NOT NULL DEFAULT '', auth_mode TEXT NOT NULL DEFAULT 'client_secret', status TEXT NOT NULL DEFAULT 'active',
		key_mappings INTEGER NOT NULL DEFAULT 0, last_sync_at TIMESTAMP, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		connection_id TEXT NOT NULL DEFAULT '', PRIMARY KEY (tenant_id, id))`); err != nil {
		t.Fatal(err)
	}
}

// A vault names an "azure" credential that already exists; the secret is
// never sent with the vault, never stored by ekm and never returned.
func TestAzureVaultUsesACredentialFromTheStore(t *testing.T) {
	h, svc, _, pub := newEKMHandler(t)
	store := svc.store.(*SQLStore)
	azureSchema(t, store)
	creds := newAzureCreds()
	svc.SetCredentials(creds)
	admin := &pkgauth.Claims{UserID: "tester", TenantID: "t1", Role: "admin", Permissions: []string{"*"}}
	noUse := &pkgauth.Claims{UserID: "u", TenantID: "t1", Role: "ops", Permissions: []string{"ekm.write"}}
	post := func(claims *pkgauth.Claims, body map[string]interface{}) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/ekm/azure/configs", bytes.NewReader(raw))
		req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims))
		w := httptest.NewRecorder()
		h.mux.ServeHTTP(w, req)
		return w
	}
	refused := func(step string, claims *pkgauth.Claims, body map[string]interface{}, status int, reason string) {
		t.Helper()
		w := post(claims, body)
		if w.Code != status || !strings.Contains(w.Body.String(), reason) {
			t.Fatalf("%s: %d %s", step, w.Code, w.Body.String())
		}
		ev := pub.Last("audit.ekm.azure_config_refused")
		if ev["reason"] != reason || ev["result"] != "refused" {
			t.Fatalf("%s audit: %+v", step, ev)
		}
	}
	vault := func(extra map[string]interface{}) map[string]interface{} {
		out := map[string]interface{}{"tenant_id": "t1", "vault_name": "kv-prod"}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
	refused("inline secret", admin, vault(map[string]interface{}{"azure_tenant_id": "x", "client_id": "y", "client_secret": "inline-secret"}), http.StatusBadRequest, "inline_credentials_not_accepted")
	refused("no credential", admin, vault(nil), http.StatusBadRequest, "credential_required")
	refused("unknown credential", admin, vault(map[string]interface{}{"connection_id": "pbconn_nope"}), http.StatusConflict, "credential_not_found")
	refused("an AWS credential", admin, vault(map[string]interface{}{"connection_id": "cred-aws"}), http.StatusConflict, "credential_wrong_type")
	refused("caller without the use permission", noUse, vault(map[string]interface{}{"connection_id": "cred-azure"}), http.StatusForbidden, "credential_use_not_permitted")
	if items, _ := store.ListAzureEKMConfigs(context.Background(), "t1"); len(items) != 0 {
		t.Fatalf("a refused request stored %d vault(s)", len(items))
	}

	w := post(admin, vault(map[string]interface{}{"connection_id": "cred-azure"}))
	if w.Code != http.StatusCreated || strings.Contains(w.Body.String(), "from-the-store") || strings.Contains(w.Body.String(), `"client_secret":`) {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var out struct {
		Config AzureEKMConfig `json:"config"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	row, _ := store.GetAzureEKMConfig(context.Background(), "t1", out.Config.ID)
	if row.ConnectionID != "cred-azure" || row.ClientSecret != "" || row.AzureTenantID != "entra-tenant" || row.ClientID != "app-1" {
		t.Fatalf("stored vault: %+v", row)
	}
	// For a call to Azure the secret comes from the store, as it is now.
	creds.creds["cred-azure"] = credstore.Credential{ID: "cred-azure", Type: "azure", Fields: map[string]string{"tenant_id": "entra-tenant", "client_id": "app-1", "client_secret": "rotated"}}
	use, err := h.azureConfigForUse(context.Background(), "t1", row.ID)
	if err != nil || use.ClientSecret != "rotated" {
		t.Fatalf("config for use: %v %q", err, use.ClientSecret)
	}
	delete(creds.creds, "cred-azure")
	if _, err := h.azureConfigForUse(context.Background(), "t1", row.ID); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("a vault whose credential is gone still got a secret: %v", err)
	}
}

// A client secret an earlier release stored in plaintext is moved into the
// store as an exposed credential and the column is emptied; a cluster
// member moves nothing.
func TestAzurePlaintextSecretsMoveIntoTheStore(t *testing.T) {
	_, svc, _, pub := newEKMHandler(t)
	store := svc.store.(*SQLStore)
	azureSchema(t, store)
	creds := newAzureCreds()
	svc.SetCredentials(creds)
	ctx := context.Background()
	old := AzureEKMConfig{ID: "azcfg_old", TenantID: "t1", AzureTenantID: "entra-old", VaultName: "kv-old", VaultURL: "https://kv-old.vault.azure.net",
		ClientID: "app-old", ClientSecret: "plaintext-secret", AuthMode: "client_secret", Status: "active"}
	if err := store.CreateAzureEKMConfig(ctx, old); err != nil {
		t.Fatal(err)
	}
	if n, _ := svc.migrateAzureSecrets(ctx, func(context.Context) bool { return false }); n != 0 {
		t.Fatal("a cluster member migrated a secret")
	}
	n, err := svc.migrateAzureSecrets(ctx, func(context.Context) bool { return true })
	if err != nil || n != 1 {
		t.Fatalf("migration: %d %v", n, err)
	}
	row, _ := store.GetAzureEKMConfig(ctx, "t1", "azcfg_old")
	if row.ClientSecret != "" || row.ConnectionID != "pbconn_ekm_azcfg_old" {
		t.Fatalf("after migration: %+v", row)
	}
	var plain string
	_ = store.db.SQL().QueryRow(`SELECT client_secret FROM ekm_azure_configs WHERE id='azcfg_old'`).Scan(&plain)
	if plain != "" {
		t.Fatal("the plaintext secret is still in the table")
	}
	moved := creds.creds[row.ConnectionID]
	if moved.Type != "azure" || moved.Fields["client_secret"] != "plaintext-secret" || moved.Fields["tenant_id"] != "entra-old" || moved.Fields["client_id"] != "app-old" || !creds.exposed[row.ConnectionID] {
		t.Fatalf("migrated credential: %+v exposed=%v", moved, creds.exposed[row.ConnectionID])
	}
	if ev := pub.Last("audit.ekm.azure_credentials_migrated"); ev["connection_id"] != row.ConnectionID || !strings.Contains(ev["exposure"].(string), "plaintext") {
		t.Fatalf("migration audit: %+v", ev)
	}
	if n, _ := svc.migrateAzureSecrets(ctx, func(context.Context) bool { return true }); n != 0 {
		t.Fatal("a secret was migrated twice")
	}
}

// Google CSE takes no service account key: nothing uses one, so a request
// carrying it is refused and audited, and none is stored or returned.
func TestGoogleCSETakesNoServiceAccountKey(t *testing.T) {
	h, svc, _, pub := newEKMHandler(t)
	store := svc.store.(*SQLStore)
	migration, err := os.ReadFile("migrations/004_google_cse.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{string(migration), `ALTER TABLE ekm_google_cse_configs ADD COLUMN authentication_client_ids TEXT NOT NULL DEFAULT '[]'`} {
		if _, err := store.db.SQL().Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	admin := &pkgauth.Claims{UserID: "tester", TenantID: "t1", Role: "admin", Permissions: []string{"*"}}
	post := func(body map[string]interface{}) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/ekm/google-cse/configs", bytes.NewReader(raw))
		req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), admin))
		w := httptest.NewRecorder()
		h.mux.ServeHTTP(w, req)
		return w
	}
	cfg := map[string]interface{}{"tenant_id": "t1", "google_workspace_customer_id": "C1", "allowed_domains": []string{"corp.test"},
		"authentication_client_ids": []string{"cse.apps.googleusercontent.com"}}
	withKey := map[string]interface{}{"service_account_key_json": `{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----"}`}
	for k, v := range cfg {
		withKey[k] = v
	}
	if w := post(withKey); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "service_account_key_not_used") {
		t.Fatalf("a service account key was accepted: %d %s", w.Code, w.Body.String())
	}
	if ev := pub.Last("audit.ekm.google_cse_config_refused"); ev["reason"] != "service_account_key_not_used" || ev["result"] != "refused" {
		t.Fatalf("refusal audit: %+v", ev)
	}
	w := post(cfg)
	if w.Code != http.StatusCreated || strings.Contains(w.Body.String(), "service_account_key_json") {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var stored string
	_ = store.db.SQL().QueryRow(`SELECT service_account_key_json FROM ekm_google_cse_configs`).Scan(&stored)
	if stored != "" {
		t.Fatal("a service account key was stored")
	}
}
