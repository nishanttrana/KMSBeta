package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	pkgaudit "vecta-kms/pkg/audit"
	pkgdb "vecta-kms/pkg/db"
)

const testBindPassword = "SuperSecret!123"

func rawIDPRow(t *testing.T, store *SQLStore, tenantID, provider string) (secretJSON string, wrapped []byte) {
	t.Helper()
	if err := store.db.SQL().QueryRow(`SELECT secret_json, secrets_wrapped_dek FROM auth_identity_provider_configs WHERE tenant_id=$1 AND provider=$2`,
		tenantID, provider).Scan(&secretJSON, &wrapped); err != nil {
		t.Fatal(err)
	}
	return secretJSON, wrapped
}

func ldapConfig(secret string) IdentityProviderConfig {
	cfg := IdentityProviderConfig{TenantID: "t1", Provider: identityProviderLDAP, Enabled: true,
		Config: map[string]any{"ldap_url": "ldaps://dc01.example.local:636"}, Secrets: map[string]any{}, UpdatedBy: "admin-1"}
	if secret != "" {
		cfg.Secrets["bind_password"] = secret
	}
	return cfg
}

// A provider's secrets are stored sealed: the row holds their names only,
// the value comes back only through the master key, and the listing the
// sign-in page reads never carries them.
func TestIdentityProviderSecretsAreSealedAtRest(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	_ = store.CreateTenant(ctx, Tenant{ID: "t1", Name: "Tenant", Status: "active"})
	got, err := store.UpsertIdentityProviderConfig(ctx, ldapConfig(testBindPassword))
	if err != nil || got.Secrets["bind_password"] != testBindPassword {
		t.Fatalf("upsert: %+v %v", got.Secrets, err)
	}
	names, wrapped := rawIDPRow(t, store, "t1", identityProviderLDAP)
	if strings.Contains(names, testBindPassword) || !strings.Contains(names, `"bind_password"`) || len(wrapped) == 0 {
		t.Fatalf("stored row: secret_json %s, %d wrapped bytes", names, len(wrapped))
	}
	list, err := store.ListIdentityProviderConfigs(ctx, "t1")
	if err != nil || len(list) != 1 || len(list[0].Secrets) != 0 || !list[0].Enabled {
		t.Fatalf("list: %+v %v", list, err)
	}
	// Clearing the secret removes the envelope.
	if _, err := store.UpsertIdentityProviderConfig(ctx, ldapConfig("")); err != nil {
		t.Fatal(err)
	}
	if names, wrapped := rawIDPRow(t, store, "t1", identityProviderLDAP); names != "{}" || len(wrapped) != 0 {
		t.Fatalf("after clearing: %s, %d wrapped bytes", names, len(wrapped))
	}
}

// Without the master key nothing secret is written or read: saving a secret
// and reading a sealed provider are refused, a provider with no secret and
// the sign-in listing still work. A plaintext write is never the fallback.
func TestIdentityProviderSecretsFailClosedWithoutKey(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	_ = store.CreateTenant(ctx, Tenant{ID: "t1", Name: "Tenant", Status: "active"})
	if _, err := store.UpsertIdentityProviderConfig(ctx, ldapConfig(testBindPassword)); err != nil {
		t.Fatal(err)
	}
	key := store.idp.key
	store.idp = &idpVault{}
	store.idp.fail(errors.New("keycore unreachable"))

	if _, err := store.GetIdentityProviderConfig(ctx, "t1", identityProviderLDAP); !errors.Is(err, errIDPKeyUnavailable) || !strings.Contains(err.Error(), "keycore unreachable") {
		t.Fatalf("read without the key: %v", err)
	}
	other := ldapConfig("another-secret")
	other.Provider = identityProviderAD
	if _, err := store.UpsertIdentityProviderConfig(ctx, other); !errors.Is(err, errIDPKeyUnavailable) {
		t.Fatalf("save without the key: %v", err)
	}
	var n int
	_ = store.db.SQL().QueryRow(`SELECT COUNT(*) FROM auth_identity_provider_configs WHERE provider=$1`, identityProviderAD).Scan(&n)
	if n != 0 {
		t.Fatal("a provider was written without the key")
	}
	saml := IdentityProviderConfig{TenantID: "t1", Provider: identityProviderSAML, Config: map[string]any{"display_name": "SSO"}, UpdatedBy: "admin-1"}
	if _, err := store.UpsertIdentityProviderConfig(ctx, saml); err != nil {
		t.Fatalf("a provider with no secret: %v", err)
	}
	if list, err := store.ListIdentityProviderConfigs(ctx, "t1"); err != nil || len(list) != 2 {
		t.Fatalf("listing without the key: %d %v", len(list), err)
	}

	// The API says why, with 503, and does not report the provider as unconfigured.
	h, logic, hstore, _ := newTestHandler(t)
	if _, err := hstore.UpsertIdentityProviderConfig(ctx, ldapConfig(testBindPassword)); err != nil {
		t.Fatal(err)
	}
	hstore.idp = &idpVault{}
	token, _, _ := logic.IssueJWT("t1", "tenant-admin", []string{"*"}, "admin-1", false, "")
	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/auth/identity/providers/ldap", nil),
		httptest.NewRequest(http.MethodGet, "/auth/identity/providers", nil),
		httptest.NewRequest(http.MethodPut, "/auth/identity/providers/ldap", bytes.NewReader([]byte(`{"enabled":false}`))),
	} {
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), "secrets_unavailable") {
			t.Fatalf("%s %s without the key: %d %s", req.Method, req.URL.Path, rr.Code, rr.Body.String())
		}
	}

	// A different key does not open it either.
	store.idp = &idpVault{}
	store.idp.set(bytes.Repeat([]byte{0x24}, 32))
	if _, err := store.GetIdentityProviderConfig(ctx, "t1", identityProviderLDAP); err == nil {
		t.Fatal("another key opened the secrets")
	}
	store.idp.set(key)
	if got, err := store.GetIdentityProviderConfig(ctx, "t1", identityProviderLDAP); err != nil || got.Secrets["bind_password"] != testBindPassword {
		t.Fatalf("with the key again: %v", err)
	}
}

// An envelope copied onto another provider's row does not open there.
func TestIdentityProviderSecretsAreBoundToTheirProvider(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	_ = store.CreateTenant(ctx, Tenant{ID: "t1", Name: "Tenant", Status: "active"})
	if _, err := store.UpsertIdentityProviderConfig(ctx, ldapConfig(testBindPassword)); err != nil {
		t.Fatal(err)
	}
	ad := ldapConfig("ad-secret-value")
	ad.Provider = identityProviderAD
	if _, err := store.UpsertIdentityProviderConfig(ctx, ad); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.SQL().Exec(`
UPDATE auth_identity_provider_configs SET
  secrets_ciphertext=(SELECT secrets_ciphertext FROM auth_identity_provider_configs WHERE provider='ldap'),
  secrets_data_iv=(SELECT secrets_data_iv FROM auth_identity_provider_configs WHERE provider='ldap'),
  secrets_wrapped_dek=(SELECT secrets_wrapped_dek FROM auth_identity_provider_configs WHERE provider='ldap'),
  secrets_wrapped_dek_iv=(SELECT secrets_wrapped_dek_iv FROM auth_identity_provider_configs WHERE provider='ldap')
WHERE provider='ad'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetIdentityProviderConfig(ctx, "t1", identityProviderAD); err == nil || !strings.Contains(err.Error(), "different provider") {
		t.Fatalf("a copied envelope opened: %v", err)
	}
}

type idpRecorder struct {
	exposed []string
	events  []pkgaudit.Event
	fail    bool
}

func (r *idpRecorder) RecordExposure(_ context.Context, tenant, itemType, itemID, source string) error {
	if r.fail {
		return errors.New("register unavailable")
	}
	r.exposed = append(r.exposed, tenant+"|"+itemType+"|"+itemID+"|"+source)
	return nil
}

func (r *idpRecorder) Emit(_ context.Context, action string, ev pkgaudit.Event) error {
	ev.Action = action
	r.events = append(r.events, ev)
	return nil
}

// Rows an earlier release stored in plaintext are sealed by the primary,
// recorded as exposed and audited; a row that can't be sealed stays as it
// was and the refusal is audited; a cluster member changes nothing.
func TestPlaintextIdentityProviderSecretsAreSealedAndRegistered(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	_ = store.CreateTenant(ctx, Tenant{ID: "t1", Name: "Tenant", Status: "active"})
	plain, _ := json.Marshal(map[string]string{"bind_password": testBindPassword})
	if _, err := store.db.SQL().Exec(`INSERT INTO auth_identity_provider_configs (tenant_id, provider, enabled, config_json, secret_json, updated_by) VALUES ('t1','ldap',1,'{}',$1,'admin-1')`, string(plain)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.SQL().Exec(`INSERT INTO auth_identity_provider_configs (tenant_id, provider, enabled, config_json, secret_json, updated_by) VALUES ('t1','saml',1,'{}','{}','admin-1')`); err != nil {
		t.Fatal(err)
	}
	// Until it is sealed the provider still works from its own row.
	if got, err := store.GetIdentityProviderConfig(ctx, "t1", identityProviderLDAP); err != nil || got.Secrets["bind_password"] != testBindPassword {
		t.Fatalf("legacy row: %v", err)
	}
	primary := func(context.Context) bool { return true }
	member := func(context.Context) bool { return false }

	rec := &idpRecorder{}
	if n, err := sealPlaintextIDPSecrets(ctx, store, rec, member, rec); n != 0 || err != nil || len(rec.exposed)+len(rec.events) != 0 {
		t.Fatalf("a cluster member sealed rows: %d %v", n, err)
	}

	// The register is unavailable: nothing is sealed, and it is audited.
	rec.fail = true
	if n, err := sealPlaintextIDPSecrets(ctx, store, rec, primary, rec); n != 0 || err == nil {
		t.Fatalf("sealed without recording the exposure: %d %v", n, err)
	}
	if len(rec.events) != 1 || rec.events[0].Action != "identity_provider_secrets_seal_refused" || rec.events[0].Result != "refused" || rec.events[0].Details["reason"] != "seal_failed" {
		t.Fatalf("refusal event: %+v", rec.events)
	}
	if names, wrapped := rawIDPRow(t, store, "t1", identityProviderLDAP); !strings.Contains(names, testBindPassword) || len(wrapped) != 0 {
		t.Fatal("the row changed although the seal was refused")
	}

	rec = &idpRecorder{}
	n, err := sealPlaintextIDPSecrets(ctx, store, rec, primary, rec)
	if n != 1 || err != nil {
		t.Fatalf("seal: %d %v", n, err)
	}
	if len(rec.exposed) != 1 || rec.exposed[0] != "t1|identity_provider_secrets|ldap|plaintext_storage" {
		t.Fatalf("exposure register: %v", rec.exposed)
	}
	if len(rec.events) != 1 || rec.events[0].Action != "identity_provider_secrets_sealed" || rec.events[0].TenantID != "t1" || rec.events[0].Result != "success" {
		t.Fatalf("event: %+v", rec.events)
	}
	if raw, _ := json.Marshal(rec.events); strings.Contains(string(raw), testBindPassword) {
		t.Fatal("the secret is in the audit event")
	}
	names, wrapped := rawIDPRow(t, store, "t1", identityProviderLDAP)
	if strings.Contains(names, testBindPassword) || len(wrapped) == 0 {
		t.Fatalf("after sealing: %s", names)
	}
	if got, err := store.GetIdentityProviderConfig(ctx, "t1", identityProviderLDAP); err != nil || got.Secrets["bind_password"] != testBindPassword {
		t.Fatalf("sealed row: %v", err)
	}
	// Nothing left to do the second time.
	rec = &idpRecorder{}
	if n, err := sealPlaintextIDPSecrets(ctx, store, rec, primary, rec); n != 0 || err != nil || len(rec.events) != 0 {
		t.Fatalf("second pass: %d %v %+v", n, err, rec.events)
	}
}

// Replacing every secret a provider held closes its exposure entry;
// saving something else, or the same value again, does not.
func TestReplacingIdentityProviderSecretsClosesExposure(t *testing.T) {
	h, logic, store, _ := newTestHandlerWithRoles(t)
	if _, err := store.UpsertIdentityProviderConfig(context.Background(), ldapConfig(testBindPassword)); err != nil {
		t.Fatal(err)
	}
	var closed []string
	h.idpRemediate = func(_ context.Context, tenantID, provider, by string) bool {
		closed = append(closed, tenantID+"|"+provider+"|"+by)
		return true
	}
	token, _, _ := logic.IssueJWT("t1", "tenant-admin", []string{"*"}, "admin-1", false, "")
	put := func(body string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPut, "/auth/identity/providers/ldap", bytes.NewReader([]byte(body)))
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK || strings.Contains(rr.Body.String(), testBindPassword) {
			t.Fatalf("put: %d %s", rr.Code, rr.Body.String())
		}
	}
	put(`{"enabled":false}`)
	put(`{"secrets":{"bind_password":"` + testBindPassword + `"}}`)
	if len(closed) != 0 {
		t.Fatalf("closed without a new secret: %v", closed)
	}
	put(`{"secrets":{"bind_password":"a-new-bind-password"}}`)
	if len(closed) != 1 || !strings.HasPrefix(closed[0], "t1|ldap|") {
		t.Fatalf("closed: %v", closed)
	}
}

// The same on real Postgres (CI integration-postgres): migration 013, the
// JSONB names column and the BYTEA envelope, and the migration of a
// plaintext row.
func TestIdentityProviderSecretsPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("VECTA_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set VECTA_TEST_POSTGRES_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	conn, err := pkgdb.Open(ctx, pkgdb.Config{PostgresDSN: dsn, MaxOpen: 2, MaxIdle: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.RunMigrations(ctx, "migrations"); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	store := NewSQLStore(conn)
	store.idp.set(bytes.Repeat([]byte{0x42}, 32))
	tenant := "t-idp-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if err := store.CreateTenant(ctx, Tenant{ID: tenant, Name: tenant, Status: "active"}); err != nil {
		t.Fatal(err)
	}
	cfg := ldapConfig(testBindPassword)
	cfg.TenantID = tenant
	if got, err := store.UpsertIdentityProviderConfig(ctx, cfg); err != nil || got.Secrets["bind_password"] != testBindPassword {
		t.Fatalf("upsert: %v", err)
	}
	var names string
	var wrapped []byte
	if err := conn.SQL().QueryRow(`SELECT secret_json::text, secrets_wrapped_dek FROM auth_identity_provider_configs WHERE tenant_id=$1 AND provider='ldap'`, tenant).Scan(&names, &wrapped); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(names, testBindPassword) || len(wrapped) == 0 {
		t.Fatalf("stored row: %s, %d wrapped bytes", names, len(wrapped))
	}
	// A row an earlier release wrote.
	plain, _ := json.Marshal(map[string]string{"client_secret": "oidc-client-secret-value"})
	if _, err := conn.SQL().Exec(`INSERT INTO auth_identity_provider_configs (tenant_id, provider, enabled, secret_json) VALUES ($1,'oidc',TRUE,$2::jsonb)`, tenant, string(plain)); err != nil {
		t.Fatal(err)
	}
	rec := &idpRecorder{}
	if n, err := sealPlaintextIDPSecrets(ctx, store, rec, func(context.Context) bool { return true }, rec); n < 1 || err != nil {
		t.Fatalf("seal: %d %v", n, err)
	}
	_ = conn.SQL().QueryRow(`SELECT secret_json::text, secrets_wrapped_dek FROM auth_identity_provider_configs WHERE tenant_id=$1 AND provider='oidc'`, tenant).Scan(&names, &wrapped)
	if strings.Contains(names, "oidc-client-secret-value") || len(wrapped) == 0 {
		t.Fatalf("migrated row: %s", names)
	}
	if got, err := store.GetIdentityProviderConfig(ctx, tenant, identityProviderOIDC); err != nil || got.Secrets["client_secret"] != "oidc-client-secret-value" {
		t.Fatalf("migrated row reads: %v", err)
	}
	// The master-key tables exist.
	for _, table := range []string{"auth_mek_state", "auth_mek_exposure"} {
		if _, err := conn.SQL().Exec(`SELECT 1 FROM ` + table + ` LIMIT 1`); err != nil {
			t.Fatalf("%s: %v", table, err)
		}
	}
}
