package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/credstore"
	pkgcrypto "vecta-kms/pkg/crypto"
	pkgdb "vecta-kms/pkg/db"
	pkgkeyaccess "vecta-kms/pkg/keyaccess"
)

type nopCloudPublisher struct {
	mu       sync.Mutex
	subjects []string
	payloads [][]byte
}

func (p *nopCloudPublisher) Publish(_ context.Context, subject string, payload []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.subjects = append(p.subjects, subject)
	p.payloads = append(p.payloads, payload)
	return nil
}

// Last returns the data of the newest event on subject, or nil.
func (p *nopCloudPublisher) Last(subject string) map[string]interface{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	return lastEventData(p.subjects, p.payloads, subject)
}

func (p *nopCloudPublisher) Count(subject string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	total := 0
	for _, s := range p.subjects {
		if s == subject {
			total++
		}
	}
	return total
}

func newCloudService(t *testing.T) (*Service, *SQLStore, *testKeycore, *nopCloudPublisher) {
	t.Helper()
	conn, err := pkgdb.Open(context.Background(), pkgdb.Config{
		UseSQLite:  true,
		SQLitePath: ":memory:",
		MaxOpen:    1,
		MaxIdle:    1,
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := createCloudSchemaForTest(conn); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	store := NewSQLStore(conn)
	keycore := newTestKeycore()
	publisher := &nopCloudPublisher{}
	mek := []byte("0123456789ABCDEF0123456789ABCDEF")
	svc := NewService(store, newMockProviderRegistry(), publisher, mek)
	svc.SetKeyAccess(pkgkeyaccess.NotDeployed())
	svc.SetCredentials(newTestCredentials())
	svc.SetBYOK(store, keycore, defaultBYOKProviders())
	return svc, store, keycore, publisher
}

// testCredentials is the credential store as the cloud service sees it. It
// starts with one credential per provider, "cred-<type>", in every tenant.
type testCredentials struct {
	mu       sync.Mutex
	creds    map[string]credstore.Credential // by ID
	imported map[string]bool                 // ID → exposed
	tests    map[string]string               // ID → last reported error ("" ok)
	err      error
}

func newTestCredentials() *testCredentials {
	c := &testCredentials{creds: map[string]credstore.Credential{}, imported: map[string]bool{}, tests: map[string]string{}}
	for _, typ := range credentialType {
		c.creds["cred-"+typ] = credstore.Credential{ID: "cred-" + typ, Type: typ, Fields: map[string]string{"access_key_id": "AKIA", "secret_access_key": "from-the-store", "region": "us-east-1"}}
	}
	c.creds["cred-hsm"] = credstore.Credential{ID: "cred-hsm", Type: "pkcs11_hsm"}
	return c
}

func (c *testCredentials) Resolve(_ context.Context, _, id string) (credstore.Credential, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return credstore.Credential{}, c.err
	}
	cred, ok := c.creds[id]
	switch {
	case !ok:
		return credstore.Credential{}, credstore.ErrNotFound
	case providerOfCredential[cred.Type] == "":
		// As compliance does: kms-cloud may not open another service's type.
		return credstore.Credential{}, credstore.ErrWrongType
	}
	return cred, nil
}

func (c *testCredentials) Import(_ context.Context, _, sourceID, name, typ string, fields map[string]string, exposed bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return "", c.err
	}
	id := "pbconn_cloud_" + sourceID
	c.creds[id] = credstore.Credential{ID: id, Name: name, Type: typ, Fields: fields}
	c.imported[id] = exposed
	return id, nil
}

func (c *testCredentials) ReportTest(_ context.Context, _, id string, testErr error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tests[id] = ""
	if testErr != nil {
		c.tests[id] = testErr.Error()
	}
	return nil
}

// attachCtx is a request context whose verified caller may attach a
// credential to a cloud account.
func attachCtx(tenant string) context.Context {
	return pkgauth.ContextWithClaims(context.Background(), &pkgauth.Claims{UserID: "tester", TenantID: tenant, Role: "admin", Permissions: []string{"*"}})
}

// legacyAccount stores an account the way a release before 8.0.0-beta did:
// with its own credentials sealed under svc's master key.
func legacyAccount(t *testing.T, svc *Service, tenant, provider, name, credentialsJSON string) CloudAccount {
	t.Helper()
	env, err := pkgcrypto.EncryptEnvelope(svc.mek, []byte(credentialsJSON))
	if err != nil {
		t.Fatal(err)
	}
	acc := CloudAccount{ID: newID("ca"), TenantID: tenant, Provider: provider, Name: name, DefaultRegion: "us-east-1", Status: "configured",
		CredentialsWrappedDEK: env.WrappedDEK, CredentialsWrappedDEKIV: env.WrappedDEKIV, CredentialsCiphertext: env.Ciphertext, CredentialsDataIV: env.DataIV}
	if err := svc.store.CreateAccount(context.Background(), acc); err != nil {
		t.Fatal(err)
	}
	return acc
}

func newCloudHandler(t *testing.T) (*Handler, *Service, *testKeycore, *nopCloudPublisher) {
	t.Helper()
	svc, _, keycore, pub := newCloudService(t)
	return NewHandler(svc), svc, keycore, pub
}

func createCloudSchemaForTest(conn *pkgdb.DB) error {
	stmts := []string{
		`CREATE TABLE cloud_accounts (
			tenant_id TEXT NOT NULL, id TEXT NOT NULL, provider TEXT NOT NULL, name TEXT NOT NULL,
			default_region TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'active',
			creds_wrapped_dek BLOB, creds_wrapped_dek_iv BLOB,
			creds_ciphertext BLOB, creds_data_iv BLOB,
			connection_id TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id), UNIQUE (tenant_id, provider, name)
		);`,
		`CREATE TABLE cloud_region_mappings (
			tenant_id TEXT NOT NULL, provider TEXT NOT NULL, vecta_region TEXT NOT NULL, cloud_region TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, provider, vecta_region)
		);`,
		`CREATE TABLE cloud_key_bindings (
			tenant_id TEXT NOT NULL, id TEXT NOT NULL, key_id TEXT NOT NULL, provider TEXT NOT NULL, account_id TEXT NOT NULL,
			cloud_key_id TEXT NOT NULL, cloud_key_ref TEXT NOT NULL DEFAULT '', region TEXT NOT NULL DEFAULT '',
			sync_status TEXT NOT NULL DEFAULT 'pending', last_synced_at TIMESTAMP, metadata_json TEXT NOT NULL DEFAULT '{}',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE cloud_sync_jobs (
			tenant_id TEXT NOT NULL, id TEXT NOT NULL, provider TEXT NOT NULL DEFAULT '', account_id TEXT NOT NULL DEFAULT '',
			mode TEXT NOT NULL DEFAULT 'full', status TEXT NOT NULL, summary_json TEXT NOT NULL DEFAULT '{}',
			error_message TEXT NOT NULL DEFAULT '', started_at TIMESTAMP NOT NULL, completed_at TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
	}
	byok, err := os.ReadFile(filepath.Join("migrations", "004_byok.sql"))
	if err != nil {
		return err
	}
	for _, stmt := range strings.Split(string(byok), ";") {
		if strings.TrimSpace(stripSQLComments(stmt)) != "" {
			stmts = append(stmts, stmt)
		}
	}
	for _, stmt := range stmts {
		if _, err := conn.SQL().Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func stripSQLComments(stmt string) string {
	out := []string{}
	for _, line := range strings.Split(stmt, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "--") {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}
