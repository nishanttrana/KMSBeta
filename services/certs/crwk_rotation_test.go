package main

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pkgcrypto "vecta-kms/pkg/crypto"
	pkgdb "vecta-kms/pkg/db"
)

// The passphrase that shipped in start-kms.sh/.ps1 before 1.10.0-beta.
const retiredPublicCRWKPassphrase = "vecta-dev-passphrase"

func randomPassphrase(t *testing.T) string {
	t.Helper()
	b, err := pkgcrypto.RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// Cheap Argon2id parameters: the tests exercise the logic, not the cost.
func crwkTestConfig(dir string) CertRootKeyConfig {
	return CertRootKeyConfig{
		StorageMode: "db_encrypted", RootKeyMode: "software",
		SealedPath:              filepath.Join(dir, "crwk.sealed"),
		BootstrapPassphraseFile: filepath.Join(dir, "bootstrap.passphrase"),
		ArgonMemoryKB:           8 * 1024, ArgonIterations: 1, ArgonParallel: 1,
	}
}

func writeSecretFile(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
}

func crwkService(t *testing.T, conn *pkgdb.DB, cfg CertRootKeyConfig) (*Service, *softwareCRWKProvider) {
	t.Helper()
	prov, err := newCertRootKeyProvider(cfg)
	if err != nil {
		t.Fatal(err)
	}
	sw, ok := prov.(*softwareCRWKProvider)
	if !ok || !sw.Status().Ready {
		t.Fatalf("provider not ready: %+v", prov.Status())
	}
	t.Cleanup(func() { _ = prov.Close() })
	return NewServiceWithSecurity(NewSQLStore(conn), nopCertPublisher{}, nil, ServiceSecurityConfig{
		CertStorageMode: "db_encrypted", RootKeyMode: "software", RootProvider: prov,
	}, false, false), sw
}

func sqliteCertsDB(t *testing.T) *pkgdb.DB {
	t.Helper()
	conn, err := pkgdb.Open(context.Background(), pkgdb.Config{UseSQLite: true, SQLitePath: ":memory:", MaxOpen: 1, MaxIdle: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := createCertsSchemaForTest(conn); err != nil {
		t.Fatal(err)
	}
	return conn
}

func TestCRWKPassphraseRefusesPublicAndWeakValues(t *testing.T) {
	for name, value := range map[string]string{
		"retired public default": retiredPublicCRWKPassphrase,
		"too short":              "Xk3!pQ9-short-passphrase",
		"repetitive":             strings.Repeat("ab12", 10),
	} {
		dir := t.TempDir()
		cfg := crwkTestConfig(dir)
		writeSecretFile(t, cfg.BootstrapPassphraseFile, value)
		_, err := newCertRootKeyProvider(cfg)
		if err == nil {
			t.Fatalf("%s: the certs service must refuse to start", name)
		}
		if strings.Contains(err.Error(), value) {
			t.Fatalf("%s: the refusal must not contain the passphrase", name)
		}
		if _, statErr := os.Stat(cfg.SealedPath); !os.IsNotExist(statErr) {
			t.Fatalf("%s: nothing may be sealed under a refused passphrase", name)
		}
	}
	// The inline variable is validated the same way.
	cfg := crwkTestConfig(t.TempDir())
	cfg.BootstrapPassphrase, cfg.BootstrapPassphraseFile = retiredPublicCRWKPassphrase, ""
	if _, err := newCertRootKeyProvider(cfg); err == nil {
		t.Fatal("CERTS_CRWK_BOOTSTRAP_PASSPHRASE with the public default must be refused")
	}
	cfg = crwkTestConfig(t.TempDir())
	writeSecretFile(t, cfg.BootstrapPassphraseFile, randomPassphrase(t))
	if p, err := newCertRootKeyProvider(cfg); err != nil || !p.Status().Ready {
		t.Fatalf("a generated passphrase must be accepted: %v", err)
	}
}

// An install sealed under the retired public passphrase migrates: the
// installer moves it to .previous and generates a new one; certs re-keys the
// CRWK, rewraps every CA signer, and audits it.
func TestCRWKMigratesOffThePublicDefault(t *testing.T) {
	exerciseCRWKMigration(t, sqliteCertsDB(t))
}

func TestCRWKMigratesOffThePublicDefaultPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("VECTA_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set VECTA_TEST_POSTGRES_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	conn, err := pkgdb.Open(ctx, pkgdb.Config{PostgresDSN: dsn, MaxOpen: 4, MaxIdle: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.RunMigrations(ctx, "migrations"); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	if _, err := conn.SQL().ExecContext(ctx, `TRUNCATE cert_cas, cert_certificates CASCADE`); err != nil {
		t.Fatalf("reset: %v", err)
	}
	exerciseCRWKMigration(t, conn)
}

func exerciseCRWKMigration(t *testing.T, conn *pkgdb.DB) {
	ctx := context.Background()
	dir := t.TempDir()
	cfg := crwkTestConfig(dir)
	cache := filepath.Join(dir, "internal-pki.json")

	// An existing install: internal PKI plus a tenant CA, wrapped by a CRWK...
	writeSecretFile(t, cfg.BootstrapPassphraseFile, randomPassphrase(t))
	svc, sw := crwkService(t, conn, cfg)
	oldVersion := sw.Status().KeyVersion
	pki, err := svc.BootstrapInternalPKI("root", cache)
	if err != nil {
		t.Fatal(err)
	}
	if err := pki.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	tenantCA, err := svc.CreateCA(ctx, CreateCARequest{TenantID: "acme", Name: "acme-root", CALevel: "root",
		Algorithm: "ECDSA-P256", KeyBackend: "software", Subject: "CN=Acme Root"})
	if err != nil {
		t.Fatal(err)
	}
	// ...sealed under the public passphrase, as start-kms.sh used to write.
	current, _ := os.ReadFile(cfg.BootstrapPassphraseFile)
	raw, _ := os.ReadFile(cfg.SealedPath)
	crwk, v, err := unsealCRWKBlob(raw, current, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	publicSealed, err := sealCRWKBlob(crwk, []byte(retiredPublicCRWKPassphrase), v, false, cfg.ArgonMemoryKB, cfg.ArgonIterations, cfg.ArgonParallel)
	if err != nil {
		t.Fatal(err)
	}
	writeSecretFile(t, cfg.SealedPath, string(publicSealed))
	_ = sw.Close()

	// The installer's migration.
	writeSecretFile(t, cfg.BootstrapPassphraseFile+".previous", retiredPublicCRWKPassphrase)
	newPassphrase := randomPassphrase(t)
	writeSecretFile(t, cfg.BootstrapPassphraseFile, newPassphrase)

	svc, sw = crwkService(t, conn, cfg)
	from, to, reason, pending := sw.PendingRotation()
	if !pending || from != oldVersion || to == oldVersion || reason != "public_default_passphrase" {
		t.Fatalf("rotation must be pending off %s for the public default: from=%s to=%s reason=%s pending=%v", oldVersion, from, to, reason, pending)
	}
	if st := sw.Status(); st.State != "rotation_pending" || !st.RotationPending {
		t.Fatalf("status must show the pending rotation: %+v", st)
	}
	// Before the rewrap the certs service still starts from its cache.
	pki, err = svc.BootstrapInternalPKI("root", cache)
	if err != nil {
		t.Fatalf("the internal PKI must load during a pending rotation: %v", err)
	}
	if err := pki.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	em := &captureEmitter{}
	if err := svc.CompleteCRWKRotation(ctx, em, pki); err != nil {
		t.Fatal(err)
	}
	ev, ok := em.last("crwk_rotated")
	if !ok || ev.Result != "success" || ev.Details["reason"] != "public_default_passphrase" || ev.Details["ca_signers_rewrapped"] != 3 {
		t.Fatalf("the rotation must be audited: %+v", ev)
	}

	for _, tenant := range []string{"root", "acme"} {
		cas, _ := svc.store.ListCAs(ctx, tenant)
		for _, ca := range cas {
			if ca.SignerKeyVersion != to {
				t.Fatalf("CA %s still wrapped under %s", ca.Name, ca.SignerKeyVersion)
			}
			// A copy of the old sealed file (plus the public passphrase) no
			// longer opens any signer.
			if _, err := aesGCMDecryptRaw(crwk, ca.SignerWrappedDEK, ca.SignerWrappedDEKIV); err == nil {
				t.Fatalf("CA %s: the retired CRWK must not unwrap it", ca.Name)
			}
		}
	}
	for _, gone := range []string{cfg.SealedPath + ".next", cfg.BootstrapPassphraseFile + ".previous"} {
		if _, err := os.Stat(gone); !os.IsNotExist(err) {
			t.Fatalf("%s must be removed after the rotation", gone)
		}
	}
	raw, _ = os.ReadFile(cfg.SealedPath)
	if _, _, err := unsealCRWKBlob(raw, []byte(retiredPublicCRWKPassphrase), 0, 0, 0); err == nil {
		t.Fatal("the sealed CRWK must no longer open with the public passphrase")
	}
	if _, err := pki.Enroll(ctx, "kms-certs", csrFor(t, "kms-certs")); err != nil {
		t.Fatalf("issuance must work after the rotation: %v", err)
	}
	_ = sw.Close()

	// Restart: the new passphrase alone opens everything, cache included.
	svc, sw = crwkService(t, conn, cfg)
	if _, _, _, pending := sw.PendingRotation(); pending || sw.Status().KeyVersion != to {
		t.Fatalf("after the rotation the new CRWK is the only one: %+v", sw.Status())
	}
	pki, err = svc.BootstrapInternalPKI("root", cache)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.loadCASigner(pki.sub); err != nil {
		t.Fatalf("the cached Sub CA must unwrap under the new CRWK: %v", err)
	}
	got, _ := svc.store.GetCA(ctx, "acme", tenantCA.ID)
	if _, err := svc.loadCASigner(got); err != nil {
		t.Fatalf("tenant CA signer: %v", err)
	}
}

// A crash between sealing the new CRWK and finishing the rewrap resumes with
// the same new key, and a failed rewrap is audited and completes nothing.
func TestCRWKRotationResumesAndAuditsFailure(t *testing.T) {
	ctx := context.Background()
	conn := sqliteCertsDB(t)
	dir := t.TempDir()
	cfg := crwkTestConfig(dir)
	first := randomPassphrase(t)
	writeSecretFile(t, cfg.BootstrapPassphraseFile, first)
	svc, sw := crwkService(t, conn, cfg)
	ca, err := svc.CreateCA(ctx, CreateCARequest{TenantID: "acme", Name: "acme-root", CALevel: "root",
		Algorithm: "ECDSA-P256", KeyBackend: "software", Subject: "CN=Acme Root"})
	if err != nil {
		t.Fatal(err)
	}
	_ = sw.Close()

	writeSecretFile(t, cfg.BootstrapPassphraseFile+".previous", first)
	writeSecretFile(t, cfg.BootstrapPassphraseFile, randomPassphrase(t))
	_, sw = crwkService(t, conn, cfg)
	_, to, reason, _ := sw.PendingRotation()
	if reason != "passphrase_rotation" {
		t.Fatalf("an operator rotation is not the public default: %s", reason)
	}
	_ = sw.Close()
	svc, sw = crwkService(t, conn, cfg) // restarted before completing
	if _, again, _, pending := sw.PendingRotation(); !pending || again != to {
		t.Fatalf("a restart must resume with the same new CRWK: %s vs %s", again, to)
	}

	// Corrupt the stored envelope: the rewrap fails, is audited, and the
	// retired key and previous passphrase stay so nothing is lost.
	bad := EncryptedSigner{WrappedDEK: []byte("not-a-wrapped-dek-0123456789"), WrappedDEKIV: ca.SignerWrappedDEKIV,
		Ciphertext: ca.SignerCiphertext, DataIV: ca.SignerDataIV, KeyVersion: ca.SignerKeyVersion, Fingerprint: ca.SignerFingerprint}
	if err := svc.store.UpdateCASignerEncryption(ctx, "acme", ca.ID, bad); err != nil {
		t.Fatal(err)
	}
	em := &captureEmitter{}
	if err := svc.CompleteCRWKRotation(ctx, em, nil); err == nil {
		t.Fatal("a signer that can't be unwrapped must fail the rotation")
	}
	ev, ok := em.last("crwk_rotated")
	if !ok || ev.Result != "failure" || ev.Details["reason"] != "rewrap_failed" {
		t.Fatalf("the failed rotation must be audited: %+v", ev)
	}
	for _, kept := range []string{cfg.SealedPath + ".next", cfg.BootstrapPassphraseFile + ".previous"} {
		if _, err := os.Stat(kept); err != nil {
			t.Fatalf("%s must be kept when the rotation fails: %v", kept, err)
		}
	}
	if _, _, _, pending := sw.PendingRotation(); !pending {
		t.Fatal("the rotation must stay pending")
	}
}

// Without the previous passphrase a mismatched sealed key is an error, never
// a silent re-initialisation that would orphan every CA signer.
func TestCRWKWrongPassphraseWithoutPreviousIsNotReady(t *testing.T) {
	dir := t.TempDir()
	cfg := crwkTestConfig(dir)
	writeSecretFile(t, cfg.BootstrapPassphraseFile, randomPassphrase(t))
	if p, err := newCertRootKeyProvider(cfg); err != nil || !p.Status().Ready {
		t.Fatalf("setup: %v", err)
	}
	before, _ := os.ReadFile(cfg.SealedPath)
	writeSecretFile(t, cfg.BootstrapPassphraseFile, randomPassphrase(t))
	p, err := newCertRootKeyProvider(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if st := p.Status(); st.Ready || !strings.Contains(st.LastError, "no previous passphrase file") {
		t.Fatalf("must not be ready: %+v", st)
	}
	after, _ := os.ReadFile(cfg.SealedPath)
	if string(before) != string(after) {
		t.Fatal("the sealed key must be left untouched")
	}
}
