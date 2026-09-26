package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"vecta-kms/pkg/svctls"
)

func parseLeafPEM(t *testing.T, raw string) *x509.Certificate {
	t.Helper()
	b, _ := pem.Decode([]byte(raw))
	if b == nil {
		t.Fatal("no PEM block")
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func subPool(t *testing.T, sub CA) *x509.CertPool {
	t.Helper()
	p := x509.NewCertPool()
	p.AppendCertsFromPEM([]byte(sub.CertPEM))
	return p
}

// A fresh install creates the root and Sub CA without a database; a restart
// loads the same CAs from the cache instead of creating new ones.
func TestBootstrapCreatesThenReusesTheInternalPKI(t *testing.T) {
	svc, _ := newCertsService(t)
	cache := filepath.Join(t.TempDir(), "internal-pki.json")
	b, err := svc.BootstrapInternalPKI("root", cache)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.created) != 2 || b.sub.ParentCAID != b.root.ID {
		t.Fatalf("fresh bootstrap must create root and Sub CA: %+v", b.created)
	}
	if info, err := os.Stat(cache); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("cache must be written 0600: %v %v", info, err)
	}
	again, err := svc.BootstrapInternalPKI("root", cache)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.created) != 0 || again.root.ID != b.root.ID || again.sub.ID != b.sub.ID {
		t.Fatalf("restart must reuse the cached CAs, created=%v", again.created)
	}
	raw, _ := os.ReadFile(cache)
	if strings.Contains(string(raw), "PRIVATE KEY") {
		t.Fatal("the cache must hold only wrapped signing keys")
	}
}

// The cache format is psql's row_to_json of cert_cas, so an export from an
// existing database loads unchanged.
func TestPKICacheReadsPsqlRowToJSON(t *testing.T) {
	svc, _ := newCertsService(t)
	b, err := svc.BootstrapInternalPKI("root", filepath.Join(t.TempDir(), "c.json"))
	if err != nil {
		t.Fatal(err)
	}
	row := map[string]interface{}{}
	raw, _ := json.Marshal(cacheFromCA(b.sub))
	_ = json.Unmarshal(raw, &row)
	row["ots_current"], row["created_at"] = 0, "2026-09-26T12:00:00+00:00" // extra columns psql adds
	export, _ := json.Marshal(map[string]interface{}{"root": cacheFromCA(b.root), "sub": row})
	path := filepath.Join(t.TempDir(), "export.json")
	if err := os.WriteFile(path, export, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := svc.BootstrapInternalPKI("root", path)
	if err != nil || loaded.sub.ID != b.sub.ID || len(loaded.created) != 0 {
		t.Fatalf("psql export must load as the same PKI: %v %+v", err, loaded)
	}
	if _, err := svc.loadCASigner(loaded.sub); err != nil {
		t.Fatalf("the Sub CA signer must unwrap from the exported row: %v", err)
	}
}

func TestBootstrapEnrolmentAndInfraCertsBeforeTheDatabase(t *testing.T) {
	svc, _ := newCertsService(t)
	b, err := svc.BootstrapInternalPKI("root", filepath.Join(t.TempDir(), "c.json"))
	if err != nil {
		t.Fatal(err)
	}
	csr := csrFor(t, "kms-certs", "evil.example")
	out, err := b.Enroll(context.Background(), "kms-certs", csr)
	if err != nil {
		t.Fatal(err)
	}
	leaf := parseLeafPEM(t, out.CertificatePEM)
	sans := append([]string{}, leaf.DNSNames...)
	sort.Strings(sans)
	if strings.Join(sans, ",") != "certs,kms-certs" {
		t.Fatalf("SANs must come from the registry: %v", leaf.DNSNames)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: subPool(t, b.sub), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("bootstrap certificate must chain to the Sub CA: %v", err)
	}

	dir := t.TempDir()
	if err := b.WriteInfraCerts(dir); err != nil {
		t.Fatal(err)
	}
	for _, host := range svctls.Infrastructure {
		certRaw, err := os.ReadFile(filepath.Join(dir, host, "tls.crt"))
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		c := parseLeafPEM(t, string(certRaw))
		if _, err := c.Verify(x509.VerifyOptions{Roots: subPool(t, b.sub), DNSName: host, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			t.Fatalf("%s certificate: %v", host, err)
		}
		wantClient := host == "consul" // Consul's internal RPC presents it as a client too
		hasClient := false
		for _, u := range c.ExtKeyUsage {
			hasClient = hasClient || u == x509.ExtKeyUsageClientAuth
		}
		if hasClient != wantClient {
			t.Fatalf("%s: client auth EKU = %v, want %v (%v)", host, hasClient, wantClient, c.ExtKeyUsage)
		}
		if info, _ := os.Stat(filepath.Join(dir, host, "tls.key")); info.Mode().Perm() != 0o600 {
			t.Fatalf("%s key must be 0600", host)
		}
	}
}

// Reconcile records the cached CAs and every bootstrap certificate, then
// issuance goes through the database (and supersedes the bootstrap one).
func TestReconcileRecordsBootstrapStateAndSwitchesToTheDatabase(t *testing.T) {
	svc, store := newCertsService(t)
	b, err := svc.BootstrapInternalPKI("root", filepath.Join(t.TempDir(), "c.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Enroll(context.Background(), "kms-certs", csrFor(t, "kms-certs")); err != nil {
		t.Fatal(err)
	}
	if err := b.WriteInfraCerts(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := b.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, ca := range []CA{b.root, b.sub} {
		if got, err := store.GetCA(context.Background(), "root", ca.ID); err != nil || got.CertPEM != ca.CertPEM {
			t.Fatalf("CA %s must be recorded: %v", ca.Name, err)
		}
	}
	certs, _ := store.ListCertificates(context.Background(), "root", "", "internal-mtls", 100, 0)
	if len(certs) != 1+len(svctls.Infrastructure) {
		t.Fatalf("every bootstrap certificate must be recorded, got %d", len(certs))
	}
	if root, sub, err := svc.EnsureInternalPKI(context.Background(), "root"); err != nil || root.ID != b.root.ID || sub.ID != b.sub.ID {
		t.Fatalf("EnsureInternalPKI must return the bootstrapped CAs: %v", err)
	}
	if _, err := b.Enroll(context.Background(), "kms-certs", csrFor(t, "kms-certs")); err != nil {
		t.Fatal(err)
	}
	active, _ := store.ListCertificates(context.Background(), "root", CertStatusActive, "internal-mtls", 100, 0)
	n := 0
	for _, c := range active {
		if c.SubjectCN == "kms-certs" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("after reconcile, enrolment supersedes the bootstrap certificate; active kms-certs = %d", n)
	}
}

func TestReconcileRefusesADifferentCAWithTheSameName(t *testing.T) {
	svc, _ := newCertsService(t)
	if _, _, err := svc.EnsureInternalPKI(context.Background(), "root"); err != nil { // database PKI
		t.Fatal(err)
	}
	b, err := svc.BootstrapInternalPKI("root", filepath.Join(t.TempDir(), "c.json")) // unrelated cache
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Reconcile(context.Background()); err == nil || !strings.Contains(err.Error(), "another active CA") {
		t.Fatalf("a cache that disagrees with the database must be refused, got %v", err)
	}
}
