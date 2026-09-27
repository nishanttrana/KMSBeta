package main

import (
	"context"
	"testing"
)

// The requested size is the size generated (it used to be ignored).
func TestGeneratedKeyMatchesRequestedAlgorithm(t *testing.T) {
	for _, tc := range []struct{ alg, leaf, ca string }{
		{"RSA-3072", "RSA-3072", "RSA-3072"},
		{"RSA-4096", "RSA-4096", "RSA-4096"},
		{"ECDSA-P384", "ECDSA-P384", "ECDSA-P384"},
		{"ECDSA-P256", "ECDSA-P256", "ECDSA-P256"},
		{"ECDSA-P521", "ECDSA-P521", "ECDSA-P521"},
		{"RSA", "RSA-2048", "RSA-3072"},      // no size: the old defaults
		{"RSA-1024", "RSA-2048", "RSA-3072"}, // never weaker than the default
	} {
		leaf, _, err := generateLeafKey(tc.alg)
		if err != nil {
			t.Fatal(err)
		}
		if got := describeKey(leaf.Public()); got != tc.leaf {
			t.Fatalf("leaf %s: generated %s, want %s", tc.alg, got, tc.leaf)
		}
		ca, _, err := generateSigningKey(tc.alg)
		if err != nil {
			t.Fatal(err)
		}
		if got := describeKey(ca.Public()); got != tc.ca {
			t.Fatalf("ca %s: generated %s, want %s", tc.alg, got, tc.ca)
		}
	}
}

// Records that name a key their certificate doesn't carry, including the
// retired post-quantum labels, are corrected once and audited; PQC profiles
// are deleted and audited.
func TestCorrectKeyLabels(t *testing.T) {
	svc, store := newCertsService(t)
	exerciseCorrectKeyLabels(t, svc, store)
}

// The same on real Postgres: the UPDATEs of algorithm with cert_class and
// ca_type, and the profile DELETE, run on the production schema.
func TestCorrectKeyLabelsPostgres(t *testing.T) {
	conn := postgresTestDB(t)
	store := NewSQLStore(conn)
	svc := NewService(store, nopCertPublisher{}, NoopKeyCoreSigner{}, []byte("0123456789ABCDEF0123456789ABCDEF"), false, false)
	exerciseCorrectKeyLabels(t, svc, store)
}

func exerciseCorrectKeyLabels(t *testing.T, svc *Service, store *SQLStore) {
	t.Helper()
	ctx := context.Background()
	ca, err := svc.CreateCA(ctx, CreateCARequest{TenantID: "acme", Name: "acme-root", CALevel: "root", Algorithm: "ECDSA-P384", KeyBackend: "software", Subject: "CN=Acme"})
	if err != nil {
		t.Fatal(err)
	}
	issue := func(cn string) Certificate {
		c, _, err := svc.IssueCertificate(ctx, IssueCertificateRequest{TenantID: "acme", CAID: ca.ID, SubjectCN: cn, CertType: "tls-server", Algorithm: "ECDSA-P256", ServerKeygen: true})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	good, sized, pqc := issue("a.example"), issue("b.example"), issue("c.example")
	// What earlier releases recorded: a wrong size, and a "PQC" certificate
	// that carries an ECDSA key.
	if err := store.setCertificateAlgorithm(ctx, "acme", sized.ID, "RSA-3072", "classical"); err != nil {
		t.Fatal(err)
	}
	if err := store.setCertificateAlgorithm(ctx, "acme", pqc.ID, "ML-DSA-65", "pqc"); err != nil {
		t.Fatal(err)
	}
	if err := store.setCAAlgorithm(ctx, "acme", ca.ID, "ECDSA-P384+ML-DSA-65", "hybrid"); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateProfile(ctx, CertificateProfile{ID: "prof-pqc", TenantID: "acme", Name: "pqc-tls-server", CertType: "tls-server", Algorithm: "ML-DSA-65", CertClass: "pqc", ProfileJSON: "{}"}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateProfile(ctx, CertificateProfile{ID: "prof-ok", TenantID: "acme", Name: "tls", CertType: "tls-server", Algorithm: "ECDSA-P384", CertClass: "classical", ProfileJSON: "{}"}); err != nil {
		t.Fatal(err)
	}

	rec := &captureEmitter{}
	n, err := svc.CorrectKeyLabels(ctx, rec)
	if err != nil || n != 4 {
		t.Fatalf("the wrong size, the PQC certificate, the hybrid CA and the PQC profile: n=%d %v", n, err)
	}
	if c, _ := store.GetCertificate(ctx, "acme", sized.ID); c.Algorithm != "ECDSA-P256" {
		t.Fatalf("the record must name the actual key, got %s", c.Algorithm)
	}
	if c, _ := store.GetCertificate(ctx, "acme", pqc.ID); c.Algorithm != "ECDSA-P256" || c.CertClass != "classical" {
		t.Fatalf("a PQC-labelled classical certificate must be relabelled: %s/%s", c.Algorithm, c.CertClass)
	}
	if got, _ := store.GetCA(ctx, "acme", ca.ID); got.Algorithm != "ECDSA-P384" || got.CAType != "classical" {
		t.Fatalf("a hybrid-labelled CA must be relabelled: %s/%s", got.Algorithm, got.CAType)
	}
	if c, _ := store.GetCertificate(ctx, "acme", good.ID); c.Algorithm != "ECDSA-P256" || c.CertClass != "classical" {
		t.Fatalf("a correct record is untouched: %s/%s", c.Algorithm, c.CertClass)
	}
	if _, err := store.GetProfile(ctx, "acme", "prof-pqc"); err == nil {
		t.Fatal("the PQC profile must be deleted")
	}
	if _, err := store.GetProfile(ctx, "acme", "prof-ok"); err != nil {
		t.Fatalf("a classical profile is kept: %v", err)
	}
	reasons := map[string]int{}
	for _, ev := range rec.events["certificate_key_label_corrected"] {
		reasons[ev.Details["reason"].(string)]++
	}
	if reasons["key_size_mismatch"] != 1 || reasons["pqc_label_removed"] != 2 || len(rec.events["pqc_profile_removed"]) != 1 {
		t.Fatalf("every correction must be audited with its reason: %v, profiles %d", reasons, len(rec.events["pqc_profile_removed"]))
	}
	if n, _ := svc.CorrectKeyLabels(ctx, rec); n != 0 {
		t.Fatalf("idempotent: second pass corrected %d", n)
	}
}
