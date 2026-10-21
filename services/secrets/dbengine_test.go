package main

import (
	"context"
	"crypto/tls"
	"regexp"
	"strings"
	"testing"
	"time"

	"vecta-kms/pkg/credstore"
)

func TestStatementTemplatesAreChecked(t *testing.T) {
	if err := checkStatements(defaultCreation, defaultRevocation); err != nil {
		t.Fatalf("defaults refused: %v", err)
	}
	for name, tc := range map[string][2][]string{
		"unknown placeholder":   {{"CREATE ROLE {{name}} PASSWORD {{password}} {{secret}};"}, defaultRevocation},
		"unclosed placeholder":  {{"CREATE ROLE {{name}} PASSWORD {{password}} {{name;"}, defaultRevocation},
		"no password":           {{"CREATE ROLE {{name}};"}, defaultRevocation},
		"no name":               {{"CREATE ROLE x PASSWORD {{password}};"}, defaultRevocation},
		"revocation names none": {defaultCreation, {"SELECT 1;"}},
		"empty statement":       {{"CREATE ROLE {{name}} PASSWORD {{password}};", " "}, defaultRevocation},
		"none":                  {nil, defaultRevocation},
	} {
		if err := checkStatements(tc[0], tc[1]); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestRenderQuotesEveryValue(t *testing.T) {
	at := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	got := render(`CREATE ROLE {{name}} PASSWORD {{password}} VALID UNTIL {{expiration}}; SELECT {{username}};`, `v_a"b`, `p'w`, at)
	want := `CREATE ROLE "v_a""b" PASSWORD 'p''w' VALID UNTIL '2026-10-21 12:00:00Z'; SELECT 'v_a"b';`
	if got != want {
		t.Fatalf("render:\n got %s\nwant %s", got, want)
	}
}

func TestLoginsAreRandomAndWithinPostgresLimits(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		u, p, err := newLogin(strings.Repeat("orders-reader", 5))
		if err != nil {
			t.Fatal(err)
		}
		if len(u) > 63 || !regexp.MustCompile(`^v_[a-z0-9_]+_[a-z0-9]{10}$`).MatchString(u) {
			t.Fatalf("login name %q", u)
		}
		if len(p) != 32 || !regexp.MustCompile(`^[A-Za-z0-9]{32}$`).MatchString(p) || seen[u] || seen[p] {
			t.Fatalf("password %q", p)
		}
		seen[u], seen[p] = true, true
	}
}

// The connection to a customer database verifies its certificate and host
// at TLS 1.3, never falls back to plaintext, and dials through ssrfguard.
func TestDatabaseConnectionsVerifyTLSAndRefuseBlockedAddresses(t *testing.T) {
	cfg, err := pgConfig(dbTarget{Host: "db.example.com", Port: "5432", Database: "app", User: "admin", Password: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLSConfig == nil || cfg.TLSConfig.ServerName != "db.example.com" || cfg.TLSConfig.InsecureSkipVerify || cfg.TLSConfig.MinVersion != tls.VersionTLS13 || len(cfg.Fallbacks) != 0 {
		t.Fatalf("TLS %+v fallbacks %d", cfg.TLSConfig, len(cfg.Fallbacks))
	}
	if _, err := cfg.DialFunc(context.Background(), "tcp", "127.0.0.1:5432"); err == nil {
		t.Fatal("dialled a loopback address the credential did not approve")
	}
	if _, err := pgConfig(dbTarget{Host: "db", Port: "70000", Database: "a", User: "u"}); err == nil {
		t.Fatal("port 70000 accepted")
	}
	if _, err := pgConfig(dbTarget{Host: "db", Port: "5432", Database: "a", User: "u", CAPEM: "not a cert"}); err == nil {
		t.Fatal("a ca_pem without a certificate accepted")
	}
	if _, err := targetFrom(credstore.Credential{ID: "c", Type: "smtp"}); err == nil {
		t.Fatal("a credential of another type accepted")
	}
}

func TestTTLsStayWithinTheRole(t *testing.T) {
	if d, err := ttlWithin(0, 3600, 7200); err != nil || d != time.Hour {
		t.Fatalf("default %v %v", d, err)
	}
	for _, req := range []int{30, 7201} {
		if _, err := ttlWithin(req, 3600, 7200); err == nil {
			t.Fatalf("ttl %d accepted", req)
		}
	}
}
