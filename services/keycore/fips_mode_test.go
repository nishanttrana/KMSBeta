package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIsFIPSApprovedKeyAlgorithm(t *testing.T) {
	cases := []struct {
		algorithm string
		want      bool
	}{
		{algorithm: "AES-256-GCM", want: true},
		{algorithm: "RSA-3072", want: true},
		{algorithm: "ECDSA-P384", want: true},
		{algorithm: "ChaCha20-Poly1305", want: false},
		{algorithm: "Camellia-256", want: false},
	}
	for _, tc := range cases {
		got := isFIPSApprovedKeyAlgorithm(tc.algorithm)
		if got != tc.want {
			t.Fatalf("algorithm=%q got=%v want=%v", tc.algorithm, got, tc.want)
		}
	}
}

func TestServiceFIPSKeyEnforcement(t *testing.T) {
	svc := &Service{fipsMode: staticFIPSModeProvider{enabled: true}}
	if err := svc.enforceFIPSKeyAlgorithm(context.Background(), "t1", "AES-256-GCM", "key.encrypt"); err != nil {
		t.Fatalf("expected AES to be allowed, got error: %v", err)
	}
	err := svc.enforceFIPSKeyAlgorithm(context.Background(), "t1", "ChaCha20-Poly1305", "key.encrypt")
	if err == nil {
		t.Fatalf("expected non-fips algorithm to be blocked")
	}
	var denied fipsModeViolationError
	if !errors.As(err, &denied) {
		t.Fatalf("expected fipsModeViolationError, got %T", err)
	}
}

func TestServiceFIPSHashAndRandomEnforcement(t *testing.T) {
	svc := &Service{fipsMode: staticFIPSModeProvider{enabled: true}}
	if err := svc.enforceFIPSHashAlgorithm(context.Background(), "t1", "sha-256"); err != nil {
		t.Fatalf("expected sha-256 to be allowed, got error: %v", err)
	}
	if err := svc.enforceFIPSHashAlgorithm(context.Background(), "t1", "blake2b-256"); err == nil {
		t.Fatalf("expected blake2b to be blocked")
	}
	if err := svc.enforceFIPSRandomSource(context.Background(), "t1", "kms-csprng"); err != nil {
		t.Fatalf("expected kms-csprng to be allowed, got error: %v", err)
	}
	if err := svc.enforceFIPSRandomSource(context.Background(), "t1", "qkd-seeded-csprng"); err == nil {
		t.Fatalf("expected qkd source to be blocked")
	}
}

func TestHTTPFIPSModeProvider(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"state":{"fips_mode":"enabled"}}`))
	}))
	defer srv.Close()

	provider := NewHTTPFIPSModeProvider(srv.URL, time.Second, 2*time.Second)
	enabled, err := provider.IsEnabled(context.Background(), "root")
	if err != nil {
		t.Fatalf("provider read failed: %v", err)
	}
	if !enabled {
		t.Fatalf("expected enabled mode")
	}
}
