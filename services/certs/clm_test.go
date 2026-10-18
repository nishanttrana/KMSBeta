package main

import (
	"context"
	"testing"
	"time"
)

// The lifetime policy holds only the tenant's own values: no external
// schedule and no preset limit (13.22.0-beta).
func TestCLMPolicyIsTheTenantsOwn(t *testing.T) {
	svc, _ := newCertsService(t)
	ctx := context.Background()

	p, err := svc.GetCLMPolicy(ctx, "t-clm")
	if err != nil {
		t.Fatal(err)
	}
	if p.Mode != CLMModeOff || p.MaxValidityDays != 0 || effectiveMaxValidityDays(p) != 0 {
		t.Fatalf("a tenant with no saved policy must have none, got %+v", p)
	}
	st, err := svc.GetCLMStatus(ctx, "t-clm")
	if err != nil {
		t.Fatal(err)
	}
	if st.OverLimitCerts != nil {
		t.Fatalf("over-limit is counted only against a limit the tenant set, got %d", *st.OverLimitCerts)
	}

	for _, bad := range []CLMPolicy{
		{TenantID: "t-clm", Mode: CLMModeWarn, MaxValidityDays: 0},
		{TenantID: "t-clm", Mode: CLMModeEnforce, MaxValidityDays: maxCLMValidityDays + 1},
		{TenantID: "t-clm", Mode: "schedule", MaxValidityDays: 90},
	} {
		if _, err := svc.UpsertCLMPolicy(ctx, bad); err == nil {
			t.Fatalf("policy %+v must be refused", bad)
		}
	}
	saved, err := svc.UpsertCLMPolicy(ctx, CLMPolicy{TenantID: "t-clm", Mode: CLMModeEnforce, MaxValidityDays: 500})
	if err != nil {
		t.Fatal(err)
	}
	got, err := svc.GetCLMPolicy(ctx, "t-clm")
	if err != nil || got.Mode != CLMModeEnforce || got.MaxValidityDays != 500 || effectiveMaxValidityDays(saved) != 500 {
		t.Fatalf("saved policy = %+v (%v), want enforce 500: no schedule tightens it", got, err)
	}
}

// Issuance follows the tenant's mode and limit, and the audit events carry
// the tenant's values only.
func TestCLMIssuanceFollowsTheTenantsPolicy(t *testing.T) {
	svc, _ := newCertsService(t)
	rec := &subjectRecorder{}
	svc.events = rec
	ctx := context.Background()
	ca, err := svc.CreateCA(ctx, CreateCARequest{TenantID: "t-life", Name: "root", CALevel: "root", Algorithm: "ECDSA-P384", KeyBackend: "software", Subject: "CN=Root"})
	if err != nil {
		t.Fatal(err)
	}
	issue := func(cn string) Certificate {
		t.Helper()
		c, _, err := svc.IssueCertificate(ctx, IssueCertificateRequest{TenantID: "t-life", CAID: ca.ID, SubjectCN: cn, CertType: "tls-server", Algorithm: "ECDSA-P256", ValidityDays: 365})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	days := func(c Certificate) int64 { return int64(c.NotAfter.Sub(c.NotBefore).Round(time.Hour).Hours() / 24) }

	if d := days(issue("no-policy.local")); d < 364 {
		t.Fatalf("with no policy the requested 365 days stand, got %d", d)
	}
	if rec.count("audit.cert.clm_validity_warning")+rec.count("audit.cert.clm_validity_clamped") != 0 {
		t.Fatal("no lifetime event may fire without a tenant policy")
	}

	if _, err := svc.UpsertCLMPolicy(ctx, CLMPolicy{TenantID: "t-life", Mode: CLMModeWarn, MaxValidityDays: 90}); err != nil {
		t.Fatal(err)
	}
	if d := days(issue("warn.local")); d < 364 {
		t.Fatalf("warn keeps the requested lifetime, got %d", d)
	}
	warned := rec.last(t, "audit.cert.clm_validity_warning")
	if warned["max_validity_days"] != float64(90) || warned["mode"] != CLMModeWarn {
		t.Fatalf("warning detail = %v", warned)
	}

	if _, err := svc.UpsertCLMPolicy(ctx, CLMPolicy{TenantID: "t-life", Mode: CLMModeEnforce, MaxValidityDays: 90}); err != nil {
		t.Fatal(err)
	}
	if d := days(issue("enforce.local")); d > 91 {
		t.Fatalf("enforce shortens to the tenant's 90 days, got %d", d)
	}
	clamped := rec.last(t, "audit.cert.clm_validity_clamped")
	for _, k := range []string{"schedule_aware", "cab_schedule_days"} {
		if _, ok := clamped[k]; ok {
			t.Fatalf("audit detail still carries %s: %v", k, clamped)
		}
	}
	if clamped["max_validity_days"] != float64(90) || clamped["requested_days"] == nil {
		t.Fatalf("clamped detail = %v", clamped)
	}
	updated := rec.last(t, "audit.cert.clm_policy_updated")
	if updated["mode"] != CLMModeEnforce || updated["max_validity_days"] != float64(90) {
		t.Fatalf("policy update detail = %v", updated)
	}

	st, err := svc.GetCLMStatus(ctx, "t-life")
	if err != nil {
		t.Fatal(err)
	}
	if st.OverLimitCerts == nil || *st.OverLimitCerts != 2 || st.ActiveTLSCerts != 3 {
		t.Fatalf("status = %+v, want 3 TLS certs, 2 over the tenant's 90 days", st)
	}
}

func TestCLMAppliesTo(t *testing.T) {
	for _, certType := range []string{"tls-server", "tls-client", "TLS-Server"} {
		if !clmAppliesTo(certType) {
			t.Errorf("clmAppliesTo(%q) = false, want true", certType)
		}
	}
	for _, certType := range []string{"email", "code-signing", "ca", ""} {
		if clmAppliesTo(certType) {
			t.Errorf("clmAppliesTo(%q) = true, want false", certType)
		}
	}
}
