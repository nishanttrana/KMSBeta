package main

import (
	"errors"
	"testing"
	"time"

	pkgcache "vecta-kms/pkg/cache"
	"vecta-kms/pkg/metering"
)

// hsm-trng, qkd-seeded-csprng and qrng-seeded-csprng used to return the OS
// CSPRNG under their own label. Without the real source they now refuse, and
// the refusal is audited.
func TestRandomNeverSubstitutesASource(t *testing.T) {
	rec := &eventRecorder{}
	svc := NewService(newStoreForTest(t), NewKeyCache(pkgcache.NewMemory(5*time.Minute), 5*time.Minute), rec,
		metering.NewMeter(0, time.Hour), []byte("0123456789ABCDEF0123456789ABCDEF"), nil, false)
	ctx := adminCtx()
	for _, src := range []string{"hsm-trng", "qkd-seeded-csprng", "qrng-seeded-csprng"} {
		rec.events = nil
		resp, err := svc.Random(ctx, RandomRequest{TenantID: "t1", Source: src, Length: 32})
		if !errors.Is(err, errRandomSourceUnavailable) {
			t.Fatalf("%s: got %+v, %v; want a refusal", src, resp, err)
		}
		refusalDetails(t, rec, "audit.crypto.random_refused")
		if rec.find("audit.crypto.random") != nil {
			t.Fatalf("%s: a refusal was audited as random bytes served", src)
		}
	}
	resp, err := svc.Random(ctx, RandomRequest{TenantID: "t1", Source: "kms-csprng", Length: 16})
	if err != nil || resp.Source != "kms-csprng" || resp.Length != 16 {
		t.Fatalf("kms-csprng: %+v %v", resp, err)
	}
}

// With a tenant HSM, hsm-trng bytes come from C_GenerateRandom on the real
// PKCS#11 library, and the audit event names the HSM.
func TestRandomFromHSM(t *testing.T) {
	svc, rec, _ := newHSMService(t, "t1")
	resp, err := svc.Random(adminCtx(), RandomRequest{TenantID: "t1", Source: "hsm-trng", Length: 48})
	if err != nil || resp.Source != "hsm-trng" || resp.Length != 48 || resp.BytesB64 == "" {
		t.Fatalf("hsm-trng: %+v %v", resp, err)
	}
	ev := rec.find("audit.crypto.random")
	if ev == nil {
		t.Fatal("no audit.crypto.random event")
	}
	if d, _ := ev["details"].(map[string]any); d["source"] != "hsm-trng" || d["hsm_serial"] == nil || d["hsm_serial"] == "" {
		t.Fatalf("event does not name the HSM: %+v", ev)
	}
	if _, err := svc.Random(adminCtx(), RandomRequest{TenantID: "t-no-hsm", Source: "hsm-trng", Length: 8}); !errors.Is(err, errRandomSourceUnavailable) {
		t.Fatalf("tenant without an HSM: %v", err)
	}
}
