package fips

import (
	"crypto/fips140"
	"os"
	"strings"
	"testing"
)

func TestModeMatchesGoRuntime(t *testing.T) {
	want := ModeOff
	if fips140.Enforced() {
		want = ModeOnly
	} else if fips140.Enabled() {
		want = ModeOn
	}
	if got := Mode(); got != want {
		t.Fatalf("Mode()=%q, runtime says %q", got, want)
	}
	if FIPSMode != (want != ModeOff) {
		t.Fatalf("FIPSMode=%v inconsistent with mode %q", FIPSMode, want)
	}
}

func TestVerifyRuntime(t *testing.T) {
	t.Setenv("VECTA_FIPS_MODE", "")
	if err := VerifyRuntime(); err != nil {
		t.Fatalf("unset VECTA_FIPS_MODE must follow the runtime: %v", err)
	}
	t.Setenv("VECTA_FIPS_MODE", "true")
	if err := VerifyRuntime(); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("legacy/unknown values must be rejected, got %v", err)
	}
	// A choice that differs from the running mode must fail closed.
	other := ModeOff
	if Mode() == ModeOff {
		other = ModeOn
	}
	t.Setenv("VECTA_FIPS_MODE", other)
	if err := VerifyRuntime(); err == nil {
		t.Fatalf("VECTA_FIPS_MODE=%s while running %s must be rejected", other, Mode())
	}
	t.Setenv("VECTA_FIPS_MODE", Mode())
	err := VerifyRuntime()
	if Mode() == ModeOff || fips140.Version() == CertifiedModuleVersion {
		if err != nil {
			t.Fatalf("matching mode on the certified module must pass: %v", err)
		}
	} else if err == nil {
		t.Fatal("FIPS mode without the certified module must be rejected")
	}
}

// CI builds with GOFIPS140=v1.0.0 and sets VECTA_REQUIRE_CERTIFIED_MODULE=1 so
// this proves the shipped binaries link the certified module.
func TestBuiltWithCertifiedModule(t *testing.T) {
	if os.Getenv("VECTA_REQUIRE_CERTIFIED_MODULE") != "1" {
		t.Skip("set VECTA_REQUIRE_CERTIFIED_MODULE=1 (with GOFIPS140) to assert the build")
	}
	if v := fips140.Version(); v != CertifiedModuleVersion {
		t.Fatalf("module version %q, want certified %q (build with GOFIPS140=%s)", v, CertifiedModuleVersion, CertifiedModuleVersion)
	}
	if fips140.Enabled() != ModuleValidated() {
		t.Fatal("ModuleValidated must equal Enabled on the certified module")
	}
}
