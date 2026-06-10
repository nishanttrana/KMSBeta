package main

import (
	"os"
	"testing"
)

// TestFeatureForgeRecognizedAsComponent verifies FeatureForge is a first-class
// replication component: its aliases normalize to the canonical "featureforge"
// name and it renders with a stable display name. Without this, a custom
// profile that selects FeatureForge would silently drop it.
func TestFeatureForgeRecognizedAsComponent(t *testing.T) {
	for _, alias := range []string{"featureforge", "feature_forge", "Feature_Forge", " FEATURE_CLASSIFICATION "} {
		if got := normalizeComponentName(alias); got != "featureforge" {
			t.Errorf("normalizeComponentName(%q) = %q, want %q", alias, got, "featureforge")
		}
	}
	if got := componentDisplayName("featureforge"); got != "FeatureForge" {
		t.Errorf("componentDisplayName(featureforge) = %q, want FeatureForge", got)
	}
}

// TestFullPresetIncludesFeatureForge ensures the full built-in replication
// profile replicates FeatureForge state alongside every other service.
func TestFullPresetIncludesFeatureForge(t *testing.T) {
	full, ok := builtinClusterProfileByID("root", "cluster-profile-full", false)
	if !ok {
		t.Fatal("cluster-profile-full preset not found")
	}
	found := false
	for _, c := range full.Components {
		if c == "featureforge" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("cluster-profile-full does not include featureforge; components=%v", full.Components)
	}
}

// TestParseEnvComponents covers the CLUSTER_BOOTSTRAP_COMPONENTS parsing used to
// seed an operator-defined custom HA profile: CSV/space separated, normalized,
// with unknown names dropped.
func TestParseEnvComponents(t *testing.T) {
	const key = "CLUSTER_BOOTSTRAP_COMPONENTS_TEST"
	t.Setenv(key, "secrets, certs ,featureforge,not_a_real_service")
	got := parseEnvComponents(key)

	want := map[string]bool{"secrets": true, "certs": true, "featureforge": true}
	if len(got) != len(want) {
		t.Fatalf("parseEnvComponents returned %v, want keys %v", got, want)
	}
	for _, c := range got {
		if !want[c] {
			t.Errorf("unexpected component %q (unknown names should be dropped)", c)
		}
	}

	_ = os.Unsetenv(key)
	if got := parseEnvComponents(key); got != nil {
		t.Errorf("parseEnvComponents on unset env = %v, want nil", got)
	}
}

// TestCustomBootstrapProfile verifies that a non-builtin profile ID plus a
// selected component set produces a seedable custom profile, while a builtin ID
// or an empty component set does not.
func TestCustomBootstrapProfile(t *testing.T) {
	s := &Service{bootstrapProfileID: "cluster-profile-custom", bootstrapComponents: []string{"secrets", "featureforge"}}
	profile, ok := s.customBootstrapProfile("root")
	if !ok {
		t.Fatal("expected custom profile to be produced")
	}
	if profile.ID != "cluster-profile-custom" {
		t.Errorf("custom profile ID = %q, want cluster-profile-custom", profile.ID)
	}
	// Core components are always merged in.
	for _, core := range []string{"auth", "keycore", "policy", "governance"} {
		if !containsComponent(profile.Components, core) {
			t.Errorf("custom profile missing required core component %q; got %v", core, profile.Components)
		}
	}
	if !containsComponent(profile.Components, "featureforge") {
		t.Errorf("custom profile missing selected featureforge; got %v", profile.Components)
	}

	// Builtin ID must not be treated as custom.
	sBuiltin := &Service{bootstrapProfileID: "cluster-profile-full", bootstrapComponents: []string{"secrets"}}
	if _, ok := sBuiltin.customBootstrapProfile("root"); ok {
		t.Error("builtin profile ID should not produce a custom profile")
	}

	// No components means nothing to seed.
	sEmpty := &Service{bootstrapProfileID: "cluster-profile-custom"}
	if _, ok := sEmpty.customBootstrapProfile("root"); ok {
		t.Error("empty component set should not produce a custom profile")
	}
}

func containsComponent(list []string, want string) bool {
	for _, c := range list {
		if c == want {
			return true
		}
	}
	return false
}
