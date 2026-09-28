package cbom

import "testing"

// Tiers follow the security strengths in pkg/cryptocatalog. Before
// 3.2.0-beta RSA-2048 was classical-128, RSA-3072 classical-192, RSA-4096
// and P-384 classical-256, and HMAC, Ed25519 and ECDH fell to "deprecated".
func TestClassifyTierUsesSecurityStrengths(t *testing.T) {
	for alg, want := range map[string]Tier{
		"RSA-2048":          TierClassical112,
		"RSA-3072":          TierClassical128,
		"RSA-4096":          TierClassical128,
		"ECDSA-P256":        TierClassical128,
		"ECDSA-P384":        TierClassical192,
		"ECDSA-P521":        TierClassical256,
		"ECDH-P384":         TierClassical192,
		"Ed25519":           TierClassical128,
		"AES-128-GCM":       TierClassical128,
		"AES-256":           TierClassical256,
		"HMAC-SHA256":       TierClassical256,
		"ML-KEM-768":        TierPQCOnly,
		"ML-DSA-65":         TierPQCOnly,
		"SLH-DSA-SHA2-128s": TierPQCOnly,
		"X25519MLKEM768":    TierPQCHybrid,
		"3DES":              TierDeprecated,
		"DES":               TierDeprecated,
		"RSA-1024":          TierDeprecated,
		"SHA-1":             TierDeprecated,
		"AES-256-ECB":       TierDeprecated,
		"X25519":            TierClassical128,
		"RSA":               TierNotAssessed,
		"Brainpool-P256":    TierNotAssessed,
	} {
		if got := ClassifyTier(alg, ""); got != want {
			t.Errorf("%s: tier %s, want %s", alg, got, want)
		}
	}
	if got := ClassifyTier("ML-KEM-768", "hybrid"); got != TierPQCHybrid {
		t.Errorf("hybrid parameter: %s", got)
	}
}

func TestMeetsFloorFailsClosed(t *testing.T) {
	cases := []struct {
		actual, floor Tier
		want          bool
	}{
		{TierClassical112, TierClassical112, true},
		{TierClassical112, TierClassical128, false}, // RSA-2048 under a 128-bit floor
		{TierClassical128, TierClassical192, false}, // RSA-3072 under a 192-bit floor
		{TierClassical256, TierClassical128, true},
		{TierPQCOnly, TierPQCHybrid, true},
		{TierPQCHybrid, TierPQCOnly, false},
		{TierDeprecated, TierClassical112, false},
		{TierNotAssessed, TierClassical112, false},
		{TierPQCOnly, "classical-100", false}, // unknown floor: nothing meets it
		{TierPQCOnly, TierDeprecated, false},  // not a floor
	}
	for _, c := range cases {
		if got := MeetsFloor(c.actual, c.floor); got != c.want {
			t.Errorf("MeetsFloor(%s, %s) = %v, want %v", c.actual, c.floor, got, c.want)
		}
	}
	for _, s := range []string{"classical-112", " PQC-Hybrid "} {
		if _, ok := ParseTier(s); !ok {
			t.Errorf("ParseTier(%q) rejected a floor", s)
		}
	}
	for _, s := range []string{"", "deprecated", "not-assessed", "classical-100"} {
		if _, ok := ParseTier(s); ok {
			t.Errorf("ParseTier(%q) accepted a non-floor", s)
		}
	}
}

func TestBuildFlagsWeakAlgorithms(t *testing.T) {
	inv := Build("t1", TierClassical128, []Entry{
		{Algorithm: "3DES", KeyCount: 2},
		{Algorithm: "RSA-2048", KeyCount: 3},
		{Algorithm: "AES-256", KeyCount: 5},
	})
	byAlg := map[string]Entry{}
	for _, e := range inv.Entries {
		byAlg[e.Algorithm] = e
	}
	if e := byAlg["3DES"]; !e.Deprecated || e.Note != "weak algorithm; below floor classical-128" {
		t.Errorf("3DES entry = %+v", e)
	}
	if e := byAlg["RSA-2048"]; e.Deprecated || e.Note != "below floor classical-128" {
		t.Errorf("RSA-2048 entry = %+v", e)
	}
	if e := byAlg["AES-256"]; e.Deprecated || e.Note != "" {
		t.Errorf("AES-256 entry = %+v", e)
	}
	if inv.ReadinessPercent != 50 {
		t.Errorf("readiness %v, want 50 (5 of 10 keys meet classical-128)", inv.ReadinessPercent)
	}
}
