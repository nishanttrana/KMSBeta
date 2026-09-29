package cryptocatalog

import "testing"

func TestCatalogFacts(t *testing.T) {
	cases := []struct {
		name, canonical      string
		bits, category       int
		vulnerable, pq, weak bool
	}{
		{"RSA-2048", "RSA-2048", 112, 0, true, false, false},
		{"rsa_3072", "RSA-3072", 128, 0, true, false, false},
		{"RSA-4096", "RSA-4096", 128, 0, true, false, false},
		{"RSA-8192", "RSA-8192", 192, 0, true, false, false},
		{"RSA-1024", "RSA-1024", 80, 0, true, false, true},
		{"ECDSA-P256", "ECDSA-P256", 128, 0, true, false, false},
		{"ECDSA-P384", "ECDSA-P384", 192, 0, true, false, false},
		{"ECDSA-P521", "ECDSA-P521", 256, 0, true, false, false},
		{"ECDH-P256", "ECDH-P256", 128, 0, true, false, false},
		{"Ed25519", "Ed25519", 128, 0, true, false, false},
		{"X25519", "X25519", 128, 0, true, false, false},
		{"DH-2048", "DH-2048", 112, 0, true, false, false},
		{"DSA", "DSA", 0, 0, true, false, false},
		{"ML-KEM-768", "ML-KEM-768", 192, 3, false, true, false},
		{"mlkem1024", "ML-KEM-1024", 256, 5, false, true, false},
		{"ML-DSA-44", "ML-DSA-44", 128, 2, false, true, false},
		{"ML-DSA-65", "ML-DSA-65", 192, 3, false, true, false},
		{"ML-DSA-87", "ML-DSA-87", 256, 5, false, true, false},
		{"SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128s", 128, 1, false, true, false},
		{"SLH-DSA-256f", "SLH-DSA-SHAKE-256f", 256, 5, false, true, false},
		{"LMS", "LMS", 0, 0, false, true, false},
		{"AES-128", "AES-128", 128, 1, false, false, false},
		{"AES-128-CBC", "AES-128-CBC", 128, 1, false, false, false},
		{"AES-256-GCM", "AES-256-GCM", 256, 5, false, false, false},
		{"AES-256-ECB", "AES-256-ECB", 256, 5, false, false, true},
		{"AES-256-FF3", "AES-256-FF3", 256, 5, false, false, true},
		{"3DES", "3TDEA", 112, 0, false, false, true},
		{"2DES", "2TDEA", 80, 0, false, false, true},
		{"DES", "DES", 0, 0, false, false, true},
		{"HMAC-SHA256", "HMAC-SHA-256", 256, 0, false, false, false},
		{"HMAC-SHA1", "HMAC-SHA-1", 128, 0, false, false, false},
		{"SHA-1", "SHA-1", 80, 0, false, false, true},
		{"SHA-224", "SHA-224", 112, 0, false, false, false},
		{"SHA-256", "SHA-256", 128, 2, false, false, false},
		{"SHA3-512", "SHA3-512", 256, 5, false, false, false},
		{"ChaCha20-Poly1305", "CHACHA20-POLY1305", 256, 0, false, false, false},
		{"MD5", "MD5", 0, 0, false, false, true},
	}
	for _, c := range cases {
		e, ok := Lookup(c.name)
		if !ok {
			t.Errorf("%s: not found", c.name)
			continue
		}
		if e.Algorithm != c.canonical || e.SecurityBits != c.bits || e.PQCCategory != c.category ||
			e.QuantumVulnerable != c.vulnerable || e.PostQuantum != c.pq || e.Weak != c.weak {
			t.Errorf("%s: got %+v", c.name, e)
		}
	}
}

func TestNamesWithoutAParameterSetAreNotAssessed(t *testing.T) {
	for _, name := range []string{"", "RSA", "AES", "ECDSA", "ML-KEM", "CRYSTALS-Kyber", "Dilithium3", "ECDSA-Brainpool-P256r1", "RSA-KEX", "AES-256-GCM-SIV", "UNKNOWN"} {
		if e, ok := Lookup(name); ok {
			t.Errorf("%q assessed as %s; a name without a parameter set must not be guessed", name, e.Algorithm)
		}
		if a := Assess(name); a.Assessed || a.Class != "unknown" || a.Ready {
			t.Errorf("%q: assessment %+v, want unknown", name, a)
		}
	}
}

func TestHybridKeyEstablishment(t *testing.T) {
	for _, name := range []string{"X25519MLKEM768", "X25519-ML-KEM-768-HYBRID", "ECDH-P256-ML-KEM-768-HYBRID", "SecP384r1MLKEM1024", "ML-KEM-768+X25519"} {
		e, ok := Lookup(name)
		if !ok || !e.Hybrid || !e.PostQuantum || e.QuantumVulnerable {
			t.Errorf("%s: %+v (ok=%v), want a quantum-resistant hybrid", name, e, ok)
		}
	}
	if e, _ := Lookup("SecP384r1MLKEM1024"); e.PQCCategory != 5 {
		t.Errorf("hybrid category follows its ML-KEM component, got %d", e.PQCCategory)
	}
	for _, name := range []string{"hybrid ML-KEM key exchange (X25519MLKEM768)", "X25519Kyber768Draft00", "ML-KEM-768 or X25519"} {
		if e, ok := Lookup(name); ok {
			t.Errorf("%q parsed as %s", name, e.Algorithm)
		}
	}
}

// The mislabels this catalogue replaced (learning.md 2026-09-29).
func TestAssessmentDoesNotRepeatTheOldMislabels(t *testing.T) {
	for name, want := range map[string]string{
		"RSA-4096":          "vulnerable",
		"ECDSA-P256":        "vulnerable",
		"SLH-DSA-SHA2-128s": "strong",
		"AES-128-CBC":       "strong",
		"AES-256-ECB":       "vulnerable",
		"3DES":              "vulnerable",
		"X25519MLKEM768":    "strong",
	} {
		if got := Assess(name).Class; got != want {
			t.Errorf("%s: class %s, want %s", name, got, want)
		}
	}
	if !Assess("SLH-DSA-SHA2-128s").PQCReady || Assess("RSA-4096").Ready {
		t.Fatal("readiness flags wrong")
	}
}

// TLS group names, as the edge probe reports them, are key establishment.
func TestTLSGroupNames(t *testing.T) {
	for name, want := range map[string]struct{ hybrid, vulnerable bool }{
		"X25519MLKEM768": {true, false}, "SecP256r1MLKEM768": {true, false}, "SecP384r1MLKEM1024": {true, false},
		"X25519": {false, true}, "CurveP256": {false, true}, "CurveP384": {false, true}, "secp384r1": {false, true},
	} {
		e, ok := Lookup(name)
		if !ok || e.Function != "key_establishment" || e.Hybrid != want.hybrid || e.QuantumVulnerable != want.vulnerable {
			t.Fatalf("%s: %+v %v", name, e, ok)
		}
	}
}
