package cryptocatalog

import (
	"testing"
	"time"
)

var (
	today     = time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	in2031    = time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	lastOf30  = time.Date(2030, 12, 31, 0, 0, 0, 0, time.UTC)
	in2036    = time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC)
	lastOf35  = time.Date(2035, 12, 31, 0, 0, 0, 0, time.UTC)
	farFuture = time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC)
)

// Each row is copied from the cited table; the test fails if the catalogue
// drifts from the source.
func TestCatalogMatchesNISTTables(t *testing.T) {
	cases := []struct {
		name                         string
		canonical                    string
		bits, category               int
		vulnerable, pq               bool
		now, on2031, on2036, farLate Status
	}{
		// SP 800-57 Pt1 Table 2 strengths; SP 800-131Ar3 Table 3/6; IR 8547 Tables 2/4.
		{"RSA-2048", "RSA-2048", 112, 0, true, false, Acceptable, Deprecated, Disallowed, Disallowed},
		{"rsa_3072", "RSA-3072", 128, 0, true, false, Acceptable, Acceptable, Disallowed, Disallowed},
		{"RSA-4096", "RSA-4096", 128, 0, true, false, Acceptable, Acceptable, Disallowed, Disallowed},
		{"RSA-8192", "RSA-8192", 192, 0, true, false, Acceptable, Acceptable, Disallowed, Disallowed},
		{"RSA-1024", "RSA-1024", 80, 0, true, false, LegacyUse, LegacyUse, LegacyUse, LegacyUse},
		// EC strength is half of len(n) (SP 800-131Ar3 §3).
		{"ECDSA-P256", "ECDSA-P256", 128, 0, true, false, Acceptable, Acceptable, Disallowed, Disallowed},
		{"ECDSA-P384", "ECDSA-P384", 192, 0, true, false, Acceptable, Acceptable, Disallowed, Disallowed},
		{"ECDSA-P521", "ECDSA-P521", 256, 0, true, false, Acceptable, Acceptable, Disallowed, Disallowed},
		{"ECDH-P256", "ECDH-P256", 128, 0, true, false, Acceptable, Acceptable, Disallowed, Disallowed},
		{"Ed25519", "Ed25519", 128, 0, true, false, Acceptable, Acceptable, Disallowed, Disallowed},
		{"DH-2048", "DH-2048", 112, 0, true, false, Acceptable, Deprecated, Disallowed, Disallowed},
		{"X25519", "X25519", 0, 0, true, false, NotApproved, NotApproved, NotApproved, NotApproved},
		{"DSA", "DSA", 0, 0, true, false, LegacyUse, LegacyUse, LegacyUse, LegacyUse},
		// FIPS 203/204/205 via IR 8547 Tables 3 and 5; SP 800-131Ar3 Table 3, Sec. 8.
		{"ML-KEM-768", "ML-KEM-768", 192, 3, false, true, Acceptable, Acceptable, Acceptable, Acceptable},
		{"mlkem1024", "ML-KEM-1024", 256, 5, false, true, Acceptable, Acceptable, Acceptable, Acceptable},
		{"ML-DSA-44", "ML-DSA-44", 128, 2, false, true, Acceptable, Acceptable, Acceptable, Acceptable},
		{"ML-DSA-65", "ML-DSA-65", 192, 3, false, true, Acceptable, Acceptable, Acceptable, Acceptable},
		{"ML-DSA-87", "ML-DSA-87", 256, 5, false, true, Acceptable, Acceptable, Acceptable, Acceptable},
		{"SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128s", 128, 1, false, true, Acceptable, Acceptable, Acceptable, Acceptable},
		{"SLH-DSA-256f", "SLH-DSA-SHAKE-256f", 256, 5, false, true, Acceptable, Acceptable, Acceptable, Acceptable},
		{"LMS", "LMS", 0, 0, false, true, Acceptable, Acceptable, Acceptable, Acceptable},
		// IR 8547 Table 6 categories; SP 800-131Ar3 Tables 1 and 2.
		{"AES-128", "AES-128", 128, 1, false, false, Acceptable, Acceptable, Acceptable, Acceptable},
		{"AES-128-CBC", "AES-128-CBC", 128, 1, false, false, Acceptable, Acceptable, Acceptable, Acceptable},
		{"AES-256-GCM", "AES-256-GCM", 256, 5, false, false, Acceptable, Acceptable, Acceptable, Acceptable},
		{"AES-256-ECB", "AES-256-ECB", 256, 5, false, false, LegacyUse, LegacyUse, LegacyUse, LegacyUse},
		{"AES-256-FF3", "AES-256-FF3", 256, 5, false, false, Disallowed, Disallowed, Disallowed, Disallowed},
		{"3DES", "3TDEA", 112, 0, false, false, LegacyUse, LegacyUse, LegacyUse, LegacyUse},
		{"2DES", "2TDEA", 80, 0, false, false, LegacyUse, LegacyUse, LegacyUse, LegacyUse},
		{"DES", "DES", 0, 0, false, false, Disallowed, Disallowed, Disallowed, Disallowed},
		// SP 800-57 Pt1 Table 3 (HMAC); SP 800-131Ar3 Table 15.
		{"HMAC-SHA256", "HMAC-SHA-256", 256, 0, false, false, Acceptable, Acceptable, Acceptable, Acceptable},
		{"HMAC-SHA1", "HMAC-SHA-1", 128, 0, false, false, Deprecated, Disallowed, Disallowed, Disallowed},
		{"HMAC-SHA-224", "HMAC-SHA-224", 192, 0, false, false, Deprecated, Disallowed, Disallowed, Disallowed},
		// IR 8547 Table 7 collision strengths; SP 800-131Ar3 Table 13.
		{"SHA-1", "SHA-1", 80, 0, false, false, LegacyUse, LegacyUse, LegacyUse, LegacyUse},
		{"SHA-224", "SHA-224", 112, 0, false, false, Deprecated, Disallowed, Disallowed, Disallowed},
		{"SHA-256", "SHA-256", 128, 2, false, false, Acceptable, Acceptable, Acceptable, Acceptable},
		{"SHA3-512", "SHA3-512", 256, 5, false, false, Acceptable, Acceptable, Acceptable, Acceptable},
		{"ChaCha20-Poly1305", "CHACHA20-POLY1305", 0, 0, false, false, NotApproved, NotApproved, NotApproved, NotApproved},
		{"MD5", "MD5", 0, 0, false, false, NotApproved, NotApproved, NotApproved, NotApproved},
	}
	for _, c := range cases {
		e, ok := Lookup(c.name)
		if !ok {
			t.Errorf("%s: not found", c.name)
			continue
		}
		if e.Algorithm != c.canonical || e.SecurityBits != c.bits || e.PQCCategory != c.category ||
			e.QuantumVulnerable != c.vulnerable || e.PostQuantum != c.pq {
			t.Errorf("%s: got %s bits=%d cat=%d qv=%v pq=%v, want %s bits=%d cat=%d qv=%v pq=%v",
				c.name, e.Algorithm, e.SecurityBits, e.PQCCategory, e.QuantumVulnerable, e.PostQuantum,
				c.canonical, c.bits, c.category, c.vulnerable, c.pq)
		}
		for _, at := range []struct {
			when time.Time
			want Status
		}{{today, c.now}, {in2031, c.on2031}, {in2036, c.on2036}, {farFuture, c.farLate}} {
			if got := e.StatusAt(at.when); got != at.want {
				t.Errorf("%s on %s: status %s, want %s", c.name, at.when.Format("2006-01-02"), got, at.want)
			}
		}
		if len(e.Sources()) == 0 {
			t.Errorf("%s: no cited source", c.name)
		}
	}
}

// "After 2030" starts on January 1, 2031; December 31 is still the old status.
func TestTransitionDayBoundaries(t *testing.T) {
	rsa, _ := Lookup("RSA-2048")
	if rsa.StatusAt(lastOf30) != Acceptable || rsa.StatusAt(in2031) != Deprecated {
		t.Fatalf("RSA-2048 deprecation boundary wrong")
	}
	if rsa.StatusAt(lastOf35) != Deprecated || rsa.StatusAt(in2036) != Disallowed {
		t.Fatalf("RSA-2048 disallowance boundary wrong")
	}
	next, ok := rsa.Next(today)
	if !ok || next.From != "2031-01-01" || next.Status != Deprecated || next.Source != SrcSP800131Ar3 {
		t.Fatalf("RSA-2048 next change = %+v", next)
	}
}

func TestNamesWithoutAParameterSetAreNotAssessed(t *testing.T) {
	for _, name := range []string{"", "RSA", "AES", "ECDSA", "ML-KEM", "CRYSTALS-Kyber", "Dilithium3", "ECDSA-Brainpool-P256r1", "RSA-KEX", "AES-256-GCM-SIV", "UNKNOWN"} {
		if e, ok := Lookup(name); ok {
			t.Errorf("%q assessed as %s; a name without a NIST parameter set must not be guessed", name, e.Algorithm)
		}
		if a := Assess(name, today); a.Assessed || a.Class != "unknown" || a.Ready {
			t.Errorf("%q: assessment %+v, want unknown", name, a)
		}
	}
}

func TestHybridKeyEstablishment(t *testing.T) {
	for _, name := range []string{"X25519MLKEM768", "X25519-ML-KEM-768-HYBRID", "ECDH-P256-ML-KEM-768-HYBRID", "SecP384r1MLKEM1024", "ML-KEM-768+X25519"} {
		e, ok := Lookup(name)
		if !ok || !e.Hybrid || !e.PostQuantum || e.QuantumVulnerable {
			t.Errorf("%s: %+v (ok=%v), want a quantum-resistant hybrid", name, e, ok)
			continue
		}
		if e.StatusAt(today) != NotTabled {
			t.Errorf("%s: status %s; the cited drafts do not table hybrids", name, e.StatusAt(today))
		}
	}
	if e, _ := Lookup("SecP384r1MLKEM1024"); e.PQCCategory != 5 {
		t.Errorf("hybrid category follows its ML-KEM component, got %d", e.PQCCategory)
	}
	// Free text that mentions ML-KEM is not an algorithm name.
	for _, name := range []string{"hybrid ML-KEM key exchange (X25519MLKEM768)", "X25519Kyber768Draft00", "ML-KEM-768 or X25519"} {
		if e, ok := Lookup(name); ok {
			t.Errorf("%q parsed as %s", name, e.Algorithm)
		}
	}
}

// The mislabels this catalogue replaced (learning.md 2026-09-29).
func TestAssessmentDoesNotRepeatTheOldMislabels(t *testing.T) {
	for name, want := range map[string]string{
		"RSA-4096":          "vulnerable", // was "strong" (QSL 88) in pqc and discovery
		"ECDSA-P256":        "vulnerable", // was "strong" (QSL 78)
		"SLH-DSA-SHA2-128s": "strong",     // was not recognised as post-quantum
		"AES-128-CBC":       "strong",     // was "legacy" in keycore
		"RSA-2048":          "vulnerable", // quantum-vulnerable, though acceptable through 2030
		"HMAC-SHA1":         "weak",       // deprecated through 2030
		"AES-256-ECB":       "vulnerable", // legacy use only
		"X25519MLKEM768":    "strong",
	} {
		if got := Assess(name, today).Class; got != want {
			t.Errorf("%s: class %s, want %s", name, got, want)
		}
	}
	if !Assess("SLH-DSA-SHA2-128s", today).PQCReady || Assess("RSA-4096", today).Ready {
		t.Fatal("readiness flags wrong")
	}
}

func TestMilestonesAreSourcedAndOrdered(t *testing.T) {
	var entries []Entry
	for _, n := range []string{"RSA-2048", "ECDSA-P384", "HMAC-SHA1", "ML-KEM-768"} {
		e, _ := Lookup(n)
		entries = append(entries, e)
	}
	ms := Milestones(entries, today)
	want := []struct {
		date   string
		status Status
		source string
	}{
		{"2031-01-01", Deprecated, SrcSP800131Ar3},
		{"2031-01-01", Disallowed, SrcSP800131Ar3},
		{"2036-01-01", Disallowed, SrcIR8547},
	}
	if len(ms) != len(want) {
		t.Fatalf("milestones = %+v", ms)
	}
	for i, w := range want {
		if ms[i].Date != w.date || ms[i].Status != w.status || ms[i].Source != w.source {
			t.Errorf("milestone %d = %+v, want %+v", i, ms[i], w)
		}
	}
	if len(Milestones(entries, farFuture)) != 0 {
		t.Error("no milestones remain after 2035")
	}
}

func TestEverySourceIsCitedWithItsDraftStatus(t *testing.T) {
	for _, id := range []string{SrcSP800131Ar3, SrcIR8547} {
		s, ok := SourceByID(id)
		if !ok || s.Revision != "ipd" || s.URL == "" {
			t.Errorf("%s must be cited as an initial public draft: %+v", id, s)
		}
	}
}
