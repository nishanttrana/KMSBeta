package tlsprofile

import (
	"crypto/tls"
	"os"
	"strings"
)

// ApplyServerDefaults applies consistent server-side TLS defaults across services.
// It prefers hybrid PQ-capable groups while retaining classic groups for interoperability.
func ApplyServerDefaults(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		cfg = &tls.Config{}
	}
	out := cfg.Clone()
	if out.MinVersion == 0 {
		out.MinVersion = tls.VersionTLS13
	}
	if shouldEnableHybridPQ() {
		out.CurvePreferences = hybridCurvePreferences()
	} else {
		out.CurvePreferences = classicCurvePreferences()
	}
	return out
}

// ApplyClientDefaults applies consistent client-side TLS defaults for internal calls.
func ApplyClientDefaults(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		cfg = &tls.Config{}
	}
	out := cfg.Clone()
	if out.MinVersion == 0 {
		out.MinVersion = tls.VersionTLS13
	}
	if shouldEnableHybridPQ() {
		out.CurvePreferences = hybridCurvePreferences()
	} else {
		out.CurvePreferences = classicCurvePreferences()
	}
	return out
}

func shouldEnableHybridPQ() bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("VECTA_TLS_PQ_PROFILE")))
	switch raw {
	case "classic", "tls13", "off", "disabled", "false", "0":
		return false
	case "hybrid", "pqc", "pq-hybrid", "tls13_hybrid_webui", "tls13_hybrid_kms":
		return true
	default:
		// Default on: keep hybrid-ready posture while retaining classic curves for negotiation fallback.
		return true
	}
}

func hybridCurvePreferences() []tls.CurveID {
	return []tls.CurveID{
		tls.X25519MLKEM768,
		tls.SecP256r1MLKEM768,
		tls.SecP384r1MLKEM1024,
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
	}
}

func classicCurvePreferences() []tls.CurveID {
	return []tls.CurveID{
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
	}
}
