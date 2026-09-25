package fips

// Impact catalogue shown before a FIPS mode change. Every "only" entry is
// backed by a strict-mode refusal test (fipstest.StrictOnly); keep the two in
// step when a feature changes.

type Impact struct {
	Service string `json:"service"`
	Feature string `json:"feature"`
	Detail  string `json:"detail"`
}

// strictOnlyUnavailable lists what stops working under "only" and resumes when
// leaving it.
var strictOnlyUnavailable = []Impact{
	{"payment", "DES / TDES operations", "PIN block translation, PVV, retail MAC (ISO 9797-1 alg 3) and TR-31 key blocks under TDES keys"},
	{"secrets", "X25519 key types", "age-x25519 and WireGuard key-pair generation"},
	{"secrets", "OpenPGP keys", "pgp-rsa-4096 generation (OpenPGP v4 fingerprints require SHA-1)"},
	{"keycore", "ML-DSA / SLH-DSA keys", "post-quantum signing keys; implemented outside the certified module until a certified snapshot includes them"},
	{"keycore", "Caller-supplied AES-GCM IVs", "keys with iv_mode external or deterministic cannot encrypt (decryption still works)"},
	{"dataprotect", "ChaCha20-Poly1305 field encryption", "fields configured for CHACHA20-POLY1305"},
	{"dataprotect", "Deterministic AES-GCM", "deterministic (searchable-equality) field encryption"},
	{"dataprotect", "Legacy (v1) data protection keys", "keys not yet migrated to keycore-derived working keys; migrate them first (Data Protection > Working-Key Derivation)"},
	{"certs", "OCSP requests with SHA-1 CertID", "clients must send SHA-256 CertIDs"},
	{"cloud", "Alibaba Cloud integration", "API signing requires HMAC-SHA1"},
}

// TransitionImpact describes a mode change: what stops, what starts, and
// general notes.
func TransitionImpact(from, to string) (stops, starts []Impact, notes []string) {
	if from == to {
		return nil, nil, []string{"No change."}
	}
	if to == ModeOnly {
		stops = append(stops, strictOnlyUnavailable...)
	}
	if from == ModeOnly {
		starts = append(starts, strictOnlyUnavailable...)
	}
	if from == ModeOff {
		notes = append(notes,
			"TLS is limited to FIPS-approved versions, cipher suites and key exchanges; clients offering only non-approved options can no longer connect.",
			"Every service runs the FIPS 140-3 power-on self-tests at startup.")
	}
	if to == ModeOff {
		notes = append(notes,
			"Security downgrade: the platform no longer runs a validated cryptographic module. FIPS posture, compliance evidence and the dashboard report \"not validated\".")
	}
	if to == ModeOn && from == ModeOnly {
		notes = append(notes, "Security downgrade: the Go runtime stops refusing non-approved algorithms; platform policy and per-tenant FIPS Policy still apply.")
	}
	notes = append(notes, "Every service restarts to apply the mode (rolling, about 1-2 minutes). Requests in flight complete; clients should retry on 503 during the rollout.")
	return stops, starts, notes
}
