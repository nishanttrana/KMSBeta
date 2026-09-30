// Package cryptocatalog is the platform's one record of the technical facts
// about each algorithm it names: classical security strength in bits,
// post-quantum security category, whether a cryptanalytically relevant
// quantum computer breaks it, and whether it is weak today (broken, below
// 112 bits, or an unsafe mode). It holds no migration dates or approval
// statuses: when and what to migrate is the customer's policy (keycore
// agility policy rules, docs/SECURITY/ALGORITHM_TRANSITIONS.md).
//
// A name the catalogue cannot parse to a specific parameter set is not
// assessed (Lookup returns false): callers show "not assessed", never a
// guess.
package cryptocatalog

import (
	"regexp"
	"strconv"
	"strings"
)

// Entry is what the catalogue knows about one algorithm and parameter set.
type Entry struct {
	Algorithm string `json:"algorithm"` // canonical name
	Family    string `json:"family"`
	// Function: signature, key_establishment, public_key (RSA and generic
	// EC: both), encryption, key_wrap, mac or hash.
	Function string `json:"function"`
	// SecurityBits is the classical security strength; 0 when the
	// parameter set does not fix one.
	SecurityBits int `json:"security_bits,omitempty"`
	// PQCCategory is the post-quantum security category (1-5); 0 when none
	// applies.
	PQCCategory int `json:"pqc_category,omitempty"`
	// QuantumVulnerable: broken by Shor's algorithm on a quantum computer.
	QuantumVulnerable bool `json:"quantum_vulnerable"`
	// PostQuantum: a quantum-resistant public-key scheme (ML-KEM, ML-DSA,
	// SLH-DSA, LMS/XMSS) or a hybrid with one.
	PostQuantum bool `json:"post_quantum,omitempty"`
	Hybrid      bool `json:"hybrid,omitempty"`
	// Weak: broken or unsafe today regardless of quantum computers.
	Weak bool   `json:"weak,omitempty"`
	Note string `json:"note,omitempty"`
}

// tlsGroupAliases maps TLS named groups (crypto/tls CurveID names and the
// RFC 8422 names) to the key establishment they are.
var tlsGroupAliases = map[string]string{
	"CURVEP256": "ECDH-P256", "CURVEP384": "ECDH-P384", "CURVEP521": "ECDH-P521",
	"SECP256R1": "ECDH-P256", "SECP384R1": "ECDH-P384", "SECP521R1": "ECDH-P521",
}

// ifcStrength is the strength of an RSA modulus or finite-field group: the
// largest standard size the key reaches.
func ifcStrength(n int) int {
	switch {
	case n >= 15360:
		return 256
	case n >= 7680:
		return 192
	case n >= 3072:
		return 128
	case n >= 2048:
		return 112
	case n >= 1024:
		return 80
	}
	return 0
}

const hybridGroup = `(?:X25519|X448|SECP(?:256|384|521)R1|(?:ECDH-)?P-?(?:256|384|521))`

var (
	reRSA   = regexp.MustCompile(`^RSA(?:-(?:PSS|OAEP|PKCS1))?-?(\d{3,5})$`)
	reDH    = regexp.MustCompile(`^(?:FF)?DHE?-?(\d{4,5})$`)
	reEC    = regexp.MustCompile(`^(ECDSA|ECDH|EC)-?(?:P-?|SECP|PRIME)(224|256|384|521)(?:R1|V1)?$`)
	reMLKEM = regexp.MustCompile(`^ML-?KEM-?(512|768|1024)$`)
	reMLDSA = regexp.MustCompile(`^ML-?DSA-?(44|65|87)$`)
	reSLH   = regexp.MustCompile(`^SLH-?DSA-(?:(SHA2|SHAKE)-)?(128|192|256)([SF])$`)
	reHBS   = regexp.MustCompile(`^(LMS|HSS|XMSS|XMSSMT)(?:-.+)?$`)
	reAES   = regexp.MustCompile(`^AES-?(128|192|256)(?:-(ECB|CBC|CBC-CS[123]|CFB|CFB8|CFB128|CTR|OFB|GCM|CCM|XTS|KW|KWP|CMAC|GMAC|FF1|FF3))?$`)
	reTDEA  = regexp.MustCompile(`^(?:3DES|TDES|TDEA|3TDEA|DES-?EDE3?|TRIPLE-?DES|2DES|2TDEA)(?:-.+)?$`)
	reDES   = regexp.MustCompile(`^DES(?:-(?:ECB|CBC|CFB|OFB))?$`)
	reHash  = regexp.MustCompile(`^(HMAC-)?(SHA-?1|SHA-?224|SHA-?256|SHA-?384|SHA-?512|SHA-?512/224|SHA-?512/256|SHA3-?224|SHA3-?256|SHA3-?384|SHA3-?512)$`)
	// A hybrid names its classical group and its ML-KEM parameter set, in
	// either order (X25519MLKEM768, ECDH-P256-ML-KEM-768-HYBRID,
	// ML-KEM-768+X25519).
	reHybrid = regexp.MustCompile(`^(?:` + hybridGroup + `[-+]?ML-?KEM-?(512|768|1024)|ML-?KEM-?(512|768|1024)[-+]?` + hybridGroup + `)(?:-HYBRID)?$`)
)

var pqLevel = map[string]int{"512": 1, "768": 3, "1024": 5}

// Lookup parses an algorithm name and returns its entry. Names that do not
// state a parameter set (a bare "RSA" or "AES") are not assessed.
func Lookup(algorithm string) (Entry, bool) {
	a := strings.ToUpper(strings.TrimSpace(algorithm))
	a = strings.NewReplacer("_", "-", " ", "-").Replace(a)
	if a == "" {
		return Entry{}, false
	}
	// TLS key-exchange group names as Go's crypto/tls prints them.
	if g, ok := tlsGroupAliases[a]; ok {
		a = g
	}
	if m := reHybrid.FindStringSubmatch(a); m != nil {
		return Entry{
			Algorithm: a, Family: "hybrid ML-KEM", Function: "key_establishment",
			PQCCategory: pqLevel[m[1]+m[2]], PostQuantum: true, Hybrid: true,
			Note: "secure while its ML-KEM component holds",
		}, true
	}
	switch {
	case reRSA.MatchString(a):
		n, _ := strconv.Atoi(reRSA.FindStringSubmatch(a)[1])
		bits := ifcStrength(n)
		return Entry{Algorithm: "RSA-" + strconv.Itoa(n), Family: "RSA", Function: "public_key",
			SecurityBits: bits, QuantumVulnerable: true, Weak: bits < 112}, true
	case reDH.MatchString(a):
		n, _ := strconv.Atoi(reDH.FindStringSubmatch(a)[1])
		bits := ifcStrength(n)
		return Entry{Algorithm: "DH-" + strconv.Itoa(n), Family: "DH", Function: "key_establishment",
			SecurityBits: bits, QuantumVulnerable: true, Weak: bits < 112}, true
	case reEC.MatchString(a):
		m := reEC.FindStringSubmatch(a)
		curve, _ := strconv.Atoi(m[2])
		family, function := "ECDSA", "signature"
		switch m[1] {
		case "ECDH":
			family, function = "ECDH", "key_establishment"
		case "EC":
			family, function = "EC", "public_key"
		}
		return Entry{Algorithm: m[1] + "-P" + m[2], Family: family, Function: function,
			SecurityBits: map[int]int{224: 112, 256: 128, 384: 192, 521: 256}[curve], QuantumVulnerable: true,
			Note: "strength is half the bit length of the curve order"}, true
	case a == "ED25519" || a == "ED448":
		return Entry{Algorithm: map[string]string{"ED25519": "Ed25519", "ED448": "Ed448"}[a], Family: "EdDSA", Function: "signature",
			SecurityBits: map[string]int{"ED25519": 128, "ED448": 224}[a], QuantumVulnerable: true}, true
	case a == "X25519" || a == "X448":
		return Entry{Algorithm: a, Family: "ECDH", Function: "key_establishment",
			SecurityBits: map[string]int{"X25519": 128, "X448": 224}[a], QuantumVulnerable: true}, true
	case a == "DSA" || strings.HasPrefix(a, "DSA-"):
		return Entry{Algorithm: "DSA", Family: "DSA", Function: "signature", QuantumVulnerable: true,
			Note: "no parameter size in the name"}, true
	case reMLKEM.MatchString(a):
		p := reMLKEM.FindStringSubmatch(a)[1]
		return Entry{Algorithm: "ML-KEM-" + p, Family: "ML-KEM", Function: "key_establishment",
			SecurityBits: map[string]int{"512": 128, "768": 192, "1024": 256}[p], PQCCategory: pqLevel[p], PostQuantum: true}, true
	case reMLDSA.MatchString(a):
		p := reMLDSA.FindStringSubmatch(a)[1]
		return Entry{Algorithm: "ML-DSA-" + p, Family: "ML-DSA", Function: "signature",
			SecurityBits: map[string]int{"44": 128, "65": 192, "87": 256}[p], PQCCategory: map[string]int{"44": 2, "65": 3, "87": 5}[p], PostQuantum: true}, true
	case reSLH.MatchString(a):
		m := reSLH.FindStringSubmatch(a)
		hash, note := m[1], ""
		if hash == "" {
			hash, note = "SHAKE", "no hash family named; keycore generates SHAKE for this name"
		}
		bits, _ := strconv.Atoi(m[2])
		return Entry{Algorithm: "SLH-DSA-" + hash + "-" + m[2] + strings.ToLower(m[3]), Family: "SLH-DSA", Function: "signature",
			SecurityBits: bits, PQCCategory: map[int]int{128: 1, 192: 3, 256: 5}[bits], PostQuantum: true, Note: note}, true
	case reHBS.MatchString(a):
		return Entry{Algorithm: a, Family: reHBS.FindStringSubmatch(a)[1], Function: "signature", PostQuantum: true,
			Note: "strength depends on the parameter set"}, true
	case reAES.MatchString(a):
		return aes(reAES.FindStringSubmatch(a)), true
	case reTDEA.MatchString(a):
		bits, name := 112, "3TDEA"
		if strings.HasPrefix(a, "2") {
			bits, name = 80, "2TDEA"
		}
		return Entry{Algorithm: name, Family: "TDEA", Function: "encryption", SecurityBits: bits, Weak: true,
			Note: "64-bit block: collision attacks after a few GB under one key"}, true
	case reDES.MatchString(a):
		return Entry{Algorithm: "DES", Family: "DES", Function: "encryption", Weak: true, Note: "56-bit key: exhaustively searchable"}, true
	case reHash.MatchString(a):
		m := reHash.FindStringSubmatch(a)
		return hashEntry(m[1] != "", hashNames[strings.ReplaceAll(m[2], "-", "")]), true
	case strings.HasPrefix(a, "CHACHA20") || strings.HasPrefix(a, "XCHACHA20"):
		return Entry{Algorithm: a, Family: "ChaCha20", Function: "encryption", SecurityBits: 256}, true
	case a == "RC4" || a == "MD5" || a == "HMAC-MD5":
		function := map[string]string{"RC4": "encryption", "MD5": "hash", "HMAC-MD5": "mac"}[a]
		return Entry{Algorithm: a, Family: strings.TrimPrefix(a, "HMAC-"), Function: function, Weak: true, Note: "broken"}, true
	}
	return Entry{}, false
}

func aes(m []string) Entry {
	bits, _ := strconv.Atoi(m[1])
	e := Entry{Algorithm: "AES-" + m[1], Family: "AES", Function: "encryption",
		SecurityBits: bits, PQCCategory: map[int]int{128: 1, 192: 3, 256: 5}[bits]}
	if mode := m[2]; mode != "" {
		e.Algorithm += "-" + mode
		switch mode {
		case "ECB":
			e.Weak, e.Note = true, "ECB leaks equal plaintext blocks"
		case "FF3":
			e.Weak, e.Note = true, "FF3 has a practical attack; FF1 does not"
		case "CMAC", "GMAC":
			e.Function = "mac"
		case "KW", "KWP":
			e.Function = "key_wrap"
		}
	}
	return e
}

var hashNames = map[string]string{
	"SHA1": "SHA-1", "SHA224": "SHA-224", "SHA256": "SHA-256", "SHA384": "SHA-384", "SHA512": "SHA-512",
	"SHA512/224": "SHA-512/224", "SHA512/256": "SHA-512/256",
	"SHA3224": "SHA3-224", "SHA3256": "SHA3-256", "SHA3384": "SHA3-384", "SHA3512": "SHA3-512",
}

// hashEntry covers hash functions (collision strength) and HMAC (strength
// with a key at least that long).
func hashEntry(isHMAC bool, h string) Entry {
	weak224 := h == "SHA-224" || h == "SHA-512/224" || h == "SHA3-224"
	if isHMAC {
		bits := 256
		switch {
		case h == "SHA-1":
			bits = 128
		case weak224:
			bits = 192
		}
		return Entry{Algorithm: "HMAC-" + h, Family: "HMAC", Function: "mac", SecurityBits: bits,
			Note: "strength also bounded by the key length"}
	}
	collision := map[string]int{"SHA-1": 80, "SHA-224": 112, "SHA-512/224": 112, "SHA3-224": 112,
		"SHA-256": 128, "SHA-512/256": 128, "SHA3-256": 128, "SHA-384": 192, "SHA3-384": 192, "SHA-512": 256, "SHA3-512": 256}[h]
	category := map[string]int{"SHA-256": 2, "SHA-512/256": 2, "SHA3-256": 2, "SHA-384": 4, "SHA3-384": 4, "SHA-512": 5, "SHA3-512": 5}[h]
	e := Entry{Algorithm: h, Family: "hash", Function: "hash", SecurityBits: collision, PQCCategory: category}
	if h == "SHA-1" {
		e.Weak, e.Note = true, "practical collisions"
	}
	return e
}

// Assessment is the per-asset view the discovery and pqc services store.
type Assessment struct {
	Assessed bool
	Entry    Entry
	// Class: "weak" (weak today), "quantum_vulnerable" (sound today, broken
	// by a quantum computer), "strong" (neither) or "unknown" (not
	// assessed). Before 7.11.0-beta the first two were one "vulnerable",
	// which put ECDSA-P256 in the same bucket as RSA-1024.
	Class string
	// Ready: neither weak nor quantum-vulnerable.
	Ready bool
	// PQCReady: a post-quantum or hybrid scheme.
	PQCReady bool
}

// Assess classifies one algorithm name.
func Assess(algorithm string) Assessment {
	e, ok := Lookup(algorithm)
	if !ok {
		return Assessment{Class: "unknown"}
	}
	a := Assessment{Assessed: true, Entry: e, Class: "strong", Ready: true, PQCReady: e.PostQuantum}
	switch {
	case e.Weak:
		a.Class, a.Ready = "weak", false
	case e.QuantumVulnerable:
		a.Class, a.Ready = "quantum_vulnerable", false
	}
	return a
}
