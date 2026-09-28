// Package cryptocatalog is the platform's one record of what NIST says about
// each algorithm it names: classical security strength, post-quantum security
// category, whether a cryptanalytically relevant quantum computer breaks it,
// and its approval-status schedule. Every fact names the document and table
// it was copied from; nothing is estimated. A name the catalogue cannot
// parse to a specific parameter set is not assessed (Lookup returns false):
// callers show "not assessed", never a guess.
//
// NIST CSWP 39-upd1 (Considerations for Achieving Crypto Agility, §2.3 as
// updated 2026-06-29) points to NIST IR 8547 and SP 800-131A Rev. 3 for the
// transition away from quantum-vulnerable algorithms. Both are initial public
// drafts, so their dates are proposed, and Sources marks them as drafts for
// every screen that shows one (docs/SECURITY/ALGORITHM_TRANSITIONS.md).
package cryptocatalog

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Status is an SP 800-131A approval status, plus two the catalogue needs
// for algorithms NIST does not table.
type Status string

const (
	Acceptable Status = "acceptable"
	// Deprecated: may be used; the data owner accepts the risk.
	Deprecated Status = "deprecated"
	// Disallowed: no longer allowed for applying protection.
	Disallowed Status = "disallowed"
	// LegacyUse: only to process already-protected data (decrypt, verify).
	LegacyUse Status = "legacy_use"
	// NotApproved: not specified by a NIST standard for this use.
	NotApproved Status = "not_approved"
	// NotTabled: a recognised scheme whose status the cited drafts do not give.
	NotTabled Status = "not_tabled"
)

// Protects reports whether NIST allows the status for applying new
// protection (encrypting, signing, establishing keys) today.
func (s Status) Protects() bool { return s == Acceptable || s == Deprecated }

// Source is a document the catalogue cites.
type Source struct {
	ID       string `json:"id"`
	Label    string `json:"label"` // short citation, e.g. "SP 800-131Ar3 ipd"
	Title    string `json:"title"`
	Revision string `json:"revision"` // "final" or "ipd" (initial public draft)
	Date     string `json:"date"`     // YYYY-MM
	URL      string `json:"url"`
}

const (
	SrcSP80057       = "SP800-57pt1r5"
	SrcSP800131Ar3   = "SP800-131Ar3"
	SrcIR8547        = "IR8547"
	SrcFIPS186       = "FIPS186-5"
	SrcFIPS203       = "FIPS203"
	SrcFIPS204       = "FIPS204"
	SrcFIPS205       = "FIPS205"
	SrcSP800208      = "SP800-208"
	SrcFIPS46Removed = "FIPS46-3"
	SrcCSWP39        = "CSWP39-upd1"
)

var sources = map[string]Source{
	SrcSP80057:       {SrcSP80057, "SP 800-57 Pt1 r5", "NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management", "final", "2020-05", "https://doi.org/10.6028/NIST.SP.800-57pt1r5"},
	SrcSP800131Ar3:   {SrcSP800131Ar3, "SP 800-131Ar3 ipd", "NIST SP 800-131A Rev. 3 (initial public draft), Transitioning the Use of Cryptographic Algorithms and Key Lengths", "ipd", "2024-10", "https://doi.org/10.6028/NIST.SP.800-131Ar3.ipd"},
	SrcIR8547:        {SrcIR8547, "IR 8547 ipd", "NIST IR 8547 (initial public draft), Transition to Post-Quantum Cryptography Standards", "ipd", "2024-11", "https://doi.org/10.6028/NIST.IR.8547.ipd"},
	SrcFIPS186:       {SrcFIPS186, "FIPS 186-5", "FIPS 186-5, Digital Signature Standard", "final", "2023-02", "https://doi.org/10.6028/NIST.FIPS.186-5"},
	SrcFIPS203:       {SrcFIPS203, "FIPS 203", "FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard", "final", "2024-08", "https://doi.org/10.6028/NIST.FIPS.203"},
	SrcFIPS204:       {SrcFIPS204, "FIPS 204", "FIPS 204, Module-Lattice-Based Digital Signature Standard", "final", "2024-08", "https://doi.org/10.6028/NIST.FIPS.204"},
	SrcFIPS205:       {SrcFIPS205, "FIPS 205", "FIPS 205, Stateless Hash-Based Digital Signature Standard", "final", "2024-08", "https://doi.org/10.6028/NIST.FIPS.205"},
	SrcSP800208:      {SrcSP800208, "SP 800-208", "NIST SP 800-208, Recommendation for Stateful Hash-Based Signature Schemes", "final", "2020-10", "https://doi.org/10.6028/NIST.SP.800-208"},
	SrcFIPS46Removed: {SrcFIPS46Removed, "FIPS 46-3 (withdrawn)", "FIPS 46-3, Data Encryption Standard (withdrawn 2005-05-19)", "withdrawn", "1999-10", "https://csrc.nist.gov/pubs/fips/46-3/final"},
	SrcCSWP39:        {SrcCSWP39, "CSWP 39-upd1", "NIST CSWP 39-upd1, Considerations for Achieving Crypto Agility: Strategies and Practices", "final", "2026-06", "https://doi.org/10.6028/NIST.CSWP.39-upd1"},
}

// SourceByID returns a cited document.
func SourceByID(id string) (Source, bool) { s, ok := sources[id]; return s, ok }

// Cite is the short citation for a schedule step, e.g.
// "SP 800-131Ar3 ipd, Table 3".
func Cite(sourceID, ref string) string {
	label := sourceID
	if s, ok := sources[sourceID]; ok {
		label = s.Label
	}
	if ref == "" {
		return label
	}
	return label + ", " + ref
}

// Step is one entry of an approval schedule: Status applies from From
// (inclusive, YYYY-MM-DD; empty means already in force).
type Step struct {
	From   string `json:"from,omitempty"`
	Status Status `json:"status"`
	Source string `json:"source"`
	Ref    string `json:"ref"` // table or section in Source
}

// Entry is what the catalogue knows about one algorithm and parameter set.
type Entry struct {
	Algorithm string `json:"algorithm"` // canonical name
	Family    string `json:"family"`
	// Function: signature, key_establishment, public_key (RSA: both),
	// encryption, mac or hash.
	Function string `json:"function"`
	// Standard is the document that specifies the algorithm, when cited.
	Standard string `json:"standard,omitempty"`
	// SecurityBits is the classical security strength; 0 when no cited
	// table gives one.
	SecurityBits   int    `json:"security_bits,omitempty"`
	StrengthSource string `json:"strength_source,omitempty"`
	// PQCCategory is the NIST post-quantum security category (IR 8547
	// Table 1); 0 when none is tabled.
	PQCCategory int `json:"pqc_category,omitempty"`
	// QuantumVulnerable: broken by Shor's algorithm on a CRQC.
	QuantumVulnerable bool `json:"quantum_vulnerable"`
	// PostQuantum: a quantum-resistant public-key scheme (FIPS 203/204/205,
	// SP 800-208).
	PostQuantum bool   `json:"post_quantum,omitempty"`
	Hybrid      bool   `json:"hybrid,omitempty"`
	Schedule    []Step `json:"schedule"`
	Note        string `json:"note,omitempty"`
}

// StatusAt is the entry's status on day t.
func (e Entry) StatusAt(t time.Time) Status {
	status := NotTabled
	day := t.UTC().Format("2006-01-02")
	for _, s := range e.Schedule {
		if s.From == "" || s.From <= day {
			status = s.Status
		}
	}
	return status
}

// Next is the first scheduled change after day t.
func (e Entry) Next(t time.Time) (Step, bool) {
	day := t.UTC().Format("2006-01-02")
	for _, s := range e.Schedule {
		if s.From > day {
			return s, true
		}
	}
	return Step{}, false
}

// Sources lists the documents behind the entry, strength source first.
func (e Entry) Sources() []Source {
	seen := map[string]bool{}
	var out []Source
	add := func(id string) {
		if s, ok := sources[id]; ok && !seen[id] {
			seen[id] = true
			out = append(out, s)
		}
	}
	add(e.Standard)
	add(e.StrengthSource)
	for _, s := range e.Schedule {
		add(s.Source)
	}
	return out
}

// "after 2030" and "after 2035" in SP 800-131Ar3 and IR 8547 mean from the
// next January 1.
const (
	after2030 = "2031-01-01"
	after2035 = "2036-01-01"
)

// quantumVulnerable is the schedule of a classical public-key scheme at a
// given strength: SP 800-131Ar3 for today's status and the 112-bit
// deprecation, IR 8547 for disallowance after 2035.
func quantumVulnerable(bits int, ref131, ref8547 string) []Step {
	switch {
	case bits < 112:
		return []Step{{Status: LegacyUse, Source: SrcSP800131Ar3, Ref: ref131}}
	case bits < 128:
		return []Step{
			{Status: Acceptable, Source: SrcSP800131Ar3, Ref: ref131},
			{From: after2030, Status: Deprecated, Source: SrcSP800131Ar3, Ref: ref131},
			{From: after2035, Status: Disallowed, Source: SrcIR8547, Ref: ref8547},
		}
	default:
		return []Step{
			{Status: Acceptable, Source: SrcSP800131Ar3, Ref: ref131},
			{From: after2035, Status: Disallowed, Source: SrcIR8547, Ref: ref8547},
		}
	}
}

// ifcStrength is SP 800-57 Pt1 Table 2 for RSA moduli and finite-field
// groups: the strength of the largest listed size the key reaches.
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

const hybridGroup = `(?:X25519|X448|SECP(?:256|384|521)R1|(?:ECDH-)?P-?(?:256|384|521))`

// Lookup parses an algorithm name and returns its entry. Names that do not
// state a parameter set (a bare "RSA" or "AES") are not assessed.
func Lookup(algorithm string) (Entry, bool) {
	a := strings.ToUpper(strings.TrimSpace(algorithm))
	a = strings.NewReplacer("_", "-", " ", "-").Replace(a)
	if a == "" {
		return Entry{}, false
	}
	if e, ok := hybrid(a); ok {
		return e, true
	}
	switch {
	case reRSA.MatchString(a):
		n, _ := strconv.Atoi(reRSA.FindStringSubmatch(a)[1])
		bits := ifcStrength(n)
		return Entry{
			Algorithm: "RSA-" + strconv.Itoa(n), Family: "RSA", Function: "public_key", Standard: SrcFIPS186,
			SecurityBits: bits, StrengthSource: SrcSP80057, QuantumVulnerable: true,
			Schedule: quantumVulnerable(bits, "Tables 3 and 6", "Tables 2 and 4"),
		}, true
	case reDH.MatchString(a):
		n, _ := strconv.Atoi(reDH.FindStringSubmatch(a)[1])
		bits := ifcStrength(n)
		return Entry{
			Algorithm: "DH-" + strconv.Itoa(n), Family: "FFC DH", Function: "key_establishment",
			SecurityBits: bits, StrengthSource: SrcSP80057, QuantumVulnerable: true,
			Schedule: quantumVulnerable(bits, "Table 5", "Table 4"),
		}, true
	case reEC.MatchString(a):
		m := reEC.FindStringSubmatch(a)
		curve, _ := strconv.Atoi(m[2])
		bits := map[int]int{224: 112, 256: 128, 384: 192, 521: 256}[curve]
		family, function, ref131, ref8547, standard := "ECDSA", "signature", "Table 3", "Table 2", SrcFIPS186
		if m[1] == "ECDH" {
			family, function, ref131, ref8547, standard = "ECC DH", "key_establishment", "Table 5", "Table 4", ""
		} else if m[1] == "EC" {
			family, function = "EC", "public_key"
		}
		return Entry{
			Algorithm: m[1] + "-P" + m[2], Family: family, Function: function, Standard: standard,
			SecurityBits: bits, StrengthSource: SrcSP800131Ar3, QuantumVulnerable: true,
			Schedule: quantumVulnerable(bits, ref131, ref8547),
			Note:     "EC strength is half the bit length of n (SP 800-131Ar3 §3)",
		}, true
	case a == "ED25519" || a == "ED448":
		bits := map[string]int{"ED25519": 128, "ED448": 224}[a]
		return Entry{
			Algorithm: map[string]string{"ED25519": "Ed25519", "ED448": "Ed448"}[a], Family: "EdDSA", Function: "signature",
			SecurityBits: bits, StrengthSource: SrcFIPS186, QuantumVulnerable: true,
			Schedule: []Step{
				{Status: Acceptable, Source: SrcSP800131Ar3, Ref: "Table 3"},
				{From: after2035, Status: Disallowed, Source: SrcIR8547, Ref: "Table 2"},
			},
		}, true
	case a == "X25519" || a == "X448":
		return Entry{
			Algorithm: a, Family: "ECDH (Montgomery)", Function: "key_establishment", QuantumVulnerable: true,
			Schedule: []Step{{Status: NotApproved, Source: SrcSP800131Ar3, Ref: "Table 5 (not an SP 800-56A scheme)"}},
		}, true
	case a == "DSA" || strings.HasPrefix(a, "DSA-"):
		return Entry{
			Algorithm: "DSA", Family: "DSA", Function: "signature", QuantumVulnerable: true,
			Schedule: []Step{{Status: LegacyUse, Source: SrcSP800131Ar3, Ref: "Table 3"}},
			Note:     "generation disallowed; verification allowed for legacy use",
		}, true
	case reMLKEM.MatchString(a):
		p := reMLKEM.FindStringSubmatch(a)[1]
		bits, cat := map[string]int{"512": 128, "768": 192, "1024": 256}[p], map[string]int{"512": 1, "768": 3, "1024": 5}[p]
		return Entry{
			Algorithm: "ML-KEM-" + p, Family: "ML-KEM", Function: "key_establishment", Standard: SrcFIPS203,
			SecurityBits: bits, StrengthSource: SrcIR8547, PQCCategory: cat, PostQuantum: true,
			Schedule: []Step{{Status: Acceptable, Source: SrcSP800131Ar3, Ref: "Sec. 8"}},
		}, true
	case reMLDSA.MatchString(a):
		p := reMLDSA.FindStringSubmatch(a)[1]
		bits, cat := map[string]int{"44": 128, "65": 192, "87": 256}[p], map[string]int{"44": 2, "65": 3, "87": 5}[p]
		return Entry{
			Algorithm: "ML-DSA-" + p, Family: "ML-DSA", Function: "signature", Standard: SrcFIPS204,
			SecurityBits: bits, StrengthSource: SrcIR8547, PQCCategory: cat, PostQuantum: true,
			Schedule: []Step{{Status: Acceptable, Source: SrcSP800131Ar3, Ref: "Table 3"}},
		}, true
	case reSLH.MatchString(a):
		m := reSLH.FindStringSubmatch(a)
		hash := m[1]
		note := ""
		if hash == "" {
			hash, note = "SHAKE", "no hash family named; keycore generates SHAKE for this name"
		}
		bits := map[string]int{"128": 128, "192": 192, "256": 256}[m[2]]
		return Entry{
			Algorithm: "SLH-DSA-" + hash + "-" + m[2] + strings.ToLower(m[3]), Family: "SLH-DSA", Function: "signature", Standard: SrcFIPS205,
			SecurityBits: bits, StrengthSource: SrcIR8547, PQCCategory: map[int]int{128: 1, 192: 3, 256: 5}[bits], PostQuantum: true,
			Schedule: []Step{{Status: Acceptable, Source: SrcSP800131Ar3, Ref: "Table 3"}},
			Note:     note,
		}, true
	case reHBS.MatchString(a):
		family := reHBS.FindStringSubmatch(a)[1]
		return Entry{
			Algorithm: a, Family: family, Function: "signature", Standard: SrcSP800208, PostQuantum: true,
			Schedule: []Step{{Status: Acceptable, Source: SrcSP800131Ar3, Ref: "Table 3"}},
			Note:     "strength and category depend on the SP 800-208 parameter set",
		}, true
	case reAES.MatchString(a):
		return aes(reAES.FindStringSubmatch(a)), true
	case reTDEA.MatchString(a):
		bits, name := 112, "3TDEA"
		if strings.HasPrefix(a, "2") {
			bits, name = 80, "2TDEA"
		}
		return Entry{
			Algorithm: name, Family: "TDEA", Function: "encryption", SecurityBits: bits, StrengthSource: SrcSP80057,
			Schedule: []Step{{Status: LegacyUse, Source: SrcSP800131Ar3, Ref: "Table 1"}},
			Note:     "encryption disallowed; decryption allowed for legacy use",
		}, true
	case reDES.MatchString(a):
		return Entry{
			Algorithm: "DES", Family: "DES", Function: "encryption",
			Schedule: []Step{{Status: Disallowed, Source: SrcFIPS46Removed, Ref: "withdrawn 2005-05-19"}},
		}, true
	case reHash.MatchString(a):
		m := reHash.FindStringSubmatch(a)
		return hashEntry(m[1] != "", m[2]), true
	case strings.HasPrefix(a, "CHACHA20") || strings.HasPrefix(a, "XCHACHA20") || a == "RC4" || a == "MD5" || a == "HMAC-MD5":
		function := map[string]string{"MD5": "hash", "HMAC-MD5": "mac"}[a]
		if function == "" {
			function = "encryption"
		}
		return Entry{
			Algorithm: a, Family: strings.SplitN(a, "-", 2)[0], Function: function,
			Schedule: []Step{{Status: NotApproved, Source: SrcSP800131Ar3, Ref: "not an approved algorithm"}},
		}, true
	}
	return Entry{}, false
}

// hybrid recognises a classical + ML-KEM key-establishment combination
// (e.g. X25519MLKEM768). It is rated by its ML-KEM component for quantum
// resistance; neither cited draft tables hybrid schemes.
func hybrid(a string) (Entry, bool) {
	m := reHybrid.FindStringSubmatch(a)
	if m == nil {
		return Entry{}, false
	}
	level := m[1] + m[2]
	return Entry{
		Algorithm: a, Family: "hybrid ML-KEM", Function: "key_establishment", Standard: SrcFIPS203,
		PQCCategory: map[string]int{"512": 1, "768": 3, "1024": 5}[level], PostQuantum: true, Hybrid: true,
		Schedule: []Step{{Status: NotTabled, Source: SrcCSWP39, Ref: "§3.2.4 (hybrid schemes)"}},
		Note:     "secure while its ML-KEM component holds; not tabled in SP 800-131Ar3 ipd or IR 8547 ipd",
	}, true
}

func aes(m []string) Entry {
	bits, _ := strconv.Atoi(m[1])
	mode := m[2]
	e := Entry{
		Algorithm: "AES-" + m[1], Family: "AES", Function: "encryption",
		SecurityBits: bits, StrengthSource: SrcIR8547, PQCCategory: map[int]int{128: 1, 192: 3, 256: 5}[bits],
		Schedule: []Step{{Status: Acceptable, Source: SrcSP800131Ar3, Ref: "Tables 1 and 2"}},
	}
	if mode != "" {
		e.Algorithm += "-" + mode
	}
	switch mode {
	case "ECB":
		e.Schedule = []Step{{Status: LegacyUse, Source: SrcSP800131Ar3, Ref: "Table 2"}}
		e.Note = "ECB disallowed for data encryption; decryption allowed for legacy use"
	case "FF3":
		e.Schedule = []Step{{Status: Disallowed, Source: SrcSP800131Ar3, Ref: "Table 2"}}
	case "FF1":
		e.Note = "acceptable only with a domain of at least one million (SP 800-131Ar3 Table 2)"
	case "CMAC", "GMAC":
		e.Function = "mac"
	case "KW", "KWP":
		e.Function = "key_wrap"
	}
	return e
}

var hashNames = map[string]string{
	"SHA1": "SHA-1", "SHA224": "SHA-224", "SHA256": "SHA-256", "SHA384": "SHA-384", "SHA512": "SHA-512",
	"SHA512/224": "SHA-512/224", "SHA512/256": "SHA-512/256",
	"SHA3224": "SHA3-224", "SHA3256": "SHA3-256", "SHA3384": "SHA3-384", "SHA3512": "SHA3-512",
}

// hashEntry covers hash functions (collision strength, used in signatures)
// and HMAC (SP 800-57 Pt1 Table 3; bounded above by the key's length).
func hashEntry(isHMAC bool, h string) Entry {
	h = hashNames[strings.ReplaceAll(h, "-", "")]
	weak224 := h == "SHA-224" || h == "SHA-512/224" || h == "SHA3-224"
	if isHMAC {
		bits := 256
		e := Entry{Algorithm: "HMAC-" + h, Family: "HMAC", Function: "mac", StrengthSource: SrcSP80057,
			Schedule: []Step{{Status: Acceptable, Source: SrcSP800131Ar3, Ref: "Table 15"}},
			Note:     "strength also bounded by the key length; keys under 128 bits are disallowed after 2030"}
		switch {
		case h == "SHA-1":
			bits = 128
		case weak224:
			bits = 192
		}
		if h == "SHA-1" || weak224 {
			e.Schedule = []Step{
				{Status: Deprecated, Source: SrcSP800131Ar3, Ref: "Table 15"},
				{From: after2030, Status: Disallowed, Source: SrcSP800131Ar3, Ref: "Table 15"},
			}
		}
		e.SecurityBits = bits
		return e
	}
	collision := map[string]int{"SHA-1": 80, "SHA-224": 112, "SHA-512/224": 112, "SHA3-224": 112,
		"SHA-256": 128, "SHA-512/256": 128, "SHA3-256": 128, "SHA-384": 192, "SHA3-384": 192, "SHA-512": 256, "SHA3-512": 256}[h]
	category := map[string]int{"SHA-256": 2, "SHA-512/256": 2, "SHA3-256": 2, "SHA-384": 4, "SHA3-384": 4, "SHA-512": 5, "SHA3-512": 5}[h]
	e := Entry{Algorithm: h, Family: "hash", Function: "hash", SecurityBits: collision, StrengthSource: SrcIR8547,
		PQCCategory: category, Schedule: []Step{{Status: Acceptable, Source: SrcSP800131Ar3, Ref: "Table 13"}}}
	switch {
	case h == "SHA-1":
		e.Schedule = []Step{{Status: LegacyUse, Source: SrcSP800131Ar3, Ref: "Table 13"}}
		e.Note = "signature generation disallowed; verification allowed for legacy use"
	case weak224:
		e.Schedule = []Step{
			{Status: Deprecated, Source: SrcSP800131Ar3, Ref: "Table 13"},
			{From: after2030, Status: Disallowed, Source: SrcSP800131Ar3, Ref: "Table 13"},
		}
	}
	return e
}

// Milestone is a dated NIST status change, used to show what a tenant's
// inventory runs into and when.
type Milestone struct {
	Date   string `json:"date"`
	Status Status `json:"status"`
	Source string `json:"source"`
	Ref    string `json:"ref"`
}

// Milestones collects the future schedule steps of the given entries, soonest
// first: one per (date, status, source), with every table reference cited.
func Milestones(entries []Entry, now time.Time) []Milestone {
	day := now.UTC().Format("2006-01-02")
	byKey := map[string]*Milestone{}
	var order []string
	for _, e := range entries {
		for _, s := range e.Schedule {
			if s.From <= day {
				continue
			}
			k := s.From + "|" + string(s.Status) + "|" + s.Source
			m, ok := byKey[k]
			if !ok {
				byKey[k] = &Milestone{Date: s.From, Status: s.Status, Source: s.Source, Ref: s.Ref}
				order = append(order, k)
				continue
			}
			if !strings.Contains(m.Ref, s.Ref) {
				m.Ref += "; " + s.Ref
			}
		}
	}
	out := make([]Milestone, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Date != out[j].Date {
			return out[i].Date < out[j].Date
		}
		return out[i].Status < out[j].Status
	})
	return out
}

// Assessment is the per-asset view the discovery and pqc services store.
type Assessment struct {
	Assessed bool
	Entry    Entry
	Status   Status
	// Class: "vulnerable" (quantum-vulnerable, or NIST no longer allows it
	// for new protection), "weak" (deprecated today), "strong" (neither),
	// "unknown" (not assessed).
	Class string
	// Ready: quantum-resistant and allowed for new protection today.
	Ready bool
	// PQCReady: a post-quantum or hybrid scheme.
	PQCReady bool
}

// Assess classifies one algorithm name on day t.
func Assess(algorithm string, t time.Time) Assessment {
	e, ok := Lookup(algorithm)
	if !ok {
		return Assessment{Class: "unknown"}
	}
	st := e.StatusAt(t)
	a := Assessment{Assessed: true, Entry: e, Status: st, PQCReady: e.PostQuantum}
	allowed := st.Protects() || st == NotTabled
	switch {
	case e.QuantumVulnerable || !allowed:
		a.Class = "vulnerable"
	case st == Deprecated:
		a.Class = "weak"
	default:
		a.Class = "strong"
	}
	a.Ready = !e.QuantumVulnerable && allowed
	return a
}
