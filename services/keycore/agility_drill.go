package main

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"vecta-kms/pkg/crypto"
	"vecta-kms/pkg/cryptocatalog"
)

// An algorithm-swap drill rehearses moving from one algorithm to another on
// this node: for each side it generates throwaway keys with keycore's own
// key generation, runs the algorithm's operation (sign and verify, encrypt
// and decrypt, or encapsulate and decapsulate) through the same engine
// functions customer keys use, checks every round trip, and times it. The
// keys never leave memory and are zeroised; nothing is added to the key
// inventory. Before anything runs, the target must pass the tenant's FIPS
// mode and its own migration policy, exactly as a real key would.

const (
	drillMaxIterations     = 10
	drillDefaultIterations = 5
	// drillBudget bounds each algorithm's measurement so a drill of slow
	// algorithms (RSA-4096 generation, SLH-DSA "s" signing) finishes inside
	// the 60 s server and gateway timeouts. Rounds stop once it is spent;
	// round_trips says how many ran.
	drillBudget = 20 * time.Second
)

// AgilityDrill is one recorded drill.
type AgilityDrill struct {
	ID         string          `json:"id"`
	TenantID   string          `json:"tenant_id"`
	From       DrillMeasure    `json:"from"`
	To         DrillMeasure    `json:"to"`
	Iterations int             `json:"iterations"`
	Result     string          `json:"result"` // passed | failed
	Error      string          `json:"error,omitempty"`
	Comparison DrillComparison `json:"comparison"`
	RunBy      string          `json:"run_by"`
	CreatedAt  time.Time       `json:"created_at"`
}

// DrillMeasure is what was measured for one algorithm. Times are medians in
// microseconds; sizes are the bytes the engine produced.
type DrillMeasure struct {
	Algorithm       string `json:"algorithm"`
	Operation       string `json:"operation"` // sign_verify | encrypt_decrypt | encapsulate_decapsulate
	KeygenMicros    int64  `json:"keygen_us"`
	OperationMicros int64  `json:"operation_us"`
	CheckMicros     int64  `json:"check_us"`
	PrivateKeyBytes int    `json:"private_key_bytes"`
	PublicKeyBytes  int    `json:"public_key_bytes,omitempty"`
	OutputBytes     int    `json:"output_bytes"` // signature, ciphertext or KEM ciphertext
	RoundTrips      int    `json:"round_trips"`  // checks that passed
}

// DrillComparison is target over source; 0 when the source value is 0.
type DrillComparison struct {
	KeygenRatio     float64 `json:"keygen_ratio"`
	OperationRatio  float64 `json:"operation_ratio"`
	CheckRatio      float64 `json:"check_ratio"`
	OutputBytesDiff int     `json:"output_bytes_diff"`
	PublicKeyDiff   int     `json:"public_key_bytes_diff"`
}

var errDrillUnsupported = errors.New("drill_unsupported")

// drillOperation names the operation a drill runs for an algorithm, or an
// error when keycore has no operation it can round-trip for it. A name
// without a parameter set ("RSA") is refused: keycore would generate its
// default size, and the measurement would carry a label that doesn't say
// what was measured.
func drillOperation(alg string) (string, error) {
	if _, ok := cryptocatalog.Lookup(alg); !ok {
		return "", fmt.Errorf("%s: name the parameter set (for example RSA-3072, ML-DSA-65, AES-256)", alg)
	}
	plan, err := planKeyGeneration(alg)
	if err != nil {
		return "", err
	}
	up := strings.ToUpper(alg)
	switch plan.kind {
	case "rsa", "ed25519", "ml-dsa-65", "ml-dsa-87", "slh-dsa":
		return "sign_verify", nil
	case "ec":
		if strings.Contains(up, "ECDH") {
			return "", errDrillUnsupported
		}
		return "sign_verify", nil
	case "ml-kem-768", "ml-kem-1024":
		return "encapsulate_decapsulate", nil
	case "symmetric":
		if isHMACKeyAlgorithm(up) {
			return "sign_verify", nil
		}
		return "encrypt_decrypt", nil
	}
	return "", errDrillUnsupported
}

// measureAlgorithm runs up to n rounds for one algorithm, fewer when
// budget is spent (at least one always runs). A failed round trip is
// an error: a drill never reports a measurement for a check that failed.
func measureAlgorithm(alg string, n int, budget time.Duration) (DrillMeasure, error) {
	op, err := drillOperation(alg)
	if err != nil {
		return DrillMeasure{}, err
	}
	m := DrillMeasure{Algorithm: alg, Operation: op}
	payload, err := crypto.RandomBytes(32)
	if err != nil {
		return m, err
	}
	var keygen, operation, check []int64
	start := time.Now()
	for i := 0; i < n && (i == 0 || time.Since(start) < budget); i++ {
		t0 := time.Now()
		raw, err := generateMaterialForCreate(alg, "asymmetric")
		if err != nil {
			return m, err
		}
		keygen = append(keygen, time.Since(t0).Microseconds())
		m.PrivateKeyBytes = len(raw)
		if op != "encrypt_decrypt" && !isHMACKeyAlgorithm(strings.ToUpper(alg)) {
			if pub, err := derivePublicFromPrivateMaterial(alg, raw); err == nil {
				m.PublicKeyBytes = len(pub)
			}
		}
		opUs, checkUs, out, err := drillRoundTrip(alg, op, raw, payload)
		crypto.Zeroize(raw)
		if err != nil {
			return m, err
		}
		operation, check = append(operation, opUs), append(check, checkUs)
		m.OutputBytes = out
		m.RoundTrips++
	}
	m.KeygenMicros, m.OperationMicros, m.CheckMicros = median(keygen), median(operation), median(check)
	return m, nil
}

func drillRoundTrip(alg, op string, raw, payload []byte) (opUs, checkUs int64, outBytes int, err error) {
	switch op {
	case "sign_verify":
		t0 := time.Now()
		sig, err := signWithKeyAlgorithm(alg, "asymmetric", raw, payload, "")
		if err != nil {
			return 0, 0, 0, err
		}
		opUs = time.Since(t0).Microseconds()
		t1 := time.Now()
		ok, err := verifyWithKeyAlgorithm(alg, "asymmetric", raw, payload, sig, "")
		if err != nil {
			return 0, 0, 0, err
		}
		if !ok {
			return 0, 0, 0, errors.New("signature did not verify")
		}
		return opUs, time.Since(t1).Microseconds(), len(sig), nil
	case "encrypt_decrypt":
		t0 := time.Now()
		ct, iv, _, err := encryptWithKeyAlgorithm(alg, "symmetric", raw, "internal", "", payload, nil)
		if err != nil {
			return 0, 0, 0, err
		}
		opUs = time.Since(t0).Microseconds()
		t1 := time.Now()
		pt, err := decryptWithKeyAlgorithm(alg, "symmetric", raw, iv, ct, nil)
		if err != nil {
			return 0, 0, 0, err
		}
		if !crypto.ConstantTimeEqual(pt, payload) {
			return 0, 0, 0, errors.New("decryption did not return the plaintext")
		}
		return opUs, time.Since(t1).Microseconds(), len(ct), nil
	case "encapsulate_decapsulate":
		t0 := time.Now()
		shared, ct, err := mlkemEncapsulate(alg, "asymmetric", raw)
		if err != nil {
			return 0, 0, 0, err
		}
		defer crypto.Zeroize(shared)
		opUs = time.Since(t0).Microseconds()
		t1 := time.Now()
		got, err := mlkemDecapsulate(alg, "asymmetric", raw, ct)
		if err != nil {
			return 0, 0, 0, err
		}
		defer crypto.Zeroize(got)
		if !crypto.ConstantTimeEqual(got, shared) {
			return 0, 0, 0, errors.New("decapsulation did not return the shared secret")
		}
		return opUs, time.Since(t1).Microseconds(), len(ct), nil
	}
	return 0, 0, 0, errDrillUnsupported
}

func compareDrill(from, to DrillMeasure) DrillComparison {
	ratio := func(a, b int64) float64 {
		if a <= 0 {
			return 0
		}
		return float64(int(float64(b)/float64(a)*100+0.5)) / 100
	}
	return DrillComparison{
		KeygenRatio:     ratio(from.KeygenMicros, to.KeygenMicros),
		OperationRatio:  ratio(from.OperationMicros, to.OperationMicros),
		CheckRatio:      ratio(from.CheckMicros, to.CheckMicros),
		OutputBytesDiff: to.OutputBytes - from.OutputBytes,
		PublicKeyDiff:   to.PublicKeyBytes - from.PublicKeyBytes,
	}
}

func median(v []int64) int64 {
	if len(v) == 0 {
		return 0
	}
	s := append([]int64(nil), v...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[len(s)/2]
}
