package main

import "time"

// AlgorithmUsage holds usage statistics for a single cryptographic algorithm.
type AlgorithmUsage struct {
	Algorithm  string  `json:"algorithm"`
	KeyCount   int     `json:"key_count"`
	Percentage float64 `json:"percentage"`
	IsLegacy   bool    `json:"is_legacy"`
	IsQuantumSafe bool `json:"is_quantum_safe"`
}

// AgilityScore summarises the overall cryptographic agility posture for a tenant.
type AgilityScore struct {
	Score            int              `json:"score"`           // 0–100
	Grade            string           `json:"grade"`           // A–F
	QuantumReadiness int              `json:"quantum_readiness"` // percentage
	LegacyKeyCount   int              `json:"legacy_key_count"`
	TotalKeys        int              `json:"total_keys"`
	Algorithms       []AlgorithmUsage `json:"algorithms"`
	Recommendations  []string         `json:"recommendations"`
}

// KeysByAlgorithm lists keys grouped under a specific algorithm.
type KeysByAlgorithm struct {
	Algorithm string `json:"algorithm"`
	Keys      []Key  `json:"keys"`
}

// MigrationPlan describes a planned algorithm migration.
type MigrationPlan struct {
	ID            string     `json:"id"`
	TenantID      string     `json:"tenant_id"`
	Name          string     `json:"name"`
	FromAlgorithm string     `json:"from_algorithm"`
	ToAlgorithm   string     `json:"to_algorithm"`
	AffectedKeys  int        `json:"affected_keys"`
	CompletedKeys int        `json:"completed_keys"`
	Status        string     `json:"status"`
	CreatedAt     time.Time  `json:"created_at"`
	TargetDate    *time.Time `json:"target_date,omitempty"`
}

// legacyAlgorithms is the set of algorithms considered cryptographically weak
// or deprecated.
var legacyAlgorithms = map[string]bool{
	"DES":        true,
	"3DES":       true,
	"RC4":        true,
	"MD5":        true,
	"SHA-1":      true,
	"RSA-1024":   true,
	"RSA-2048":   true,
	"AES-128-CBC": true,
	"AES-128-ECB": true,
	"AES-256-ECB": true,
}

// quantumSafeAlgorithms is the set of algorithms considered quantum-resistant.
var quantumSafeAlgorithms = map[string]bool{
	"ML-KEM-768":   true,
	"ML-KEM-1024":  true,
	"ML-DSA-44":    true,
	"ML-DSA-65":    true,
	"ML-DSA-87":    true,
	"CRYSTALS-Kyber": true,
	"CRYSTALS-Dilithium": true,
	"SPHINCS+":     true,
	"FALCON-512":   true,
	"FALCON-1024":  true,
}

// computeAgilityScore calculates a real cryptographic agility score from the
// provided algorithm usage distribution.
//
// Scoring methodology:
//   - Base score starts at 100.
//   - Each percentage point of legacy algorithm usage subtracts 0.6 points
//     (max −60).
//   - Algorithms that are NOT quantum-safe but also NOT legacy subtract a
//     smaller penalty of 0.2 points per percentage point (max −20).
//   - The quantum-readiness percentage forms part of the final score.
//   - Grade thresholds: A ≥ 85, B ≥ 70, C ≥ 55, D ≥ 40, F < 40.
func computeAgilityScore(algos []AlgorithmUsage) AgilityScore {
	var totalKeys int
	for i := range algos {
		totalKeys += algos[i].KeyCount
	}

	// Annotate algorithms and compute totals.
	var legacyKeys, quantumSafeKeys int
	for i := range algos {
		if totalKeys > 0 {
			algos[i].Percentage = float64(algos[i].KeyCount) / float64(totalKeys) * 100
		}
		algos[i].IsLegacy = legacyAlgorithms[algos[i].Algorithm]
		algos[i].IsQuantumSafe = quantumSafeAlgorithms[algos[i].Algorithm]
		if algos[i].IsLegacy {
			legacyKeys += algos[i].KeyCount
		}
		if algos[i].IsQuantumSafe {
			quantumSafeKeys += algos[i].KeyCount
		}
	}

	var legacyPct, quantumPct float64
	if totalKeys > 0 {
		legacyPct = float64(legacyKeys) / float64(totalKeys) * 100
		quantumPct = float64(quantumSafeKeys) / float64(totalKeys) * 100
	}

	score := 100.0
	score -= legacyPct * 0.6
	// Non-legacy, non-quantum-safe keys also reduce score slightly.
	nonQuantumSafeNonLegacyPct := 100.0 - legacyPct - quantumPct
	if nonQuantumSafeNonLegacyPct > 0 {
		score -= nonQuantumSafeNonLegacyPct * 0.2
	}
	if score < 0 {
		score = 0
	}

	intScore := int(score + 0.5)

	grade := "F"
	switch {
	case intScore >= 85:
		grade = "A"
	case intScore >= 70:
		grade = "B"
	case intScore >= 55:
		grade = "C"
	case intScore >= 40:
		grade = "D"
	}

	var recommendations []string
	if legacyKeys > 0 {
		recommendations = append(recommendations, "Migrate legacy algorithm keys (DES, 3DES, RC4) to AES-256-GCM or stronger.")
	}
	if quantumPct < 20 {
		recommendations = append(recommendations, "Increase quantum-safe key usage (ML-KEM, ML-DSA) to at least 20% of inventory.")
	}
	if quantumPct < 50 {
		recommendations = append(recommendations, "Create migration plans for transitioning existing keys to post-quantum algorithms.")
	}
	if len(algos) == 1 {
		recommendations = append(recommendations, "Diversify algorithm usage to reduce single-algorithm dependency risk.")
	}
	if len(recommendations) == 0 {
		recommendations = append(recommendations, "Cryptographic posture is strong. Continue monitoring for newly deprecated algorithms.")
	}

	return AgilityScore{
		Score:            intScore,
		Grade:            grade,
		QuantumReadiness: int(quantumPct + 0.5),
		LegacyKeyCount:   legacyKeys,
		TotalKeys:        totalKeys,
		Algorithms:       algos,
		Recommendations:  recommendations,
	}
}
