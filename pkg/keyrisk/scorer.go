package keyrisk

import (
	"context"
	"math"
	"time"
)

// KeyMetadata holds all attributes needed to compute a key's risk score.
type KeyMetadata struct {
	KeyID                  string
	TenantID               string
	Algorithm              string
	KeySize                int
	CreatedAt              time.Time
	LastRotated            time.Time
	RotationPolicyInterval time.Duration // 0 means no policy
	AccessCount30d         int
	UnusualAccessCount     int
	DependentServices      int
	FIPSApproved           bool
	HSMBacked              bool
	PlaintextInTransit     bool
	ExposedInLogs          bool
}

// RiskFactor represents a single dimension of risk.
type RiskFactor struct {
	Name        string  `json:"name"`
	Score       float64 `json:"score"`
	Weight      float64 `json:"weight"`
	Description string  `json:"description"`
	Remediation string  `json:"remediation"`
}

// RiskCategory classifies the overall risk level.
type RiskCategory string

const (
	RiskCritical RiskCategory = "critical"
	RiskHigh     RiskCategory = "high"
	RiskMedium   RiskCategory = "medium"
	RiskLow      RiskCategory = "low"
)

// KeyRiskScore is the computed risk assessment for a single key.
type KeyRiskScore struct {
	KeyID        string       `json:"key_id"`
	TenantID     string       `json:"tenant_id"`
	OverallScore float64      `json:"overall_score"`
	Factors      []RiskFactor `json:"factors"`
	Category     RiskCategory `json:"category"`
	ComputedAt   time.Time    `json:"computed_at"`
}

// Weights holds the relative importance of each risk factor.
type Weights struct {
	Algorithm  float64
	Age        float64
	Rotation   float64
	Access     float64
	Blast      float64
	Compliance float64
	Exposure   float64
}

// DefaultWeights returns the standard weight configuration.
func DefaultWeights() Weights {
	return Weights{
		Algorithm:  0.20,
		Age:        0.15,
		Rotation:   0.20,
		Access:     0.15,
		Blast:      0.10,
		Compliance: 0.10,
		Exposure:   0.10,
	}
}

// Scorer computes risk scores for cryptographic keys.
type Scorer struct {
	Weights Weights
}

// NewScorer creates a Scorer with the given weights. Pass nil-like zero value to use defaults.
func NewScorer(w Weights) *Scorer {
	if w == (Weights{}) {
		w = DefaultWeights()
	}
	return &Scorer{Weights: w}
}

// ScoreKey evaluates a single key and returns its risk score.
func (s *Scorer) ScoreKey(_ context.Context, key KeyMetadata) KeyRiskScore {
	factors := []RiskFactor{
		s.algorithmStrength(key),
		s.keyAge(key),
		s.rotationCompliance(key),
		s.accessPatterns(key),
		s.blastRadius(key),
		s.complianceGaps(key),
		s.exposureRisk(key),
	}

	var weightedSum, totalWeight float64
	for _, f := range factors {
		weightedSum += f.Score * f.Weight
		totalWeight += f.Weight
	}

	overall := 0.0
	if totalWeight > 0 {
		overall = math.Round(weightedSum / totalWeight)
	}

	category := categorize(overall)

	return KeyRiskScore{
		KeyID:        key.KeyID,
		TenantID:     key.TenantID,
		OverallScore: overall,
		Factors:      factors,
		Category:     category,
		ComputedAt:   time.Now().UTC(),
	}
}

func categorize(score float64) RiskCategory {
	switch {
	case score >= 80:
		return RiskCritical
	case score >= 60:
		return RiskHigh
	case score >= 30:
		return RiskMedium
	default:
		return RiskLow
	}
}

func (s *Scorer) algorithmStrength(key KeyMetadata) RiskFactor {
	var score float64
	var desc, remediation string

	algoKey := key.Algorithm
	switch algoKey {
	case "AES":
		switch key.KeySize {
		case 256:
			score = 0
			desc = "AES-256 is the gold standard for symmetric encryption"
		case 192:
			score = 10
			desc = "AES-192 provides strong security"
		case 128:
			score = 20
			desc = "AES-128 is acceptable but weaker than AES-256"
			remediation = "Upgrade to AES-256 for maximum security margin"
		default:
			score = 50
			desc = "Non-standard AES key size"
			remediation = "Use standard AES key sizes (128, 192, 256)"
		}
	case "RSA":
		switch {
		case key.KeySize >= 4096:
			score = 5
			desc = "RSA-4096 provides strong asymmetric security"
		case key.KeySize >= 2048:
			score = 25
			desc = "RSA-2048 meets minimum requirements but is approaching end of recommended life"
			remediation = "Plan migration to RSA-4096 or ECDSA P-384"
		case key.KeySize >= 1024:
			score = 90
			desc = "RSA-1024 is considered insecure and can be factored with sufficient resources"
			remediation = "Immediately migrate to RSA-2048 or stronger"
		default:
			score = 100
			desc = "RSA key size below 1024 bits is trivially breakable"
			remediation = "Immediately migrate to RSA-2048 or stronger"
		}
	case "3DES", "TDEA":
		score = 80
		desc = "3DES is deprecated due to Sweet32 attack and small block size"
		remediation = "Migrate to AES-256 immediately"
	case "DES":
		score = 100
		desc = "DES is completely insecure with a 56-bit key"
		remediation = "Migrate to AES-256 immediately"
	case "PQC", "KYBER", "DILITHIUM", "ML-KEM", "ML-DSA":
		score = 0
		desc = "Post-quantum cryptography algorithm provides future-proof security"
	case "ECDSA", "EC":
		switch {
		case key.KeySize >= 384:
			score = 5
			desc = "ECDSA P-384 or stronger provides excellent security"
		case key.KeySize >= 256:
			score = 10
			desc = "ECDSA P-256 provides strong security"
		default:
			score = 40
			desc = "Weak elliptic curve parameters"
			remediation = "Use P-256 or P-384 curves"
		}
	default:
		score = 50
		desc = "Unknown or unrecognized algorithm: " + algoKey
		remediation = "Evaluate algorithm security and consider migration to a well-known standard"
	}

	return RiskFactor{
		Name:        "algorithm_strength",
		Score:       score,
		Weight:      s.Weights.Algorithm,
		Description: desc,
		Remediation: remediation,
	}
}

func (s *Scorer) keyAge(key KeyMetadata) RiskFactor {
	age := time.Since(key.CreatedAt)
	var score float64
	var desc, remediation string

	switch {
	case age > 5*365*24*time.Hour:
		score = 100
		desc = "Key is over 5 years old, significantly increasing cryptanalysis risk"
		remediation = "Rotate key immediately and establish an annual rotation policy"
	case age > 3*365*24*time.Hour:
		score = 80
		desc = "Key is over 3 years old"
		remediation = "Schedule key rotation within 30 days"
	case age > 2*365*24*time.Hour:
		score = 50
		desc = "Key is over 2 years old"
		remediation = "Plan key rotation within 90 days"
	case age > 365*24*time.Hour:
		score = 30
		desc = "Key is over 1 year old"
		remediation = "Consider rotating key to limit exposure window"
	case age > 90*24*time.Hour:
		score = 10
		desc = "Key age is within acceptable range (90 days to 1 year)"
	default:
		score = 0
		desc = "Key is fresh, created within the last 90 days"
	}

	return RiskFactor{
		Name:        "key_age",
		Score:       score,
		Weight:      s.Weights.Age,
		Description: desc,
		Remediation: remediation,
	}
}

func (s *Scorer) rotationCompliance(key KeyMetadata) RiskFactor {
	var score float64
	var desc, remediation string

	if key.RotationPolicyInterval == 0 {
		// No rotation policy at all
		if key.LastRotated.IsZero() {
			score = 100
			desc = "Key has never been rotated and has no rotation policy"
			remediation = "Establish a rotation policy and rotate the key immediately"
		} else {
			score = 60
			desc = "Key has been rotated before but lacks a defined rotation policy"
			remediation = "Define and enforce a rotation policy"
		}
	} else if key.LastRotated.IsZero() {
		score = 100
		desc = "Key has never been rotated despite having a rotation policy"
		remediation = "Rotate the key immediately"
	} else {
		overdue := time.Since(key.LastRotated) - key.RotationPolicyInterval
		switch {
		case overdue <= 0:
			score = 0
			desc = "Key is rotated on schedule"
		case overdue < 30*24*time.Hour:
			score = 30
			desc = "Key rotation is overdue by less than 30 days"
			remediation = "Rotate key as soon as possible"
		case overdue < 90*24*time.Hour:
			score = 60
			desc = "Key rotation is overdue by 30-90 days"
			remediation = "Rotate key immediately and review rotation automation"
		default:
			score = 90
			desc = "Key rotation is overdue by more than 90 days"
			remediation = "Rotate key immediately, investigate why automation failed"
		}
	}

	return RiskFactor{
		Name:        "rotation_compliance",
		Score:       score,
		Weight:      s.Weights.Rotation,
		Description: desc,
		Remediation: remediation,
	}
}

func (s *Scorer) accessPatterns(key KeyMetadata) RiskFactor {
	var score float64
	var desc, remediation string

	unusualRatio := 0.0
	if key.AccessCount30d > 0 {
		unusualRatio = float64(key.UnusualAccessCount) / float64(key.AccessCount30d)
	}

	switch {
	case key.UnusualAccessCount == 0 && key.AccessCount30d <= 1000:
		score = 0
		desc = "Normal access patterns observed"
	case unusualRatio > 0.3:
		score = 80
		desc = "High rate of unauthorized or anomalous access attempts detected"
		remediation = "Investigate access logs, review IAM policies, consider key rotation"
	case key.AccessCount30d > 10000:
		score = 50
		desc = "Abnormal spike in key access volume detected"
		remediation = "Verify access spike is legitimate, review application behavior"
	case key.UnusualAccessCount > 0:
		score = 30
		desc = "Some unusual-hour or anomalous access patterns detected"
		remediation = "Review access logs for the flagged time periods"
	default:
		score = 0
		desc = "Access patterns are within normal bounds"
	}

	return RiskFactor{
		Name:        "access_patterns",
		Score:       score,
		Weight:      s.Weights.Access,
		Description: desc,
		Remediation: remediation,
	}
}

func (s *Scorer) blastRadius(key KeyMetadata) RiskFactor {
	deps := key.DependentServices
	var score float64
	var desc, remediation string

	switch {
	case deps == 0:
		score = 0
		desc = "No known dependent services"
	case deps < 5:
		score = 10
		desc = "Small blast radius with fewer than 5 dependent services"
	case deps < 20:
		score = 30
		desc = "Moderate blast radius with 5-19 dependent services"
		remediation = "Consider isolating key usage per service"
	case deps < 50:
		score = 60
		desc = "Large blast radius with 20-49 dependent services"
		remediation = "Split key usage across multiple keys to reduce impact"
	default:
		score = 80
		desc = "Critical blast radius with 50+ dependent services"
		remediation = "Urgently segment key usage, implement key-per-service model"
	}

	return RiskFactor{
		Name:        "blast_radius",
		Score:       score,
		Weight:      s.Weights.Blast,
		Description: desc,
		Remediation: remediation,
	}
}

func (s *Scorer) complianceGaps(key KeyMetadata) RiskFactor {
	var score float64
	var desc, remediation string

	// Evaluate compliance based on FIPS approval and HSM backing
	switch {
	case key.FIPSApproved && key.HSMBacked:
		score = 0
		desc = "All compliance controls met: FIPS-approved algorithm in HSM"
	case key.FIPSApproved && !key.HSMBacked:
		score = 20
		desc = "FIPS-approved algorithm but not HSM-backed; minor compliance gap"
		remediation = "Consider migrating key to HSM for full compliance"
	case !key.FIPSApproved && key.HSMBacked:
		score = 70
		desc = "FIPS violation: algorithm is not FIPS-approved"
		remediation = "Migrate to a FIPS 140-2/3 approved algorithm immediately"
	default:
		score = 90
		desc = "Critical compliance gap: non-FIPS algorithm without HSM protection"
		remediation = "Migrate to FIPS-approved algorithm and HSM-backed storage"
	}

	return RiskFactor{
		Name:        "compliance_gaps",
		Score:       score,
		Weight:      s.Weights.Compliance,
		Description: desc,
		Remediation: remediation,
	}
}

func (s *Scorer) exposureRisk(key KeyMetadata) RiskFactor {
	var score float64
	var desc, remediation string

	switch {
	case key.ExposedInLogs:
		score = 100
		desc = "Key material has been detected in application logs"
		remediation = "Rotate key immediately, purge logs, fix logging configuration"
	case key.PlaintextInTransit:
		score = 60
		desc = "Key material transmitted in plaintext over the network"
		remediation = "Enable TLS for all key transport, use key wrapping"
	case !key.HSMBacked:
		score = 20
		desc = "Key stored in software vault without HSM protection"
		remediation = "Consider HSM-backed storage for higher assurance"
	default:
		score = 0
		desc = "Key is HSM-protected with no known exposure"
	}

	return RiskFactor{
		Name:        "exposure_risk",
		Score:       score,
		Weight:      s.Weights.Exposure,
		Description: desc,
		Remediation: remediation,
	}
}
