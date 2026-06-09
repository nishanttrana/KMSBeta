package health

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"
)

// ScorerService implements HealthScorer interface
type ScorerService struct {
	db     *sql.DB
	config ScoringConfig
}

// NewScorerService creates a new health scorer service
func NewScorerService(db *sql.DB, config ScoringConfig) *ScorerService {
	if config.MaxKeyAge == 0 {
		config.MaxKeyAge = 365
	}
	if config.RotationIntervalDays == 0 {
		config.RotationIntervalDays = 90
	}
	if config.EntropySizeInBits == 0 {
		config.EntropySizeInBits = 256
	}
	if config.BackupVerificationDays == 0 {
		config.BackupVerificationDays = 30
	}
	if config.ExpiryWarningDays == 0 {
		config.ExpiryWarningDays = 90
	}

	return &ScorerService{db: db, config: config}
}

// CalculateHealth computes overall health score for a key
func (s *ScorerService) CalculateHealth(tenantID, keyID string) (*HealthScore, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Fetch key details
	query := `
SELECT k.created_at, k.algorithm, k.ops_total, k.expiry_date, k.status
FROM keys k
WHERE k.tenant_id = $1 AND k.id = $2
`

	var createdAt time.Time
	var algorithm string
	var opsTotal sql.NullInt64
	var expiryDate sql.NullTime
	var status string

	err := s.db.QueryRowContext(ctx, query, tenantID, keyID).Scan(
		&createdAt, &algorithm, &opsTotal, &expiryDate, &status)
	if err != nil {
		return nil, err
	}

	// Calculate individual scores
	ageScore := s.CalculateAgeScore(createdAt)
	algorithmScore := s.CalculateAlgorithmScore(algorithm)
	entropy := s.config.EntropySizeInBits
	entropyScore := s.CalculateEntropyScore(entropy)

	// Get last rotation
	rotationQuery := `
SELECT COALESCE(MAX(created_at), NOW()) FROM key_rotation_metrics
WHERE tenant_id = $1 AND key_id = $2 AND status = 'completed'
`
	var lastRotation time.Time
	s.db.QueryRowContext(ctx, rotationQuery, tenantID, keyID).Scan(&lastRotation)

	opsPerDay := 0.0
	if opsTotal.Valid && opsTotal.Int64 > 0 {
		daysSinceCreation := time.Since(createdAt).Hours() / 24
		if daysSinceCreation > 0 {
			opsPerDay = float64(opsTotal.Int64) / daysSinceCreation
		}
	}
	totalOps := int64(0)
	if opsTotal.Valid {
		totalOps = opsTotal.Int64
	}
	usageScore := s.CalculateUsageScore(totalOps, opsPerDay)

	// Check backup status
	backupQuery := `
SELECT COALESCE(MAX(backup_verified_at), NULL) FROM key_inventory
WHERE tenant_id = $1 AND key_id = $2
`
	var backupVerifiedAt sql.NullTime
	s.db.QueryRowContext(ctx, backupQuery, tenantID, keyID).Scan(&backupVerifiedAt)

	backupStatus := s.DetermineBackupStatus(getTimePtr(backupVerifiedAt))

	// Determine rotation overdue
	rotationOverdue := time.Since(lastRotation).Hours() > float64(s.config.RotationIntervalDays*24)

	// Check expiry imminence
	expiryImminently := false
	if expiryDate.Valid {
		daysUntilExpiry := time.Until(expiryDate.Time).Hours() / 24
		expiryImminently = daysUntilExpiry < float64(s.config.ExpiryWarningDays)
	}

	// Calculate overall health score (weighted average)
	healthScore := int(
		(float64(ageScore)*0.15 +
			float64(algorithmScore)*0.25 +
			float64(entropyScore)*0.15 +
			float64(usageScore)*0.20 +
			float64(calculateBackupScore(backupStatus))*0.15 +
			float64(boolToScore(rotationOverdue))*0.10) / 1.0)

	score := &HealthScore{
		KeyID:           keyID,
		TenantID:        tenantID,
		HealthScore:     healthScore,
		EntropyScore:    entropyScore,
		AgeScore:        ageScore,
		UsageScore:      usageScore,
		AlgorithmScore:  algorithmScore,
		BackupStatus:    backupStatus,
		RotationOverdue: rotationOverdue,
		ExpiryImminent:  expiryImminently,
		UpdatedAt:       time.Now(),
	}

	// Generate recommendations
	score.RecommendedActions = s.GenerateRecommendations(score)

	// Store in database
	if err := s.storeHealthScore(ctx, score); err != nil {
		return nil, err
	}

	return score, nil
}

// CalculateEntropyScore scores entropy
func (s *ScorerService) CalculateEntropyScore(entropyValue int) int {
	if entropyValue >= s.config.EntropySizeInBits {
		return 100
	}
	if entropyValue < 128 {
		return 50
	}
	return int(float64(entropyValue) / float64(s.config.EntropySizeInBits) * 100)
}

// CalculateAgeScore scores key age
func (s *ScorerService) CalculateAgeScore(createdAt time.Time) int {
	ageInDays := time.Since(createdAt).Hours() / 24
	maxAgeInDays := float64(s.config.MaxKeyAge)

	if ageInDays > maxAgeInDays {
		return 50
	}

	score := int((1 - (ageInDays / maxAgeInDays)) * 100)
	if score < 0 {
		score = 0
	}
	return score
}

// CalculateUsageScore scores key usage patterns
func (s *ScorerService) CalculateUsageScore(totalOps int64, opsPerDay float64) int {
	if totalOps == 0 {
		return 50 // Unused keys get medium score
	}
	if opsPerDay > 1000 {
		return 100 // High usage is good
	}
	if opsPerDay > 10 {
		return 85
	}
	if opsPerDay > 0 {
		return 70
	}
	return 50
}

// CalculateAlgorithmScore scores algorithm security
func (s *ScorerService) CalculateAlgorithmScore(algorithm string) int {
	switch strings.ToUpper(strings.TrimSpace(algorithm)) {
	case "RSA-2048", "RSA-3072", "RSA-4096", "ECDSA-P256", "ECDSA-P384", "ECDSA-P521", "EC-P256", "EC-P384", "EC-P521":
		return 100
	case "AES-128", "AES-192", "AES-256":
		return 100
	case "SHA-256", "SHA-384", "SHA-512":
		return 100
	case "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128S", "SLH-DSA-SHA2-192S", "SLH-DSA-SHA2-256S":
		return 100
	case "RSA-1024", "ECDSA-P192", "EC-P192", "MD5", "SHA-1", "DES", "3DES":
		return 40
	default:
		return 70
	}
}

// DetermineBackupStatus determines backup health
func (s *ScorerService) DetermineBackupStatus(lastVerified *time.Time) string {
	if lastVerified == nil {
		return "missing"
	}

	daysSinceVerified := time.Since(*lastVerified).Hours() / 24
	if daysSinceVerified < float64(s.config.BackupVerificationDays) {
		return "verified"
	}
	if daysSinceVerified < float64(s.config.BackupVerificationDays*2) {
		return "stale"
	}
	return "missing"
}

// GenerateRecommendations generates actionable recommendations
func (s *ScorerService) GenerateRecommendations(score *HealthScore) []string {
	var recommendations []string

	if score.HealthScore < 60 {
		recommendations = append(recommendations, "Schedule immediate key review")
	}

	if score.RotationOverdue {
		recommendations = append(recommendations, "Rotate key immediately - rotation overdue")
	}

	if score.ExpiryImminent {
		recommendations = append(recommendations, "Schedule key replacement - expiry approaching")
	}

	if score.BackupStatus == "missing" {
		recommendations = append(recommendations, "Verify and backup key material")
	}

	if score.AlgorithmScore < 60 {
		recommendations = append(recommendations, "Consider migrating to stronger algorithm")
	}

	if score.EntropyScore < 70 {
		recommendations = append(recommendations, "Regenerate key with higher entropy")
	}

	return recommendations
}

// GetHealthSummary returns overall health summary for tenant
func (s *ScorerService) GetHealthSummary(tenantID string) (map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	query := `
SELECT
COUNT(*) as total_keys,
COALESCE(AVG(health_score), 0) as avg_health,
COUNT(CASE WHEN health_score >= 80 THEN 1 END) as healthy_keys,
COUNT(CASE WHEN health_score < 60 THEN 1 END) as at_risk_keys,
COUNT(CASE WHEN rotation_overdue THEN 1 END) as overdue_rotations,
COUNT(CASE WHEN expiry_imminent THEN 1 END) as expiring_soon
FROM key_health_scores
WHERE tenant_id = $1
`

	var totalKeys, healthyKeys, atRiskKeys, overdueRotations, expiringSoon int
	var avgHealth float64

	err := s.db.QueryRowContext(ctx, query, tenantID).Scan(
		&totalKeys, &avgHealth, &healthyKeys, &atRiskKeys, &overdueRotations, &expiringSoon)
	if err != nil {
		return nil, err
	}

	healthPercentage := 0.0
	if totalKeys > 0 {
		healthPercentage = (float64(healthyKeys) / float64(totalKeys)) * 100
	}

	return map[string]interface{}{
		"total_keys":        totalKeys,
		"average_health":    avgHealth,
		"healthy_keys":      healthyKeys,
		"at_risk_keys":      atRiskKeys,
		"overdue_rotations": overdueRotations,
		"expiring_soon":     expiringSoon,
		"health_percentage": healthPercentage,
	}, nil
}

// Private helper functions
func (s *ScorerService) storeHealthScore(ctx context.Context, score *HealthScore) error {
	warningsJSON, _ := json.Marshal(score.ComplianceWarnings)
	recommendationsJSON, _ := json.Marshal(score.RecommendedActions)

	query := `
INSERT INTO key_health_scores
(key_id, tenant_id, health_score, entropy_score, age_score, usage_score,
 algorithm_score, backup_status, rotation_overdue, expiry_imminent,
 compliance_warnings, recommended_actions, last_audit_date, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW())
ON CONFLICT (tenant_id, key_id) DO UPDATE SET
health_score = EXCLUDED.health_score,
entropy_score = EXCLUDED.entropy_score,
age_score = EXCLUDED.age_score,
usage_score = EXCLUDED.usage_score,
algorithm_score = EXCLUDED.algorithm_score,
backup_status = EXCLUDED.backup_status,
rotation_overdue = EXCLUDED.rotation_overdue,
expiry_imminent = EXCLUDED.expiry_imminent,
compliance_warnings = EXCLUDED.compliance_warnings,
recommended_actions = EXCLUDED.recommended_actions,
updated_at = NOW()
`

	_, err := s.db.ExecContext(ctx, query,
		score.KeyID, score.TenantID, score.HealthScore, score.EntropyScore,
		score.AgeScore, score.UsageScore, score.AlgorithmScore,
		score.BackupStatus, score.RotationOverdue, score.ExpiryImminent,
		warningsJSON, recommendationsJSON, score.LastAuditDate)

	return err
}

func calculateBackupScore(status string) int {
	switch status {
	case "verified":
		return 100
	case "stale":
		return 60
	case "missing":
		return 20
	default:
		return 50
	}
}

func boolToScore(b bool) int {
	if b {
		return 20 // Penalty for overdue
	}
	return 100 // No penalty
}

func getTimePtr(nullTime sql.NullTime) *time.Time {
	if nullTime.Valid {
		return &nullTime.Time
	}
	return nil
}
