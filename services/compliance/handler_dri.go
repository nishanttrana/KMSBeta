package main

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// KeyRiskItem represents a single key with its computed risk metadata.
type KeyRiskItem struct {
	KeyID          string   `json:"key_id"`
	KeyName        string   `json:"key_name"`
	Algorithm      string   `json:"algorithm"`
	Status         string   `json:"status"`
	RiskScore      int      `json:"risk_score"`     // 0-100
	RiskLevel      string   `json:"risk_level"`     // low, medium, high, critical
	RiskFactors    []string `json:"risk_factors"`
	OpsTotal       int64    `json:"ops_total"`
	ExportAllowed  bool     `json:"export_allowed"`
	LastUsed       string   `json:"last_used"`
	CreatedAt      string   `json:"created_at"`
	Recommendation string   `json:"recommendation"`
}

// DataRiskSummary represents the aggregated risk posture for a tenant.
type DataRiskSummary struct {
	TenantID          string         `json:"tenant_id"`
	OverallRiskScore  int            `json:"overall_risk_score"`
	CriticalKeys      int            `json:"critical_keys"`
	HighRiskKeys      int            `json:"high_risk_keys"`
	UnrotatedKeys     int            `json:"unrotated_keys"`
	ExportableKeys    int            `json:"exportable_keys"`
	WeakAlgorithmKeys int            `json:"weak_algorithm_keys"`
	UnusedKeys        int            `json:"unused_keys"`
	ExpiringKeys      int            `json:"expiring_keys"`
	RiskByAlgorithm   map[string]int `json:"risk_by_algorithm"`
	ComputedAt        time.Time      `json:"computed_at"`
}

// RemediationItem represents a single guided remediation action.
type RemediationItem struct {
	ID            string   `json:"id"`
	Priority      int      `json:"priority"`     // 1 = highest
	Category      string   `json:"category"`     // rotation, algorithm, access, export
	Title         string   `json:"title"`
	Description   string   `json:"description"`
	AffectedCount int      `json:"affected_count"`
	Action        string   `json:"action"` // rotate, restrict-export, upgrade-algorithm, etc.
	ResourceIDs   []string `json:"resource_ids"`
}

// computeKeyRisk scores a single key map returned by the keycore client.
// Returns score (0-100), a list of contributing factors, and a recommendation string.
func computeKeyRisk(key map[string]interface{}) (score int, factors []string, recommendation string) {
	score = 0

	// Factor 1: Weak / deprecated algorithm (+40).
	alg := strings.ToLower(fmt.Sprintf("%v", key["algorithm"]))
	weakAlgos := []string{"des", "3des", "rc4", "md5", "sha1", "rsa-1024", "rsa-512"}
	for _, w := range weakAlgos {
		if strings.Contains(alg, w) {
			score += 40
			factors = append(factors, "deprecated algorithm: "+alg)
			break // count once even if multiple tokens match
		}
	}

	// Factor 2: Export allowed (+25).
	if fmt.Sprintf("%v", key["export_allowed"]) == "true" {
		score += 25
		factors = append(factors, "key is exportable")
	}

	// Factor 3: No rotation in 365+ days (+20).
	if createdStr := fmt.Sprintf("%v", key["created_at"]); createdStr != "" && createdStr != "<nil>" {
		if t, err := time.Parse(time.RFC3339, createdStr); err == nil {
			if time.Since(t) > 365*24*time.Hour {
				score += 20
				factors = append(factors, "not rotated in over 1 year")
			}
		}
	}

	// Factor 4: Expiring within 30 days (+15).
	if expStr := fmt.Sprintf("%v", key["expires_at"]); expStr != "" && expStr != "<nil>" {
		if t, err := time.Parse(time.RFC3339, expStr); err == nil {
			remaining := time.Until(t)
			if remaining < 30*24*time.Hour && remaining > 0 {
				score += 15
				factors = append(factors, "expires within 30 days")
			}
		}
	}

	// Factor 5: Key has never been used (+10).
	if ops, _ := key["ops_total"].(float64); ops == 0 {
		score += 10
		factors = append(factors, "key has never been used")
	}

	// Cap at 100.
	if score > 100 {
		score = 100
	}

	switch {
	case score == 0:
		recommendation = "No immediate action required."
	case score >= 60:
		recommendation = "Immediate remediation required."
	case score >= 30:
		recommendation = "Schedule remediation."
	default:
		recommendation = "Monitor and review periodically."
	}

	return
}

// riskLevel maps a numeric score to a label.
func riskLevel(score int) string {
	switch {
	case score >= 75:
		return "critical"
	case score >= 50:
		return "high"
	case score >= 25:
		return "medium"
	default:
		return "low"
	}
}

// buildKeyRiskItems fetches all keys and converts them to KeyRiskItem values.
func buildKeyRiskItems(keys []map[string]interface{}) []KeyRiskItem {
	items := make([]KeyRiskItem, 0, len(keys))
	for _, k := range keys {
		score, factors, rec := computeKeyRisk(k)

		keyID := fmt.Sprintf("%v", k["id"])
		keyName := fmt.Sprintf("%v", k["name"])
		alg := fmt.Sprintf("%v", k["algorithm"])
		status := fmt.Sprintf("%v", k["status"])
		createdAt := fmt.Sprintf("%v", k["created_at"])
		lastUsed := fmt.Sprintf("%v", k["last_used_at"])
		exportAllowed := fmt.Sprintf("%v", k["export_allowed"]) == "true"

		var opsTotal int64
		if ops, ok := k["ops_total"].(float64); ok {
			opsTotal = int64(ops)
		}

		// Normalise "<nil>" sentinel values from the keycore response.
		if createdAt == "<nil>" {
			createdAt = ""
		}
		if lastUsed == "<nil>" {
			lastUsed = ""
		}

		if factors == nil {
			factors = []string{}
		}

		items = append(items, KeyRiskItem{
			KeyID:          keyID,
			KeyName:        keyName,
			Algorithm:      alg,
			Status:         status,
			RiskScore:      score,
			RiskLevel:      riskLevel(score),
			RiskFactors:    factors,
			OpsTotal:       opsTotal,
			ExportAllowed:  exportAllowed,
			LastUsed:       lastUsed,
			CreatedAt:      createdAt,
			Recommendation: rec,
		})
	}

	// Sort descending by risk score.
	sort.Slice(items, func(i, j int) bool {
		return items[i].RiskScore > items[j].RiskScore
	})

	return items
}

// handleGetKeyRiskRanking returns keys ranked by risk score (highest risk first).
// GET /compliance/risk/keys?tenant_id=&limit=50
// Response: {"items": [...KeyRiskItem...], "request_id": "..."}
func (h *Handler) handleGetKeyRiskRanking(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}

	limit := atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}

	keys, err := h.svc.keycore.ListKeys(r.Context(), tenantID, 500)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}

	items := buildKeyRiskItems(keys)

	// Publish audit alert if any critical-risk keys are found (score >= 75).
	criticalIDs := make([]string, 0)
	for _, item := range items {
		if item.RiskScore >= 75 {
			criticalIDs = append(criticalIDs, item.KeyID)
		}
	}
	if len(criticalIDs) > 0 {
		_ = h.svc.publishAudit(r.Context(), "audit.compliance.critical_keys_detected", tenantID, map[string]interface{}{
			"critical_key_count": len(criticalIDs),
			"key_ids":            criticalIDs,
		})
	}

	if limit < len(items) {
		items = items[:limit]
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items":      items,
		"request_id": reqID,
	})
}

// handleGetDataRiskSummary returns the overall data risk posture for a tenant.
// GET /compliance/risk/summary?tenant_id=
// Response: {"summary": DataRiskSummary, "request_id": "..."}
func (h *Handler) handleGetDataRiskSummary(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}

	keys, err := h.svc.keycore.ListKeys(r.Context(), tenantID, 500)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}

	items := buildKeyRiskItems(keys)

	summary := DataRiskSummary{
		TenantID:        tenantID,
		RiskByAlgorithm: map[string]int{},
		ComputedAt:      time.Now().UTC(),
	}

	totalScore := 0
	for _, item := range items {
		totalScore += item.RiskScore

		switch item.RiskLevel {
		case "critical":
			summary.CriticalKeys++
		case "high":
			summary.HighRiskKeys++
		}

		if item.ExportAllowed {
			summary.ExportableKeys++
		}
		if item.OpsTotal == 0 {
			summary.UnusedKeys++
		}

		alg := strings.ToLower(item.Algorithm)
		weakAlgos := []string{"des", "3des", "rc4", "md5", "sha1", "rsa-1024", "rsa-512"}
		for _, w := range weakAlgos {
			if strings.Contains(alg, w) {
				summary.WeakAlgorithmKeys++
				break
			}
		}

		for _, f := range item.RiskFactors {
			if strings.HasPrefix(f, "not rotated") {
				summary.UnrotatedKeys++
			}
			if strings.HasPrefix(f, "expires within") {
				summary.ExpiringKeys++
			}
		}

		// Track average risk score per algorithm family.
		algKey := strings.ToLower(item.Algorithm)
		if algKey == "" || algKey == "<nil>" {
			algKey = "unknown"
		}
		summary.RiskByAlgorithm[algKey] += item.RiskScore
	}

	if len(items) > 0 {
		summary.OverallRiskScore = totalScore / len(items)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"summary":    summary,
		"request_id": reqID,
	})
}

// handleGetRiskRemediation returns guided remediation actions ranked by priority.
// GET /compliance/risk/remediation?tenant_id=
// Response: {"items": [...RemediationItem...], "request_id": "..."}
func (h *Handler) handleGetRiskRemediation(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}

	keys, err := h.svc.keycore.ListKeys(r.Context(), tenantID, 500)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}

	items := buildKeyRiskItems(keys)

	// Collect resource ID sets for each remediation category.
	var (
		weakAlgIDs   []string
		exportIDs    []string
		unrotatedIDs []string
		expiringIDs  []string
		unusedIDs    []string
	)

	weakAlgos := []string{"des", "3des", "rc4", "md5", "sha1", "rsa-1024", "rsa-512"}

	for _, item := range items {
		alg := strings.ToLower(item.Algorithm)
		for _, w := range weakAlgos {
			if strings.Contains(alg, w) {
				weakAlgIDs = append(weakAlgIDs, item.KeyID)
				break
			}
		}
		if item.ExportAllowed {
			exportIDs = append(exportIDs, item.KeyID)
		}
		for _, f := range item.RiskFactors {
			if strings.HasPrefix(f, "not rotated") {
				unrotatedIDs = append(unrotatedIDs, item.KeyID)
			}
			if strings.HasPrefix(f, "expires within") {
				expiringIDs = append(expiringIDs, item.KeyID)
			}
		}
		if item.OpsTotal == 0 {
			unusedIDs = append(unusedIDs, item.KeyID)
		}
	}

	var remediations []RemediationItem
	priority := 1

	if len(weakAlgIDs) > 0 {
		remediations = append(remediations, RemediationItem{
			ID:            newID("rem"),
			Priority:      priority,
			Category:      "algorithm",
			Title:         "Upgrade deprecated cryptographic algorithms",
			Description:   "Keys using deprecated or weak algorithms (DES, 3DES, RC4, MD5, SHA-1, RSA-1024, RSA-512) pose a significant security risk. Migrate to AES-256, RSA-2048+, or post-quantum algorithms.",
			AffectedCount: len(weakAlgIDs),
			Action:        "upgrade-algorithm",
			ResourceIDs:   weakAlgIDs,
		})
		priority++
	}

	if len(expiringIDs) > 0 {
		remediations = append(remediations, RemediationItem{
			ID:            newID("rem"),
			Priority:      priority,
			Category:      "rotation",
			Title:         "Renew keys expiring within 30 days",
			Description:   "Keys approaching their expiry date should be renewed or rotated before they expire to avoid service disruption.",
			AffectedCount: len(expiringIDs),
			Action:        "rotate",
			ResourceIDs:   expiringIDs,
		})
		priority++
	}

	if len(exportIDs) > 0 {
		remediations = append(remediations, RemediationItem{
			ID:            newID("rem"),
			Priority:      priority,
			Category:      "export",
			Title:         "Restrict key export permissions",
			Description:   "Exportable keys increase the attack surface. Restrict export unless strictly required by application workflows.",
			AffectedCount: len(exportIDs),
			Action:        "restrict-export",
			ResourceIDs:   exportIDs,
		})
		priority++
	}

	if len(unrotatedIDs) > 0 {
		remediations = append(remediations, RemediationItem{
			ID:            newID("rem"),
			Priority:      priority,
			Category:      "rotation",
			Title:         "Rotate keys not rotated in over 1 year",
			Description:   "Long-lived keys increase the blast radius of a key compromise. Establish a rotation policy of at most 12 months.",
			AffectedCount: len(unrotatedIDs),
			Action:        "rotate",
			ResourceIDs:   unrotatedIDs,
		})
		priority++
	}

	if len(unusedIDs) > 0 {
		remediations = append(remediations, RemediationItem{
			ID:            newID("rem"),
			Priority:      priority,
			Category:      "access",
			Title:         "Review and decommission unused keys",
			Description:   "Keys that have never been used may indicate orphaned resources. Review and deactivate or delete them to reduce unnecessary attack surface.",
			AffectedCount: len(unusedIDs),
			Action:        "decommission",
			ResourceIDs:   unusedIDs,
		})
	}

	if remediations == nil {
		remediations = []RemediationItem{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items":      remediations,
		"request_id": reqID,
	})
}
