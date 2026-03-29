package main

import (
	"net/http"
	"regexp"
	"strings"
	"time"
)

// PIIPattern defines a regex pattern for detecting a specific data class.
type PIIPattern struct {
	Label       string
	Regex       *regexp.Regexp
	Regulation  []string
	Severity    string
	Description string
}

// piiPatterns is the built-in catalog of sensitive data patterns.
var piiPatterns = []PIIPattern{
	{
		Label:       "email",
		Regex:       regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
		Regulation:  []string{"GDPR", "CCPA"},
		Severity:    "medium",
		Description: "Email address",
	},
	{
		Label:       "credit_card",
		Regex:       regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b`),
		Regulation:  []string{"PCI-DSS"},
		Severity:    "high",
		Description: "Payment card number (PAN)",
	},
	{
		Label:       "ssn",
		Regex:       regexp.MustCompile(`\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b`),
		Regulation:  []string{"GDPR", "CCPA"},
		Severity:    "high",
		Description: "US Social Security Number",
	},
	{
		Label:       "uk_nino",
		Regex:       regexp.MustCompile(`\b[A-CEGHJ-PR-TW-Z]{2}[0-9]{6}[A-D]\b`),
		Regulation:  []string{"GDPR"},
		Severity:    "high",
		Description: "UK National Insurance Number",
	},
	{
		Label:       "ipv4",
		Regex:       regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`),
		Regulation:  []string{"GDPR"},
		Severity:    "low",
		Description: "IPv4 address",
	},
	{
		Label:       "iban",
		Regex:       regexp.MustCompile(`\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]{0,16})\b`),
		Regulation:  []string{"GDPR", "PCI-DSS"},
		Severity:    "high",
		Description: "International Bank Account Number",
	},
	{
		Label:       "aws_access_key",
		Regex:       regexp.MustCompile(`\b(AKIA|AIPA|ABIA|ACCA)[A-Z0-9]{16}\b`),
		Regulation:  []string{"NIST"},
		Severity:    "high",
		Description: "AWS access key ID",
	},
	{
		Label:       "private_key_pem",
		Regex:       regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`),
		Regulation:  []string{"GDPR", "NIST"},
		Severity:    "high",
		Description: "PEM private key material",
	},
	{
		Label:       "jwt_token",
		Regex:       regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b`),
		Regulation:  []string{"NIST"},
		Severity:    "medium",
		Description: "JSON Web Token",
	},
	{
		Label:       "phone_us",
		Regex:       regexp.MustCompile(`\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b`),
		Regulation:  []string{"GDPR", "CCPA"},
		Severity:    "medium",
		Description: "US phone number",
	},
	{
		Label:       "medical_record",
		Regex:       regexp.MustCompile(`(?i)\b(?:mrn|patient[_\s]id|medical[_\s]record)[:\s=]+[A-Z0-9]{6,12}\b`),
		Regulation:  []string{"HIPAA"},
		Severity:    "high",
		Description: "Medical Record Number",
	},
}

// PIIScanRequest is the input for a PII scan.
type PIIScanRequest struct {
	TenantID   string   `json:"tenant_id"`
	Content    string   `json:"content"`
	SourceName string   `json:"source_name"`
	SourceType string   `json:"source_type"` // file, database_column, api_response, log
	Labels     []string `json:"labels"`
}

// PIIFinding is a single PII detection result.
type PIIFinding struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	SourceName  string    `json:"source_name"`
	SourceType  string    `json:"source_type"`
	DataClass   string    `json:"data_class"`
	Regulation  []string  `json:"regulation"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	MatchCount  int       `json:"match_count"`
	Redacted    string    `json:"redacted_sample"`
	ScannedAt   time.Time `json:"scanned_at"`
}

// PIIScanResponse is the result of a PII scan.
type PIIScanResponse struct {
	SourceName    string       `json:"source_name"`
	SourceType    string       `json:"source_type"`
	TotalFindings int          `json:"total_findings"`
	Findings      []PIIFinding `json:"findings"`
	RiskLevel     string       `json:"risk_level"`
	Regulations   []string     `json:"regulations"`
	ScannedAt     time.Time    `json:"scanned_at"`
}

// handlePIIScan scans provided content for PII/sensitive data patterns.
// POST /discovery/pii/scan
func (h *Handler) handlePIIScan(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req PIIScanRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	if req.TenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required", reqID, "")
		return
	}
	if len(req.Content) > 1*1024*1024 {
		writeErr(w, http.StatusRequestEntityTooLarge, "content_too_large", "content exceeds 1 MB", reqID, req.TenantID)
		return
	}

	findings := scanForPII(req.TenantID, req.Content, req.SourceName, req.SourceType)
	riskLevel := "low"
	regsSet := map[string]struct{}{}
	for _, f := range findings {
		for _, reg := range f.Regulation {
			regsSet[reg] = struct{}{}
		}
		if f.Severity == "high" {
			riskLevel = "high"
		} else if f.Severity == "medium" && riskLevel != "high" {
			riskLevel = "medium"
		}
	}
	regs := make([]string, 0, len(regsSet))
	for reg := range regsSet {
		regs = append(regs, reg)
	}

	resp := PIIScanResponse{
		SourceName:    req.SourceName,
		SourceType:    req.SourceType,
		TotalFindings: len(findings),
		Findings:      findings,
		RiskLevel:     riskLevel,
		Regulations:   regs,
		ScannedAt:     time.Now().UTC(),
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": resp, "request_id": reqID})
}

// handleListPIIPatterns returns the built-in PII pattern catalog.
// GET /discovery/pii/patterns
func (h *Handler) handleListPIIPatterns(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	type patternInfo struct {
		Label       string   `json:"label"`
		Description string   `json:"description"`
		Regulation  []string `json:"regulation"`
		Severity    string   `json:"severity"`
	}
	out := make([]patternInfo, len(piiPatterns))
	for i, p := range piiPatterns {
		out[i] = patternInfo{Label: p.Label, Description: p.Description, Regulation: p.Regulation, Severity: p.Severity}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": out, "count": len(out), "request_id": reqID})
}

// handleGetDataInventory returns a structured data inventory view aggregated from assets.
// GET /discovery/data-inventory?tenant_id=
func (h *Handler) handleGetDataInventory(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}

	assets, err := h.svc.ListAssets(r.Context(), tenantID, 1000, 0, "", "", "")
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}

	type InventoryItem struct {
		Source         string `json:"source"`
		AssetType      string `json:"asset_type"`
		Count          int    `json:"count"`
		Classification string `json:"classification"`
		PQCReady       int    `json:"pqc_ready"`
		AtRisk         int    `json:"at_risk"`
	}

	bySource := map[string]*InventoryItem{}
	for _, a := range assets {
		key := a.Source + "|" + a.AssetType + "|" + a.Classification
		item := bySource[key]
		if item == nil {
			item = &InventoryItem{
				Source:         a.Source,
				AssetType:      a.AssetType,
				Classification: a.Classification,
			}
			bySource[key] = item
		}
		item.Count++
		if a.PQCReady {
			item.PQCReady++
		}
		if a.StrengthBits > 0 && a.StrengthBits < 128 {
			item.AtRisk++
		}
	}

	items := make([]*InventoryItem, 0, len(bySource))
	for _, v := range bySource {
		items = append(items, v)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items":      items,
		"total":      len(assets),
		"request_id": reqID,
	})
}

// scanForPII runs all PII patterns against the content and returns findings.
func scanForPII(tenantID, content, sourceName, sourceType string) []PIIFinding {
	var findings []PIIFinding
	for _, pattern := range piiPatterns {
		matches := pattern.Regex.FindAllString(content, -1)
		if len(matches) == 0 {
			continue
		}
		sample := ""
		if loc := pattern.Regex.FindStringIndex(content); loc != nil {
			start := max(0, loc[0]-20)
			end := min(len(content), loc[1]+20)
			before := content[start:loc[0]]
			matched := content[loc[0]:loc[1]]
			after := content[loc[1]:end]
			masked := strings.Repeat("*", min(len(matched), 6)) + "…"
			sample = strings.TrimSpace(before + masked + after)
		}
		regsCopy := make([]string, len(pattern.Regulation))
		copy(regsCopy, pattern.Regulation)
		findings = append(findings, PIIFinding{
			ID:          newID("pii"),
			TenantID:    tenantID,
			SourceName:  sourceName,
			SourceType:  sourceType,
			DataClass:   pattern.Label,
			Regulation:  regsCopy,
			Severity:    pattern.Severity,
			Description: pattern.Description,
			MatchCount:  len(matches),
			Redacted:    sample,
			ScannedAt:   time.Now().UTC(),
		})
	}
	return findings
}
