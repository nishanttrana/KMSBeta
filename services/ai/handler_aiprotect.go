package main

import (
	"net/http"
	"regexp"
	"strings"
	"time"
)

// AIProtectPolicy represents a tenant-scoped data protection policy.
type AIProtectPolicy struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	// comma-separated pattern names to scan for: email,ssn,credit_card,api_key,private_key,jwt,phone
	Patterns    []string  `json:"patterns"`
	// action on match: "redact", "block", "warn"
	Action      string    `json:"action"`
	Scope       string    `json:"scope"` // "input", "output", "both"
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// AIProtectScanRequest is the request body for scan and redact endpoints.
type AIProtectScanRequest struct {
	TenantID string   `json:"tenant_id"`
	Text     string   `json:"text"`
	Patterns []string `json:"patterns"` // if empty uses all patterns
	Context  string   `json:"context"`  // "input" or "output"
}

// AIProtectFinding is a single match found during a scan.
type AIProtectFinding struct {
	Pattern string `json:"pattern"`
	Match   string `json:"match"`  // redacted to first 4 chars + "***"
	Offset  int    `json:"offset"`
	Count   int    `json:"count"`
}

// AIProtectScanResult is the result of a scan or redact operation.
type AIProtectScanResult struct {
	RequestID    string             `json:"request_id"`
	TenantID     string             `json:"tenant_id"`
	Safe         bool               `json:"safe"`
	FindingCount int                `json:"finding_count"`
	Findings     []AIProtectFinding `json:"findings"`
	RedactedText string             `json:"redacted_text"`
	ScannedAt    time.Time          `json:"scanned_at"`
}

// AIProtectAuditEntry records an audit log entry for a protect operation.
type AIProtectAuditEntry struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	Action       string    `json:"action"` // "scan", "redact", "block"
	FindingCount int       `json:"finding_count"`
	Patterns     []string  `json:"patterns_matched"`
	Context      string    `json:"context"`
	PolicyID     string    `json:"policy_id,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

// aiProtectPatterns holds compiled regexes for each supported pattern name.
var aiProtectPatterns = map[string]*regexp.Regexp{
	"email":       regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
	"credit_card": regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b`),
	"ssn":         regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
	"api_key":     regexp.MustCompile(`(?i)(?:api[_-]?key|token|secret)[^\S\r\n]*[:=][^\S\r\n]*[A-Za-z0-9_\-]{16,}`),
	"private_key": regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`),
	"jwt":         regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b`),
	"phone":       regexp.MustCompile(`\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`),
	"aws_key":     regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	"password":    regexp.MustCompile(`(?i)password[^\S\r\n]*[:=][^\S\r\n]*\S{6,}`),
}

// partialRedact keeps the first 4 characters of a match and appends "***".
func partialRedact(s string) string {
	r := []rune(s)
	if len(r) <= 4 {
		return string(r) + "***"
	}
	return string(r[:4]) + "***"
}

// resolvePatterns returns the subset of aiProtectPatterns requested. If
// requested is empty all patterns are returned.
func resolvePatterns(requested []string) map[string]*regexp.Regexp {
	if len(requested) == 0 {
		return aiProtectPatterns
	}
	out := make(map[string]*regexp.Regexp, len(requested))
	for _, name := range requested {
		name = strings.TrimSpace(name)
		if re, ok := aiProtectPatterns[name]; ok {
			out[name] = re
		}
	}
	return out
}

// runScan executes the pattern scan against text and returns findings.
// When doRedact is true the returned redactedText has every match replaced
// with [REDACTED:<pattern>]; otherwise redactedText equals the original text.
func runScan(text string, patterns map[string]*regexp.Regexp, doRedact bool) (findings []AIProtectFinding, redactedText string, matchedPatternNames []string) {
	redactedText = text
	// Track per-pattern aggregated findings (first offset, total count).
	type agg struct {
		firstMatch  string
		firstOffset int
		count       int
	}
	aggMap := map[string]*agg{}

	for name, re := range patterns {
		locs := re.FindAllStringIndex(text, -1)
		if len(locs) == 0 {
			continue
		}
		a := &agg{count: len(locs)}
		first := locs[0]
		a.firstOffset = first[0]
		a.firstMatch = partialRedact(text[first[0]:first[1]])
		aggMap[name] = a
	}

	// Build findings slice and collect matched pattern names.
	patternNames := make([]string, 0, len(aggMap))
	for name := range aggMap {
		patternNames = append(patternNames, name)
	}

	findings = make([]AIProtectFinding, 0, len(aggMap))
	for _, name := range patternNames {
		a := aggMap[name]
		findings = append(findings, AIProtectFinding{
			Pattern: name,
			Match:   a.firstMatch,
			Offset:  a.firstOffset,
			Count:   a.count,
		})
	}
	matchedPatternNames = patternNames

	if doRedact {
		for name, re := range patterns {
			if _, found := aggMap[name]; !found {
				continue
			}
			label := "[REDACTED:" + name + "]"
			redactedText = re.ReplaceAllString(redactedText, label)
		}
	}

	return findings, redactedText, matchedPatternNames
}

// handleAIProtectScan handles POST /ai/protect/scan.
func (h *Handler) handleAIProtectScan(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req AIProtectScanRequest
	if err := decodeJSONAllowEmpty(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	if req.TenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required (body or X-Tenant-ID)", reqID, "")
		return
	}

	patterns := resolvePatterns(req.Patterns)
	findings, redactedText, matchedNames := runScan(req.Text, patterns, false)

	result := AIProtectScanResult{
		RequestID:    reqID,
		TenantID:     req.TenantID,
		Safe:         len(findings) == 0,
		FindingCount: len(findings),
		Findings:     findings,
		RedactedText: redactedText,
		ScannedAt:    time.Now().UTC(),
	}

	entry := AIProtectAuditEntry{
		ID:           newID("aipa"),
		TenantID:     req.TenantID,
		Action:       "scan",
		FindingCount: len(findings),
		Patterns:     matchedNames,
		Context:      req.Context,
	}
	_ = h.svc.store.InsertAIProtectAuditEntry(r.Context(), entry)

	if len(findings) > 0 {
		_ = h.svc.publishAudit(r.Context(), "audit.ai.pii_found", req.TenantID, map[string]interface{}{
			"action":        "scan",
			"finding_count": len(findings),
			"patterns":      matchedNames,
			"context":       req.Context,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"result": result, "request_id": reqID})
}

// handleAIProtectRedact handles POST /ai/protect/redact.
func (h *Handler) handleAIProtectRedact(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req AIProtectScanRequest
	if err := decodeJSONAllowEmpty(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	if req.TenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required (body or X-Tenant-ID)", reqID, "")
		return
	}

	patterns := resolvePatterns(req.Patterns)
	findings, redactedText, matchedNames := runScan(req.Text, patterns, true)

	result := AIProtectScanResult{
		RequestID:    reqID,
		TenantID:     req.TenantID,
		Safe:         len(findings) == 0,
		FindingCount: len(findings),
		Findings:     findings,
		RedactedText: redactedText,
		ScannedAt:    time.Now().UTC(),
	}

	entry := AIProtectAuditEntry{
		ID:           newID("aipa"),
		TenantID:     req.TenantID,
		Action:       "redact",
		FindingCount: len(findings),
		Patterns:     matchedNames,
		Context:      req.Context,
	}
	_ = h.svc.store.InsertAIProtectAuditEntry(r.Context(), entry)

	if len(findings) > 0 {
		_ = h.svc.publishAudit(r.Context(), "audit.ai.pii_found", req.TenantID, map[string]interface{}{
			"action":        "redact",
			"finding_count": len(findings),
			"patterns":      matchedNames,
			"context":       req.Context,
		})
		_ = h.svc.publishAudit(r.Context(), "audit.ai.redaction_applied", req.TenantID, map[string]interface{}{
			"finding_count": len(findings),
			"patterns":      matchedNames,
			"context":       req.Context,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"result": result, "request_id": reqID})
}

// handleListAIProtectPolicies handles GET /ai/protect/policies.
func (h *Handler) handleListAIProtectPolicies(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required (query or X-Tenant-ID)", reqID, "")
		return
	}
	policies, err := h.svc.store.ListAIProtectPolicies(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"policies": policies, "request_id": reqID})
}

// handleCreateAIProtectPolicy handles POST /ai/protect/policies.
func (h *Handler) handleCreateAIProtectPolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)

	var req AIProtectPolicy
	if err := decodeJSONAllowEmpty(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantID)
	if req.TenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required (body or X-Tenant-ID)", reqID, "")
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "name is required", reqID, req.TenantID)
		return
	}

	// Apply defaults.
	req.ID = newID("aipp")
	if strings.TrimSpace(req.Action) == "" {
		req.Action = "redact"
	}
	if strings.TrimSpace(req.Scope) == "" {
		req.Scope = "both"
	}
	if !req.Enabled {
		// Default to enabled=true unless explicitly set to false by caller.
		// Because decodeJSONAllowEmpty uses DisallowUnknownFields, the zero
		// value false will be present when not sent — we default to true.
		req.Enabled = true
	}
	if req.Patterns == nil {
		req.Patterns = []string{}
	}

	policy, err := h.svc.store.CreateAIProtectPolicy(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	_ = h.svc.publishAudit(r.Context(), "audit.ai.policy_created", policy.TenantID, map[string]interface{}{
		"policy_id": policy.ID,
		"name":      policy.Name,
		"action":    policy.Action,
		"scope":     policy.Scope,
		"enabled":   policy.Enabled,
	})
	writeJSON(w, http.StatusCreated, map[string]interface{}{"policy": policy, "request_id": reqID})
}

// handleDeleteAIProtectPolicy handles DELETE /ai/protect/policies/{id}.
func (h *Handler) handleDeleteAIProtectPolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required (query or X-Tenant-ID)", reqID, "")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "id is required", reqID, tenantID)
		return
	}

	if err := h.svc.store.DeleteAIProtectPolicy(r.Context(), tenantID, id); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	_ = h.svc.publishAudit(r.Context(), "audit.ai.policy_deleted", tenantID, map[string]interface{}{
		"policy_id": id,
	})
	w.WriteHeader(http.StatusNoContent)
}

// handleListAIProtectAudit handles GET /ai/protect/audit.
func (h *Handler) handleListAIProtectAudit(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required (query or X-Tenant-ID)", reqID, "")
		return
	}
	entries, err := h.svc.store.ListAIProtectAuditEntries(r.Context(), tenantID, 200)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"entries": entries, "request_id": reqID})
}
