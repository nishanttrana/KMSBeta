package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

type EventPublisher interface {
	Publish(ctx context.Context, subject string, payload []byte) error
}

type Service struct {
	store         Store
	events        EventPublisher
	verifier      *ProviderVerifier
	now           func() time.Time
	clusterNodeID string
}

func NewService(store Store, events EventPublisher, clusterNodeID string) *Service {
	return &Service{
		store:         store,
		events:        events,
		verifier:      NewProviderVerifier(),
		now:           func() time.Time { return time.Now().UTC() },
		clusterNodeID: strings.TrimSpace(clusterNodeID),
	}
}

var supportedProviders = []string{
	"aws_nitro_enclaves",
	"aws_nitro_tpm",
	"azure_secure_key_release",
	"gcp_confidential_space",
	"generic",
}

func defaultAttestationPolicy(tenantID string) AttestationPolicy {
	return AttestationPolicy{
		TenantID:             strings.TrimSpace(tenantID),
		Enabled:              false,
		Provider:             "aws_nitro_enclaves",
		Mode:                 "enforce",
		KeyScopes:            []string{},
		ApprovedImages:       []string{},
		ApprovedSubjects:     []string{},
		AllowedAttesters:     []string{},
		RequiredMeasurements: map[string]string{"pcr0": "", "pcr8": ""},
		RequiredClaims:       map[string]string{},
		RequireSecureBoot:    true,
		RequireDebugDisabled: true,
		MaxEvidenceAgeSec:    300,
		ClusterScope:         "cluster_wide",
		AllowedClusterNodes:  []string{},
		FallbackAction:       "deny",
	}
}

func normalizeProvider(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "aws_nitro_enclaves", "aws-nitro-enclaves", "nitro-enclaves":
		return "aws_nitro_enclaves"
	case "aws_nitro_tpm", "aws-nitro-tpm", "nitro-tpm":
		return "aws_nitro_tpm"
	case "azure_secure_key_release", "azure-secure-key-release", "azure_skr", "azure":
		return "azure_secure_key_release"
	case "gcp_confidential_space", "gcp-confidential-space", "confidential-space", "gcp":
		return "gcp_confidential_space"
	case "generic":
		return "generic"
	default:
		return ""
	}
}

func normalizeMode(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "monitor":
		return "monitor"
	default:
		return "enforce"
	}
}

func normalizeClusterScope(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "node_allowlist", "node-allowlist":
		return "node_allowlist"
	default:
		return "cluster_wide"
	}
}

func normalizeFallbackAction(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "review":
		return "review"
	default:
		return "deny"
	}
}

func normalizeStringMap(values map[string]string) map[string]string {
	out := map[string]string{}
	for key, value := range values {
		k := strings.TrimSpace(strings.ToLower(key))
		v := strings.TrimSpace(value)
		if k == "" || v == "" {
			continue
		}
		out[k] = v
	}
	return out
}

func normalizeAttestationPolicy(in AttestationPolicy) AttestationPolicy {
	in.TenantID = strings.TrimSpace(in.TenantID)
	in.Provider = firstNonEmpty(normalizeProvider(in.Provider), "aws_nitro_enclaves")
	in.Mode = normalizeMode(in.Mode)
	in.KeyScopes = uniqueStrings(in.KeyScopes)
	in.ApprovedImages = uniqueStrings(in.ApprovedImages)
	in.ApprovedSubjects = uniqueStrings(in.ApprovedSubjects)
	in.AllowedAttesters = uniqueStrings(in.AllowedAttesters)
	if in.Provider == "aws_nitro_enclaves" || in.Provider == "aws_nitro_tpm" {
		for _, value := range in.AllowedAttesters {
			trimmed := strings.ToLower(strings.TrimSpace(value))
			if strings.HasPrefix(trimmed, "arn:aws:iam::") || strings.Contains(trimmed, "nitro-attestation") {
				in.AllowedAttesters = uniqueStrings(append(in.AllowedAttesters, "aws.nitro-enclaves"))
				break
			}
		}
	}
	in.RequiredMeasurements = normalizeStringMap(in.RequiredMeasurements)
	in.RequiredClaims = normalizeStringMap(in.RequiredClaims)
	in.ClusterScope = normalizeClusterScope(in.ClusterScope)
	in.AllowedClusterNodes = uniqueStrings(in.AllowedClusterNodes)
	in.FallbackAction = normalizeFallbackAction(in.FallbackAction)
	if in.MaxEvidenceAgeSec <= 0 {
		in.MaxEvidenceAgeSec = 300
	}
	if in.MaxEvidenceAgeSec > 86400 {
		in.MaxEvidenceAgeSec = 86400
	}
	in.UpdatedBy = strings.TrimSpace(in.UpdatedBy)
	return in
}

func normalizeAttestedReleaseRequest(in AttestedReleaseRequest, defaultNodeID string) AttestedReleaseRequest {
	in.TenantID = strings.TrimSpace(in.TenantID)
	in.KeyID = strings.TrimSpace(in.KeyID)
	in.KeyScope = strings.TrimSpace(strings.ToLower(in.KeyScope))
	in.Provider = firstNonEmpty(normalizeProvider(in.Provider), "generic")
	in.AttestationDocument = strings.TrimSpace(in.AttestationDocument)
	in.AttestationFormat = firstNonEmpty(normalizeAttestationFormat(in.AttestationFormat), "auto")
	in.WorkloadIdentity = strings.TrimSpace(in.WorkloadIdentity)
	in.Attester = strings.TrimSpace(in.Attester)
	in.ImageRef = strings.TrimSpace(in.ImageRef)
	in.ImageDigest = strings.TrimSpace(in.ImageDigest)
	in.Audience = strings.TrimSpace(in.Audience)
	in.Nonce = strings.TrimSpace(in.Nonce)
	in.Claims = normalizeStringMap(in.Claims)
	in.Measurements = normalizeStringMap(in.Measurements)
	in.ClusterNodeID = firstNonEmpty(strings.TrimSpace(in.ClusterNodeID), defaultNodeID)
	in.Requester = strings.TrimSpace(in.Requester)
	in.ReleaseReason = strings.TrimSpace(in.ReleaseReason)
	return in
}

func (s *Service) GetAttestationPolicy(ctx context.Context, tenantID string) (AttestationPolicy, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return AttestationPolicy{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	item, err := s.store.GetAttestationPolicy(ctx, tenantID)
	if err != nil {
		if err == errNotFound {
			return defaultAttestationPolicy(tenantID), nil
		}
		return AttestationPolicy{}, err
	}
	return normalizeAttestationPolicy(item), nil
}

func (s *Service) UpdateAttestationPolicy(ctx context.Context, in AttestationPolicy) (AttestationPolicy, error) {
	in = normalizeAttestationPolicy(in)
	if in.TenantID == "" {
		return AttestationPolicy{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	if in.Enabled && len(in.ApprovedImages) == 0 {
		return AttestationPolicy{}, newServiceError(http.StatusBadRequest, "bad_request", "at least one approved image is required when attested release is enabled")
	}
	if in.ClusterScope == "node_allowlist" && len(in.AllowedClusterNodes) == 0 {
		return AttestationPolicy{}, newServiceError(http.StatusBadRequest, "bad_request", "allowed_cluster_nodes is required when cluster_scope is node_allowlist")
	}
	item, err := s.store.UpsertAttestationPolicy(ctx, in)
	if err != nil {
		return AttestationPolicy{}, err
	}
	_ = s.publishAudit(ctx, "audit.confidential.policy_updated", item.TenantID, map[string]interface{}{
		"provider":               item.Provider,
		"mode":                   item.Mode,
		"approved_image_count":   len(item.ApprovedImages),
		"key_scope_count":        len(item.KeyScopes),
		"cluster_scope":          item.ClusterScope,
		"fallback_action":        item.FallbackAction,
		"require_secure_boot":    item.RequireSecureBoot,
		"require_debug_disabled": item.RequireDebugDisabled,
	})
	return item, nil
}

func (s *Service) ListReleaseHistory(ctx context.Context, tenantID string, limit int) ([]AttestedReleaseRecord, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	return s.store.ListReleaseRecords(ctx, tenantID, limit)
}

func (s *Service) GetReleaseRecord(ctx context.Context, tenantID string, id string) (AttestedReleaseRecord, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return AttestedReleaseRecord{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	item, err := s.store.GetReleaseRecord(ctx, tenantID, id)
	if err != nil {
		if err == errNotFound {
			return AttestedReleaseRecord{}, newServiceError(http.StatusNotFound, "not_found", "release record not found")
		}
		return AttestedReleaseRecord{}, err
	}
	return item, nil
}

func (s *Service) GetAttestationSummary(ctx context.Context, tenantID string) (AttestationSummary, error) {
	policy, err := s.GetAttestationPolicy(ctx, tenantID)
	if err != nil {
		return AttestationSummary{}, err
	}
	items, err := s.store.ListReleaseRecords(ctx, tenantID, 250)
	if err != nil {
		return AttestationSummary{}, err
	}
	summary := AttestationSummary{
		TenantID:           strings.TrimSpace(tenantID),
		PolicyEnabled:      policy.Enabled,
		Provider:           policy.Provider,
		ApprovedImageCount: len(policy.ApprovedImages),
		KeyScopeCount:      len(policy.KeyScopes),
	}
	since := s.now().Add(-24 * time.Hour)
	nodes := map[string]struct{}{}
	for _, item := range items {
		if !item.CreatedAt.IsZero() && item.CreatedAt.After(since) {
			switch strings.ToLower(strings.TrimSpace(item.Decision)) {
			case "release":
				summary.ReleaseCount24h++
			case "review":
				summary.ReviewCount24h++
			default:
				summary.DenyCount24h++
			}
			if item.CryptographicallyVerified {
				summary.CryptographicallyVerifiedCount24h++
			}
		}
		if summary.LastDecisionAt.IsZero() || item.CreatedAt.After(summary.LastDecisionAt) {
			summary.LastDecisionAt = item.CreatedAt
			summary.LatestDecision = item.Decision
		}
		if nodeID := strings.TrimSpace(item.ClusterNodeID); nodeID != "" {
			nodes[nodeID] = struct{}{}
		}
	}
	summary.UniqueClusterNodes = len(nodes)
	return summary, nil
}

func (s *Service) EvaluateAttestedRelease(ctx context.Context, in AttestedReleaseRequest) (AttestedReleaseDecision, error) {
	in = normalizeAttestedReleaseRequest(in, s.clusterNodeID)
	if in.TenantID == "" {
		return AttestedReleaseDecision{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	if in.KeyID == "" {
		return AttestedReleaseDecision{}, newServiceError(http.StatusBadRequest, "bad_request", "key_id is required")
	}
	policy, err := s.GetAttestationPolicy(ctx, in.TenantID)
	if err != nil {
		return AttestedReleaseDecision{}, err
	}

	verification := attestationVerification{
		Claims:       copyStringMap(in.Claims),
		Measurements: copyStringMap(in.Measurements),
	}
	if s.verifier != nil {
		verification = s.verifier.Verify(ctx, in)
	}
	evaluated := verification.applyTo(in)
	evaluated = normalizeAttestedReleaseRequest(evaluated, s.clusterNodeID)

	now := s.now()
	measuredHash := canonicalMapHash(evaluated.Measurements)
	claimsHash := canonicalMapHash(evaluated.Claims)
	evidenceTime := parseTimeString(evaluated.EvidenceIssuedAt)
	policyVersion := hashString(mustJSON(policy))
	releaseID := newID("rel")

	reasons := append([]string{}, verification.Issues...)
	matchedClaims := []string{}
	matchedMeasurements := []string{}
	missingClaims := []string{}
	missingMeasurements := []string{}
	missingAttributes := append([]string{}, verification.MissingAttributes...)

	if !policy.Enabled {
		reasons = append(reasons, "attested key release is disabled for this tenant")
		missingAttributes = append(missingAttributes, "policy_enabled")
	}
	if policy.Provider != "generic" && policy.Provider != evaluated.Provider {
		reasons = append(reasons, "attestation provider does not match tenant policy")
		missingAttributes = append(missingAttributes, "provider")
	}
	if len(policy.KeyScopes) > 0 && !containsFold(policy.KeyScopes, evaluated.KeyScope) && !containsFold(policy.KeyScopes, evaluated.KeyID) {
		reasons = append(reasons, "key scope is not approved for attested release")
		missingAttributes = append(missingAttributes, "key_scope")
	}
	if len(policy.ApprovedImages) > 0 && !matchesApprovedImage(policy.ApprovedImages, evaluated.ImageRef, evaluated.ImageDigest) {
		reasons = append(reasons, "workload image is not approved")
		missingAttributes = append(missingAttributes, "approved_image")
	}
	if len(policy.ApprovedSubjects) > 0 && !containsFold(policy.ApprovedSubjects, evaluated.WorkloadIdentity) {
		reasons = append(reasons, "workload identity is not approved")
		missingAttributes = append(missingAttributes, "approved_subject")
	}
	if len(policy.AllowedAttesters) > 0 && !containsFold(policy.AllowedAttesters, evaluated.Attester) {
		reasons = append(reasons, "attestation issuer is not approved")
		missingAttributes = append(missingAttributes, "attester")
	}
	if normalizeProvider(evaluated.Provider) != "generic" && !verification.CryptographicallyVerified {
		reasons = append(reasons, "provider attestation document was not cryptographically verified")
		missingAttributes = append(missingAttributes, "cryptographic_verification")
	}
	if policy.RequireSecureBoot && !evaluated.SecureBoot {
		reasons = append(reasons, "secure boot evidence is required")
		missingAttributes = append(missingAttributes, "secure_boot")
	}
	if policy.RequireDebugDisabled && !evaluated.DebugDisabled {
		reasons = append(reasons, "debug must be disabled for release")
		missingAttributes = append(missingAttributes, "debug_disabled")
	}
	if evidenceTime.IsZero() {
		reasons = append(reasons, "evidence_issued_at is required")
		missingAttributes = append(missingAttributes, "evidence_issued_at")
	} else {
		maxAge := time.Duration(policy.MaxEvidenceAgeSec) * time.Second
		if evidenceTime.Before(now.Add(-maxAge)) {
			reasons = append(reasons, "attestation evidence is older than tenant policy allows")
			missingAttributes = append(missingAttributes, "evidence_freshness")
		}
		if evidenceTime.After(now.Add(5 * time.Minute)) {
			reasons = append(reasons, "attestation evidence timestamp is in the future")
			missingAttributes = append(missingAttributes, "evidence_freshness")
		}
	}
	if policy.ClusterScope == "node_allowlist" && len(policy.AllowedClusterNodes) > 0 && !containsFold(policy.AllowedClusterNodes, evaluated.ClusterNodeID) {
		reasons = append(reasons, "cluster node is not approved for attested release")
		missingAttributes = append(missingAttributes, "cluster_node")
	}
	for _, key := range sortedStringKeys(policy.RequiredClaims) {
		want := strings.TrimSpace(policy.RequiredClaims[key])
		got := strings.TrimSpace(evaluated.Claims[strings.ToLower(strings.TrimSpace(key))])
		if got == "" {
			reasons = append(reasons, "required attestation claim is missing: "+key)
			missingClaims = append(missingClaims, key)
			continue
		}
		if got != want {
			reasons = append(reasons, "attestation claim mismatch for "+key)
			missingClaims = append(missingClaims, key)
			continue
		}
		matchedClaims = append(matchedClaims, key)
	}
	for _, key := range sortedStringKeys(policy.RequiredMeasurements) {
		want := strings.TrimSpace(policy.RequiredMeasurements[key])
		got := strings.TrimSpace(evaluated.Measurements[strings.ToLower(strings.TrimSpace(key))])
		if got == "" {
			reasons = append(reasons, "required measurement is missing: "+key)
			missingMeasurements = append(missingMeasurements, key)
			continue
		}
		if got != want {
			reasons = append(reasons, "measurement mismatch for "+key)
			missingMeasurements = append(missingMeasurements, key)
			continue
		}
		matchedMeasurements = append(matchedMeasurements, key)
	}

	decision := "release"
	allowed := true
	if len(reasons) > 0 {
		allowed = false
		if policy.Mode == "monitor" {
			decision = "review"
		} else {
			decision = policy.FallbackAction
		}
		if decision == "" {
			decision = "deny"
		}
	}

	expiresAt := time.Time{}
	if allowed {
		ttl := time.Duration(policy.MaxEvidenceAgeSec) * time.Second
		if ttl <= 0 || ttl > 10*time.Minute {
			ttl = 10 * time.Minute
		}
		expiresAt = now.Add(ttl)
	}

	result := AttestedReleaseDecision{
		ReleaseID:                 releaseID,
		Decision:                  decision,
		Allowed:                   allowed,
		Reasons:                   uniqueStrings(reasons),
		MatchedClaims:             uniqueStrings(matchedClaims),
		MatchedMeasurements:       uniqueStrings(matchedMeasurements),
		MissingClaims:             uniqueStrings(missingClaims),
		MissingMeasurements:       uniqueStrings(missingMeasurements),
		MissingAttributes:         uniqueStrings(missingAttributes),
		MeasurementHash:           measuredHash,
		ClaimsHash:                claimsHash,
		PolicyVersion:             policyVersion,
		Provider:                  evaluated.Provider,
		ClusterNodeID:             evaluated.ClusterNodeID,
		CryptographicallyVerified: verification.CryptographicallyVerified,
		VerificationMode:          verification.VerificationMode,
		VerificationIssuer:        verification.VerificationIssuer,
		VerificationKeyID:         verification.VerificationKeyID,
		AttestationDocumentHash:   verification.AttestationDocumentHash,
		AttestationDocumentFormat: verification.AttestationDocumentFormat,
		ExpiresAt:                 expiresAt,
		EvaluatedAt:               now,
		Profile:                   policy,
	}

	record := AttestedReleaseRecord{
		ID:                        releaseID,
		TenantID:                  in.TenantID,
		KeyID:                     in.KeyID,
		KeyScope:                  evaluated.KeyScope,
		Provider:                  evaluated.Provider,
		WorkloadIdentity:          evaluated.WorkloadIdentity,
		Attester:                  evaluated.Attester,
		ImageRef:                  evaluated.ImageRef,
		ImageDigest:               evaluated.ImageDigest,
		Audience:                  evaluated.Audience,
		Nonce:                     evaluated.Nonce,
		EvidenceIssuedAt:          evidenceTime,
		Claims:                    evaluated.Claims,
		Measurements:              evaluated.Measurements,
		SecureBoot:                evaluated.SecureBoot,
		DebugDisabled:             evaluated.DebugDisabled,
		ClusterNodeID:             evaluated.ClusterNodeID,
		Requester:                 evaluated.Requester,
		ReleaseReason:             evaluated.ReleaseReason,
		Decision:                  result.Decision,
		Allowed:                   result.Allowed,
		Reasons:                   result.Reasons,
		MatchedClaims:             result.MatchedClaims,
		MatchedMeasurements:       result.MatchedMeasurements,
		MissingClaims:             result.MissingClaims,
		MissingMeasurements:       result.MissingMeasurements,
		MissingAttributes:         result.MissingAttributes,
		MeasurementHash:           result.MeasurementHash,
		ClaimsHash:                result.ClaimsHash,
		PolicyVersion:             result.PolicyVersion,
		CryptographicallyVerified: result.CryptographicallyVerified,
		VerificationMode:          result.VerificationMode,
		VerificationIssuer:        result.VerificationIssuer,
		VerificationKeyID:         result.VerificationKeyID,
		AttestationDocumentHash:   result.AttestationDocumentHash,
		AttestationDocumentFormat: result.AttestationDocumentFormat,
		ExpiresAt:                 result.ExpiresAt,
		CreatedAt:                 now,
	}
	if !in.DryRun {
		if err := s.store.InsertReleaseRecord(ctx, record); err != nil {
			return AttestedReleaseDecision{}, err
		}
	}

	_ = s.publishAudit(ctx, "audit.confidential.key_release_evaluated", in.TenantID, map[string]interface{}{
		"release_id":                  releaseID,
		"key_id":                      in.KeyID,
		"key_scope":                   evaluated.KeyScope,
		"provider":                    evaluated.Provider,
		"decision":                    result.Decision,
		"allowed":                     result.Allowed,
		"measurement_hash":            result.MeasurementHash,
		"claims_hash":                 result.ClaimsHash,
		"policy_version":              result.PolicyVersion,
		"cluster_node_id":             evaluated.ClusterNodeID,
		"workload_identity":           evaluated.WorkloadIdentity,
		"image_digest":                evaluated.ImageDigest,
		"image_ref":                   evaluated.ImageRef,
		"attester":                    evaluated.Attester,
		"cryptographically_verified":  result.CryptographicallyVerified,
		"verification_mode":           result.VerificationMode,
		"verification_issuer":         result.VerificationIssuer,
		"verification_key_id":         result.VerificationKeyID,
		"attestation_document_hash":   result.AttestationDocumentHash,
		"attestation_document_format": result.AttestationDocumentFormat,
		"dry_run":                     in.DryRun,
	})

	return result, nil
}

func matchesApprovedImage(approved []string, imageRef string, imageDigest string) bool {
	if len(approved) == 0 {
		return true
	}
	ref := strings.TrimSpace(imageRef)
	digest := strings.TrimSpace(imageDigest)
	for _, item := range approved {
		candidate := strings.TrimSpace(item)
		if candidate == "" {
			continue
		}
		if ref != "" && strings.EqualFold(candidate, ref) {
			return true
		}
		if digest != "" && strings.EqualFold(candidate, digest) {
			return true
		}
		if ref != "" && digest != "" && strings.EqualFold(candidate, ref+"@"+digest) {
			return true
		}
	}
	return false
}

func (s *Service) publishAudit(ctx context.Context, subject string, tenantID string, data map[string]interface{}) error {
	if s.events == nil {
		return nil
	}
	payload := map[string]interface{}{
		"tenant_id":   strings.TrimSpace(tenantID),
		"subject":     strings.TrimSpace(subject),
		"service":     "kms-confidential",
		"occurred_at": s.now().UTC().Format(time.RFC3339Nano),
		"data":        data,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return s.events.Publish(ctx, subject, body)
}
