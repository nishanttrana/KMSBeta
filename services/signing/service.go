package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"
)

type Service struct {
	store   Store
	keycore KeyCoreClient
	events  EventPublisher
	now     func() time.Time
}

func NewService(store Store, keycore KeyCoreClient, events EventPublisher) *Service {
	return &Service{
		store:   store,
		keycore: keycore,
		events:  events,
		now:     func() time.Time { return time.Now().UTC() },
	}
}

func defaultSettings(tenantID string) SigningSettings {
	return SigningSettings{
		TenantID:             strings.TrimSpace(tenantID),
		Enabled:              false,
		RequireTransparency:  true,
		AllowedIdentityModes: []string{"oidc", "workload"},
	}
}

func normalizeSettings(item SigningSettings) SigningSettings {
	item.TenantID = strings.TrimSpace(item.TenantID)
	item.DefaultProfileID = strings.TrimSpace(item.DefaultProfileID)
	item.UpdatedBy = strings.TrimSpace(item.UpdatedBy)
	item.AllowedIdentityModes = normalizeStringList(item.AllowedIdentityModes)
	if len(item.AllowedIdentityModes) == 0 {
		item.AllowedIdentityModes = []string{"oidc", "workload"}
	}
	return item
}

func normalizeProfile(item SigningProfile) SigningProfile {
	item.ID = firstNonEmpty(strings.TrimSpace(item.ID), newID("sigprof"))
	item.TenantID = strings.TrimSpace(item.TenantID)
	item.Name = trimLimit(item.Name, 120)
	item.ArtifactType = normalizeArtifactType(item.ArtifactType)
	item.KeyID = strings.TrimSpace(item.KeyID)
	item.SigningAlgorithm = firstNonEmpty(strings.TrimSpace(item.SigningAlgorithm), "ecdsa-sha384")
	item.IdentityMode = normalizeIdentityMode(item.IdentityMode)
	item.AllowedWorkloadPatterns = normalizeStringList(item.AllowedWorkloadPatterns)
	item.AllowedOIDCIssuers = normalizeStringList(item.AllowedOIDCIssuers)
	item.AllowedSubjectPatterns = normalizeStringList(item.AllowedSubjectPatterns)
	item.AllowedRepositories = normalizeStringList(item.AllowedRepositories)
	item.Description = trimLimit(item.Description, 280)
	item.UpdatedBy = strings.TrimSpace(item.UpdatedBy)
	return item
}

func normalizeArtifactType(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "git", "git_commit", "git-commit":
		return "git"
	case "oci", "container", "container_image":
		return "oci"
	default:
		return "blob"
	}
}

func normalizeIdentityMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "workload", "spiffe", "spiffe_svid":
		return "workload"
	default:
		return "oidc"
	}
}

func (s *Service) ensureSettings(ctx context.Context, tenantID string) (SigningSettings, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return SigningSettings{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	item, err := s.store.GetSettings(ctx, tenantID)
	if err == nil {
		return normalizeSettings(item), nil
	}
	if err != errNotFound {
		return SigningSettings{}, err
	}
	return s.store.UpsertSettings(ctx, defaultSettings(tenantID))
}

func (s *Service) GetSettings(ctx context.Context, tenantID string) (SigningSettings, error) {
	item, err := s.ensureSettings(ctx, tenantID)
	if err != nil {
		return SigningSettings{}, err
	}
	_ = publishAudit(ctx, s.events, "audit.signing.settings_viewed", tenantID, map[string]interface{}{"enabled": item.Enabled})
	return item, nil
}

func (s *Service) UpdateSettings(ctx context.Context, in SigningSettings) (SigningSettings, error) {
	item := normalizeSettings(in)
	if item.TenantID == "" {
		return SigningSettings{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	saved, err := s.store.UpsertSettings(ctx, item)
	if err != nil {
		return SigningSettings{}, err
	}
	_ = publishAudit(ctx, s.events, "audit.signing.settings_updated", saved.TenantID, map[string]interface{}{
		"enabled":               saved.Enabled,
		"default_profile_id":    saved.DefaultProfileID,
		"require_transparency":  saved.RequireTransparency,
		"allowed_identity_modes": saved.AllowedIdentityModes,
	})
	return saved, nil
}

func (s *Service) ListProfiles(ctx context.Context, tenantID string) ([]SigningProfile, error) {
	if _, err := s.ensureSettings(ctx, tenantID); err != nil {
		return nil, err
	}
	items, err := s.store.ListProfiles(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	_ = publishAudit(ctx, s.events, "audit.signing.profiles_viewed", tenantID, map[string]interface{}{"count": len(items)})
	return items, nil
}

func (s *Service) UpsertProfile(ctx context.Context, in SigningProfile) (SigningProfile, error) {
	item := normalizeProfile(in)
	if item.TenantID == "" || item.Name == "" || item.KeyID == "" {
		return SigningProfile{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id, name, and key_id are required")
	}
	if _, err := s.ensureSettings(ctx, item.TenantID); err != nil {
		return SigningProfile{}, err
	}
	saved, err := s.store.UpsertProfile(ctx, item)
	if err != nil {
		return SigningProfile{}, err
	}
	_ = publishAudit(ctx, s.events, "audit.signing.profile_upserted", saved.TenantID, map[string]interface{}{
		"profile_id":      saved.ID,
		"artifact_type":   saved.ArtifactType,
		"identity_mode":   saved.IdentityMode,
		"transparency_required": saved.TransparencyRequired,
	})
	return saved, nil
}

func (s *Service) DeleteProfile(ctx context.Context, tenantID string, id string) error {
	if err := s.store.DeleteProfile(ctx, tenantID, id); err != nil {
		return err
	}
	_ = publishAudit(ctx, s.events, "audit.signing.profile_deleted", tenantID, map[string]interface{}{"profile_id": strings.TrimSpace(id)})
	return nil
}

func (s *Service) GetSummary(ctx context.Context, tenantID string) (SigningSummary, error) {
	settings, err := s.ensureSettings(ctx, tenantID)
	if err != nil {
		return SigningSummary{}, err
	}
	profiles, _ := s.store.ListProfiles(ctx, tenantID)
	records, _ := s.store.ListRecords(ctx, tenantID, "", "", 2000)
	summary := SigningSummary{
		TenantID:       tenantID,
		Enabled:        settings.Enabled,
		ProfileCount:   len(profiles),
		ArtifactCounts: []SigningArtifactCount{},
	}
	cutoff := s.now().Add(-24 * time.Hour)
	counts := map[string]int{}
	for _, item := range records {
		if !item.CreatedAt.IsZero() && item.CreatedAt.Before(cutoff) {
			continue
		}
		summary.RecordCount24h++
		counts[item.ArtifactType]++
		if item.TransparencyEntryID != "" {
			summary.TransparencyLogged24h++
		}
		switch item.IdentityMode {
		case "workload":
			summary.WorkloadSigned24h++
		default:
			summary.OIDCSigned24h++
		}
		if strings.EqualFold(item.VerificationStatus, "failed") {
			summary.VerificationFailures24h++
		}
	}
	for artifactType, count := range counts {
		summary.ArtifactCounts = append(summary.ArtifactCounts, SigningArtifactCount{ArtifactType: artifactType, Count24h: count})
	}
	sort.Slice(summary.ArtifactCounts, func(i, j int) bool { return summary.ArtifactCounts[i].ArtifactType < summary.ArtifactCounts[j].ArtifactType })
	_ = publishAudit(ctx, s.events, "audit.signing.summary_viewed", tenantID, map[string]interface{}{
		"profile_count": len(profiles),
		"record_count_24h": summary.RecordCount24h,
	})
	return summary, nil
}

type signingEnvelope struct {
	TenantID         string `json:"tenant_id"`
	ProfileID        string `json:"profile_id"`
	ArtifactType     string `json:"artifact_type"`
	ArtifactName     string `json:"artifact_name"`
	DigestSHA256     string `json:"digest_sha256"`
	Repository       string `json:"repository,omitempty"`
	CommitSHA        string `json:"commit_sha,omitempty"`
	OCIReference     string `json:"oci_reference,omitempty"`
	IdentityMode     string `json:"identity_mode"`
	OIDCIssuer       string `json:"oidc_issuer,omitempty"`
	OIDCSubject      string `json:"oidc_subject,omitempty"`
	WorkloadIdentity string `json:"workload_identity,omitempty"`
	IssuedAt         string `json:"issued_at"`
}

func (s *Service) SignArtifact(ctx context.Context, in SignArtifactInput) (SignArtifactResult, error) {
	input := in
	input.TenantID = strings.TrimSpace(input.TenantID)
	if input.TenantID == "" {
		return SignArtifactResult{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	settings, err := s.ensureSettings(ctx, input.TenantID)
	if err != nil {
		return SignArtifactResult{}, err
	}
	if !settings.Enabled {
		return SignArtifactResult{}, newServiceError(http.StatusConflict, "disabled", "artifact signing is disabled for this tenant")
	}
	profileID := firstNonEmpty(input.ProfileID, settings.DefaultProfileID)
	if profileID == "" {
		return SignArtifactResult{}, newServiceError(http.StatusBadRequest, "bad_request", "profile_id is required")
	}
	profile, err := s.store.GetProfile(ctx, input.TenantID, profileID)
	if err != nil {
		if err == errNotFound {
			return SignArtifactResult{}, newServiceError(http.StatusNotFound, "not_found", "signing profile not found")
		}
		return SignArtifactResult{}, err
	}
	if !profile.Enabled {
		return SignArtifactResult{}, newServiceError(http.StatusConflict, "disabled", "signing profile is disabled")
	}
	identityMode := normalizeIdentityMode(firstNonEmpty(input.IdentityMode, profile.IdentityMode))
	if !matchesPatternList(settings.AllowedIdentityModes, identityMode) {
		return SignArtifactResult{}, newServiceError(http.StatusForbidden, "identity_mode_denied", "identity mode is not allowed by tenant policy")
	}
	switch identityMode {
	case "workload":
		if !matchesPatternList(profile.AllowedWorkloadPatterns, input.WorkloadIdentity) {
			return SignArtifactResult{}, newServiceError(http.StatusForbidden, "workload_identity_denied", "workload identity is not allowed for this signing profile")
		}
	default:
		if len(profile.AllowedOIDCIssuers) > 0 && !matchesPatternList(profile.AllowedOIDCIssuers, input.OIDCIssuer) {
			return SignArtifactResult{}, newServiceError(http.StatusForbidden, "oidc_issuer_denied", "oidc issuer is not allowed for this signing profile")
		}
		if !matchesPatternList(profile.AllowedSubjectPatterns, input.OIDCSubject) {
			return SignArtifactResult{}, newServiceError(http.StatusForbidden, "oidc_subject_denied", "oidc subject is not allowed for this signing profile")
		}
	}
	if len(profile.AllowedRepositories) > 0 && !matchesPatternList(profile.AllowedRepositories, firstNonEmpty(input.Repository, input.OCIReference)) {
		return SignArtifactResult{}, newServiceError(http.StatusForbidden, "repository_denied", "repository or artifact reference is not allowed for this signing profile")
	}

	artifactType := normalizeArtifactType(firstNonEmpty(input.ArtifactType, profile.ArtifactType))
	digest := strings.ToLower(strings.TrimSpace(input.DigestSHA256))
	if digest == "" {
		rawPayload, decodeErr := base64.StdEncoding.DecodeString(strings.TrimSpace(input.PayloadB64))
		if decodeErr != nil {
			return SignArtifactResult{}, newServiceError(http.StatusBadRequest, "bad_request", "payload must be valid base64 when digest_sha256 is omitted")
		}
		sum := sha256.Sum256(rawPayload)
		digest = hex.EncodeToString(sum[:])
	}

	envelope := signingEnvelope{
		TenantID:         input.TenantID,
		ProfileID:        profile.ID,
		ArtifactType:     artifactType,
		ArtifactName:     trimLimit(input.ArtifactName, 200),
		DigestSHA256:     digest,
		Repository:       trimLimit(input.Repository, 240),
		CommitSHA:        trimLimit(input.CommitSHA, 120),
		OCIReference:     trimLimit(input.OCIReference, 240),
		IdentityMode:     identityMode,
		OIDCIssuer:       trimLimit(input.OIDCIssuer, 240),
		OIDCSubject:      trimLimit(input.OIDCSubject, 240),
		WorkloadIdentity: trimLimit(input.WorkloadIdentity, 240),
		IssuedAt:         s.now().Format(time.RFC3339),
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		return SignArtifactResult{}, err
	}
	signResp, err := s.keycore.Sign(ctx, profile.KeyID, KeyCoreSignRequest{
		TenantID:  input.TenantID,
		DataB64:   base64.StdEncoding.EncodeToString(payload),
		Algorithm: profile.SigningAlgorithm,
	})
	if err != nil {
		return SignArtifactResult{}, err
	}
	transparencyIndex, err := s.store.NextTransparencyIndex(ctx, input.TenantID)
	if err != nil {
		return SignArtifactResult{}, err
	}
	record := SigningRecord{
		ID:                 newID("sigrec"),
		TenantID:           input.TenantID,
		ProfileID:          profile.ID,
		ArtifactType:       artifactType,
		ArtifactName:       envelope.ArtifactName,
		DigestSHA256:       digest,
		SignatureB64:       signResp.SignatureB64,
		KeyID:              firstNonEmpty(signResp.KeyID, profile.KeyID),
		SigningAlgorithm:   profile.SigningAlgorithm,
		IdentityMode:       identityMode,
		OIDCIssuer:         envelope.OIDCIssuer,
		OIDCSubject:        envelope.OIDCSubject,
		WorkloadIdentity:   envelope.WorkloadIdentity,
		Repository:         envelope.Repository,
		CommitSHA:          envelope.CommitSHA,
		OCIReference:       envelope.OCIReference,
		TransparencyEntryID: newID("tlog"),
		TransparencyHash:   sha256Hex(string(payload), signResp.SignatureB64),
		TransparencyIndex:  transparencyIndex,
		VerificationStatus: "logged",
		Metadata: map[string]interface{}{
			"envelope":      parseJSONObjectString(string(payload)),
			"requested_by":  strings.TrimSpace(input.RequestedBy),
			"profile_name":  profile.Name,
		},
		CreatedAt: s.now(),
	}
	if profile.TransparencyRequired || settings.RequireTransparency {
		// Transparency metadata is always written for tenant auditability.
	}
	if err := s.store.CreateRecord(ctx, record); err != nil {
		return SignArtifactResult{}, err
	}
	_ = publishAudit(ctx, s.events, "audit.signing.artifact_signed", input.TenantID, map[string]interface{}{
		"record_id":            record.ID,
		"profile_id":           record.ProfileID,
		"artifact_type":        record.ArtifactType,
		"artifact_name":        record.ArtifactName,
		"key_id":               record.KeyID,
		"identity_mode":        record.IdentityMode,
		"transparency_entry_id": record.TransparencyEntryID,
		"transparency_index":   record.TransparencyIndex,
	})
	return SignArtifactResult{Record: record, Envelope: parseJSONObjectString(string(payload))}, nil
}

func (s *Service) VerifyArtifact(ctx context.Context, in VerifyArtifactInput) (VerifyArtifactResult, error) {
	tenantID := strings.TrimSpace(in.TenantID)
	if tenantID == "" {
		return VerifyArtifactResult{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	recordID := strings.TrimSpace(in.RecordID)
	if recordID == "" {
		return VerifyArtifactResult{}, newServiceError(http.StatusBadRequest, "bad_request", "record_id is required")
	}
	record, err := s.store.GetRecord(ctx, tenantID, recordID)
	if err != nil {
		if err == errNotFound {
			return VerifyArtifactResult{}, newServiceError(http.StatusNotFound, "not_found", "signing record not found")
		}
		return VerifyArtifactResult{}, err
	}
	envelope := record.Metadata["envelope"]
	envelopeRaw, err := json.Marshal(envelope)
	if err != nil {
		return VerifyArtifactResult{}, err
	}
	verifyResp, err := s.keycore.Verify(ctx, record.KeyID, KeyCoreVerifyRequest{
		TenantID:     tenantID,
		DataB64:      base64.StdEncoding.EncodeToString(envelopeRaw),
		SignatureB64: record.SignatureB64,
		Algorithm:    record.SigningAlgorithm,
	})
	if err != nil {
		return VerifyArtifactResult{}, err
	}
	status := "verified"
	if !verifyResp.Valid {
		status = "failed"
	}
	_ = publishAudit(ctx, s.events, "audit.signing.artifact_verified", tenantID, map[string]interface{}{
		"record_id":           record.ID,
		"artifact_type":       record.ArtifactType,
		"verification_status": status,
		"transparency_hash":   record.TransparencyHash,
	})
	return VerifyArtifactResult{
		Valid:               verifyResp.Valid,
		RecordID:            record.ID,
		TransparencyHash:    record.TransparencyHash,
		TransparencyEntryID: record.TransparencyEntryID,
		VerifiedAt:          s.now(),
	}, nil
}

func (s *Service) ListRecords(ctx context.Context, tenantID string, profileID string, artifactType string, limit int) ([]SigningRecord, error) {
	if _, err := s.ensureSettings(ctx, tenantID); err != nil {
		return nil, err
	}
	items, err := s.store.ListRecords(ctx, tenantID, profileID, artifactType, limit)
	if err != nil {
		return nil, err
	}
	_ = publishAudit(ctx, s.events, "audit.signing.records_viewed", tenantID, map[string]interface{}{
		"profile_id":    strings.TrimSpace(profileID),
		"artifact_type": strings.TrimSpace(artifactType),
		"count":         len(items),
	})
	return items, nil
}

func publishAudit(ctx context.Context, publisher EventPublisher, subject string, tenantID string, details map[string]interface{}) error {
	if publisher == nil {
		return nil
	}
	payload := map[string]interface{}{
		"tenant_id":  strings.TrimSpace(tenantID),
		"details":    details,
		"emitted_at": time.Now().UTC().Format(time.RFC3339),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return publisher.Publish(ctx, subject, raw)
}
