package main

import (
	"context"
	"time"
)

type EventPublisher interface {
	Publish(ctx context.Context, subject string, payload []byte) error
}

type Store interface {
	GetSettings(ctx context.Context, tenantID string) (SigningSettings, error)
	UpsertSettings(ctx context.Context, item SigningSettings) (SigningSettings, error)
	ListProfiles(ctx context.Context, tenantID string) ([]SigningProfile, error)
	UpsertProfile(ctx context.Context, item SigningProfile) (SigningProfile, error)
	DeleteProfile(ctx context.Context, tenantID string, id string) error
	GetProfile(ctx context.Context, tenantID string, id string) (SigningProfile, error)
	CreateRecord(ctx context.Context, item SigningRecord) error
	GetRecord(ctx context.Context, tenantID string, id string) (SigningRecord, error)
	ListRecords(ctx context.Context, tenantID string, profileID string, artifactType string, limit int) ([]SigningRecord, error)
	NextTransparencyIndex(ctx context.Context, tenantID string) (int, error)
}

type KeyCoreClient interface {
	Sign(ctx context.Context, keyID string, req KeyCoreSignRequest) (KeyCoreSignResponse, error)
	Verify(ctx context.Context, keyID string, req KeyCoreVerifyRequest) (KeyCoreVerifyResponse, error)
}

type SigningSettings struct {
	TenantID             string    `json:"tenant_id"`
	Enabled              bool      `json:"enabled"`
	DefaultProfileID     string    `json:"default_profile_id,omitempty"`
	RequireTransparency  bool      `json:"require_transparency"`
	AllowedIdentityModes []string  `json:"allowed_identity_modes"`
	UpdatedBy            string    `json:"updated_by,omitempty"`
	UpdatedAt            time.Time `json:"updated_at,omitempty"`
}

// SigningPolicy adds content-level constraints on top of identity checks.
// All non-empty constraints are AND-ed: a signing request must satisfy every
// populated field to be allowed. This closes the gap where any identity
// matching the profile could otherwise sign arbitrary content.
type SigningPolicy struct {
	// RequiredBranchPatterns restricts signing to specific git ref patterns.
	// Glob-style. Example: ["refs/heads/main", "refs/heads/release/*"]
	// Empty = no branch restriction.
	RequiredBranchPatterns []string `json:"required_branch_patterns,omitempty"`
	// RequiredArtifactTags lists metadata tags that must be present on the
	// artifact (passed via signing request metadata). Example: ["release", "signed-build"]
	RequiredArtifactTags []string `json:"required_artifact_tags,omitempty"`
	// AllowedDigests pins signing to an explicit SHA-256 allowlist. When set,
	// only listed digests may be signed. Useful for gating on CI-produced hashes.
	AllowedDigests []string `json:"allowed_digests,omitempty"`
	// BlockNonCICommits rejects signing requests that lack a recognized CI
	// identity claim (e.g., missing OIDC job_workflow_ref or workload selector).
	BlockNonCICommits bool `json:"block_non_ci_commits"`
	// RequireCommitSignature requires that git commit signing requests include
	// a GPG or SSH commit signature in the request metadata before KMS signing.
	RequireCommitSignature bool `json:"require_commit_signature"`
}

type SigningProfile struct {
	ID                      string        `json:"id"`
	TenantID                string        `json:"tenant_id"`
	Name                    string        `json:"name"`
	ArtifactType            string        `json:"artifact_type"`
	KeyID                   string        `json:"key_id"`
	SigningAlgorithm        string        `json:"signing_algorithm"`
	IdentityMode            string        `json:"identity_mode"`
	AllowedWorkloadPatterns []string      `json:"allowed_workload_patterns"`
	AllowedOIDCIssuers      []string      `json:"allowed_oidc_issuers"`
	AllowedSubjectPatterns  []string      `json:"allowed_subject_patterns"`
	AllowedRepositories     []string      `json:"allowed_repositories"`
	// Policy adds content-level constraints beyond identity verification.
	Policy                  SigningPolicy  `json:"policy"`
	TransparencyRequired    bool          `json:"transparency_required"`
	Enabled                 bool          `json:"enabled"`
	Description             string        `json:"description,omitempty"`
	UpdatedBy               string        `json:"updated_by,omitempty"`
	UpdatedAt               time.Time     `json:"updated_at,omitempty"`
}

type SigningRecord struct {
	ID                string                 `json:"id"`
	TenantID          string                 `json:"tenant_id"`
	ProfileID         string                 `json:"profile_id"`
	ArtifactType      string                 `json:"artifact_type"`
	ArtifactName      string                 `json:"artifact_name"`
	DigestSHA256      string                 `json:"digest_sha256"`
	SignatureB64      string                 `json:"signature"`
	KeyID             string                 `json:"key_id"`
	SigningAlgorithm  string                 `json:"signing_algorithm"`
	IdentityMode      string                 `json:"identity_mode"`
	OIDCIssuer        string                 `json:"oidc_issuer,omitempty"`
	OIDCSubject       string                 `json:"oidc_subject,omitempty"`
	WorkloadIdentity  string                 `json:"workload_identity,omitempty"`
	Repository        string                 `json:"repository,omitempty"`
	CommitSHA         string                 `json:"commit_sha,omitempty"`
	OCIReference      string                 `json:"oci_reference,omitempty"`
	TransparencyEntryID string               `json:"transparency_entry_id,omitempty"`
	TransparencyHash  string                 `json:"transparency_hash,omitempty"`
	TransparencyIndex int                    `json:"transparency_index,omitempty"`
	VerificationStatus string                `json:"verification_status,omitempty"`
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt         time.Time              `json:"created_at,omitempty"`
}

type SigningArtifactCount struct {
	ArtifactType string `json:"artifact_type"`
	Count24h     int    `json:"count_24h"`
}

type SigningSummary struct {
	TenantID                string                `json:"tenant_id"`
	Enabled                 bool                  `json:"enabled"`
	ProfileCount            int                   `json:"profile_count"`
	RecordCount24h          int                   `json:"record_count_24h"`
	TransparencyLogged24h   int                   `json:"transparency_logged_24h"`
	WorkloadSigned24h       int                   `json:"workload_signed_24h"`
	OIDCSigned24h           int                   `json:"oidc_signed_24h"`
	VerificationFailures24h int                   `json:"verification_failures_24h"`
	ArtifactCounts          []SigningArtifactCount `json:"artifact_counts"`
}

type SignArtifactInput struct {
	TenantID         string                 `json:"tenant_id"`
	ProfileID        string                 `json:"profile_id,omitempty"`
	ArtifactType     string                 `json:"artifact_type"`
	ArtifactName     string                 `json:"artifact_name"`
	PayloadB64       string                 `json:"payload,omitempty"`
	DigestSHA256     string                 `json:"digest_sha256,omitempty"`
	Repository       string                 `json:"repository,omitempty"`
	CommitSHA        string                 `json:"commit_sha,omitempty"`
	OCIReference     string                 `json:"oci_reference,omitempty"`
	IdentityMode     string                 `json:"identity_mode,omitempty"`
	OIDCIssuer       string                 `json:"oidc_issuer,omitempty"`
	OIDCSubject      string                 `json:"oidc_subject,omitempty"`
	WorkloadIdentity string                 `json:"workload_identity,omitempty"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
	RequestedBy      string                 `json:"requested_by,omitempty"`
}

type SignArtifactResult struct {
	Record   SigningRecord          `json:"record"`
	Envelope map[string]interface{} `json:"envelope"`
}

type VerifyArtifactInput struct {
	TenantID  string `json:"tenant_id"`
	RecordID  string `json:"record_id,omitempty"`
	ProfileID string `json:"profile_id,omitempty"`
}

type VerifyArtifactResult struct {
	Valid             bool      `json:"valid"`
	RecordID          string    `json:"record_id,omitempty"`
	TransparencyHash  string    `json:"transparency_hash,omitempty"`
	TransparencyEntryID string  `json:"transparency_entry_id,omitempty"`
	VerifiedAt        time.Time `json:"verified_at"`
}

type KeyCoreSignRequest struct {
	TenantID  string `json:"tenant_id"`
	DataB64   string `json:"data"`
	Algorithm string `json:"algorithm,omitempty"`
}

type KeyCoreSignResponse struct {
	SignatureB64 string `json:"signature"`
	Version      int    `json:"version"`
	KeyID        string `json:"key_id"`
}

type KeyCoreVerifyRequest struct {
	TenantID     string `json:"tenant_id"`
	DataB64      string `json:"data"`
	SignatureB64 string `json:"signature"`
	Algorithm    string `json:"algorithm,omitempty"`
}

type KeyCoreVerifyResponse struct {
	Valid bool `json:"verified"`
}
