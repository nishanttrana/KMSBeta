package main

import "time"

type AttestationPolicy struct {
	TenantID             string            `json:"tenant_id"`
	Enabled              bool              `json:"enabled"`
	Provider             string            `json:"provider"`
	Mode                 string            `json:"mode"`
	KeyScopes            []string          `json:"key_scopes"`
	ApprovedImages       []string          `json:"approved_images"`
	ApprovedSubjects     []string          `json:"approved_subjects"`
	AllowedAttesters     []string          `json:"allowed_attesters"`
	RequiredMeasurements map[string]string `json:"required_measurements"`
	RequiredClaims       map[string]string `json:"required_claims"`
	RequireSecureBoot    bool              `json:"require_secure_boot"`
	RequireDebugDisabled bool              `json:"require_debug_disabled"`
	MaxEvidenceAgeSec    int               `json:"max_evidence_age_sec"`
	ClusterScope         string            `json:"cluster_scope"`
	AllowedClusterNodes  []string          `json:"allowed_cluster_nodes"`
	FallbackAction       string            `json:"fallback_action"`
	UpdatedBy            string            `json:"updated_by,omitempty"`
	UpdatedAt            time.Time         `json:"updated_at"`
}

type AttestedReleaseRequest struct {
	TenantID            string            `json:"tenant_id"`
	KeyID               string            `json:"key_id"`
	KeyScope            string            `json:"key_scope"`
	Provider            string            `json:"provider"`
	AttestationDocument string            `json:"attestation_document"`
	AttestationFormat   string            `json:"attestation_format"`
	WorkloadIdentity    string            `json:"workload_identity"`
	Attester            string            `json:"attester"`
	ImageRef            string            `json:"image_ref"`
	ImageDigest         string            `json:"image_digest"`
	Audience            string            `json:"audience"`
	Nonce               string            `json:"nonce"`
	EvidenceIssuedAt    string            `json:"evidence_issued_at"`
	Claims              map[string]string `json:"claims"`
	Measurements        map[string]string `json:"measurements"`
	SecureBoot          bool              `json:"secure_boot"`
	DebugDisabled       bool              `json:"debug_disabled"`
	ClusterNodeID       string            `json:"cluster_node_id"`
	Requester           string            `json:"requester"`
	ReleaseReason       string            `json:"release_reason"`
	DryRun              bool              `json:"dry_run"`
}

type AttestedReleaseDecision struct {
	ReleaseID                 string            `json:"release_id"`
	Decision                  string            `json:"decision"`
	Allowed                   bool              `json:"allowed"`
	Reasons                   []string          `json:"reasons"`
	MatchedClaims             []string          `json:"matched_claims"`
	MatchedMeasurements       []string          `json:"matched_measurements"`
	MissingClaims             []string          `json:"missing_claims"`
	MissingMeasurements       []string          `json:"missing_measurements"`
	MissingAttributes         []string          `json:"missing_attributes"`
	MeasurementHash           string            `json:"measurement_hash"`
	ClaimsHash                string            `json:"claims_hash"`
	PolicyVersion             string            `json:"policy_version"`
	Provider                  string            `json:"provider"`
	ClusterNodeID             string            `json:"cluster_node_id"`
	CryptographicallyVerified bool              `json:"cryptographically_verified"`
	VerificationMode          string            `json:"verification_mode"`
	VerificationIssuer        string            `json:"verification_issuer"`
	VerificationKeyID         string            `json:"verification_key_id"`
	AttestationDocumentHash   string            `json:"attestation_document_hash"`
	AttestationDocumentFormat string            `json:"attestation_document_format"`
	ExpiresAt                 time.Time         `json:"expires_at,omitempty"`
	EvaluatedAt               time.Time         `json:"evaluated_at"`
	Profile                   AttestationPolicy `json:"policy"`
}

type AttestedReleaseRecord struct {
	ID                        string            `json:"id"`
	TenantID                  string            `json:"tenant_id"`
	KeyID                     string            `json:"key_id"`
	KeyScope                  string            `json:"key_scope"`
	Provider                  string            `json:"provider"`
	WorkloadIdentity          string            `json:"workload_identity"`
	Attester                  string            `json:"attester"`
	ImageRef                  string            `json:"image_ref"`
	ImageDigest               string            `json:"image_digest"`
	Audience                  string            `json:"audience"`
	Nonce                     string            `json:"nonce,omitempty"`
	EvidenceIssuedAt          time.Time         `json:"evidence_issued_at,omitempty"`
	Claims                    map[string]string `json:"claims,omitempty"`
	Measurements              map[string]string `json:"measurements,omitempty"`
	SecureBoot                bool              `json:"secure_boot"`
	DebugDisabled             bool              `json:"debug_disabled"`
	ClusterNodeID             string            `json:"cluster_node_id"`
	Requester                 string            `json:"requester"`
	ReleaseReason             string            `json:"release_reason"`
	Decision                  string            `json:"decision"`
	Allowed                   bool              `json:"allowed"`
	Reasons                   []string          `json:"reasons"`
	MatchedClaims             []string          `json:"matched_claims"`
	MatchedMeasurements       []string          `json:"matched_measurements"`
	MissingClaims             []string          `json:"missing_claims"`
	MissingMeasurements       []string          `json:"missing_measurements"`
	MissingAttributes         []string          `json:"missing_attributes"`
	MeasurementHash           string            `json:"measurement_hash"`
	ClaimsHash                string            `json:"claims_hash"`
	PolicyVersion             string            `json:"policy_version"`
	CryptographicallyVerified bool              `json:"cryptographically_verified"`
	VerificationMode          string            `json:"verification_mode"`
	VerificationIssuer        string            `json:"verification_issuer"`
	VerificationKeyID         string            `json:"verification_key_id"`
	AttestationDocumentHash   string            `json:"attestation_document_hash"`
	AttestationDocumentFormat string            `json:"attestation_document_format"`
	ExpiresAt                 time.Time         `json:"expires_at,omitempty"`
	CreatedAt                 time.Time         `json:"created_at"`
}

type AttestationSummary struct {
	TenantID                          string    `json:"tenant_id"`
	PolicyEnabled                     bool      `json:"policy_enabled"`
	Provider                          string    `json:"provider"`
	ApprovedImageCount                int       `json:"approved_image_count"`
	KeyScopeCount                     int       `json:"key_scope_count"`
	ReleaseCount24h                   int       `json:"release_count_24h"`
	DenyCount24h                      int       `json:"deny_count_24h"`
	ReviewCount24h                    int       `json:"review_count_24h"`
	CryptographicallyVerifiedCount24h int       `json:"cryptographically_verified_count_24h"`
	UniqueClusterNodes                int       `json:"unique_cluster_nodes"`
	LastDecisionAt                    time.Time `json:"last_decision_at,omitempty"`
	LatestDecision                    string    `json:"latest_decision,omitempty"`
}
