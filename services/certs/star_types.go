package main

import "time"

type ACMESTARSubscription struct {
	ID                  string    `json:"id"`
	TenantID            string    `json:"tenant_id"`
	Name                string    `json:"name"`
	AccountID           string    `json:"account_id"`
	CAID                string    `json:"ca_id"`
	ProfileID           string    `json:"profile_id,omitempty"`
	SubjectCN           string    `json:"subject_cn"`
	SANs                []string  `json:"sans"`
	CertType            string    `json:"cert_type"`
	CertClass           string    `json:"cert_class"`
	Algorithm           string    `json:"algorithm"`
	ValidityHours       int       `json:"validity_hours"`
	RenewBeforeMinutes  int       `json:"renew_before_minutes"`
	AutoRenew           bool      `json:"auto_renew"`
	AllowDelegation     bool      `json:"allow_delegation"`
	DelegatedSubscriber string    `json:"delegated_subscriber,omitempty"`
	LatestCertID        string    `json:"latest_cert_id,omitempty"`
	IssuanceCount       int       `json:"issuance_count"`
	Status              string    `json:"status"`
	RolloutGroup        string    `json:"rollout_group,omitempty"`
	LastIssuedAt        time.Time `json:"last_issued_at,omitempty"`
	NextRenewalAt       time.Time `json:"next_renewal_at,omitempty"`
	LastError           string    `json:"last_error,omitempty"`
	CreatedBy           string    `json:"created_by,omitempty"`
	MetadataJSON        string    `json:"metadata_json,omitempty"`
	CreatedAt           time.Time `json:"created_at,omitempty"`
	UpdatedAt           time.Time `json:"updated_at,omitempty"`
}

type ACMESTARMassRolloutRisk struct {
	RolloutGroup     string    `json:"rollout_group"`
	Count            int       `json:"count"`
	RiskLevel        string    `json:"risk_level"`
	ScheduledStart   time.Time `json:"scheduled_start,omitempty"`
	ScheduledEnd     time.Time `json:"scheduled_end,omitempty"`
	SubscriptionIDs  []string  `json:"subscription_ids,omitempty"`
	DelegatedTargets []string  `json:"delegated_targets,omitempty"`
}

type ACMESTARSummary struct {
	TenantID              string                  `json:"tenant_id"`
	Enabled               bool                    `json:"enabled"`
	DelegationEnabled     bool                    `json:"delegation_enabled"`
	SubscriptionCount     int                     `json:"subscription_count"`
	DelegatedCount        int                     `json:"delegated_count"`
	AutoRenewCount        int                     `json:"auto_renew_count"`
	DueSoonCount          int                     `json:"due_soon_count"`
	ErrorCount            int                     `json:"error_count"`
	MassRolloutRiskCount  int                     `json:"mass_rollout_risk_count"`
	Subscriptions         []ACMESTARSubscription  `json:"subscriptions"`
	MassRolloutRisks      []ACMESTARMassRolloutRisk `json:"mass_rollout_risks"`
	RecommendedWindowHint string                  `json:"recommended_window_hint,omitempty"`
}

type CreateACMESTARSubscriptionRequest struct {
	TenantID            string                 `json:"tenant_id"`
	Name                string                 `json:"name"`
	AccountID           string                 `json:"account_id"`
	CAID                string                 `json:"ca_id"`
	ProfileID           string                 `json:"profile_id,omitempty"`
	SubjectCN           string                 `json:"subject_cn"`
	SANs                []string               `json:"sans"`
	CertType            string                 `json:"cert_type,omitempty"`
	CertClass           string                 `json:"cert_class,omitempty"`
	Algorithm           string                 `json:"algorithm,omitempty"`
	ValidityHours       int                    `json:"validity_hours,omitempty"`
	RenewBeforeMinutes  int                    `json:"renew_before_minutes,omitempty"`
	AutoRenew           *bool                  `json:"auto_renew,omitempty"`
	AllowDelegation     *bool                  `json:"allow_delegation,omitempty"`
	DelegatedSubscriber string                 `json:"delegated_subscriber,omitempty"`
	RolloutGroup        string                 `json:"rollout_group,omitempty"`
	Metadata            map[string]interface{} `json:"metadata,omitempty"`
	CreatedBy           string                 `json:"created_by,omitempty"`
}

type RefreshACMESTARSubscriptionRequest struct {
	TenantID   string `json:"tenant_id"`
	Force      bool   `json:"force,omitempty"`
	RequestedBy string `json:"requested_by,omitempty"`
}
