package main

import "time"

type CertRenewalInfo struct {
	TenantID             string    `json:"tenant_id"`
	CertID               string    `json:"cert_id"`
	ARIID                string    `json:"ari_id"`
	CAID                 string    `json:"ca_id"`
	CAName               string    `json:"ca_name"`
	SubjectCN            string    `json:"subject_cn"`
	Protocol             string    `json:"protocol"`
	NotAfter             time.Time `json:"not_after"`
	WindowStart          time.Time `json:"window_start"`
	WindowEnd            time.Time `json:"window_end"`
	ScheduledRenewalAt   time.Time `json:"scheduled_renewal_at"`
	ExplanationURL       string    `json:"explanation_url"`
	RetryAfterSeconds    int       `json:"retry_after_seconds"`
	NextPollAt           time.Time `json:"next_poll_at"`
	RenewalState         string    `json:"renewal_state"`
	RiskLevel            string    `json:"risk_level"`
	MissedWindowAt       time.Time `json:"missed_window_at"`
	EmergencyRotationAt  time.Time `json:"emergency_rotation_at"`
	MassRenewalBucket    string    `json:"mass_renewal_bucket"`
	WindowSource         string    `json:"window_source"`
	MetadataJSON         string    `json:"metadata_json"`
	UpdatedAt            time.Time `json:"updated_at"`
}

type CertRenewalScheduleEntry struct {
	Bucket            string    `json:"bucket"`
	CAID              string    `json:"ca_id"`
	CAName            string    `json:"ca_name"`
	Count             int       `json:"count"`
	RiskLevel         string    `json:"risk_level"`
	ScheduledStart    time.Time `json:"scheduled_start"`
	ScheduledEnd      time.Time `json:"scheduled_end"`
	CertIDs           []string  `json:"cert_ids"`
}

type CertRenewalSummary struct {
	TenantID                string                     `json:"tenant_id"`
	ARIEnabled              bool                       `json:"ari_enabled"`
	RecommendedPollHours    int                        `json:"recommended_poll_hours"`
	RenewalWindows          []CertRenewalInfo          `json:"renewal_windows"`
	CADirectedSchedule      []CertRenewalScheduleEntry `json:"ca_directed_schedule"`
	MassRenewalRisks        []CertRenewalScheduleEntry `json:"mass_renewal_risks"`
	MissedWindowCount       int                        `json:"missed_window_count"`
	EmergencyRotationCount  int                        `json:"emergency_rotation_count"`
	DueSoonCount            int                        `json:"due_soon_count"`
	NonCompliantCount       int                        `json:"non_compliant_count"`
	STARSubscriptionCount   int                        `json:"star_subscription_count"`
	STARDelegatedCount      int                        `json:"star_delegated_count"`
	STARDueSoonCount        int                        `json:"star_due_soon_count"`
	STARMassRolloutRiskCount int                       `json:"star_mass_rollout_risk_count"`
}

type ACMERenewalWindow struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

type ACMERenewalInfoResponse struct {
	SuggestedWindow ACMERenewalWindow `json:"suggestedWindow"`
	ExplanationURL string            `json:"explanationURL,omitempty"`
}
