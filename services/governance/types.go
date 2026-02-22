package main

import "time"

type ApprovalPolicy struct {
	ID                   string    `json:"id"`
	TenantID             string    `json:"tenant_id"`
	Name                 string    `json:"name"`
	Description          string    `json:"description"`
	Scope                string    `json:"scope"`
	TriggerActions       []string  `json:"trigger_actions"`
	RequiredApprovals    int       `json:"required_approvals"`
	TotalApprovers       int       `json:"total_approvers"`
	ApproverRoles        []string  `json:"approver_roles"`
	ApproverUsers        []string  `json:"approver_users"`
	TimeoutHours         int       `json:"timeout_hours"`
	EscalationHours      int       `json:"escalation_hours"`
	EscalationTo         []string  `json:"escalation_to"`
	RetentionDays        int       `json:"retention_days"`
	NotificationChannels []string  `json:"notification_channels"`
	Status               string    `json:"status"`
	CreatedAt            time.Time `json:"created_at"`
}

type ApprovalRequest struct {
	ID                string                 `json:"id"`
	TenantID          string                 `json:"tenant_id"`
	PolicyID          string                 `json:"policy_id"`
	Action            string                 `json:"action"`
	TargetType        string                 `json:"target_type"`
	TargetID          string                 `json:"target_id"`
	TargetDetails     map[string]interface{} `json:"target_details"`
	RequesterID       string                 `json:"requester_id"`
	RequesterEmail    string                 `json:"requester_email"`
	RequesterIP       string                 `json:"requester_ip"`
	Status            string                 `json:"status"`
	RequiredApprovals int                    `json:"required_approvals"`
	CurrentApprovals  int                    `json:"current_approvals"`
	CurrentDenials    int                    `json:"current_denials"`
	CreatedAt         time.Time              `json:"created_at"`
	ExpiresAt         time.Time              `json:"expires_at"`
	ResolvedAt        time.Time              `json:"resolved_at"`
	RetainUntil       time.Time              `json:"retain_until"`
	CallbackService   string                 `json:"callback_service"`
	CallbackAction    string                 `json:"callback_action"`
	CallbackPayload   map[string]interface{} `json:"callback_payload"`
}

type ApprovalVote struct {
	ID            string    `json:"id"`
	RequestID     string    `json:"request_id"`
	TenantID      string    `json:"tenant_id"`
	ApproverID    string    `json:"approver_id"`
	ApproverEmail string    `json:"approver_email"`
	Vote          string    `json:"vote"`
	VoteMethod    string    `json:"vote_method"`
	Comment       string    `json:"comment"`
	TokenHash     []byte    `json:"-"`
	VotedAt       time.Time `json:"voted_at"`
	IPAddress     string    `json:"ip_address"`
}

type ApprovalToken struct {
	ID            string    `json:"id"`
	RequestID     string    `json:"request_id"`
	ApproverEmail string    `json:"approver_email"`
	TokenHash     []byte    `json:"-"`
	Action        string    `json:"action"`
	Used          bool      `json:"used"`
	ExpiresAt     time.Time `json:"expires_at"`
	CreatedAt     time.Time `json:"created_at"`
}

type CreateApprovalRequestInput struct {
	TenantID        string                 `json:"tenant_id"`
	PolicyID        string                 `json:"policy_id"`
	Action          string                 `json:"action"`
	TargetType      string                 `json:"target_type"`
	TargetID        string                 `json:"target_id"`
	TargetDetails   map[string]interface{} `json:"target_details"`
	RequesterID     string                 `json:"requester_id"`
	RequesterEmail  string                 `json:"requester_email"`
	RequesterIP     string                 `json:"requester_ip"`
	CallbackService string                 `json:"callback_service"`
	CallbackAction  string                 `json:"callback_action"`
	CallbackPayload map[string]interface{} `json:"callback_payload"`
}

type VoteInput struct {
	TenantID      string `json:"tenant_id"`
	RequestID     string `json:"request_id"`
	Vote          string `json:"vote"`
	Comment       string `json:"comment"`
	Token         string `json:"token"`
	ChallengeCode string `json:"challenge_code"`
	ApproverID    string `json:"approver_id"`
	ApproverEmail string `json:"approver_email"`
	VoteMethod    string `json:"vote_method"`
	IPAddress     string `json:"ip_address"`
}

type ApprovalRequestDetails struct {
	Request ApprovalRequest `json:"request"`
	Votes   []ApprovalVote  `json:"votes"`
}

type CreateKeyApprovalInput struct {
	TenantID        string                 `json:"tenant_id"`
	KeyID           string                 `json:"key_id"`
	Operation       string                 `json:"operation"`
	PayloadHash     string                 `json:"payload_hash"`
	RequesterID     string                 `json:"requester_id"`
	RequesterEmail  string                 `json:"requester_email"`
	RequesterIP     string                 `json:"requester_ip"`
	CallbackService string                 `json:"callback_service"`
	CallbackAction  string                 `json:"callback_action"`
	CallbackPayload map[string]interface{} `json:"callback_payload"`
}

type ApprovalStatus struct {
	Status           string    `json:"status"`
	CurrentApprovals int       `json:"current_approvals"`
	CurrentDenials   int       `json:"current_denials"`
	ExpiresAt        time.Time `json:"expires_at"`
}

type GovernanceSettings struct {
	TenantID                   string    `json:"tenant_id"`
	ApprovalExpiryMinutes      int       `json:"approval_expiry_minutes"`
	ExpiryCheckIntervalSeconds int       `json:"expiry_check_interval_seconds"`
	SMTPHost                   string    `json:"smtp_host"`
	SMTPPort                   string    `json:"smtp_port"`
	SMTPUsername               string    `json:"smtp_username"`
	SMTPPassword               string    `json:"smtp_password,omitempty"`
	SMTPFrom                   string    `json:"smtp_from"`
	SMTPStartTLS               bool      `json:"smtp_starttls"`
	NotifyDashboard            bool      `json:"notify_dashboard"`
	NotifyEmail                bool      `json:"notify_email"`
	ChallengeResponseEnabled   bool      `json:"challenge_response_enabled"`
	UpdatedBy                  string    `json:"updated_by"`
	UpdatedAt                  time.Time `json:"updated_at"`
}

type GovernanceSystemState struct {
	TenantID            string    `json:"tenant_id"`
	FIPSMode            string    `json:"fips_mode"`
	HSMMode             string    `json:"hsm_mode"`
	ClusterMode         string    `json:"cluster_mode"`
	LicenseKey          string    `json:"license_key,omitempty"`
	LicenseStatus       string    `json:"license_status"`
	MgmtIP              string    `json:"mgmt_ip"`
	ClusterIP           string    `json:"cluster_ip"`
	DNSServers          string    `json:"dns_servers"`
	NTPServers          string    `json:"ntp_servers"`
	TLSMode             string    `json:"tls_mode"`
	TLSCertPEM          string    `json:"tls_cert_pem,omitempty"`
	TLSKeyPEM           string    `json:"tls_key_pem,omitempty"`
	TLSCABundlePEM      string    `json:"tls_ca_bundle_pem,omitempty"`
	BackupSchedule      string    `json:"backup_schedule"`
	BackupTarget        string    `json:"backup_target"`
	BackupRetentionDays int       `json:"backup_retention_days"`
	BackupEncrypted     bool      `json:"backup_encrypted"`
	ProxyEndpoint       string    `json:"proxy_endpoint"`
	SNMPTarget          string    `json:"snmp_target"`
	UpdatedBy           string    `json:"updated_by"`
	UpdatedAt           time.Time `json:"updated_at"`
}

type SystemIntegrityStatus struct {
	TenantID  string            `json:"tenant_id"`
	Status    string            `json:"status"`
	Checks    map[string]string `json:"checks"`
	Timestamp time.Time         `json:"timestamp"`
}
