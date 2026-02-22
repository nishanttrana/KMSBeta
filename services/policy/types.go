package main

import "time"

type Decision string

const (
	DecisionAllow Decision = "ALLOW"
	DecisionDeny  Decision = "DENY"
	DecisionWarn  Decision = "WARN"
)

type Policy struct {
	ID             string
	TenantID       string
	Name           string
	Description    string
	Status         string
	SpecType       string
	Labels         map[string]any
	RawYAML        string
	ParsedJSON     map[string]any
	CurrentVersion int
	CurrentCommit  string
	CreatedBy      string
	UpdatedBy      string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type PolicyVersion struct {
	ID               string
	TenantID         string
	PolicyID         string
	Version          int
	CommitHash       string
	ParentCommitHash string
	ChangeType       string
	ChangeMessage    string
	RawYAML          string
	ParsedJSON       map[string]any
	CreatedBy        string
	CreatedAt        time.Time
}

type PolicyDoc struct {
	APIVersion string         `yaml:"apiVersion" json:"apiVersion"`
	Kind       string         `yaml:"kind" json:"kind"`
	Metadata   PolicyMetadata `yaml:"metadata" json:"metadata"`
	Spec       PolicySpec     `yaml:"spec" json:"spec"`
}

type PolicyMetadata struct {
	Name        string         `yaml:"name" json:"name"`
	Tenant      string         `yaml:"tenant" json:"tenant"`
	Description string         `yaml:"description" json:"description"`
	Labels      map[string]any `yaml:"labels" json:"labels"`
}

type PolicySpec struct {
	Type    string        `yaml:"type" json:"type"`
	Targets PolicyTargets `yaml:"targets" json:"targets"`
	Rules   []PolicyRule  `yaml:"rules" json:"rules"`
}

type PolicyTargets struct {
	Selector map[string]any `yaml:"selector" json:"selector"`
}

type PolicyRule struct {
	Name      string         `yaml:"name" json:"name"`
	Condition string         `yaml:"condition" json:"condition"`
	Action    string         `yaml:"action" json:"action"`
	Message   string         `yaml:"message" json:"message"`
	Notify    []string       `yaml:"notify" json:"notify"`
	Params    map[string]any `yaml:",inline" json:"params,omitempty"`
}

type CreatePolicyRequest struct {
	TenantID      string `json:"tenant_id"`
	YAML          string `json:"yaml"`
	Actor         string `json:"actor"`
	CommitMessage string `json:"commit_message"`
}

type UpdatePolicyRequest struct {
	TenantID      string `json:"tenant_id"`
	YAML          string `json:"yaml"`
	Actor         string `json:"actor"`
	CommitMessage string `json:"commit_message"`
}

type EvaluatePolicyRequest struct {
	TenantID          string         `json:"tenant_id"`
	Operation         string         `json:"operation"`
	KeyID             string         `json:"key_id"`
	Algorithm         string         `json:"algorithm"`
	Purpose           string         `json:"purpose"`
	IVMode            string         `json:"iv_mode"`
	OpsTotal          int64          `json:"ops_total"`
	OpsLimit          int64          `json:"ops_limit"`
	DaysSinceRotation int            `json:"days_since_rotation"`
	KeyStatus         string         `json:"key_status"`
	Labels            map[string]any `json:"labels"`
}

type RuleOutcome struct {
	PolicyID      string `json:"policy_id"`
	PolicyVersion int    `json:"policy_version"`
	RuleName      string `json:"rule_name"`
	Action        string `json:"action"`
	Message       string `json:"message"`
}

type EvaluatePolicyResponse struct {
	Decision Decision      `json:"decision"`
	Reason   string        `json:"reason"`
	Outcomes []RuleOutcome `json:"outcomes"`
}

type EvaluationRecord struct {
	ID         string
	TenantID   string
	PolicyID   string
	Operation  string
	KeyID      string
	Decision   Decision
	Reason     string
	Request    map[string]any
	Outcomes   []RuleOutcome
	OccurredAt time.Time
}
