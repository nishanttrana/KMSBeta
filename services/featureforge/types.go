package main

import (
	"context"
	"time"
)

// Mode is the operating mode of an intent. The two modes have different risk
// profiles and therefore different guardrail paths.
type Mode string

const (
	// ModeConfig: admin intent maps to a FIXED, allow-listed catalog action.
	// The classifier only fills a schema; it never produces code. Runs locally
	// (no MCP server). This is the safely-automatable path.
	ModeConfig Mode = "config"

	// ModeScaffold: engineer feature request; code is scaffolded/built/validated
	// by the EXTERNAL MCP server (MCP_SERVER_URL), deployed to STAGING only.
	// Prod promotion is always a human + governance-quorum decision.
	ModeScaffold Mode = "scaffold"
)

// Stage represents how far an intent has progressed through the pipeline.
type Stage string

const (
	StageReceived   Stage = "received"
	StageClassified Stage = "classified"
	StageValidated  Stage = "validated"
	StagePolicyOK   Stage = "policy_ok"
	StageDryRunOK   Stage = "dryrun_ok"
	StageTestedOK   Stage = "tested_ok"
	StageStaged     Stage = "staged"
	StageAwaitProd  Stage = "awaiting_prod"
	StageProd       Stage = "deployed_prod"
	StageRejected   Stage = "rejected"
	StageFailed     Stage = "failed"
)

// Intent is a single natural-language request flowing through the forge.
type Intent struct {
	ID         string                 `json:"id"`
	TenantID   string                 `json:"tenant_id"`
	Actor      string                 `json:"actor"`
	RawText    string                 `json:"raw_text"`
	Mode       Mode                   `json:"mode"`
	Stage      Stage                  `json:"stage"`
	Action     string                 `json:"action"`
	Params     map[string]interface{} `json:"params"`
	Confidence float64                `json:"confidence"`
	Reasons    []string               `json:"reasons"`
	// MCPJobID is the build job id returned by the external MCP server
	// (scaffold mode only).
	MCPJobID string `json:"mcp_job_id,omitempty"`
	// ApprovalID is the governance approval opened for prod promotion, if any.
	ApprovalID string    `json:"approval_id,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// CatalogAction is one allow-listed thing config mode is permitted to do.
type CatalogAction struct {
	Name           string            `json:"name"`
	Summary        string            `json:"summary"`
	RequiredParams map[string]string `json:"required_params"`
	RequiresQuorum bool              `json:"requires_quorum"`
	Sensitive      bool              `json:"sensitive"`
	// Applier names the per-action applier. "policy" => applies to the real
	// policy service; "stub" => persisted in featureforge only (for now).
	Applier string `json:"applier"`
}

// GuardrailResult is the outcome of a single guardrail layer.
type GuardrailResult struct {
	Layer  string `json:"layer"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

// AuditEvent is one guardrail-pipeline transition. It is persisted locally
// (ff_events, the per-intent trail) and mirrored onto the platform audit
// stream via pkg/audit.
type AuditEvent struct {
	IntentID  string    `json:"intent_id"`
	TenantID  string    `json:"tenant_id"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Stage     Stage     `json:"stage"`
	Outcome   string    `json:"outcome"`
	Detail    string    `json:"detail"`
	RequestID string    `json:"request_id,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// Approval is a recorded second-principal sign-off. Prod promotion is
// impossible without at least one approval from a principal other than the
// intent's submitter (enforced in Service.Approve / PromoteToProd).
type Approval struct {
	IntentID  string    `json:"intent_id"`
	TenantID  string    `json:"tenant_id"`
	Approver  string    `json:"approver"`
	Comment   string    `json:"comment,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// --- Collaborator interfaces (real HTTP clients in production) ------------

// Classifier turns raw text into a structured, catalog-bound intent.
type Classifier interface {
	Classify(raw string, catalog []CatalogAction) (mode Mode, action string, params map[string]interface{}, confidence float64, err error)
}

// PolicyClient checks/apply actions against the existing policy service.
type PolicyClient interface {
	Evaluate(tenantID, action string, params map[string]interface{}) (GuardrailResult, error)
	Apply(tenantID, actor, action string, params map[string]interface{}) (GuardrailResult, error)
}

// GovernanceClient opens a quorum-gated approval against governance.
type GovernanceClient interface {
	RequestApproval(in *Intent) (approvalID string, err error)
	ApprovalState(approvalID string) (approved bool, err error)
}

// AuditClient mirrors pipeline events onto the central audit spine
// (pkg/audit over NATS JetStream).
type AuditClient interface {
	Emit(ctx context.Context, ev AuditEvent) error
}

// MCPClient drives the EXTERNAL MCP server that scaffolds, builds, and
// validates code for scaffold-mode intents.
type MCPClient interface {
	// Submit asks the MCP server to scaffold + build + validate the feature.
	// Returns a job id used to poll status.
	Submit(in *Intent) (jobID string, err error)
	// Status reports the build/validation result for a job.
	Status(jobID string) (GuardrailResult, error)
}

// LocalSandbox runs config-mode dry-runs locally (no MCP server).
type LocalSandbox interface {
	DryRunConfig(action string, params map[string]interface{}) (GuardrailResult, error)
}
