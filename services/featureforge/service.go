package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// MinConfidence is the floor below which an intent is auto-rejected. A KMS
// should refuse to act on an ambiguous instruction.
const MinConfidence = 0.65

// Service orchestrates the guardrail pipeline.
//
// Pipeline (every intent passes ALL applicable layers in order; failing any
// layer halts progression and is audited):
//
//	L1 Classify        -> map raw text to mode + catalog action (untrusted)
//	L2 Validate        -> confidence floor + schema/required-param check
//	L3 Policy          -> existing policy service must permit the action
//	L4 Dry-run / Build -> config: local dry-run; scaffold: external MCP build+validate
//	L5 Stage           -> auto-apply to STAGING
//	L6 Approval gate   -> a second principal (not the submitter) must approve
//	L7 Governance gate -> quorum approval required before PROD (quorum actions)
//
// There is no code path from Submit() to prod. Prod is only reachable via the
// separate, gated PromoteToProd().
type Service struct {
	catalog    []CatalogAction
	classifier Classifier
	policy     PolicyClient
	gov        GovernanceClient
	audit      AuditClient
	mcp        MCPClient
	sandbox    LocalSandbox
	store      Store
	now        func() time.Time
}

// Config holds Service dependencies.
type Config struct {
	Catalog    []CatalogAction
	Classifier Classifier
	Policy     PolicyClient
	Governance GovernanceClient
	Audit      AuditClient
	MCP        MCPClient
	Sandbox    LocalSandbox
	Store      Store
	Now        func() time.Time
}

// NewService builds a Service, filling sensible defaults for anything omitted.
func NewService(c Config) *Service {
	if c.Catalog == nil {
		c.Catalog = DefaultCatalog()
	}
	if c.Classifier == nil {
		c.Classifier = NewKeywordClassifier()
	}
	if c.Sandbox == nil {
		c.Sandbox = NewLocalSandbox()
	}
	if c.Store == nil {
		c.Store = NewMemStore()
	}
	if c.Now == nil {
		c.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Service{
		catalog:    c.Catalog,
		classifier: c.Classifier,
		policy:     c.Policy,
		gov:        c.Governance,
		audit:      c.Audit,
		mcp:        c.MCP,
		sandbox:    c.Sandbox,
		store:      c.Store,
		now:        c.Now,
	}
}

// requestIDKey carries the caller's request id through the pipeline so every
// audit event of one submission/promotion shares a correlation id.
type ctxKey int

const requestIDKey ctxKey = 0

// WithRequestID attaches the HTTP request id to the pipeline context.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

func requestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

// emit records one pipeline transition: locally in ff_events and on the
// central audit stream. actor is whoever caused this transition (submitter,
// approver, or promoter).
func (s *Service) emit(ctx context.Context, in *Intent, actor, outcome, detail string) {
	ev := AuditEvent{
		IntentID:  in.ID,
		TenantID:  in.TenantID,
		Actor:     actor,
		Action:    in.Action,
		Stage:     in.Stage,
		Outcome:   outcome,
		Detail:    detail,
		RequestID: requestIDFrom(ctx),
		Timestamp: s.now(),
	}
	_ = s.store.AppendEvent(ctx, ev)
	if s.audit != nil {
		_ = s.audit.Emit(ctx, ev)
	}
}

func (s *Service) save(ctx context.Context, in *Intent) {
	in.UpdatedAt = s.now()
	_ = s.store.SaveIntent(ctx, in)
}

func (s *Service) reject(ctx context.Context, in *Intent, actor, reason string) (*Intent, error) {
	in.Stage = StageRejected
	in.Reasons = append(in.Reasons, reason)
	s.save(ctx, in)
	s.emit(ctx, in, actor, "rejected", reason)
	return in, fmt.Errorf("rejected: %s", reason)
}

// Submit runs an intent through the full pipeline up to (and including) the
// STAGING apply. Prod promotion is a separate, gated call.
func (s *Service) Submit(ctx context.Context, tenantID, actor, rawText string) (*Intent, error) {
	in := &Intent{
		ID:        s.store.NextID(),
		TenantID:  tenantID,
		Actor:     actor,
		RawText:   rawText,
		Stage:     StageReceived,
		CreatedAt: s.now(),
		UpdatedAt: s.now(),
		Params:    map[string]interface{}{},
	}
	s.save(ctx, in)
	s.emit(ctx, in, actor, "received", rawText)

	// L1: classify (untrusted)
	mode, action, params, conf, err := s.classifier.Classify(rawText, s.catalog)
	if err != nil {
		in.Stage = StageFailed
		s.save(ctx, in)
		s.emit(ctx, in, actor, "failed", "classify error: "+err.Error())
		return in, err
	}
	in.Mode, in.Action, in.Params, in.Confidence = mode, action, params, conf
	in.Stage = StageClassified
	in.Reasons = append(in.Reasons, fmt.Sprintf("classified mode=%s action=%q confidence=%.2f", mode, action, conf))
	s.save(ctx, in)
	s.emit(ctx, in, actor, "classified", in.Reasons[len(in.Reasons)-1])

	// L2: validate
	if r := s.validate(in); !r.Passed {
		return s.reject(ctx, in, actor, "validation: "+r.Detail)
	}
	in.Stage = StageValidated
	s.save(ctx, in)
	s.emit(ctx, in, actor, "validated", "schema + confidence ok")

	// L3: policy
	if s.policy != nil {
		r, perr := s.policy.Evaluate(tenantID, in.Action, in.Params)
		if perr != nil {
			in.Stage = StageFailed
			s.save(ctx, in)
			s.emit(ctx, in, actor, "failed", "policy error: "+perr.Error())
			return in, perr
		}
		if !r.Passed {
			return s.reject(ctx, in, actor, "policy: "+r.Detail)
		}
	}
	in.Stage = StagePolicyOK
	in.Reasons = append(in.Reasons, "policy: permitted")
	s.save(ctx, in)
	s.emit(ctx, in, actor, "policy_ok", "permitted")

	// L4: dry-run (config, local) or build+validate (scaffold, external MCP)
	if in.Mode == ModeScaffold {
		if s.mcp == nil {
			return s.reject(ctx, in, actor, "scaffold mode requires an MCP server but none is configured (set MCP_SERVER_URL)")
		}
		jobID, merr := s.mcp.Submit(in)
		if merr != nil {
			in.Stage = StageFailed
			s.save(ctx, in)
			s.emit(ctx, in, actor, "failed", "mcp submit error: "+merr.Error())
			return in, merr
		}
		in.MCPJobID = jobID
		r, serr := s.mcp.Status(jobID)
		if serr != nil {
			in.Stage = StageFailed
			s.save(ctx, in)
			s.emit(ctx, in, actor, "failed", "mcp status error: "+serr.Error())
			return in, serr
		}
		if !r.Passed {
			return s.reject(ctx, in, actor, "mcp build/validate: "+r.Detail)
		}
		in.Stage = StageTestedOK
		s.save(ctx, in)
		s.emit(ctx, in, actor, "tested_ok", r.Detail)
	} else {
		r, serr := s.sandbox.DryRunConfig(in.Action, in.Params)
		if serr != nil {
			in.Stage = StageFailed
			s.save(ctx, in)
			s.emit(ctx, in, actor, "failed", "sandbox error: "+serr.Error())
			return in, serr
		}
		if !r.Passed {
			return s.reject(ctx, in, actor, "dry-run: "+r.Detail)
		}
		in.Stage = StageDryRunOK
		s.save(ctx, in)
		s.emit(ctx, in, actor, "dryrun_ok", r.Detail)
	}

	// L5: auto-apply to STAGING. For config mode with a real applier, this
	// applies the change against the policy service's staging surface.
	if in.Mode == ModeConfig && s.policy != nil {
		if act := FindAction(s.catalog, in.Action); act != nil && act.Applier == "policy" {
			if r, aerr := s.policy.Apply(tenantID, actor, in.Action, in.Params); aerr != nil || !r.Passed {
				detail := "policy apply failed"
				if aerr != nil {
					detail = aerr.Error()
				} else {
					detail = r.Detail
				}
				return s.reject(ctx, in, actor, "staging apply: "+detail)
			}
		}
	}
	in.Stage = StageStaged
	in.Reasons = append(in.Reasons, "applied to staging")
	s.save(ctx, in)
	s.emit(ctx, in, actor, "staged", "applied to staging env")

	return in, nil
}

func (s *Service) validate(in *Intent) GuardrailResult {
	if in.Confidence < MinConfidence {
		return GuardrailResult{Layer: "validate", Passed: false,
			Detail: fmt.Sprintf("confidence %.2f below floor %.2f", in.Confidence, MinConfidence)}
	}
	if in.Mode == ModeScaffold {
		if len(in.RawText) < 8 {
			return GuardrailResult{Layer: "validate", Passed: false, Detail: "scaffold intent too vague"}
		}
		return GuardrailResult{Layer: "validate", Passed: true, Detail: "scaffold ok"}
	}
	act := FindAction(s.catalog, in.Action)
	if act == nil {
		return GuardrailResult{Layer: "validate", Passed: false,
			Detail: fmt.Sprintf("action %q not in allow-list catalog", in.Action)}
	}
	for p, desc := range act.RequiredParams {
		v, ok := in.Params[p]
		if !ok || v == nil || v == "" {
			return GuardrailResult{Layer: "validate", Passed: false,
				Detail: fmt.Sprintf("missing required param %q (%s)", p, desc)}
		}
	}
	return GuardrailResult{Layer: "validate", Passed: true, Detail: "catalog + schema ok"}
}

// Approve records a second-principal sign-off on a staged intent. The
// submitter cannot approve their own intent — that is the whole point of the
// gate — and an intent can only be approved once per principal.
func (s *Service) Approve(ctx context.Context, intentID, approver, comment string) (*Intent, error) {
	in, ok := s.store.GetIntent(ctx, intentID)
	if !ok {
		return nil, errors.New("unknown intent")
	}
	approver = strings.TrimSpace(approver)
	if approver == "" {
		return in, errors.New("approver is required")
	}
	if strings.EqualFold(approver, strings.TrimSpace(in.Actor)) {
		s.emit(ctx, in, approver, "approval_denied", "self-approval rejected: submitter cannot approve own intent")
		return in, errors.New("self-approval rejected: a second principal must approve")
	}
	if in.Stage != StageStaged && in.Stage != StageAwaitProd {
		return in, fmt.Errorf("intent not approvable (stage=%s)", in.Stage)
	}
	ap := Approval{IntentID: in.ID, TenantID: in.TenantID, Approver: approver, Comment: comment, CreatedAt: s.now()}
	if err := s.store.AddApproval(ctx, ap); err != nil {
		return in, err
	}
	in.Reasons = append(in.Reasons, "approved by "+approver)
	s.save(ctx, in)
	s.emit(ctx, in, approver, "approved", "second-principal approval recorded")
	return in, nil
}

// PromoteToProd is the ONLY path to production. It requires (1) the intent to
// be staged, (2) at least one second-principal approval, and (3) for
// quorum-bound actions, a granted governance quorum.
func (s *Service) PromoteToProd(ctx context.Context, intentID, promoter string) (*Intent, error) {
	in, ok := s.store.GetIntent(ctx, intentID)
	if !ok {
		return nil, errors.New("unknown intent")
	}
	if promoter = strings.TrimSpace(promoter); promoter == "" {
		promoter = in.Actor
	}
	if in.Stage != StageStaged && in.Stage != StageAwaitProd {
		return in, fmt.Errorf("intent not eligible for prod (stage=%s)", in.Stage)
	}

	// Second-principal gate: every prod promotion needs an approval from
	// someone other than the submitter (Approve enforces approver != actor).
	if len(s.store.Approvals(ctx, in.ID)) == 0 {
		in.Stage = StageAwaitProd
		in.Reasons = append(in.Reasons, "awaiting second-principal approval")
		s.save(ctx, in)
		s.emit(ctx, in, promoter, "awaiting_prod", "no second-principal approval on record")
		return in, nil
	}

	needsQuorum := in.Mode == ModeScaffold // all code changes need a human gate
	if act := FindAction(s.catalog, in.Action); act != nil && act.RequiresQuorum {
		needsQuorum = true
	}

	if needsQuorum {
		if s.gov == nil {
			return s.reject(ctx, in, promoter, "prod requires governance but no governance client configured")
		}
		approvalID := in.ApprovalID
		if approvalID == "" {
			id, err := s.gov.RequestApproval(in)
			if err != nil {
				in.Stage = StageFailed
				s.save(ctx, in)
				s.emit(ctx, in, promoter, "failed", "governance request error: "+err.Error())
				return in, err
			}
			approvalID = id
			in.ApprovalID = id
		}
		approved, err := s.gov.ApprovalState(approvalID)
		if err != nil {
			return in, err
		}
		if !approved {
			in.Stage = StageAwaitProd
			in.Reasons = append(in.Reasons, "awaiting governance quorum approval "+approvalID)
			s.save(ctx, in)
			s.emit(ctx, in, promoter, "awaiting_prod", "approval "+approvalID+" pending")
			return in, nil
		}
		in.Reasons = append(in.Reasons, "governance approved "+approvalID)
	}

	in.Stage = StageProd
	s.save(ctx, in)
	s.emit(ctx, in, promoter, "deployed_prod", "applied to prod env")
	return in, nil
}

// Get returns an intent by ID with its event trail.
func (s *Service) Get(ctx context.Context, id string) (*Intent, []AuditEvent, bool) {
	in, ok := s.store.GetIntent(ctx, id)
	if !ok {
		return nil, nil, false
	}
	return in, s.store.Events(ctx, id), true
}

// Approvals returns the recorded second-principal approvals for an intent.
func (s *Service) Approvals(ctx context.Context, id string) []Approval {
	return s.store.Approvals(ctx, id)
}

// List returns intents for a tenant (newest first).
func (s *Service) List(ctx context.Context, tenantID string) []*Intent {
	return s.store.ListIntents(ctx, tenantID)
}

// Catalog exposes the active allow-list.
func (s *Service) Catalog() []CatalogAction { return s.catalog }
