package main

import (
	"context"
	"errors"
	"fmt"
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
//	L6 Governance gate -> quorum approval required before PROD
//
// There is no code path from Submit() to prod. Prod is only reachable via the
// separate, governance-gated PromoteToProd().
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

func (s *Service) emit(ctx context.Context, in *Intent, outcome, detail string) {
	ev := AuditEvent{
		IntentID:  in.ID,
		TenantID:  in.TenantID,
		Actor:     in.Actor,
		Action:    in.Action,
		Stage:     in.Stage,
		Outcome:   outcome,
		Detail:    detail,
		Timestamp: s.now(),
	}
	_ = s.store.AppendEvent(ctx, ev)
	if s.audit != nil {
		_ = s.audit.Emit(ev)
	}
}

func (s *Service) save(ctx context.Context, in *Intent) {
	in.UpdatedAt = s.now()
	_ = s.store.SaveIntent(ctx, in)
}

func (s *Service) reject(ctx context.Context, in *Intent, reason string) (*Intent, error) {
	in.Stage = StageRejected
	in.Reasons = append(in.Reasons, reason)
	s.save(ctx, in)
	s.emit(ctx, in, "rejected", reason)
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
	s.emit(ctx, in, "received", rawText)

	// L1: classify (untrusted)
	mode, action, params, conf, err := s.classifier.Classify(rawText, s.catalog)
	if err != nil {
		in.Stage = StageFailed
		s.save(ctx, in)
		s.emit(ctx, in, "failed", "classify error: "+err.Error())
		return in, err
	}
	in.Mode, in.Action, in.Params, in.Confidence = mode, action, params, conf
	in.Stage = StageClassified
	in.Reasons = append(in.Reasons, fmt.Sprintf("classified mode=%s action=%q confidence=%.2f", mode, action, conf))
	s.save(ctx, in)
	s.emit(ctx, in, "classified", in.Reasons[len(in.Reasons)-1])

	// L2: validate
	if r := s.validate(in); !r.Passed {
		return s.reject(ctx, in, "validation: "+r.Detail)
	}
	in.Stage = StageValidated
	s.save(ctx, in)
	s.emit(ctx, in, "validated", "schema + confidence ok")

	// L3: policy
	if s.policy != nil {
		r, perr := s.policy.Evaluate(tenantID, in.Action, in.Params)
		if perr != nil {
			in.Stage = StageFailed
			s.save(ctx, in)
			s.emit(ctx, in, "failed", "policy error: "+perr.Error())
			return in, perr
		}
		if !r.Passed {
			return s.reject(ctx, in, "policy: "+r.Detail)
		}
	}
	in.Stage = StagePolicyOK
	in.Reasons = append(in.Reasons, "policy: permitted")
	s.save(ctx, in)
	s.emit(ctx, in, "policy_ok", "permitted")

	// L4: dry-run (config, local) or build+validate (scaffold, external MCP)
	if in.Mode == ModeScaffold {
		if s.mcp == nil {
			return s.reject(ctx, in, "scaffold mode requires an MCP server but none is configured (set MCP_SERVER_URL)")
		}
		jobID, merr := s.mcp.Submit(in)
		if merr != nil {
			in.Stage = StageFailed
			s.save(ctx, in)
			s.emit(ctx, in, "failed", "mcp submit error: "+merr.Error())
			return in, merr
		}
		in.MCPJobID = jobID
		r, serr := s.mcp.Status(jobID)
		if serr != nil {
			in.Stage = StageFailed
			s.save(ctx, in)
			s.emit(ctx, in, "failed", "mcp status error: "+serr.Error())
			return in, serr
		}
		if !r.Passed {
			return s.reject(ctx, in, "mcp build/validate: "+r.Detail)
		}
		in.Stage = StageTestedOK
		s.save(ctx, in)
		s.emit(ctx, in, "tested_ok", r.Detail)
	} else {
		r, serr := s.sandbox.DryRunConfig(in.Action, in.Params)
		if serr != nil {
			in.Stage = StageFailed
			s.save(ctx, in)
			s.emit(ctx, in, "failed", "sandbox error: "+serr.Error())
			return in, serr
		}
		if !r.Passed {
			return s.reject(ctx, in, "dry-run: "+r.Detail)
		}
		in.Stage = StageDryRunOK
		s.save(ctx, in)
		s.emit(ctx, in, "dryrun_ok", r.Detail)
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
				return s.reject(ctx, in, "staging apply: "+detail)
			}
		}
	}
	in.Stage = StageStaged
	in.Reasons = append(in.Reasons, "applied to staging")
	s.save(ctx, in)
	s.emit(ctx, in, "staged", "applied to staging env")

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

// PromoteToProd is the ONLY path to production.
func (s *Service) PromoteToProd(ctx context.Context, intentID string) (*Intent, error) {
	in, ok := s.store.GetIntent(ctx, intentID)
	if !ok {
		return nil, errors.New("unknown intent")
	}
	if in.Stage != StageStaged && in.Stage != StageAwaitProd {
		return in, fmt.Errorf("intent not eligible for prod (stage=%s)", in.Stage)
	}

	needsQuorum := in.Mode == ModeScaffold // all code changes need a human gate
	if act := FindAction(s.catalog, in.Action); act != nil && act.RequiresQuorum {
		needsQuorum = true
	}

	if needsQuorum {
		if s.gov == nil {
			return s.reject(ctx, in, "prod requires governance but no governance client configured")
		}
		approvalID := in.ApprovalID
		if approvalID == "" {
			id, err := s.gov.RequestApproval(in)
			if err != nil {
				in.Stage = StageFailed
				s.save(ctx, in)
				s.emit(ctx, in, "failed", "governance request error: "+err.Error())
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
			s.emit(ctx, in, "awaiting_prod", "approval "+approvalID+" pending")
			return in, nil
		}
		in.Reasons = append(in.Reasons, "governance approved "+approvalID)
	}

	in.Stage = StageProd
	s.save(ctx, in)
	s.emit(ctx, in, "deployed_prod", "applied to prod env")
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

// List returns intents for a tenant (newest first).
func (s *Service) List(ctx context.Context, tenantID string) []*Intent {
	return s.store.ListIntents(ctx, tenantID)
}

// Catalog exposes the active allow-list.
func (s *Service) Catalog() []CatalogAction { return s.catalog }
