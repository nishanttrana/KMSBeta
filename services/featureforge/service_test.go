package main

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- test stubs ----------------------------------------------------------

type stubPolicy struct{ deny map[string]bool }

func (p *stubPolicy) Evaluate(_, action string, params map[string]interface{}) (GuardrailResult, error) {
	if p.deny[action] {
		return GuardrailResult{Layer: "policy", Passed: false, Detail: "denied"}, nil
	}
	if action == "policy.restrict_algorithm" {
		if alg, _ := params["algorithm"].(string); strings.HasPrefix(strings.ToUpper(alg), "ML-") {
			return GuardrailResult{Layer: "policy", Passed: false, Detail: "refusing to block PQC"}, nil
		}
	}
	return GuardrailResult{Layer: "policy", Passed: true, Detail: "permitted"}, nil
}
func (p *stubPolicy) Apply(_, _, _ string, _ map[string]interface{}) (GuardrailResult, error) {
	return GuardrailResult{Layer: "apply", Passed: true, Detail: "applied"}, nil
}

type stubGov struct {
	mu       sync.Mutex
	auto     bool
	seq      int
	last     string
	approved map[string]bool
}

func newStubGov(auto bool) *stubGov { return &stubGov{auto: auto, approved: map[string]bool{}} }
func (g *stubGov) RequestApproval(_ *Intent) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.seq++
	id := "gov-" + time.Now().Format("150405.000000")
	id = id + "-" + itoa(g.seq)
	g.approved[id] = g.auto
	g.last = id
	return id, nil
}
func (g *stubGov) ApprovalState(id string) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.approved[id], nil
}
func (g *stubGov) approve() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.approved[g.last] = true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

type stubMCP struct{ fail bool }

func (m *stubMCP) Submit(_ *Intent) (string, error) { return "job-1", nil }
func (m *stubMCP) Status(_ string) (GuardrailResult, error) {
	if m.fail {
		return GuardrailResult{Layer: "mcp", Passed: false, Detail: "build failed"}, nil
	}
	return GuardrailResult{Layer: "mcp", Passed: true, Detail: "build + validate passed"}, nil
}

func newSvc(t *testing.T, autoApprove, mcpFail bool) (*Service, *stubGov) {
	t.Helper()
	gov := newStubGov(autoApprove)
	return NewService(Config{
		Policy:     &stubPolicy{deny: map[string]bool{}},
		Governance: gov,
		MCP:        &stubMCP{fail: mcpFail},
		Store:      NewMemStore(),
		Now:        func() time.Time { return time.Now().UTC() },
	}), gov
}

// --- tests ---------------------------------------------------------------

func TestConfig_BlockRSA1024_Stages_NotProd(t *testing.T) {
	svc, _ := newSvc(t, false, false)
	in, err := svc.Submit(context.Background(), "t1", "alice", "block RSA-1024 for this tenant")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if in.Action != "policy.restrict_algorithm" || in.Params["algorithm"] != "RSA-1024" {
		t.Fatalf("classification wrong: %s %v", in.Action, in.Params)
	}
	if in.Stage != StageStaged {
		t.Fatalf("want staged, got %s", in.Stage)
	}
	_, trail, _ := svc.Get(context.Background(), in.ID)
	for _, e := range trail {
		if e.Stage == StageProd {
			t.Fatal("staging wall violated: reached prod via Submit")
		}
	}
}

func TestConfig_NonQuorum_PromotesToProd(t *testing.T) {
	svc, _ := newSvc(t, false, false)
	in, _ := svc.Submit(context.Background(), "t", "a", "block RSA-1024")
	out, err := svc.PromoteToProd(context.Background(), in.ID)
	if err != nil {
		t.Fatalf("promote err: %v", err)
	}
	if out.Stage != StageProd {
		t.Fatalf("want prod, got %s", out.Stage)
	}
}

func TestConfig_QuorumAction_WaitsThenApproves(t *testing.T) {
	svc, gov := newSvc(t, false, false)
	in, _ := svc.Submit(context.Background(), "t", "a", "require approval for key delete")
	if in.Stage != StageStaged {
		t.Fatalf("want staged, got %s (%v)", in.Stage, in.Reasons)
	}
	out, _ := svc.PromoteToProd(context.Background(), in.ID)
	if out.Stage != StageAwaitProd {
		t.Fatalf("want awaiting_prod, got %s", out.Stage)
	}
	gov.approve()
	out2, _ := svc.PromoteToProd(context.Background(), in.ID)
	if out2.Stage != StageProd {
		t.Fatalf("want prod after approval, got %s", out2.Stage)
	}
}

func TestScaffold_NeedsMCP_AndQuorum(t *testing.T) {
	svc, gov := newSvc(t, false, false)
	in, err := svc.Submit(context.Background(), "t", "bob", "build a new EdDSA signing endpoint service")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if in.Mode != ModeScaffold || in.MCPJobID == "" {
		t.Fatalf("expected scaffold + mcp job, got mode=%s job=%q", in.Mode, in.MCPJobID)
	}
	if in.Stage != StageStaged {
		t.Fatalf("want staged, got %s", in.Stage)
	}
	out, _ := svc.PromoteToProd(context.Background(), in.ID)
	if out.Stage != StageAwaitProd {
		t.Fatalf("scaffold prod must be quorum-gated, got %s", out.Stage)
	}
	gov.approve()
	out2, _ := svc.PromoteToProd(context.Background(), in.ID)
	if out2.Stage != StageProd {
		t.Fatalf("want prod after approval, got %s", out2.Stage)
	}
}

func TestScaffold_NoMCPConfigured_Rejected(t *testing.T) {
	svc := NewService(Config{Store: NewMemStore(), Governance: newStubGov(false)})
	in, err := svc.Submit(context.Background(), "t", "bob", "build a new signing endpoint service")
	if err == nil {
		t.Fatal("expected rejection when MCP not configured")
	}
	if in.Stage != StageRejected {
		t.Fatalf("want rejected, got %s", in.Stage)
	}
}

func TestScaffold_BuildFails_Rejected(t *testing.T) {
	svc, _ := newSvc(t, false, true)
	in, err := svc.Submit(context.Background(), "t", "bob", "build a new signing endpoint service")
	if err == nil {
		t.Fatal("expected rejection on failed build")
	}
	if in.Stage != StageRejected {
		t.Fatalf("want rejected, got %s", in.Stage)
	}
}

func TestLowConfidence_Rejected(t *testing.T) {
	svc, _ := newSvc(t, false, false)
	in, err := svc.Submit(context.Background(), "t", "a", "do something vague please")
	if err == nil {
		t.Fatal("expected rejection")
	}
	if in.Stage != StageRejected {
		t.Fatalf("want rejected, got %s", in.Stage)
	}
}

func TestAuditTrailComplete(t *testing.T) {
	svc, _ := newSvc(t, true, false)
	in, _ := svc.Submit(context.Background(), "t", "a", "block RSA-1024")
	_, _ = svc.PromoteToProd(context.Background(), in.ID)
	_, trail, _ := svc.Get(context.Background(), in.ID)
	seen := map[Stage]bool{}
	for _, e := range trail {
		seen[e.Stage] = true
	}
	for _, want := range []Stage{StageReceived, StageClassified, StageValidated, StagePolicyOK, StageDryRunOK, StageStaged, StageProd} {
		if !seen[want] {
			t.Errorf("missing audit event for stage %s", want)
		}
	}
}
