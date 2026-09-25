package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type capturePublisher struct {
	mu     sync.Mutex
	events map[string][]map[string]interface{}
}

func (p *capturePublisher) Publish(_ context.Context, subject string, payload []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	var ev map[string]interface{}
	_ = json.Unmarshal(payload, &ev)
	if p.events == nil {
		p.events = map[string][]map[string]interface{}{}
	}
	p.events[subject] = append(p.events[subject], ev)
	return nil
}

func observe(t *testing.T, store *SQLStore, service, mode string) {
	t.Helper()
	if _, err := store.db.SQL().Exec(`INSERT INTO platform_fips_observed (service, instance, mode, started_at) VALUES ($1,'i1',$2,CURRENT_TIMESTAMP)`, service, mode); err != nil {
		t.Fatal(err)
	}
}

func TestFIPSModeChangeImpactAndRollout(t *testing.T) {
	store := newGovernanceStore(t)
	pub := &capturePublisher{}
	svc := NewService(store, pub, &mockEmailSender{}, &mockCallbackExecutor{}, "http://localhost:8050")
	ctx := context.Background()
	if err := store.SetPlatformFIPSMode(ctx, PlatformFIPSMode{Mode: "on", RequestedBy: "seed"}); err != nil {
		t.Fatal(err)
	}
	observe(t, store, "kms-keycore", "on")
	observe(t, store, "kms-payment", "on")

	impact, err := svc.FIPSModeImpact(ctx, "only")
	if err != nil {
		t.Fatal(err)
	}
	if impact.From != "on" || impact.Downgrade || len(impact.Stops) == 0 || len(impact.Restarts) != 2 || impact.EstimatedSecs <= 0 {
		t.Fatalf("on->only impact: %+v", impact)
	}
	if !strings.Contains(strings.ToLower(impact.Stops[0].Feature+impact.Stops[0].Detail), "des") {
		t.Fatalf("payment TDES must be listed as stopping: %+v", impact.Stops[0])
	}

	if _, err := svc.SetFIPSMode(ctx, "off", "on", "", "admin1"); !errors.Is(err, errFIPSModeConfirm) {
		t.Fatalf("a mismatched confirmation must be refused, got %v", err)
	}
	impact, err = svc.SetFIPSMode(ctx, "off", "off", "lab testing", "admin1")
	if err != nil || !impact.Downgrade {
		t.Fatalf("on->off must be recorded as a downgrade: %+v %v", impact, err)
	}
	ev := pub.events["audit.governance.fips_mode_changed"]
	if len(ev) != 1 {
		t.Fatalf("expected one fips_mode_changed audit event, got %d", len(ev))
	}
	data, _ := ev[0]["data"].(map[string]interface{})
	if data["severity"] != "critical" || data["from"] != "on" || data["to"] != "off" || data["actor"] != "admin1" {
		t.Fatalf("downgrade audit event must be critical and complete: %+v", data)
	}

	status, err := svc.FIPSModeStatus(ctx)
	if err != nil || status.Effective != "off" || status.Converged || status.Pending != 2 {
		t.Fatalf("services still on must show as pending: %+v %v", status, err)
	}
	if _, err := store.db.SQL().Exec(`UPDATE platform_fips_observed SET mode = 'off'`); err != nil {
		t.Fatal(err)
	}
	if status, _ = svc.FIPSModeStatus(ctx); !status.Converged {
		t.Fatalf("all services in the new mode must show converged: %+v", status)
	}
}

func TestFIPSModeAPIIsRootAdminOnly(t *testing.T) {
	store := newGovernanceStore(t)
	h := NewHandler(NewService(store, nil, &mockEmailSender{}, &mockCallbackExecutor{}, "http://localhost:8050"))
	req := httptest.NewRequest(http.MethodPut, "/governance/system/fips-mode?tenant_id=tenant-a", strings.NewReader(`{"mode":"off","confirm":"off"}`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("a non-root tenant must not change the platform FIPS mode, got %d %s", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/governance/system/fips-mode/impact?tenant_id=root&target=bogus", nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("an invalid target must be rejected, got %d", rr.Code)
	}
}

func TestFIPSRolloutIsAuditedOncePerStartAndOnCompletion(t *testing.T) {
	store := newGovernanceStore(t)
	pub := &capturePublisher{}
	svc := NewService(store, pub, &mockEmailSender{}, &mockCallbackExecutor{}, "http://localhost:8050")
	ctx := context.Background()
	if err := store.SetPlatformFIPSMode(ctx, PlatformFIPSMode{Mode: "only", Previous: "on", RequestedBy: "admin1"}); err != nil {
		t.Fatal(err)
	}
	observe(t, store, "kms-keycore", "only")
	observe(t, store, "kms-auth", "on")

	for i := 0; i < 2; i++ { // re-running must not duplicate events
		if err := svc.AuditFIPSRollout(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(pub.events["audit.governance.fips_mode_applied"]); n != 2 {
		t.Fatalf("one applied event per service start, got %d", n)
	}
	if n := len(pub.events["audit.governance.fips_mode_rollout_completed"]); n != 0 {
		t.Fatal("rollout is not complete while kms-auth still runs on")
	}
	// kms-auth restarts into the platform mode.
	if _, err := store.db.SQL().Exec(`UPDATE platform_fips_observed SET mode = 'only', started_at = CURRENT_TIMESTAMP + 1 WHERE service = 'kms-auth'`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := svc.AuditFIPSRollout(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(pub.events["audit.governance.fips_mode_applied"]); n != 3 {
		t.Fatalf("the restart must add one applied event, got %d", n)
	}
	if n := len(pub.events["audit.governance.fips_mode_rollout_completed"]); n != 1 {
		t.Fatalf("completion must be audited exactly once, got %d", n)
	}
}
