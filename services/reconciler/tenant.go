package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// TenantManifest is the declarative form operators commit to git. The
// reconciler reads manifests from a directory mounted into the pod and
// applies the two parts it acts on: the tenant's ops budget and its
// policies. Other keys in the file are ignored.
type TenantManifest struct {
	Tenant   TenantSpec       `yaml:"tenant" json:"tenant"`
	Policies []PolicyManifest `yaml:"policies,omitempty" json:"policies,omitempty"`
}

// TenantSpec is the per-tenant config block.
type TenantSpec struct {
	ID              string `yaml:"id" json:"id"`
	OpsBudgetPerDay int64  `yaml:"ops_budget_per_day,omitempty" json:"ops_budget_per_day,omitempty"`
}

// PolicyManifest is the YAML body for one policy plus its identifier.
type PolicyManifest struct {
	ID   string `yaml:"id" json:"id"`
	YAML string `yaml:"yaml" json:"yaml"`
}

// tenantReconciler is the controller that applies tenant manifests: the
// ops budget (policy quota) and the policies. Nothing else in a manifest is
// applied.
type tenantReconciler struct {
	client    *http.Client
	policyURL string
	logger    logIface

	mu        sync.Mutex
	manifests []TenantManifest
}

func newTenantReconciler(client *http.Client, policyURL string, l logIface) *tenantReconciler {
	return &tenantReconciler{
		client:    client,
		policyURL: strings.TrimRight(policyURL, "/"),
		logger:    l,
	}
}

func (r *tenantReconciler) Name() string { return "tenant" }

func (r *tenantReconciler) Reconcile(ctx context.Context) error {
	manifests, err := r.loadManifests()
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.manifests = manifests
	r.mu.Unlock()
	var errs []error
	for _, m := range manifests {
		if err := r.applyTenant(ctx, m); err != nil {
			errs = append(errs, fmt.Errorf("tenant %s: %w", m.Tenant.ID, err))
		}
	}
	return errors.Join(errs...)
}

// loadManifests reads every *.yaml from RECONCILER_MANIFEST_DIR. The
// directory is typically mounted from a ConfigMap or a git-sync
// sidecar; the reconciler doesn't care where the files come from, only
// that they exist.
func (r *tenantReconciler) loadManifests() ([]TenantManifest, error) {
	dir := strings.TrimSpace(os.Getenv("RECONCILER_MANIFEST_DIR"))
	if dir == "" {
		dir = "/etc/vecta/manifests"
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	out := make([]TenantManifest, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var m TenantManifest
		if err := yaml.Unmarshal(raw, &m); err != nil {
			continue
		}
		if m.Tenant.ID == "" {
			continue
		}
		out = append(out, m)
	}
	return out, nil
}

// applyTenant performs the reconciliation for one manifest.
func (r *tenantReconciler) applyTenant(ctx context.Context, m TenantManifest) error {
	// Policy budget — sets the quota tracker on the policy service.
	// Skipped when the budget is zero.
	if m.Tenant.OpsBudgetPerDay > 0 {
		err := r.putJSON(ctx, r.policyURL+"/policy/quota/"+m.Tenant.ID, map[string]any{
			"limit":          m.Tenant.OpsBudgetPerDay,
			"warn_at":        0.8,
			"window_seconds": 86400,
		})
		if err != nil {
			return err
		}
	}
	// Policies — created under the tenant. The policy service refuses a
	// second policy with the same name, so a policy is created once; a
	// later edit in the manifest is not applied (the refusal is logged).
	for _, p := range m.Policies {
		if err := r.postJSON(ctx, r.policyURL+"/policies", map[string]any{
			"tenant_id": m.Tenant.ID,
			"yaml":      p.YAML,
			"actor":     "reconciler",
		}); err != nil {
			r.logger.Printf("apply policy %s: %v", p.ID, err)
		}
	}
	return nil
}
