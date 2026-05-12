package main

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// TenantManifest is the declarative form operators commit to git. The
// reconciler reads manifests from a directory mounted into the pod and
// applies them; the apply path is idempotent so the same manifest can
// be re-applied freely.
type TenantManifest struct {
	APIVersion string           `yaml:"apiVersion" json:"apiVersion"`
	Kind       string           `yaml:"kind" json:"kind"`
	Tenant     TenantSpec       `yaml:"tenant" json:"tenant"`
	Policies   []PolicyManifest `yaml:"policies,omitempty" json:"policies,omitempty"`
	Roles      []KMIPRole       `yaml:"kmip_roles,omitempty" json:"kmip_roles,omitempty"`
	Channels   map[string]any   `yaml:"audit_channels,omitempty" json:"audit_channels,omitempty"`
}

// TenantSpec is the per-tenant config block.
type TenantSpec struct {
	ID                string            `yaml:"id" json:"id"`
	Name              string            `yaml:"name" json:"name"`
	Status            string            `yaml:"status" json:"status"`
	MinAlgorithmTier  string            `yaml:"min_algorithm_tier,omitempty" json:"min_algorithm_tier,omitempty"`
	OpsBudgetPerDay   int64             `yaml:"ops_budget_per_day,omitempty" json:"ops_budget_per_day,omitempty"`
	Labels            map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
}

// PolicyManifest is the YAML body for one policy plus its identifier so
// re-applies are stable.
type PolicyManifest struct {
	ID   string `yaml:"id" json:"id"`
	YAML string `yaml:"yaml" json:"yaml"`
}

// KMIPRole is a minimal projection of the role config the KMIP service
// understands.
type KMIPRole struct {
	Name       string   `yaml:"name" json:"name"`
	Operations []string `yaml:"operations" json:"operations"`
}

// tenantReconciler is the controller that applies tenant manifests.
type tenantReconciler struct {
	client     *http.Client
	keycoreURL string
	kmipURL    string
	policyURL  string
	auditURL   string
	logger     logger

	mu       sync.Mutex
	manifests []TenantManifest
}

func newTenantReconciler(client *http.Client, keycoreURL, kmipURL, policyURL, auditURL string, l logger) *tenantReconciler {
	return &tenantReconciler{
		client:     client,
		keycoreURL: strings.TrimRight(keycoreURL, "/"),
		kmipURL:    strings.TrimRight(kmipURL, "/"),
		policyURL:  strings.TrimRight(policyURL, "/"),
		auditURL:   strings.TrimRight(auditURL, "/"),
		logger:     l,
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
	for _, m := range manifests {
		if err := r.applyTenant(ctx, m); err != nil {
			r.logger.Printf("tenant %s: %v", m.Tenant.ID, err)
		}
	}
	return nil
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

// applyTenant performs the actual reconciliation for one manifest. Each
// step is idempotent — applying the same manifest twice should produce
// no audit events the second time.
func (r *tenantReconciler) applyTenant(ctx context.Context, m TenantManifest) error {
	// Step 1: tenant onboarding via keycore (creates default MEK,
	// registers the tenant ID, sets posture defaults). The endpoint is
	// idempotent on the keycore side; we just announce intent.
	if err := r.postJSON(ctx, r.keycoreURL+"/tenants/onboard", m.Tenant); err != nil {
		return err
	}
	// Step 2: policy budget — sets the quota tracker on the policy
	// service. Skipped when the budget is zero.
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
	// Step 3: policies — upsert each policy under the tenant.
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
