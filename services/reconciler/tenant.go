package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
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
	if len(m.Policies) == 0 {
		return nil
	}
	existing, err := r.listPolicies(ctx, m.Tenant.ID)
	if err != nil {
		return fmt.Errorf("list policies: %w", err)
	}
	var errs []error
	for _, p := range m.Policies {
		if err := r.applyPolicy(ctx, m.Tenant.ID, p, existing); err != nil {
			errs = append(errs, fmt.Errorf("policy %s: %w", p.ID, err))
		}
	}
	return errors.Join(errs...)
}

// appliedPolicy is the part of the policy service's Policy the reconciler
// compares (the service encodes it without JSON tags).
type appliedPolicy struct {
	ID      string
	Name    string
	RawYAML string
}

// applyPolicy converges one manifest policy: the policy service keys a
// policy on (tenant, metadata.name), so it is created when absent, updated
// when its YAML differs, and left alone when identical so an unchanged tick
// writes nothing and emits no policy audit event. A policy removed from the
// manifest is not deleted (docs/AUTOMATION_ALKM_PQC.md).
func (r *tenantReconciler) applyPolicy(ctx context.Context, tenantID string, p PolicyManifest, existing map[string]appliedPolicy) error {
	var doc struct {
		Metadata struct {
			Name string `yaml:"name"`
		} `yaml:"metadata"`
	}
	if err := yaml.Unmarshal([]byte(p.YAML), &doc); err != nil {
		return fmt.Errorf("parse yaml: %w", err)
	}
	name := strings.TrimSpace(doc.Metadata.Name)
	if name == "" {
		return errors.New("metadata.name is required")
	}
	body := map[string]any{"tenant_id": tenantID, "yaml": p.YAML, "actor": "reconciler"}
	cur, ok := existing[name]
	switch {
	case !ok:
		return r.postJSON(ctx, r.policyURL+"/policies", body)
	case cur.RawYAML == p.YAML:
		return nil
	default:
		body["commit_message"] = "reconciler: manifest " + p.ID
		return r.putJSON(ctx, r.policyURL+"/policies/"+url.PathEscape(cur.ID)+"?tenant_id="+url.QueryEscape(tenantID), body)
	}
}

// listPolicies returns the tenant's policies by name, paging through the
// policy service's list (at most 1000 per page).
func (r *tenantReconciler) listPolicies(ctx context.Context, tenantID string) (map[string]appliedPolicy, error) {
	const page = 1000
	out := map[string]appliedPolicy{}
	for offset := 0; ; offset += page {
		var resp struct {
			Items []appliedPolicy `json:"items"`
		}
		u := fmt.Sprintf("%s/policies?tenant_id=%s&limit=%d&offset=%d", r.policyURL, url.QueryEscape(tenantID), page, offset)
		if err := getJSON(ctx, r.client, u, &resp); err != nil {
			return nil, err
		}
		for _, p := range resp.Items {
			out[p.Name] = p
		}
		if len(resp.Items) < page {
			return out, nil
		}
	}
}
