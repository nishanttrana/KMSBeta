package main

import (
	"context"
	"net/http"
	"strings"
)

// quotaReconciler periodically syncs declarative tenant budgets to the
// policy service's in-memory quota tracker. Without a periodic sync the
// tracker would forget budgets after policy-service restarts; the
// reconciler is the source of truth.
type quotaReconciler struct {
	client    *http.Client
	policyURL string
	logger    logIface
}

func newQuotaReconciler(client *http.Client, policyURL string, l logIface) *quotaReconciler {
	return &quotaReconciler{
		client:    client,
		policyURL: strings.TrimRight(policyURL, "/"),
		logger:    l,
	}
}

func (r *quotaReconciler) Name() string { return "quota" }

// Reconcile reads the desired budgets from the manifest directory and
// pushes them to the policy service. The tenant reconciler already
// touches these as part of onboarding; this reconciler re-applies them
// every cycle so a policy-service restart re-hydrates within minutes.
func (r *quotaReconciler) Reconcile(ctx context.Context) error {
	tr := &tenantReconciler{}
	manifests, err := tr.loadManifests()
	if err != nil {
		return err
	}
	for _, m := range manifests {
		if m.Tenant.OpsBudgetPerDay <= 0 {
			continue
		}
		_ = doJSON(ctx, r.client, http.MethodPut,
			r.policyURL+"/policy/quota/"+m.Tenant.ID,
			map[string]any{
				"limit":          m.Tenant.OpsBudgetPerDay,
				"warn_at":        0.8,
				"window_seconds": 86400,
			})
	}
	return nil
}
