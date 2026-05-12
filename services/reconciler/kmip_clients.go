package main

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// kmipClientReconciler walks the KMIP client list, evaluates each one
// against the decommission policy, and asks the KMIP service to apply
// the resulting status change.
type kmipClientReconciler struct {
	client  *http.Client
	kmipURL string
	logger  logger
}

func newKMIPClientReconciler(client *http.Client, kmipURL string, l logger) *kmipClientReconciler {
	return &kmipClientReconciler{
		client:  client,
		kmipURL: strings.TrimRight(kmipURL, "/"),
		logger:  l,
	}
}

func (r *kmipClientReconciler) Name() string { return "kmip-clients" }

// Reconcile fetches the candidate list and POSTs the resulting actions.
// The KMIP service decides the final action; the reconciler trusts that
// decision so the rule lives in one place.
func (r *kmipClientReconciler) Reconcile(ctx context.Context) error {
	var due struct {
		Items []struct {
			ClientID string `json:"client_id"`
			TenantID string `json:"tenant_id"`
			Action   string `json:"action"`
			Reason   string `json:"reason"`
		} `json:"items"`
	}
	if err := getJSON(ctx, r.client, r.kmipURL+"/kmip/clients/decommission-candidates", &due); err != nil {
		return nil
	}
	for _, item := range due.Items {
		ctxOp, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := doJSON(ctxOp, r.client, http.MethodPost,
			r.kmipURL+"/kmip/clients/"+item.ClientID+"/decommission",
			map[string]any{
				"action":    item.Action,
				"reason":    item.Reason,
				"actor":     "reconciler",
				"tenant_id": item.TenantID,
			})
		cancel()
		if err != nil {
			r.logger.Printf("decommission %s (%s): %v", item.ClientID, item.Action, err)
		}
	}
	return nil
}
