package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// keyLifecycleReconciler drives the automated lifecycle moves keycore's
// GET /keys/due-for-lifecycle names: rotate (operator expiry, cryptoperiod,
// 80% of ops_limit) and destroy (compromised, or deactivated past grace).
// It calls keycore endpoints rather than reaching into the database so all
// changes flow through the same audit path as operator-initiated actions.
type keyLifecycleReconciler struct {
	client     *http.Client
	keycoreURL string
	logger     logIface
}

func newKeyLifecycleReconciler(client *http.Client, keycoreURL string, l logIface) *keyLifecycleReconciler {
	return &keyLifecycleReconciler{
		client:     client,
		keycoreURL: strings.TrimRight(keycoreURL, "/"),
		logger:     l,
	}
}

func (r *keyLifecycleReconciler) Name() string { return "keylifecycle" }

// Reconcile asks keycore to list keys due for lifecycle action and then
// invokes the appropriate transition endpoint. The keycore-side list
// endpoint knows the cryptoperiods, the ops_limit threshold and the grace
// window; the reconciler is just the trigger that calls back in.
func (r *keyLifecycleReconciler) Reconcile(ctx context.Context) error {
	var due struct {
		Items []struct {
			TenantID string `json:"tenant_id"`
			KeyID    string `json:"key_id"`
			Action   string `json:"action"` // "rotate" or "destroy"
			Reason   string `json:"reason"`
		} `json:"items"`
	}
	// A failed scan is the controller's status (last_error in System
	// Administration → Health), not "nothing due".
	if err := getJSON(ctx, r.client, r.keycoreURL+"/keys/due-for-lifecycle?max=200", &due); err != nil {
		return fmt.Errorf("due-for-lifecycle: %w", err)
	}
	for _, item := range due.Items {
		path := lifecyclePath(item.Action, item.KeyID)
		if path == "" {
			continue
		}
		ctxOp, cancel := context.WithTimeout(ctx, 5*time.Second)
		// keycore resolves the key within the tenant the item belongs to.
		err := doJSON(ctxOp, r.client, http.MethodPost, r.keycoreURL+path+"?tenant_id="+url.QueryEscape(item.TenantID), map[string]any{
			"actor":  "reconciler",
			"reason": item.Reason,
		})
		cancel()
		if err != nil {
			r.logger.Printf("keylifecycle %s for %s: %v", item.Action, item.KeyID, err)
		}
	}
	return nil
}

func lifecyclePath(action, keyID string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "rotate":
		return "/keys/" + keyID + "/rotate"
	case "destroy":
		return "/keys/" + keyID + "/destroy"
	default:
		return ""
	}
}
