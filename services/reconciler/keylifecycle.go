package main

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// keyLifecycleReconciler drives the automated lifecycle moves: state
// machine transitions, predictive rotation, grace-window promotion, and
// cryptoperiod enforcement. It calls keycore endpoints rather than
// reaching into the database so all changes flow through the same audit
// path as operator-initiated actions.
type keyLifecycleReconciler struct {
	client     *http.Client
	keycoreURL string
	logger     logger
}

func newKeyLifecycleReconciler(client *http.Client, keycoreURL string, l logger) *keyLifecycleReconciler {
	return &keyLifecycleReconciler{
		client:     client,
		keycoreURL: strings.TrimRight(keycoreURL, "/"),
		logger:     l,
	}
}

func (r *keyLifecycleReconciler) Name() string { return "keylifecycle" }

// Reconcile asks keycore to list keys due for lifecycle action and then
// invokes the appropriate transition endpoint. The keycore-side list
// endpoint already knows about cryptoperiods, predictive rotation
// thresholds, and grace windows; the reconciler is just the trigger
// that calls back in.
func (r *keyLifecycleReconciler) Reconcile(ctx context.Context) error {
	var due struct {
		Items []struct {
			TenantID string `json:"tenant_id"`
			KeyID    string `json:"key_id"`
			Action   string `json:"action"`   // "rotate", "deactivate", "destroy", "archive"
			Reason   string `json:"reason"`
		} `json:"items"`
	}
	if err := getJSON(ctx, r.client, r.keycoreURL+"/keys/due-for-lifecycle?max=200", &due); err != nil {
		// The endpoint is new and may not exist on older keycore builds.
		// Treat 404 as "nothing to do" rather than a hard error so the
		// reconciler can run against rolling deployments.
		return nil
	}
	for _, item := range due.Items {
		path := lifecyclePath(item.Action, item.KeyID)
		if path == "" {
			continue
		}
		ctxOp, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := doJSON(ctxOp, r.client, http.MethodPost, r.keycoreURL+path, map[string]any{
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
	case "deactivate":
		return "/keys/" + keyID + "/deactivate"
	case "destroy":
		return "/keys/" + keyID + "/destroy"
	case "archive":
		return "/keys/" + keyID + "/archive"
	default:
		return ""
	}
}
