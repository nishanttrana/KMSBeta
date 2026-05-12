package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// logIface is the minimal interface the reconcilers accept for logging.
// *log.Logger satisfies it via Printf.
type logIface interface {
	Printf(format string, args ...any)
}

// postJSON is the standard helper for reconciler -> downstream-service
// calls. It encodes the body as JSON, treats any 2xx as success, and
// reads the response body so the connection can be returned to the pool.
func (r *tenantReconciler) postJSON(ctx context.Context, url string, body any) error {
	return doJSON(ctx, r.client, http.MethodPost, url, body)
}

// putJSON is identical but uses PUT.
func (r *tenantReconciler) putJSON(ctx context.Context, url string, body any) error {
	return doJSON(ctx, r.client, http.MethodPut, url, body)
}

func doJSON(ctx context.Context, client *http.Client, method, url string, body any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Reconciler-Source", "vecta-reconciler/v1")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("%s %s: status %d", method, url, resp.StatusCode)
}

// getJSON is the GET helper, returning the decoded body for callers that
// need to inspect downstream state.
func getJSON(ctx context.Context, client *http.Client, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Reconciler-Source", "vecta-reconciler/v1")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		return errors.New(resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
