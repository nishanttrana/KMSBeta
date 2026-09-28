package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/resilience"
	"vecta-kms/pkg/ssrfguard"
)

// WebhookDispatcher wraps webhook delivery with per-target circuit breakers
// and bounded exponential-backoff retries. The dispatcher replaces ad-hoc
// http.Client.Do(...) call sites so a sustained failure on one downstream
// cannot cascade into the wider system.
//
// Each registered webhook gets its own breaker; tripping one webhook
// leaves the others untouched. Breakers half-open on a 30s cool-down so
// transient outages recover automatically without operator intervention.
type WebhookDispatcher struct {
	client   *http.Client
	validate func(string) error // https + SSRF guard; tests substitute a local server
	retry    resilience.RetryConfig
	mu       sync.RWMutex
	breakers map[string]*resilience.Breaker
	onEvent  func(target string, ok bool, latency time.Duration, err error)
}

// NewWebhookDispatcher constructs a dispatcher with production defaults:
// 15s timeout per attempt, three attempts with 200ms→3.2s backoff, and
// breakers that trip after 5 consecutive failures over 60s.
func NewWebhookDispatcher() *WebhookDispatcher {
	r := resilience.DefaultRetryConfig()
	r.MaxAttempts = 3
	r.InitialDelay = 200 * time.Millisecond
	r.MaxDelay = 3200 * time.Millisecond
	r.Multiplier = 2.0
	r.JitterFraction = 0.1
	return &WebhookDispatcher{
		client:   ssrfguard.NewHTTPSClient(15 * time.Second),
		validate: validateWebhookURL,
		retry:    r,
		breakers: make(map[string]*resilience.Breaker),
	}
}

// OnEvent registers an optional callback for delivery telemetry. Used by
// the audit store to record per-attempt timing and the breaker's state
// transitions onto the immutable chain.
func (d *WebhookDispatcher) OnEvent(cb func(target string, ok bool, latency time.Duration, err error)) {
	d.onEvent = cb
}

// Deliver attempts to POST payload to wh.URL, signing with the webhook
// secret and respecting per-target circuit-breaker state. Returns the
// final HTTP status (0 on transport failure), the attempts made and any error.
func (d *WebhookDispatcher) Deliver(ctx context.Context, wh Webhook, eventType, eventID string, payload []byte) (int, int, error) {
	if err := d.validate(wh.URL); err != nil {
		return 0, 0, err
	}
	return d.Attempt(ctx, wh.ID, hostOf(wh.URL), func(ctx context.Context) (int, error) {
		return d.doOnce(ctx, wh, eventType, eventID, payload)
	})
}

// Attempt runs send with the retry policy behind the stream's breaker (key)
// and returns the last status, the attempts made and any error. SIEM
// destinations (pkg/siem) go through it as well as webhooks.
func (d *WebhookDispatcher) Attempt(ctx context.Context, key, target string, send func(context.Context) (int, error)) (int, int, error) {
	br := d.breakerFor(key)
	var status int
	var lastErr error
	attempt := 0
	err := resilience.Retry(ctx, d.retry, func(ctx context.Context) error {
		attempt++
		var s int
		var e error
		_, brErr := br.Execute(func() (any, error) {
			start := time.Now()
			s, e = send(ctx)
			if e == nil && s != 0 && (s < 200 || s >= 300) {
				e = fmt.Errorf("non-2xx response: %d", s)
			}
			if d.onEvent != nil {
				d.onEvent(target, e == nil, time.Since(start), e)
			}
			return nil, e
		})
		status = s
		lastErr = e
		if brErr != nil {
			return brErr
		}
		return nil
	})
	if err != nil && lastErr == nil {
		lastErr = err
	}
	return status, attempt, lastErr
}

func (d *WebhookDispatcher) doOnce(ctx context.Context, wh Webhook, eventType, eventID string, payload []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, wh.URL, bytes.NewReader(payload))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "VectaKMS-Webhook/1.0")
	for k, v := range wh.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("X-KMS-Event-Type", eventType)
	req.Header.Set("X-KMS-Event-ID", eventID)
	if wh.Secret != "" {
		req.Header.Set("X-KMS-Signature", "sha256="+hex.EncodeToString(pkgcrypto.HMACSHA256([]byte(wh.Secret), payload)))
	}
	resp, err := d.client.Do(req)
	if err != nil {
		// *url.Error quotes the full URL; a Slack or Teams URL is itself a
		// credential and would land in the delivery log and audit.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = fmt.Errorf("%s: %v", req.URL.Hostname(), ue.Err)
		}
		return 0, err
	}
	defer resp.Body.Close()        //nolint:errcheck
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	return resp.StatusCode, nil
}

func (d *WebhookDispatcher) breakerFor(id string) *resilience.Breaker {
	d.mu.RLock()
	if b, ok := d.breakers[id]; ok {
		d.mu.RUnlock()
		return b
	}
	d.mu.RUnlock()
	d.mu.Lock()
	defer d.mu.Unlock()
	if b, ok := d.breakers[id]; ok {
		return b
	}
	b := resilience.NewBreaker("webhook-" + id)
	d.breakers[id] = b
	return b
}

// ErrCircuitOpen is exported so callers can detect the breaker tripping
// vs. a transient HTTP failure when interpreting Deliver's error.
var ErrCircuitOpen = errors.New("webhook circuit open")
