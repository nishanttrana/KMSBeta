package resilience

import (
	"context"
	"errors"
	"fmt"
	"crypto/rand"
	"encoding/binary"
	"math"
	"net"
	"os"
	"strings"
	"time"
)

// RetryConfig controls exponential backoff retry behavior.
type RetryConfig struct {
	// MaxAttempts is the total number of attempts (including the initial call).
	// A value of 1 means no retries.
	MaxAttempts int
	// InitialDelay is the base delay before the first retry.
	InitialDelay time.Duration
	// MaxDelay caps the backoff delay regardless of the multiplier.
	MaxDelay time.Duration
	// Multiplier is applied to the delay after each failed attempt.
	Multiplier float64
	// JitterFraction adds randomness to the delay. A value of 0.1 means +/-10%
	// of the computed delay. Must be in [0, 1].
	JitterFraction float64
	// ShouldRetry, if set, overrides the default IsRetryable check. Return true
	// to retry the error.
	ShouldRetry func(err error) bool
	// OnRetry, if set, is called before each retry with the attempt number
	// (starting at 2) and the error from the previous attempt.
	OnRetry func(attempt int, err error)
}

// DefaultRetryConfig returns a production-ready retry configuration:
// 3 attempts, 100ms initial delay, 5s max delay, 2x multiplier, 10% jitter.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:    3,
		InitialDelay:   100 * time.Millisecond,
		MaxDelay:       5 * time.Second,
		Multiplier:     2.0,
		JitterFraction: 0.1,
	}
}

// Retry executes fn with exponential backoff and jitter. It respects context
// cancellation and only retries errors deemed transient by IsRetryable (or a
// custom ShouldRetry function).
//
// The function returns nil on the first successful attempt, or the last error
// after all attempts are exhausted.
func Retry(ctx context.Context, cfg RetryConfig, fn func(ctx context.Context) error) error {
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 1
	}
	if cfg.InitialDelay <= 0 {
		cfg.InitialDelay = 100 * time.Millisecond
	}
	if cfg.MaxDelay <= 0 {
		cfg.MaxDelay = 5 * time.Second
	}
	if cfg.Multiplier <= 0 {
		cfg.Multiplier = 2.0
	}

	retryable := cfg.ShouldRetry
	if retryable == nil {
		retryable = IsRetryable
	}

	var lastErr error
	delay := cfg.InitialDelay

	for attempt := 1; attempt <= cfg.MaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return fmt.Errorf("context cancelled after %d attempts: %w (last error: %v)", attempt-1, err, lastErr)
			}
			return err
		}

		lastErr = fn(ctx)
		if lastErr == nil {
			return nil
		}

		// Do not retry non-transient errors or on the last attempt.
		if attempt == cfg.MaxAttempts || !retryable(lastErr) {
			break
		}

		if cfg.OnRetry != nil {
			cfg.OnRetry(attempt+1, lastErr)
		}

		// Compute jittered delay.
		jitteredDelay := applyJitter(delay, cfg.JitterFraction)

		select {
		case <-ctx.Done():
			return fmt.Errorf("context cancelled during backoff after %d attempts: %w (last error: %v)", attempt, ctx.Err(), lastErr)
		case <-time.After(jitteredDelay):
		}

		// Advance delay for next iteration.
		delay = time.Duration(float64(delay) * cfg.Multiplier)
		if delay > cfg.MaxDelay {
			delay = cfg.MaxDelay
		}
	}
	return lastErr
}

// applyJitter adds randomness to a delay. A jitterFraction of 0.1 yields a
// delay in the range [delay*0.9, delay*1.1].
func applyJitter(delay time.Duration, jitterFraction float64) time.Duration {
	if jitterFraction <= 0 || jitterFraction > 1 {
		return delay
	}
	jitter := (cryptoFloat64()*2 - 1) * jitterFraction * float64(delay)
	d := time.Duration(float64(delay) + jitter)
	if d <= 0 {
		return time.Millisecond
	}
	return d
}

// cryptoFloat64 returns a cryptographically secure float64 in [0, 1).
func cryptoFloat64() float64 {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return float64(binary.LittleEndian.Uint64(b[:])>>11) / (1 << 53)
}

// TransientError wraps an error and marks it as retryable.
type TransientError struct {
	Err error
}

func (e *TransientError) Error() string {
	return fmt.Sprintf("transient: %v", e.Err)
}

func (e *TransientError) Unwrap() error {
	return e.Err
}

// MarkTransient wraps err so that IsRetryable returns true.
func MarkTransient(err error) error {
	if err == nil {
		return nil
	}
	return &TransientError{Err: err}
}

// httpStatusError is an interface for errors that carry an HTTP status code
// (e.g., from HTTP client libraries).
type httpStatusError interface {
	StatusCode() int
}

// IsRetryable determines whether an error is transient and safe to retry.
// It checks for:
//   - Errors explicitly marked as TransientError
//   - Network dial/connection errors (connection refused, reset)
//   - Context deadline exceeded (but not context cancelled)
//   - os.ErrDeadlineExceeded
//   - HTTP 503 (Service Unavailable) and 429 (Too Many Requests)
//   - Common transient error message patterns
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}

	// Explicitly marked transient.
	var te *TransientError
	if errors.As(err, &te) {
		return true
	}

	// Network errors: connection refused, connection reset, DNS temporary failures.
	var netErr *net.OpError
	if errors.As(err, &netErr) {
		return true
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.Temporary() {
		return true
	}

	// Timeout errors (deadline exceeded is transient; plain cancellation is not).
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	if errors.Is(err, context.Canceled) {
		return false
	}

	// Interface-based: any error exposing Timeout().
	type timeouter interface {
		Timeout() bool
	}
	var tErr timeouter
	if errors.As(err, &tErr) && tErr.Timeout() {
		return true
	}

	// HTTP status codes exposed via interface.
	var httpErr httpStatusError
	if errors.As(err, &httpErr) {
		code := httpErr.StatusCode()
		if code == 429 || code == 503 || code == 502 || code == 504 {
			return true
		}
	}

	// Heuristic: common transient substrings in error messages.
	msg := strings.ToLower(err.Error())
	transientPatterns := []string{
		"connection refused",
		"connection reset",
		"broken pipe",
		"no such host",
		"tls handshake timeout",
		"service unavailable",
		"too many requests",
		"i/o timeout",
		"temporary failure",
	}
	for _, pat := range transientPatterns {
		if strings.Contains(msg, pat) {
			return true
		}
	}

	return false
}

// RetryableError is a convenience for creating errors that always pass IsRetryable.
// Use MarkTransient(err) for wrapping existing errors.
func RetryableError(msg string) error {
	return &TransientError{Err: errors.New(msg)}
}

// backoffDelay computes the delay for a given attempt (0-indexed) using
// exponential backoff. Exported for testing.
func backoffDelay(attempt int, initial time.Duration, multiplier float64, maxDelay time.Duration) time.Duration {
	d := time.Duration(float64(initial) * math.Pow(multiplier, float64(attempt)))
	if d > maxDelay {
		return maxDelay
	}
	return d
}
