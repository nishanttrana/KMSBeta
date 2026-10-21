// Package resilience provides enterprise resilience patterns including circuit
// breakers, retry with exponential backoff, and bulkhead concurrency limiting
// for KMS service-to-service communication.
package resilience

import (
	"log"
	"time"

	"github.com/sony/gobreaker"
)

// BreakerSettings holds the configuration for a circuit breaker instance.
type BreakerSettings struct {
	// MaxRequests is the number of requests allowed in the half-open state.
	MaxRequests uint32
	// Interval is the cyclic period of the closed state for clearing internal counts.
	// If zero, the internal counts are never cleared while in the closed state.
	Interval time.Duration
	// Timeout is the duration the breaker stays in the open state before transitioning
	// to half-open.
	Timeout time.Duration
	// ReadyToTrip determines whether the breaker should trip based on current counts.
	ReadyToTrip func(counts gobreaker.Counts) bool
	// OnStateChange is called whenever the breaker transitions between states.
	OnStateChange func(name string, from, to gobreaker.State)
}

// Option configures a Breaker.
type Option func(*BreakerSettings)

// defaultReadyToTrip trips the breaker after 5 consecutive failures.
func defaultReadyToTrip(counts gobreaker.Counts) bool {
	return counts.ConsecutiveFailures >= 5
}

// Breaker wraps sony/gobreaker with KMS-specific defaults and a simplified API.
type Breaker struct {
	cb   *gobreaker.CircuitBreaker
	name string
}

// NewBreaker creates a circuit breaker with sensible KMS defaults.
// Defaults: trip after 5 consecutive failures, 30s open-state timeout,
// 3 requests allowed in half-open state.
func NewBreaker(name string, opts ...Option) *Breaker {
	settings := BreakerSettings{
		MaxRequests: 3,
		Interval:    0,
		Timeout:     30 * time.Second,
		ReadyToTrip: defaultReadyToTrip,
		OnStateChange: func(n string, from, to gobreaker.State) {
			log.Printf("[resilience] circuit breaker %q: %s -> %s", n, from, to)
		},
	}
	for _, opt := range opts {
		opt(&settings)
	}

	cb := gobreaker.NewCircuitBreaker(gobreaker.Settings{
		Name:          name,
		MaxRequests:   settings.MaxRequests,
		Interval:      settings.Interval,
		Timeout:       settings.Timeout,
		ReadyToTrip:   settings.ReadyToTrip,
		OnStateChange: settings.OnStateChange,
	})

	return &Breaker{cb: cb, name: name}
}

// Execute runs fn through the circuit breaker. If the breaker is open,
// gobreaker.ErrOpenState is returned without calling fn. If the breaker is
// half-open and the maximum number of probe requests has been reached,
// gobreaker.ErrTooManyRequests is returned.
func (b *Breaker) Execute(fn func() (any, error)) (any, error) {
	return b.cb.Execute(fn)
}

// State returns the current state of the circuit breaker (Closed, HalfOpen, Open).
func (b *Breaker) State() gobreaker.State {
	return b.cb.State()
}

// Name returns the breaker's identifier.
func (b *Breaker) Name() string {
	return b.name
}

// Counts returns the internal request/failure counters for monitoring.
func (b *Breaker) Counts() gobreaker.Counts {
	return b.cb.Counts()
}
