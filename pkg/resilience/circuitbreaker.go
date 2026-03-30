// Package resilience provides enterprise resilience patterns including circuit
// breakers, retry with exponential backoff, and bulkhead concurrency limiting
// for KMS service-to-service communication.
package resilience

import (
	"fmt"
	"log"
	"sync"
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

// WithMaxRequests sets the number of requests allowed in the half-open state.
func WithMaxRequests(n uint32) Option {
	return func(s *BreakerSettings) {
		s.MaxRequests = n
	}
}

// WithInterval sets the cyclic period of the closed state for clearing internal counts.
func WithInterval(d time.Duration) Option {
	return func(s *BreakerSettings) {
		s.Interval = d
	}
}

// WithTimeout sets the duration the breaker stays in the open state before transitioning
// to half-open.
func WithTimeout(d time.Duration) Option {
	return func(s *BreakerSettings) {
		s.Timeout = d
	}
}

// WithReadyToTrip sets a custom function that determines whether the breaker
// should trip based on the current failure counts.
func WithReadyToTrip(fn func(counts gobreaker.Counts) bool) Option {
	return func(s *BreakerSettings) {
		s.ReadyToTrip = fn
	}
}

// WithOnStateChange sets a callback invoked whenever the breaker transitions states.
func WithOnStateChange(fn func(name string, from, to gobreaker.State)) Option {
	return func(s *BreakerSettings) {
		s.OnStateChange = fn
	}
}

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

// BreakerRegistry is a thread-safe collection of named circuit breakers for
// service-to-service calls. It allows centralized management and monitoring of
// all breakers within a KMS node.
type BreakerRegistry struct {
	mu       sync.RWMutex
	breakers map[string]*Breaker
	defaults []Option
}

// NewBreakerRegistry creates an empty registry. Any opts provided are applied
// as defaults when creating breakers via GetOrCreate.
func NewBreakerRegistry(defaults ...Option) *BreakerRegistry {
	return &BreakerRegistry{
		breakers: make(map[string]*Breaker),
		defaults: defaults,
	}
}

// Get returns the breaker with the given name, or nil if it does not exist.
func (r *BreakerRegistry) Get(name string) *Breaker {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.breakers[name]
}

// GetOrCreate returns the existing breaker for name, or creates one with the
// registry defaults merged with any additional opts. Additional opts take
// precedence over registry defaults.
func (r *BreakerRegistry) GetOrCreate(name string, opts ...Option) *Breaker {
	r.mu.RLock()
	b, ok := r.breakers[name]
	r.mu.RUnlock()
	if ok {
		return b
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Double-check after acquiring write lock.
	if b, ok = r.breakers[name]; ok {
		return b
	}

	merged := make([]Option, 0, len(r.defaults)+len(opts))
	merged = append(merged, r.defaults...)
	merged = append(merged, opts...)

	b = NewBreaker(name, merged...)
	r.breakers[name] = b
	return b
}

// Remove deletes a breaker from the registry.
func (r *BreakerRegistry) Remove(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.breakers, name)
}

// All returns a snapshot of all registered breakers keyed by name.
func (r *BreakerRegistry) All() map[string]*Breaker {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]*Breaker, len(r.breakers))
	for k, v := range r.breakers {
		out[k] = v
	}
	return out
}

// String returns a human-readable summary of all breakers and their states.
func (r *BreakerRegistry) String() string {
	all := r.All()
	if len(all) == 0 {
		return "BreakerRegistry(empty)"
	}
	s := fmt.Sprintf("BreakerRegistry(%d breakers):\n", len(all))
	for name, b := range all {
		c := b.Counts()
		s += fmt.Sprintf("  %s: state=%s requests=%d failures=%d\n",
			name, b.State(), c.Requests, c.TotalFailures)
	}
	return s
}
