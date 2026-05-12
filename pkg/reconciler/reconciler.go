// Package reconciler provides a generic controller-loop primitive used by
// the tenant-lifecycle, key-lifecycle, and PQC migration controllers.
// A reconciler periodically compares "desired" declarative state against
// "actual" live state and emits a list of actions to converge the two.
//
// The reconciler is intentionally small: it owns the loop, backoff, and
// concurrency guarantees. Domain logic (what "desired" means, what the
// actions are) lives in the caller via the Reconciler interface.
package reconciler

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Reconciler is implemented by domain controllers. Reconcile is invoked on
// every tick; it should be idempotent — the same desired vs. actual state
// must produce the same actions every time.
type Reconciler interface {
	// Name identifies the reconciler in logs and metrics.
	Name() string
	// Reconcile runs one pass. Implementations should return a non-nil error
	// only for transient problems they want retried on backoff; expected
	// "nothing to do" outcomes should return nil.
	Reconcile(ctx context.Context) error
}

// Config tunes the reconciliation loop. Defaults are conservative —
// 30s interval, 5s minimum backoff, 10x cap — to avoid hammering downstream
// services during transient outages.
type Config struct {
	Interval     time.Duration
	MaxBackoff   time.Duration
	InitialDelay time.Duration
}

// DefaultConfig returns a production-tuned config (30s interval, 5m max
// backoff, 5s initial delay so services have time to come up).
func DefaultConfig() Config {
	return Config{
		Interval:     30 * time.Second,
		MaxBackoff:   5 * time.Minute,
		InitialDelay: 5 * time.Second,
	}
}

// Runner drives one or more reconcilers concurrently. Each reconciler runs
// in its own goroutine with independent backoff state, so a stuck
// reconciler cannot stall the others.
type Runner struct {
	cfg       Config
	logger    Logger
	reconcs   []Reconciler
	mu        sync.Mutex
	lastError map[string]error
	lastRunAt map[string]time.Time
}

// Logger is the minimal logging interface the runner requires. Any *log.Logger
// satisfies it via the Printf method.
type Logger interface {
	Printf(format string, args ...any)
}

// NewRunner constructs a runner. If cfg is the zero value, defaults are
// applied. Logger may be nil (logs are suppressed).
func NewRunner(cfg Config, logger Logger, reconcs ...Reconciler) *Runner {
	if cfg.Interval <= 0 {
		cfg = DefaultConfig()
	}
	return &Runner{
		cfg:       cfg,
		logger:    logger,
		reconcs:   reconcs,
		lastError: make(map[string]error),
		lastRunAt: make(map[string]time.Time),
	}
}

// Run blocks until ctx is cancelled. Each registered reconciler runs in its
// own goroutine; failures are recorded and reported via Status() but never
// crash the runner.
func (r *Runner) Run(ctx context.Context) {
	if len(r.reconcs) == 0 {
		return
	}
	if r.cfg.InitialDelay > 0 {
		select {
		case <-ctx.Done():
			return
		case <-time.After(r.cfg.InitialDelay):
		}
	}
	var wg sync.WaitGroup
	for _, rec := range r.reconcs {
		wg.Add(1)
		go func(rc Reconciler) {
			defer wg.Done()
			r.driveOne(ctx, rc)
		}(rec)
	}
	wg.Wait()
}

func (r *Runner) driveOne(ctx context.Context, rc Reconciler) {
	backoff := r.cfg.Interval
	t := time.NewTimer(backoff)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		start := time.Now()
		err := rc.Reconcile(ctx)
		r.recordResult(rc.Name(), err, start)
		if err != nil {
			r.logf("reconciler %s failed: %v", rc.Name(), err)
			backoff = nextBackoff(backoff, r.cfg.MaxBackoff)
		} else {
			backoff = r.cfg.Interval
		}
		t.Reset(backoff)
	}
}

func (r *Runner) recordResult(name string, err error, start time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastError[name] = err
	r.lastRunAt[name] = start
}

// Status returns a snapshot of each reconciler's most recent outcome — used
// by the watchdog and the dashboard to surface which controllers are
// healthy.
func (r *Runner) Status() []Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Status, 0, len(r.reconcs))
	for _, rec := range r.reconcs {
		name := rec.Name()
		s := Status{
			Name:      name,
			LastRunAt: r.lastRunAt[name],
		}
		if e := r.lastError[name]; e != nil {
			s.LastError = e.Error()
		}
		out = append(out, s)
	}
	return out
}

func (r *Runner) logf(format string, args ...any) {
	if r.logger == nil {
		return
	}
	r.logger.Printf(format, args...)
}

// Status is a single reconciler's latest outcome.
type Status struct {
	Name      string    `json:"name"`
	LastRunAt time.Time `json:"last_run_at"`
	LastError string    `json:"last_error,omitempty"`
}

func nextBackoff(current, cap time.Duration) time.Duration {
	next := current * 2
	if next > cap {
		next = cap
	}
	if next < time.Second {
		next = time.Second
	}
	return next
}

// ErrTransient marks a transient failure suitable for retry. Reconcilers
// can wrap errors with this sentinel to make their intent explicit.
var ErrTransient = errors.New("transient reconciler failure")
