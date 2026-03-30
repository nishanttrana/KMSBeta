package rotation

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

// RotationPolicy defines an automated key rotation schedule.
type RotationPolicy struct {
	ID           string
	TenantID     string
	KeyPattern   string
	Interval     time.Duration
	Algorithm    string
	AutoApprove  bool
	NotifyEmails []string
	MaxVersions  int
	Enabled      bool
	LastRun      time.Time
	NextRun      time.Time
}

// RotationResult captures the outcome of a single key rotation.
type RotationResult struct {
	PolicyID   string
	KeyID      string
	OldVersion string
	NewVersion string
	Success    bool
	Error      string
	Duration   time.Duration
	Timestamp  time.Time
}

// RotationExecutor performs the actual key rotation against the key store.
type RotationExecutor interface {
	RotateKey(ctx context.Context, tenantID, keyID, algorithm string) (newVersion string, err error)
}

// Option configures a Scheduler.
type Option func(*Scheduler)

// WithCheckInterval sets how often the scheduler scans for due policies.
func WithCheckInterval(d time.Duration) Option {
	return func(s *Scheduler) {
		if d > 0 {
			s.checkInterval = d
		}
	}
}

// WithMaxConcurrent limits how many rotations can run in parallel.
func WithMaxConcurrent(n int) Option {
	return func(s *Scheduler) {
		if n > 0 {
			s.maxConcurrent = n
		}
	}
}

// WithNotifier registers a callback invoked after each rotation completes.
func WithNotifier(fn func(RotationResult)) Option {
	return func(s *Scheduler) {
		if fn != nil {
			s.notifier = fn
		}
	}
}

// Scheduler runs automated key rotations based on configured policies.
type Scheduler struct {
	mu            sync.RWMutex
	policies      map[string]RotationPolicy        // policyID -> policy
	history       map[string][]RotationResult       // policyID -> results (most recent first)
	executor      RotationExecutor
	notifier      func(RotationResult)
	checkInterval time.Duration
	maxConcurrent int
	done          chan struct{}
	stopped       chan struct{}
}

// NewScheduler creates a rotation scheduler. Call Start to begin processing.
func NewScheduler(executor RotationExecutor, opts ...Option) *Scheduler {
	s := &Scheduler{
		policies:      make(map[string]RotationPolicy),
		history:       make(map[string][]RotationResult),
		executor:      executor,
		checkInterval: 1 * time.Minute,
		maxConcurrent: 5,
		done:          make(chan struct{}),
		stopped:       make(chan struct{}),
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Start begins the background scheduling loop. It blocks until ctx is
// cancelled or Stop is called.
func (s *Scheduler) Start(ctx context.Context) {
	ticker := time.NewTicker(s.checkInterval)
	defer ticker.Stop()
	defer close(s.stopped)

	for {
		select {
		case <-ticker.C:
			s.tick(ctx)
		case <-ctx.Done():
			return
		case <-s.done:
			return
		}
	}
}

// Stop signals the scheduler to shut down gracefully and waits for it to finish.
func (s *Scheduler) Stop() {
	select {
	case <-s.done:
		// already closed
	default:
		close(s.done)
	}
	<-s.stopped
}

// AddPolicy registers a rotation policy. If NextRun is zero it is computed
// from the current time plus the policy interval with jitter applied.
func (s *Scheduler) AddPolicy(_ context.Context, policy RotationPolicy) error {
	if policy.ID == "" {
		return fmt.Errorf("rotation: policy ID is required")
	}
	if policy.TenantID == "" {
		return fmt.Errorf("rotation: tenant ID is required")
	}
	if policy.Interval <= 0 {
		return fmt.Errorf("rotation: interval must be positive")
	}

	if policy.NextRun.IsZero() {
		policy.NextRun = time.Now().Add(applyJitter(policy.Interval))
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies[policy.ID] = policy
	return nil
}

// RemovePolicy deletes a policy by ID.
func (s *Scheduler) RemovePolicy(_ context.Context, policyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.policies[policyID]; !ok {
		return fmt.Errorf("rotation: policy %q not found", policyID)
	}
	delete(s.policies, policyID)
	return nil
}

// ListPolicies returns all policies for a tenant.
func (s *Scheduler) ListPolicies(_ context.Context, tenantID string) ([]RotationPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []RotationPolicy
	for _, p := range s.policies {
		if p.TenantID == tenantID {
			out = append(out, p)
		}
	}
	return out, nil
}

// GetHistory returns the most recent rotation results for a policy,
// limited to the specified count.
func (s *Scheduler) GetHistory(_ context.Context, policyID string, limit int) ([]RotationResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	h := s.history[policyID]
	if limit <= 0 || limit > len(h) {
		limit = len(h)
	}
	out := make([]RotationResult, limit)
	copy(out, h[:limit])
	return out, nil
}

// tick evaluates all policies and rotates keys that are due.
func (s *Scheduler) tick(ctx context.Context) {
	now := time.Now()

	s.mu.RLock()
	var due []RotationPolicy
	for _, p := range s.policies {
		if p.Enabled && !p.NextRun.After(now) {
			due = append(due, p)
		}
	}
	s.mu.RUnlock()

	if len(due) == 0 {
		return
	}

	sem := make(chan struct{}, s.maxConcurrent)
	var wg sync.WaitGroup

	for _, p := range due {
		sem <- struct{}{}
		wg.Add(1)
		go func(policy RotationPolicy) {
			defer wg.Done()
			defer func() { <-sem }()
			s.executeRotation(ctx, policy)
		}(p)
	}

	wg.Wait()
}

func (s *Scheduler) executeRotation(ctx context.Context, policy RotationPolicy) {
	start := time.Now()
	newVer, err := s.executor.RotateKey(ctx, policy.TenantID, policy.KeyPattern, policy.Algorithm)

	result := RotationResult{
		PolicyID:   policy.ID,
		KeyID:      policy.KeyPattern,
		NewVersion: newVer,
		Success:    err == nil,
		Duration:   time.Since(start),
		Timestamp:  start,
	}
	if err != nil {
		result.Error = err.Error()
	}

	// Update policy timing and persist result.
	s.mu.Lock()
	if p, ok := s.policies[policy.ID]; ok {
		p.LastRun = start
		p.NextRun = time.Now().Add(applyJitter(p.Interval))
		s.policies[policy.ID] = p
	}
	s.history[policy.ID] = append([]RotationResult{result}, s.history[policy.ID]...)
	// Cap history at 1000 entries per policy.
	if len(s.history[policy.ID]) > 1000 {
		s.history[policy.ID] = s.history[policy.ID][:1000]
	}
	s.mu.Unlock()

	if s.notifier != nil {
		s.notifier(result)
	}
}

// applyJitter returns d with +/-10% random variation to prevent thundering herd.
func applyJitter(d time.Duration) time.Duration {
	jitter := float64(d) * (0.9 + cryptoFloat64()*0.2)
	return time.Duration(jitter)
}

// cryptoFloat64 returns a cryptographically secure float64 in [0, 1).
func cryptoFloat64() float64 {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return float64(binary.LittleEndian.Uint64(b[:])>>11) / (1 << 53)
}
