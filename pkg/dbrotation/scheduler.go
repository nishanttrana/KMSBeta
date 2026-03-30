package dbrotation

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// Scheduler runs periodic checks for due credential rotations.
type Scheduler struct {
	rotator       *Rotator
	store         *Store
	checkInterval time.Duration
	maxConcurrent int
	logf          func(string, ...interface{})

	mu      sync.Mutex
	running bool
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// SchedulerOption configures a Scheduler.
type SchedulerOption func(*Scheduler)

// WithSchedulerInterval sets how often the scheduler checks for due rotations.
func WithSchedulerInterval(d time.Duration) SchedulerOption {
	return func(s *Scheduler) {
		if d > 0 {
			s.checkInterval = d
		}
	}
}

// WithSchedulerConcurrency limits how many rotations can run in parallel.
func WithSchedulerConcurrency(n int) SchedulerOption {
	return func(s *Scheduler) {
		if n > 0 {
			s.maxConcurrent = n
		}
	}
}

// WithSchedulerLogger sets a log function for the scheduler.
func WithSchedulerLogger(logf func(string, ...interface{})) SchedulerOption {
	return func(s *Scheduler) {
		if logf != nil {
			s.logf = logf
		}
	}
}

// NewScheduler creates a Scheduler that periodically rotates due database credentials.
func NewScheduler(rotator *Rotator, store *Store, opts ...SchedulerOption) *Scheduler {
	s := &Scheduler{
		rotator:       rotator,
		store:         store,
		checkInterval: 1 * time.Minute,
		maxConcurrent: 5,
		logf:          log.Printf,
		stopCh:        make(chan struct{}),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Start begins the scheduler's background loop.
func (s *Scheduler) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("dbrotation/scheduler: already running")
	}
	s.running = true
	s.stopCh = make(chan struct{})
	s.wg.Add(1)
	go s.loop()

	s.logf("[dbrotation/scheduler] started with interval=%s concurrency=%d", s.checkInterval, s.maxConcurrent)
	return nil
}

// Stop gracefully shuts down the scheduler.
func (s *Scheduler) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	close(s.stopCh)
	s.mu.Unlock()

	s.wg.Wait()
	s.logf("[dbrotation/scheduler] stopped")
}

// loop is the main scheduler goroutine.
func (s *Scheduler) loop() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.checkInterval)
	defer ticker.Stop()

	// Run an initial check immediately
	s.checkAndRotate()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.checkAndRotate()
		}
	}
}

// checkAndRotate finds due targets and rotates them concurrently.
func (s *Scheduler) checkAndRotate() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	now := time.Now().UTC()
	targets, err := s.store.ListDueTargets(ctx, now)
	if err != nil {
		s.logf("[dbrotation/scheduler] error listing due targets: %v", err)
		return
	}

	if len(targets) == 0 {
		return
	}

	s.logf("[dbrotation/scheduler] found %d targets due for rotation", len(targets))

	sem := make(chan struct{}, s.maxConcurrent)
	var wg sync.WaitGroup

	for _, target := range targets {
		// Skip non-active targets
		if target.Status == StatusDisabled || target.Status == StatusRotating {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(t *RotationTarget) {
			defer wg.Done()
			defer func() { <-sem }()

			rotCtx, rotCancel := context.WithTimeout(ctx, 2*time.Minute)
			defer rotCancel()

			event, err := s.rotator.RotateTarget(rotCtx, t.ID)
			if err != nil {
				s.logf("[dbrotation/scheduler] rotation failed for target %s (%s@%s): %v",
					t.ID, t.Username, t.DBType, err)
				return
			}

			if event.Success {
				s.logf("[dbrotation/scheduler] rotated target %s (%s@%s) in %s",
					t.ID, t.Username, t.DBType, event.Duration)
			} else {
				s.logf("[dbrotation/scheduler] rotation failed for target %s (%s@%s): %s",
					t.ID, t.Username, t.DBType, event.Error)
			}
		}(target)
	}

	wg.Wait()
}

// RunOnce performs a single check-and-rotate cycle. Useful for testing.
func (s *Scheduler) RunOnce() {
	s.checkAndRotate()
}
