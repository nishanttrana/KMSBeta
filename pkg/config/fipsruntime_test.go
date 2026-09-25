package config

import (
	"context"
	"sync"
	"testing"
	"time"
)

type fakeFIPSStore struct {
	mu    sync.Mutex
	modes []string // successive Desired results; last one repeats
}

func (f *fakeFIPSStore) Desired(context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.modes[0]
	if len(f.modes) > 1 {
		f.modes = f.modes[1:]
	}
	return m, nil
}

func (f *fakeFIPSStore) ReportObserved(context.Context, string, string, string, string, bool, time.Time) error {
	return nil
}

func runWatcher(t *testing.T, running string, modes ...string) (bool, []string) {
	t.Helper()
	var (
		stopped bool
		delayed []string
	)
	quit := make(chan struct{})
	finished := make(chan struct{})
	w := fipsWatcher{
		store: &fakeFIPSStore{modes: modes}, service: "kms-test", running: running, interval: 0,
		delay: func(s string) time.Duration { delayed = append(delayed, s); return 0 },
		sleep: func(time.Duration) { time.Sleep(time.Millisecond) },
		stop:  func() { stopped = true },
		quit:  quit,
	}
	go func() { w.run(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(100 * time.Millisecond):
		close(quit)
		<-finished
	}
	return stopped, delayed
}

func TestWatcherRestartsOnModeChange(t *testing.T) {
	if stopped, delayed := runWatcher(t, "on", "on", "only", "only"); !stopped || len(delayed) != 1 {
		t.Fatalf("a changed platform mode must trigger one tiered restart: stopped=%v delayed=%v", stopped, delayed)
	}
}

func TestWatcherIgnoresUnchangedOrInvalidMode(t *testing.T) {
	if stopped, _ := runWatcher(t, "on", "on", "", "bogus", "on"); stopped {
		t.Fatal("unchanged, unset or invalid modes must not restart the service")
	}
}

func TestWatcherReevaluatesWhenModeFlipsBack(t *testing.T) {
	// only -> (after the tier delay) back to on: no restart.
	if stopped, _ := runWatcher(t, "on", "only", "on"); stopped {
		t.Fatal("a change reverted during the restart delay must not restart the service")
	}
}
