package main

import (
	"context"
	"errors"
	"sync"
)

// HBSState is one stateful hash-based signing key's tracked counter.
// XMSS and LMS keys are catastrophic if a signature index is ever reused;
// the tracker is the single source of truth for which index to use next,
// and is the only path through which an HBS sign can run.
type HBSState struct {
	TenantID    string
	KeyID       string
	Algorithm   string // "XMSS-SHA2_10_256", "LMS-SHA256-M32-H10", etc.
	NextIndex   uint64
	MaxIndex    uint64
	Exhausted   bool
}

// HBSStore is the persistence backend. The interface is narrow so the
// in-memory variant used by tests and the database-backed production
// variant share the same locking guarantees.
type HBSStore interface {
	Get(ctx context.Context, tenantID, keyID string) (HBSState, error)
	ReserveIndex(ctx context.Context, tenantID, keyID string) (uint64, error)
	MarkExhausted(ctx context.Context, tenantID, keyID string) error
}

// HBSTracker is the API surface used by signing call sites. ReserveIndex
// atomically advances the counter and returns the index to sign with;
// the actual XMSS/LMS sign happens in the caller because index reuse —
// even by a millisecond — must be made impossible by the tracker, not by
// the signer.
type HBSTracker struct {
	store HBSStore
	mu    sync.Mutex // protects nothing — present so future in-process caches can hook without churn
}

// NewHBSTracker constructs a tracker around the supplied store.
func NewHBSTracker(store HBSStore) *HBSTracker {
	return &HBSTracker{store: store}
}

// ReserveIndex returns the next safe-to-use one-time index. The caller
// MUST use the returned index exactly once; if the sign fails the index
// is still consumed (HBS does not permit "rollback" — the safe move is
// always to advance).
func (t *HBSTracker) ReserveIndex(ctx context.Context, tenantID, keyID string) (uint64, error) {
	if t == nil || t.store == nil {
		return 0, errors.New("HBS tracker not configured")
	}
	state, err := t.store.Get(ctx, tenantID, keyID)
	if err != nil {
		return 0, err
	}
	if state.Exhausted || (state.MaxIndex > 0 && state.NextIndex >= state.MaxIndex) {
		_ = t.store.MarkExhausted(ctx, tenantID, keyID)
		return 0, ErrHBSKeyExhausted
	}
	return t.store.ReserveIndex(ctx, tenantID, keyID)
}

// ErrHBSKeyExhausted signals that the one-time key tree has no remaining
// indices and the key must be rotated. The reconciler watches for this
// audit event and auto-rotates.
var ErrHBSKeyExhausted = errors.New("HBS key exhausted; rotation required")

// MemoryHBSStore is the test-friendly backend. Production deployments
// should use store_hbs_sql.go (filed under TODO until the schema lands).
type MemoryHBSStore struct {
	mu     sync.Mutex
	states map[string]*HBSState
}

func NewMemoryHBSStore() *MemoryHBSStore {
	return &MemoryHBSStore{states: make(map[string]*HBSState)}
}

func (s *MemoryHBSStore) Get(_ context.Context, tenantID, keyID string) (HBSState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.states[tenantID+"|"+keyID]
	if !ok {
		return HBSState{}, errors.New("HBS state not found")
	}
	return *st, nil
}

func (s *MemoryHBSStore) ReserveIndex(_ context.Context, tenantID, keyID string) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := tenantID + "|" + keyID
	st, ok := s.states[k]
	if !ok {
		return 0, errors.New("HBS state not found")
	}
	if st.Exhausted {
		return 0, ErrHBSKeyExhausted
	}
	if st.MaxIndex > 0 && st.NextIndex >= st.MaxIndex {
		st.Exhausted = true
		return 0, ErrHBSKeyExhausted
	}
	idx := st.NextIndex
	st.NextIndex++
	return idx, nil
}

func (s *MemoryHBSStore) MarkExhausted(_ context.Context, tenantID, keyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st, ok := s.states[tenantID+"|"+keyID]; ok {
		st.Exhausted = true
	}
	return nil
}

// Register seeds the store with a new HBS state. Used at key-creation
// time by the keycore handler.
func (s *MemoryHBSStore) Register(state HBSState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := state
	s.states[state.TenantID+"|"+state.KeyID] = &cp
}
