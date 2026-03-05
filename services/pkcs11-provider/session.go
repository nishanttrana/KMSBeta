package main

import (
	"sync"
	"sync/atomic"
)

// SessionState tracks per-session data for PKCS#11 operations.
type SessionState struct {
	Handle    uint64
	SlotID    uint64
	LoggedIn  bool
	FindActive bool
	FindKeys  []KeyObject
	FindIndex int

	// Active crypto operation state
	EncryptKeyID string
	DecryptKeyID string
	SignKeyID    string
	VerifyKeyID  string
}

// KeyObject represents a KMS key exposed as a PKCS#11 object.
type KeyObject struct {
	ObjectHandle uint64
	KeyID        string
	Label        string
	Algorithm    string
	KeySize      int
	Exportable   bool
	Version      int
}

// SessionManager manages open PKCS#11 sessions.
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[uint64]*SessionState
	counter  atomic.Uint64
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[uint64]*SessionState),
	}
}

func (sm *SessionManager) Open(slotID uint64) uint64 {
	handle := sm.counter.Add(1)
	sm.mu.Lock()
	sm.sessions[handle] = &SessionState{
		Handle: handle,
		SlotID: slotID,
	}
	sm.mu.Unlock()
	return handle
}

func (sm *SessionManager) Get(handle uint64) (*SessionState, bool) {
	sm.mu.RLock()
	s, ok := sm.sessions[handle]
	sm.mu.RUnlock()
	return s, ok
}

func (sm *SessionManager) Close(handle uint64) {
	sm.mu.Lock()
	delete(sm.sessions, handle)
	sm.mu.Unlock()
}

func (sm *SessionManager) CloseAll() {
	sm.mu.Lock()
	sm.sessions = make(map[uint64]*SessionState)
	sm.mu.Unlock()
}
