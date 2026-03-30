package breakglass

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Status constants for an emergency access request lifecycle.
const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusDenied   = "denied"
	StatusExpired  = "expired"
	StatusUsed     = "used"
)

// Sentinel errors returned by Manager methods.
var (
	ErrRequestNotFound  = errors.New("breakglass: request not found")
	ErrAlreadyApproved  = errors.New("breakglass: approver has already approved this request")
	ErrQuorumNotMet     = errors.New("breakglass: quorum not met")
	ErrRequestExpired   = errors.New("breakglass: request has expired")
	ErrRequestNotUsable = errors.New("breakglass: request is not in an approved/pending state")
	ErrUnauthorized     = errors.New("breakglass: requestor does not match original request")
	ErrSelfApproval     = errors.New("breakglass: requestor cannot approve their own request")
	ErrBadChallenge     = errors.New("breakglass: invalid challenge response")
)

// EmergencyRequest represents a break-glass access request that requires
// multi-party quorum approval before granting access to sensitive key material.
type EmergencyRequest struct {
	ID                string
	TenantID          string
	RequestorID       string
	Reason            string
	TargetKeyID       string
	RequiredApprovals int
	Approvals         []Approval
	Status            string
	ExpiresAt         time.Time
	CreatedAt         time.Time
}

// Approval records a single approver's consent.
type Approval struct {
	ApproverID    string
	ApproverEmail string
	ApprovedAt    time.Time
	Challenge     string
}

// AuditEvent captures the full context of a break-glass action for compliance.
type AuditEvent struct {
	EventType   string // "request_created", "approval_added", "quorum_met", "access_granted", "request_expired"
	RequestID   string
	TenantID    string
	ActorID     string
	TargetKeyID string
	Status      string
	Approvals   int
	Required    int
	Reason      string
	OccurredAt  time.Time
}

// Store abstracts persistence for break-glass requests.
type Store interface {
	CreateRequest(ctx context.Context, req *EmergencyRequest) error
	GetRequest(ctx context.Context, requestID string) (*EmergencyRequest, error)
	AddApproval(ctx context.Context, requestID string, approval Approval) error
	UpdateStatus(ctx context.Context, requestID string, status string) error
	ListPending(ctx context.Context, tenantID string) ([]*EmergencyRequest, error)
}

// KeyRetriever is called by ExecuteBreakGlass to fetch the actual key material
// after quorum has been verified. This keeps key-fetch logic decoupled from
// the break-glass workflow.
type KeyRetriever func(ctx context.Context, tenantID, keyID string) ([]byte, error)

// Option configures a Manager.
type Option func(*Manager)

// Manager orchestrates the break-glass emergency access workflow.
type Manager struct {
	mu           sync.Mutex
	store        Store
	quorum       int
	expiry       time.Duration
	auditHook    func(AuditEvent)
	keyRetriever KeyRetriever
}

// NewManager creates a Manager with sensible defaults.
func NewManager(store Store, opts ...Option) *Manager {
	m := &Manager{
		store:  store,
		quorum: 2,
		expiry: 1 * time.Hour,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// WithQuorum sets the number of approvals required before access is granted.
func WithQuorum(n int) Option {
	return func(m *Manager) {
		if n > 0 {
			m.quorum = n
		}
	}
}

// WithExpiry sets how long a request remains valid before it expires.
func WithExpiry(d time.Duration) Option {
	return func(m *Manager) {
		if d > 0 {
			m.expiry = d
		}
	}
}

// WithAuditHook registers a callback invoked on every break-glass event.
func WithAuditHook(fn func(AuditEvent)) Option {
	return func(m *Manager) {
		m.auditHook = fn
	}
}

// WithKeyRetriever sets the function used to fetch key material during ExecuteBreakGlass.
func WithKeyRetriever(fn KeyRetriever) Option {
	return func(m *Manager) {
		m.keyRetriever = fn
	}
}

// RequestEmergencyAccess creates a new break-glass request. The request starts
// in "pending" status and must accumulate the required number of approvals
// before the key material can be retrieved.
func (m *Manager) RequestEmergencyAccess(ctx context.Context, req EmergencyRequest) (*EmergencyRequest, error) {
	if req.TenantID == "" || req.RequestorID == "" || req.TargetKeyID == "" {
		return nil, errors.New("breakglass: tenant_id, requestor_id, and target_key_id are required")
	}
	if req.Reason == "" {
		return nil, errors.New("breakglass: reason is required for audit compliance")
	}

	if req.ID == "" {
		req.ID = generateID("bg")
	}
	req.Status = StatusPending
	req.RequiredApprovals = m.quorum
	req.Approvals = nil
	req.CreatedAt = time.Now().UTC()
	req.ExpiresAt = req.CreatedAt.Add(m.expiry)

	if err := m.store.CreateRequest(ctx, &req); err != nil {
		return nil, fmt.Errorf("breakglass: create request: %w", err)
	}

	m.publishAudit(AuditEvent{
		EventType:   "request_created",
		RequestID:   req.ID,
		TenantID:    req.TenantID,
		ActorID:     req.RequestorID,
		TargetKeyID: req.TargetKeyID,
		Status:      req.Status,
		Required:    req.RequiredApprovals,
		Reason:      req.Reason,
		OccurredAt:  req.CreatedAt,
	})

	return &req, nil
}

// ApproveRequest records an approval and checks whether quorum is now met.
func (m *Manager) ApproveRequest(ctx context.Context, requestID, approverID, challenge string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	req, err := m.store.GetRequest(ctx, requestID)
	if err != nil {
		return ErrRequestNotFound
	}

	if time.Now().UTC().After(req.ExpiresAt) {
		_ = m.store.UpdateStatus(ctx, requestID, StatusExpired)
		return ErrRequestExpired
	}

	if req.Status != StatusPending && req.Status != StatusApproved {
		return ErrRequestNotUsable
	}

	// Prevent self-approval.
	if approverID == req.RequestorID {
		return ErrSelfApproval
	}

	// Prevent duplicate approvals from the same approver.
	for _, a := range req.Approvals {
		if a.ApproverID == approverID {
			return ErrAlreadyApproved
		}
	}

	if challenge == "" {
		return ErrBadChallenge
	}

	approval := Approval{
		ApproverID: approverID,
		ApprovedAt: time.Now().UTC(),
		Challenge:  challenge,
	}

	if err := m.store.AddApproval(ctx, requestID, approval); err != nil {
		return fmt.Errorf("breakglass: add approval: %w", err)
	}

	req.Approvals = append(req.Approvals, approval)

	m.publishAudit(AuditEvent{
		EventType:   "approval_added",
		RequestID:   req.ID,
		TenantID:    req.TenantID,
		ActorID:     approverID,
		TargetKeyID: req.TargetKeyID,
		Status:      req.Status,
		Approvals:   len(req.Approvals),
		Required:    req.RequiredApprovals,
		OccurredAt:  approval.ApprovedAt,
	})

	if m.IsQuorumMet(req) {
		if err := m.store.UpdateStatus(ctx, requestID, StatusApproved); err != nil {
			return fmt.Errorf("breakglass: update status: %w", err)
		}
		m.publishAudit(AuditEvent{
			EventType:   "quorum_met",
			RequestID:   req.ID,
			TenantID:    req.TenantID,
			ActorID:     approverID,
			TargetKeyID: req.TargetKeyID,
			Status:      StatusApproved,
			Approvals:   len(req.Approvals),
			Required:    req.RequiredApprovals,
			OccurredAt:  time.Now().UTC(),
		})
	}

	return nil
}

// ExecuteBreakGlass retrieves the target key material if quorum is met and
// the request has not expired. It marks the request as "used" afterwards.
func (m *Manager) ExecuteBreakGlass(ctx context.Context, requestID, requestorID string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	req, err := m.store.GetRequest(ctx, requestID)
	if err != nil {
		return nil, ErrRequestNotFound
	}

	if time.Now().UTC().After(req.ExpiresAt) {
		_ = m.store.UpdateStatus(ctx, requestID, StatusExpired)
		return nil, ErrRequestExpired
	}

	if requestorID != req.RequestorID {
		return nil, ErrUnauthorized
	}

	if !m.IsQuorumMet(req) {
		return nil, ErrQuorumNotMet
	}

	if req.Status != StatusApproved && req.Status != StatusPending {
		return nil, ErrRequestNotUsable
	}

	if m.keyRetriever == nil {
		return nil, errors.New("breakglass: no key retriever configured")
	}

	keyMaterial, err := m.keyRetriever(ctx, req.TenantID, req.TargetKeyID)
	if err != nil {
		return nil, fmt.Errorf("breakglass: retrieve key: %w", err)
	}

	if err := m.store.UpdateStatus(ctx, requestID, StatusUsed); err != nil {
		return nil, fmt.Errorf("breakglass: mark used: %w", err)
	}

	m.publishAudit(AuditEvent{
		EventType:   "access_granted",
		RequestID:   req.ID,
		TenantID:    req.TenantID,
		ActorID:     requestorID,
		TargetKeyID: req.TargetKeyID,
		Status:      StatusUsed,
		Approvals:   len(req.Approvals),
		Required:    req.RequiredApprovals,
		Reason:      req.Reason,
		OccurredAt:  time.Now().UTC(),
	})

	return keyMaterial, nil
}

// IsQuorumMet returns true when the request has accumulated enough approvals.
func (m *Manager) IsQuorumMet(req *EmergencyRequest) bool {
	return len(req.Approvals) >= req.RequiredApprovals
}

// publishAudit sends an event to the configured audit hook, if any.
func (m *Manager) publishAudit(evt AuditEvent) {
	if m.auditHook != nil {
		m.auditHook(evt)
	}
}

// generateID creates a prefixed random identifier.
func generateID(prefix string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return prefix + "-" + hex.EncodeToString(b)
}
