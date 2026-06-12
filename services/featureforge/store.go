package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

// Store persists intents, their guardrail event trail, and assigns IDs.
type Store interface {
	NextID() string
	SaveIntent(ctx context.Context, in *Intent) error
	GetIntent(ctx context.Context, id string) (*Intent, bool)
	ListIntents(ctx context.Context, tenantID string) []*Intent
	AppendEvent(ctx context.Context, ev AuditEvent) error
	Events(ctx context.Context, intentID string) []AuditEvent
	AddApproval(ctx context.Context, ap Approval) error
	Approvals(ctx context.Context, intentID string) []Approval
}

// --- In-memory store (tests, and a fallback) -----------------------------

type memStore struct {
	mu        sync.Mutex
	seq       int
	intents   map[string]*Intent
	events    map[string][]AuditEvent
	approvals map[string][]Approval
}

// NewMemStore returns an in-memory Store.
func NewMemStore() Store {
	return &memStore{intents: map[string]*Intent{}, events: map[string][]AuditEvent{}, approvals: map[string][]Approval{}}
}

func (m *memStore) NextID() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq++
	return fmt.Sprintf("ff-%d", m.seq)
}

func (m *memStore) SaveIntent(_ context.Context, in *Intent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *in
	m.intents[in.ID] = &cp
	return nil
}

func (m *memStore) GetIntent(_ context.Context, id string) (*Intent, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	in, ok := m.intents[id]
	if !ok {
		return nil, false
	}
	cp := *in
	return &cp, true
}

func (m *memStore) ListIntents(_ context.Context, tenantID string) []*Intent {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Intent
	for _, in := range m.intents {
		if in.TenantID == tenantID {
			cp := *in
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

func (m *memStore) AppendEvent(_ context.Context, ev AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events[ev.IntentID] = append(m.events[ev.IntentID], ev)
	return nil
}

func (m *memStore) Events(_ context.Context, intentID string) []AuditEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]AuditEvent, len(m.events[intentID]))
	copy(out, m.events[intentID])
	return out
}

func (m *memStore) AddApproval(_ context.Context, ap Approval) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ex := range m.approvals[ap.IntentID] {
		if ex.Approver == ap.Approver {
			return fmt.Errorf("approval by %s already recorded", ap.Approver)
		}
	}
	m.approvals[ap.IntentID] = append(m.approvals[ap.IntentID], ap)
	return nil
}

func (m *memStore) Approvals(_ context.Context, intentID string) []Approval {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Approval, len(m.approvals[intentID]))
	copy(out, m.approvals[intentID])
	return out
}

// --- SQL store (production) ----------------------------------------------

type sqlStore struct {
	db *pkgdb.DB
}

// NewSQLStore returns a Store backed by the shared DB.
func NewSQLStore(db *pkgdb.DB) Store {
	return &sqlStore{db: db}
}

func (s *sqlStore) NextID() string {
	return fmt.Sprintf("ff-%d", time.Now().UTC().UnixNano())
}

func (s *sqlStore) SaveIntent(ctx context.Context, in *Intent) error {
	params, _ := json.Marshal(in.Params)
	reasons, _ := json.Marshal(in.Reasons)
	const q = `
INSERT INTO ff_intents
  (id, tenant_id, actor, raw_text, mode, stage, action, params, confidence, reasons, mcp_job_id, approval_id, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
ON CONFLICT (id) DO UPDATE SET
  mode=excluded.mode, stage=excluded.stage, action=excluded.action,
  params=excluded.params, confidence=excluded.confidence, reasons=excluded.reasons,
  mcp_job_id=excluded.mcp_job_id, approval_id=excluded.approval_id, updated_at=excluded.updated_at`
	_, err := s.db.SQL().ExecContext(ctx, q,
		in.ID, in.TenantID, in.Actor, in.RawText, string(in.Mode), string(in.Stage), in.Action,
		string(params), in.Confidence, string(reasons), in.MCPJobID, in.ApprovalID,
		in.CreatedAt, in.UpdatedAt)
	return err
}

func scanIntent(rows *sql.Rows) (*Intent, error) {
	var in Intent
	var mode, stage, params, reasons string
	if err := rows.Scan(&in.ID, &in.TenantID, &in.Actor, &in.RawText, &mode, &stage, &in.Action,
		&params, &in.Confidence, &reasons, &in.MCPJobID, &in.ApprovalID, &in.CreatedAt, &in.UpdatedAt); err != nil {
		return nil, err
	}
	in.Mode = Mode(mode)
	in.Stage = Stage(stage)
	_ = json.Unmarshal([]byte(params), &in.Params)
	_ = json.Unmarshal([]byte(reasons), &in.Reasons)
	if in.Params == nil {
		in.Params = map[string]interface{}{}
	}
	return &in, nil
}

const intentCols = `id, tenant_id, actor, raw_text, mode, stage, action, params, confidence, reasons, mcp_job_id, approval_id, created_at, updated_at`

func (s *sqlStore) GetIntent(ctx context.Context, id string) (*Intent, bool) {
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT `+intentCols+` FROM ff_intents WHERE id=$1`, id)
	if err != nil {
		return nil, false
	}
	defer rows.Close() //nolint:errcheck
	if !rows.Next() {
		return nil, false
	}
	in, err := scanIntent(rows)
	if err != nil {
		return nil, false
	}
	return in, true
}

func (s *sqlStore) ListIntents(ctx context.Context, tenantID string) []*Intent {
	rows, err := s.db.SQL().QueryContext(ctx,
		`SELECT `+intentCols+` FROM ff_intents WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 200`, tenantID)
	if err != nil {
		return nil
	}
	defer rows.Close() //nolint:errcheck
	var out []*Intent
	for rows.Next() {
		if in, err := scanIntent(rows); err == nil {
			out = append(out, in)
		}
	}
	return out
}

func (s *sqlStore) AppendEvent(ctx context.Context, ev AuditEvent) error {
	const q = `INSERT INTO ff_events (intent_id, tenant_id, actor, action, stage, outcome, detail, request_id, ts)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	_, err := s.db.SQL().ExecContext(ctx, q,
		ev.IntentID, ev.TenantID, ev.Actor, ev.Action, string(ev.Stage), ev.Outcome, ev.Detail, ev.RequestID, ev.Timestamp)
	return err
}

func (s *sqlStore) AddApproval(ctx context.Context, ap Approval) error {
	const q = `INSERT INTO ff_approvals (intent_id, tenant_id, approver, comment, created_at)
VALUES ($1,$2,$3,$4,$5)`
	_, err := s.db.SQL().ExecContext(ctx, q, ap.IntentID, ap.TenantID, ap.Approver, ap.Comment, ap.CreatedAt)
	return err
}

func (s *sqlStore) Approvals(ctx context.Context, intentID string) []Approval {
	rows, err := s.db.SQL().QueryContext(ctx,
		`SELECT intent_id, tenant_id, approver, comment, created_at FROM ff_approvals WHERE intent_id=$1 ORDER BY created_at ASC`, intentID)
	if err != nil {
		return nil
	}
	defer rows.Close() //nolint:errcheck
	var out []Approval
	for rows.Next() {
		var ap Approval
		if err := rows.Scan(&ap.IntentID, &ap.TenantID, &ap.Approver, &ap.Comment, &ap.CreatedAt); err == nil {
			out = append(out, ap)
		}
	}
	return out
}

func (s *sqlStore) Events(ctx context.Context, intentID string) []AuditEvent {
	rows, err := s.db.SQL().QueryContext(ctx,
		`SELECT intent_id, tenant_id, actor, action, stage, outcome, detail, request_id, ts FROM ff_events WHERE intent_id=$1 ORDER BY id ASC`, intentID)
	if err != nil {
		return nil
	}
	defer rows.Close() //nolint:errcheck
	var out []AuditEvent
	for rows.Next() {
		var ev AuditEvent
		var stage string
		if err := rows.Scan(&ev.IntentID, &ev.TenantID, &ev.Actor, &ev.Action, &stage, &ev.Outcome, &ev.Detail, &ev.RequestID, &ev.Timestamp); err == nil {
			ev.Stage = Stage(stage)
			out = append(out, ev)
		}
	}
	return out
}
