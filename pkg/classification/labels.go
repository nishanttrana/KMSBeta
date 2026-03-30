package classification

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Level represents the data classification sensitivity level.
type Level int

const (
	Public       Level = 0
	Internal     Level = 1
	Confidential Level = 2
	Restricted   Level = 3
	TopSecret    Level = 4
)

// String returns the human-readable name of a classification level.
func (l Level) String() string {
	switch l {
	case Public:
		return "Public"
	case Internal:
		return "Internal"
	case Confidential:
		return "Confidential"
	case Restricted:
		return "Restricted"
	case TopSecret:
		return "TopSecret"
	default:
		return fmt.Sprintf("Level(%d)", int(l))
	}
}

// Label represents a data classification label applied to a key.
type Label struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	KeyID         string    `json:"key_id"`
	Level         Level     `json:"level"`
	Categories    []string  `json:"categories"` // PII, PCI, HIPAA, financial, IP
	AppliedBy     string    `json:"applied_by"`
	AppliedAt     time.Time `json:"applied_at"`
	Justification string    `json:"justification"`
}

// Policy defines classification-based security requirements for a tenant.
type Policy struct {
	TenantID               string              `json:"tenant_id"`
	MinLevelForHSM         Level               `json:"min_level_for_hsm"`
	MinLevelForRotationDays map[Level]int       `json:"min_level_for_rotation_days"` // e.g., {Restricted: 30, Confidential: 90}
	MinLevelForMFA         Level               `json:"min_level_for_mfa"`
	DeniedOperationsByLevel map[Level][]string  `json:"denied_operations_by_level"` // e.g., {Public: ["export"]}
}

// ClassificationRule defines a rule for auto-classifying keys.
type ClassificationRule struct {
	AlgorithmPattern string   `json:"algorithm_pattern,omitempty"` // regex or exact match
	MinKeySize       int      `json:"min_key_size,omitempty"`
	Categories       []string `json:"categories"`
	Level            Level    `json:"level"`
	Justification    string   `json:"justification"`
}

// Store is the persistence interface for classification data.
type Store interface {
	UpsertLabel(ctx context.Context, label Label) error
	GetLabel(ctx context.Context, keyID, tenantID string) (*Label, error)
	GetPolicy(ctx context.Context, tenantID string) (*Policy, error)
	ListKeysByTenant(ctx context.Context, tenantID string) ([]KeyInfo, error)
}

// KeyInfo is minimal key metadata used for bulk classification rule matching.
type KeyInfo struct {
	KeyID     string
	Algorithm string
	KeySize   int
}

// Engine manages classification labels and enforces policies.
type Engine struct {
	store       Store
	policyCache map[string]*Policy
	cacheMu     sync.RWMutex
}

// NewEngine creates a classification Engine.
func NewEngine(store Store) *Engine {
	return &Engine{
		store:       store,
		policyCache: make(map[string]*Policy),
	}
}

// ApplyLabel assigns a classification label to a key.
func (e *Engine) ApplyLabel(ctx context.Context, keyID, tenantID string, level Level, categories []string, justification string) error {
	if keyID == "" || tenantID == "" {
		return fmt.Errorf("classification: key_id and tenant_id are required")
	}
	if level < Public || level > TopSecret {
		return fmt.Errorf("classification: invalid level %d", level)
	}

	label := Label{
		ID:            fmt.Sprintf("lbl_%s_%s", tenantID, keyID),
		TenantID:      tenantID,
		KeyID:         keyID,
		Level:         level,
		Categories:    categories,
		AppliedBy:     "system",
		AppliedAt:     time.Now().UTC(),
		Justification: justification,
	}

	if err := e.store.UpsertLabel(ctx, label); err != nil {
		return fmt.Errorf("classification: upsert label: %w", err)
	}

	// Invalidate policy cache for this tenant (label change may affect policy enforcement)
	e.cacheMu.Lock()
	delete(e.policyCache, tenantID)
	e.cacheMu.Unlock()

	return nil
}

// GetLabel retrieves the classification label for a key.
func (e *Engine) GetLabel(ctx context.Context, keyID, tenantID string) (*Label, error) {
	label, err := e.store.GetLabel(ctx, keyID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("classification: get label: %w", err)
	}
	return label, nil
}

// EnforcePolicy checks whether an operation is allowed for the key's classification level.
func (e *Engine) EnforcePolicy(ctx context.Context, keyID, tenantID, operation string) error {
	label, err := e.store.GetLabel(ctx, keyID, tenantID)
	if err != nil {
		return fmt.Errorf("classification: get label for enforcement: %w", err)
	}
	if label == nil {
		// No label means no restrictions
		return nil
	}

	policy, err := e.getPolicy(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("classification: get policy: %w", err)
	}
	if policy == nil {
		return nil
	}

	// Check denied operations for this level
	if denied, ok := policy.DeniedOperationsByLevel[label.Level]; ok {
		for _, op := range denied {
			if op == operation {
				return fmt.Errorf("classification: operation %q is denied for %s-level keys (key=%s)",
					operation, label.Level, keyID)
			}
		}
	}

	return nil
}

// BulkClassify auto-classifies keys matching the given rules. Returns the number of labels applied.
func (e *Engine) BulkClassify(ctx context.Context, tenantID string, rules []ClassificationRule) (int, error) {
	keys, err := e.store.ListKeysByTenant(ctx, tenantID)
	if err != nil {
		return 0, fmt.Errorf("classification: list keys: %w", err)
	}

	applied := 0
	for _, key := range keys {
		if ctx.Err() != nil {
			return applied, ctx.Err()
		}

		for _, rule := range rules {
			if matchesRule(key, rule) {
				err := e.ApplyLabel(ctx, key.KeyID, tenantID, rule.Level, rule.Categories, rule.Justification)
				if err != nil {
					return applied, err
				}
				applied++
				break // first matching rule wins
			}
		}
	}

	return applied, nil
}

// matchesRule checks if a key matches a classification rule.
func matchesRule(key KeyInfo, rule ClassificationRule) bool {
	if rule.AlgorithmPattern != "" && key.Algorithm != rule.AlgorithmPattern {
		return false
	}
	if rule.MinKeySize > 0 && key.KeySize < rule.MinKeySize {
		return false
	}
	return true
}

// getPolicy retrieves the policy for a tenant, using the cache when available.
func (e *Engine) getPolicy(ctx context.Context, tenantID string) (*Policy, error) {
	e.cacheMu.RLock()
	if p, ok := e.policyCache[tenantID]; ok {
		e.cacheMu.RUnlock()
		return p, nil
	}
	e.cacheMu.RUnlock()

	policy, err := e.store.GetPolicy(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	if policy != nil {
		e.cacheMu.Lock()
		e.policyCache[tenantID] = policy
		e.cacheMu.Unlock()
	}

	return policy, nil
}
