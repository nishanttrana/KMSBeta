package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Operations that apply new protection: a decrypt_only rule refuses them. (A
// quantum_vulnerable decrypt_only rule is how a tenant requires post-quantum
// algorithms for new protection; a below_strength rule sets a strength
// floor.) Operations that only process data
// already protected stay allowed under decrypt_only. Lifecycle operations
// (destroy, export, approval and export-policy changes) are never refused by
// the migration policy, so a disallowed key can still be retired.
var (
	protectOps = map[string]bool{
		"key.create": true, "key.import": true, "key.form": true, "key.rotate": true,
		"key.encrypt": true, "key.sign": true, "key.wrap": true, "key.mac": true,
		"key.derive": true, "key.service_derive": true, "key.kem_encapsulate": true,
	}
	consumeOps = map[string]bool{
		"key.decrypt": true, "key.verify": true, "key.unwrap": true,
		"key.kem_decapsulate": true, "key.attested_release": true,
	}
)

// cryptoPolicyRefusal is a key operation refused by the tenant's migration
// policy. It is also a policyDeniedError, so every
// handler answers 403 policy_denied; the audit reason is specific.
type cryptoPolicyRefusal struct {
	Reason  string // crypto_policy_disallowed or crypto_policy_decrypt_only
	Message string
	Rule    *AgilityRule
}

func (e cryptoPolicyRefusal) Error() string { return e.Message }

func (e cryptoPolicyRefusal) As(target any) bool {
	if t, ok := target.(*policyDeniedError); ok {
		*t = policyDeniedError{Reason: e.Message}
		return true
	}
	return false
}

// agilityRuleCache keeps each tenant's rules for a few seconds so a key
// operation doesn't read the table every time. Local writes invalidate it;
// a rule replicated from the primary applies within the TTL.
type agilityRuleCache struct {
	mu      sync.Mutex
	entries map[string]agilityRuleCacheEntry
}

type agilityRuleCacheEntry struct {
	rules []AgilityRule
	at    time.Time
}

const agilityRuleCacheTTL = 10 * time.Second

func (s *Service) agilityRules(ctx context.Context, tenantID string) ([]AgilityRule, error) {
	s.agilityCache.mu.Lock()
	if e, ok := s.agilityCache.entries[tenantID]; ok && time.Since(e.at) < agilityRuleCacheTTL {
		s.agilityCache.mu.Unlock()
		return e.rules, nil
	}
	s.agilityCache.mu.Unlock()
	rules, err := s.store.ListAgilityRules(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	s.agilityCache.mu.Lock()
	if s.agilityCache.entries == nil {
		s.agilityCache.entries = map[string]agilityRuleCacheEntry{}
	}
	s.agilityCache.entries[tenantID] = agilityRuleCacheEntry{rules: rules, at: time.Now()}
	s.agilityCache.mu.Unlock()
	return rules, nil
}

func (s *Service) invalidateAgilityRules(tenantID string) {
	s.agilityCache.mu.Lock()
	delete(s.agilityCache.entries, tenantID)
	s.agilityCache.mu.Unlock()
}

// enforceCryptoPolicy applies the tenant's migration policy to one key
// operation. A refusal is audited as
// audit.key.crypto_policy_refused.
func (s *Service) enforceCryptoPolicy(ctx context.Context, req PolicyEvaluateRequest) error {
	alg, op := strings.TrimSpace(req.Algorithm), strings.TrimSpace(req.Operation)
	if alg == "" || (!protectOps[op] && !consumeOps[op]) {
		return nil
	}
	rules, err := s.agilityRules(ctx, req.TenantID)
	if err != nil {
		return fmt.Errorf("crypto policy check failed: %w", err)
	}
	var refusal *cryptoPolicyRefusal
	if rule, _ := policyFor(rules, alg, time.Now()); rule != nil {
		switch {
		case rule.Action == ActionDisallowed:
			refusal = &cryptoPolicyRefusal{Reason: "crypto_policy_disallowed", Rule: rule,
				Message: fmt.Sprintf("%s is disallowed by migration policy rule %q", alg, rule.Name)}
		case rule.Action == ActionDecryptOnly && protectOps[op]:
			refusal = &cryptoPolicyRefusal{Reason: "crypto_policy_decrypt_only", Rule: rule,
				Message: fmt.Sprintf("%s is limited to decrypt and verify by migration policy rule %q", alg, rule.Name)}
		}
	}
	if refusal == nil {
		return nil
	}
	data := map[string]any{
		"result": "refused", "reason": refusal.Reason, "operation": op,
		"algorithm": alg, "key_id": req.KeyID, "message": refusal.Message,
	}
	if refusal.Rule != nil {
		data["rule_id"], data["rule_name"], data["rule_action"] = refusal.Rule.ID, refusal.Rule.Name, refusal.Rule.Action
	}
	_ = s.publishAudit(ctx, "audit.key.crypto_policy_refused", req.TenantID, data)
	return *refusal
}
