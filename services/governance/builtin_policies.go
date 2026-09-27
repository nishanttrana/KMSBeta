package main

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"

	"vecta-kms/pkg/clusterstate"
	pkgcrypto "vecta-kms/pkg/crypto"
)

// builtinPolicies are approval policies governance creates for a tenant the
// first time an action they cover needs approval and no active policy covers
// it, so a platform feature that requires dual control works on a fresh
// tenant. After that they are ordinary policies: administrators edit their
// approvers or disable them. Deleting one is refused, because it would be
// created again on the next request (disable it instead).
var builtinPolicies = []ApprovalPolicy{{
	Name:           "Posture escalation (built-in)",
	Description:    "Created by the platform for posture remediation escalations. Any tenant administrator other than the requester may approve. Edit the approvers or disable this policy in Governance.",
	Scope:          "posture",
	TriggerActions: []string{"posture.escalate_remediation"},
	QuorumMode:     "threshold",
	ApproverRoles:  []string{"admin", "tenant-admin"},
}}

// builtinPolicyID is the policy's ID in a tenant: fixed, so a disabled
// built-in policy is found and never created twice.
func builtinPolicyID(tenantID string, p ApprovalPolicy) string {
	sum := pkgcrypto.SHA256([]byte("builtin-policy|" + strings.TrimSpace(tenantID) + "|" + p.Name))
	return "apol_builtin_" + hex.EncodeToString(sum[:12])
}

func isBuiltinPolicyID(tenantID, policyID string) bool {
	for _, p := range builtinPolicies {
		if builtinPolicyID(tenantID, p) == policyID {
			return true
		}
	}
	return false
}

// errBuiltinPolicyDelete refuses deleting a built-in policy.
var errBuiltinPolicyDelete = errors.New("a built-in policy can't be deleted (it would be created again); disable it or edit its approvers instead")

// ensureBuiltinPolicy returns the built-in policy covering action for
// tenantID, creating it on first use. It returns errNotFound when no
// built-in policy covers the action, when the tenant's built-in policy
// exists but an administrator disabled it, and on a cluster member (the
// table is replicated; the primary creates it).
func (s *Service) ensureBuiltinPolicy(ctx context.Context, tenantID, action string) (ApprovalPolicy, error) {
	for _, p := range builtinPolicies {
		covers := false
		for _, t := range p.TriggerActions {
			covers = covers || actionMatches(t, action)
		}
		if !covers {
			continue
		}
		id := builtinPolicyID(tenantID, p)
		if existing, err := s.store.GetPolicy(ctx, tenantID, id); err == nil {
			if existing.Status == "active" {
				return existing, nil
			}
			return ApprovalPolicy{}, errNotFound // disabled: the administrator's choice
		} else if !errors.Is(err, errNotFound) {
			return ApprovalPolicy{}, err
		}
		if !clusterstate.RunsPrimaryJobs(ctx) {
			return ApprovalPolicy{}, errNotFound
		}
		p.ID, p.TenantID = id, tenantID
		p.TriggerActions = append([]string(nil), p.TriggerActions...)
		p.ApproverRoles = append([]string(nil), p.ApproverRoles...)
		p = normalizePolicy(p)
		if err := s.store.CreatePolicy(ctx, p); err != nil {
			// A concurrent request may have created it first.
			if existing, gerr := s.store.GetPolicy(ctx, tenantID, id); gerr == nil && existing.Status == "active" {
				return existing, nil
			}
			return ApprovalPolicy{}, err
		}
		_ = s.publishAudit(ctx, "audit.governance.builtin_policy_created", tenantID, map[string]interface{}{
			"policy_id":       id,
			"name":            p.Name,
			"trigger_actions": p.TriggerActions,
			"approver_roles":  p.ApproverRoles,
			"trigger":         action,
			"severity":        "warning",
			"result":          "success",
		})
		return s.store.GetPolicy(ctx, tenantID, id)
	}
	return ApprovalPolicy{}, errNotFound
}
