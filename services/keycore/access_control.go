package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
)

type keyAccessCtxKey string

const (
	accessActorContextKey keyAccessCtxKey = "key_access_actor"
)

type AccessSubjectType string

const (
	AccessSubjectUser  AccessSubjectType = "user"
	AccessSubjectGroup AccessSubjectType = "group"
)

type KeyAccessGrant struct {
	SubjectType AccessSubjectType `json:"subject_type"`
	SubjectID   string            `json:"subject_id"`
	Operations  []string          `json:"operations"`
}

type KeyAccessPolicy struct {
	TenantID string           `json:"tenant_id"`
	KeyID    string           `json:"key_id"`
	Grants   []KeyAccessGrant `json:"grants"`
}

type AccessGroup struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedBy   string    `json:"created_by"`
	MemberCount int       `json:"member_count"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type AccessActor struct {
	UserID       string
	Username     string
	Role         string
	Permissions  []string
	Groups       []string
	Authenticated bool
}

func contextWithAccessActor(ctx context.Context, actor AccessActor) context.Context {
	return context.WithValue(ctx, accessActorContextKey, actor)
}

func accessActorFromContext(ctx context.Context) AccessActor {
	raw := ctx.Value(accessActorContextKey)
	if raw == nil {
		return AccessActor{}
	}
	actor, ok := raw.(AccessActor)
	if !ok {
		return AccessActor{}
	}
	return actor
}

func actorIsAdmin(actor AccessActor) bool {
	role := strings.ToLower(strings.TrimSpace(actor.Role))
	if role == "admin" || role == "super-admin" || role == "tenant-admin" {
		return true
	}
	for _, p := range actor.Permissions {
		perm := strings.ToLower(strings.TrimSpace(p))
		if perm == "*" || strings.HasPrefix(perm, "key.") || strings.HasPrefix(perm, "auth.") {
			if strings.Contains(perm, "admin") || perm == "*" {
				return true
			}
		}
	}
	return false
}

func actorMatchesCreator(actor AccessActor, createdBy string) bool {
	createdBy = strings.TrimSpace(createdBy)
	if createdBy == "" {
		return false
	}
	if strings.EqualFold(createdBy, strings.TrimSpace(actor.UserID)) {
		return true
	}
	if strings.EqualFold(createdBy, strings.TrimSpace(actor.Username)) {
		return true
	}
	return false
}

func normalizeAccessSubjectType(raw AccessSubjectType) (AccessSubjectType, error) {
	switch strings.ToLower(strings.TrimSpace(string(raw))) {
	case "user":
		return AccessSubjectUser, nil
	case "group":
		return AccessSubjectGroup, nil
	default:
		return "", errors.New("subject_type must be user or group")
	}
}

func normalizeAccessOperation(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "*", "all":
		return "all", nil
	case "encrypt":
		return "encrypt", nil
	case "decrypt":
		return "decrypt", nil
	case "wrap":
		return "wrap", nil
	case "unwrap":
		return "unwrap", nil
	case "sign":
		return "sign", nil
	case "verify":
		return "verify", nil
	case "mac":
		return "mac", nil
	case "derive":
		return "derive", nil
	case "kem-encapsulate", "kem_encapsulate":
		return "kem-encapsulate", nil
	case "kem-decapsulate", "kem_decapsulate":
		return "kem-decapsulate", nil
	case "export":
		return "export", nil
	default:
		return "", fmt.Errorf("unsupported operation %q", raw)
	}
}

func normalizeAccessOperations(raw []string) ([]string, error) {
	if len(raw) == 0 {
		return nil, errors.New("operations are required")
	}
	set := map[string]struct{}{}
	for _, op := range raw {
		norm, err := normalizeAccessOperation(op)
		if err != nil {
			return nil, err
		}
		set[norm] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for op := range set {
		out = append(out, op)
	}
	sort.Strings(out)
	return out, nil
}

func operationAllowed(operations []string, op string) bool {
	norm, err := normalizeAccessOperation(op)
	if err != nil {
		return false
	}
	for _, candidate := range operations {
		if strings.EqualFold(strings.TrimSpace(candidate), "all") {
			return true
		}
		if strings.EqualFold(strings.TrimSpace(candidate), norm) {
			return true
		}
	}
	return false
}

func normalizeActorGroups(groups []string) []string {
	set := map[string]struct{}{}
	for _, g := range groups {
		trimmed := strings.TrimSpace(g)
		if trimmed == "" {
			continue
		}
		set[trimmed] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for g := range set {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

func (s *Service) enforceKeyAccess(ctx context.Context, key Key, operation string) error {
	normOperation, err := normalizeAccessOperation(operation)
	if err != nil {
		return err
	}
	actor := accessActorFromContext(ctx)
	grants, err := s.store.ListKeyAccessGrants(ctx, key.TenantID, key.ID)
	if err != nil {
		return err
	}

	// Legacy safe default: without grants, only creator/admin can use the key when caller identity is available.
	if len(grants) == 0 {
		if !actor.Authenticated {
			return nil
		}
		if actorIsAdmin(actor) || actorMatchesCreator(actor, key.CreatedBy) {
			return nil
		}
		return errors.New("access denied: key is not assigned to caller")
	}

	if !actor.Authenticated {
		return errors.New("access denied: authenticated caller required for key with access policy")
	}
	if actorIsAdmin(actor) {
		return nil
	}

	groupIDs := normalizeActorGroups(actor.Groups)
	if strings.TrimSpace(actor.UserID) != "" {
		fromStore, err := s.store.ListAccessGroupIDsForUser(ctx, key.TenantID, actor.UserID)
		if err != nil {
			return err
		}
		groupIDs = normalizeActorGroups(append(groupIDs, fromStore...))
	}

	for _, grant := range grants {
		if !operationAllowed(grant.Operations, normOperation) {
			continue
		}
		switch grant.SubjectType {
		case AccessSubjectUser:
			if strings.EqualFold(strings.TrimSpace(grant.SubjectID), strings.TrimSpace(actor.UserID)) ||
				strings.EqualFold(strings.TrimSpace(grant.SubjectID), strings.TrimSpace(actor.Username)) {
				return nil
			}
		case AccessSubjectGroup:
			if slices.Contains(groupIDs, strings.TrimSpace(grant.SubjectID)) {
				return nil
			}
		}
	}
	return errors.New("access denied: operation not permitted for caller on this key")
}

func (s *Service) GetKeyAccessPolicy(ctx context.Context, tenantID string, keyID string) (KeyAccessPolicy, error) {
	if _, err := s.GetKey(ctx, tenantID, keyID); err != nil {
		return KeyAccessPolicy{}, err
	}
	grants, err := s.store.ListKeyAccessGrants(ctx, tenantID, keyID)
	if err != nil {
		return KeyAccessPolicy{}, err
	}
	return KeyAccessPolicy{
		TenantID: tenantID,
		KeyID:    keyID,
		Grants:   grants,
	}, nil
}

func (s *Service) ReplaceKeyAccessPolicy(ctx context.Context, tenantID string, keyID string, grants []KeyAccessGrant, updatedBy string) error {
	key, err := s.GetKey(ctx, tenantID, keyID)
	if err != nil {
		return err
	}
	if isDeletedLike(key.Status) {
		return errors.New("cannot update access policy for deleted keys")
	}

	normalized := make([]KeyAccessGrant, 0, len(grants))
	seen := map[string]struct{}{}
	for _, item := range grants {
		subjectType, err := normalizeAccessSubjectType(item.SubjectType)
		if err != nil {
			return err
		}
		subjectID := strings.TrimSpace(item.SubjectID)
		if subjectID == "" {
			return errors.New("subject_id is required")
		}
		operations, err := normalizeAccessOperations(item.Operations)
		if err != nil {
			return err
		}
		key := strings.Join([]string{string(subjectType), strings.ToLower(subjectID)}, "|")
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate grant for %s:%s", subjectType, subjectID)
		}
		seen[key] = struct{}{}
		normalized = append(normalized, KeyAccessGrant{
			SubjectType: subjectType,
			SubjectID:   subjectID,
			Operations:  operations,
		})
	}

	if err := s.store.ReplaceKeyAccessGrants(ctx, tenantID, keyID, normalized, updatedBy); err != nil {
		return err
	}
	_ = s.publishAudit(ctx, "audit.key.access_policy_updated", tenantID, map[string]any{
		"key_id":      keyID,
		"grant_count": len(normalized),
		"updated_by":  strings.TrimSpace(updatedBy),
	})
	return nil
}

func (s *Service) ListAccessGroups(ctx context.Context, tenantID string) ([]AccessGroup, error) {
	if strings.TrimSpace(tenantID) == "" {
		return nil, errors.New("tenant_id is required")
	}
	return s.store.ListAccessGroups(ctx, tenantID)
}

func (s *Service) CreateAccessGroup(ctx context.Context, tenantID string, name string, description string, createdBy string) (AccessGroup, error) {
	tenantID = strings.TrimSpace(tenantID)
	name = strings.TrimSpace(name)
	if tenantID == "" {
		return AccessGroup{}, errors.New("tenant_id is required")
	}
	if name == "" {
		return AccessGroup{}, errors.New("group name is required")
	}
	group := AccessGroup{
		ID:          newID("grp"),
		TenantID:    tenantID,
		Name:        name,
		Description: strings.TrimSpace(description),
		CreatedBy:   strings.TrimSpace(createdBy),
	}
	out, err := s.store.CreateAccessGroup(ctx, group)
	if err != nil {
		return AccessGroup{}, err
	}
	_ = s.publishAudit(ctx, "audit.key.access_group_created", tenantID, map[string]any{
		"group_id": out.ID,
		"name":     out.Name,
	})
	return out, nil
}

func (s *Service) DeleteAccessGroup(ctx context.Context, tenantID string, groupID string) error {
	tenantID = strings.TrimSpace(tenantID)
	groupID = strings.TrimSpace(groupID)
	if tenantID == "" || groupID == "" {
		return errors.New("tenant_id and group_id are required")
	}
	if err := s.store.DeleteAccessGroup(ctx, tenantID, groupID); err != nil {
		return err
	}
	_ = s.publishAudit(ctx, "audit.key.access_group_deleted", tenantID, map[string]any{
		"group_id": groupID,
	})
	return nil
}

func (s *Service) SetAccessGroupMembers(ctx context.Context, tenantID string, groupID string, userIDs []string) error {
	tenantID = strings.TrimSpace(tenantID)
	groupID = strings.TrimSpace(groupID)
	if tenantID == "" || groupID == "" {
		return errors.New("tenant_id and group_id are required")
	}
	normalized := make([]string, 0, len(userIDs))
	seen := map[string]struct{}{}
	for _, userID := range userIDs {
		trimmed := strings.TrimSpace(userID)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}
	if err := s.store.ReplaceAccessGroupMembers(ctx, tenantID, groupID, normalized); err != nil {
		return err
	}
	_ = s.publishAudit(ctx, "audit.key.access_group_members_updated", tenantID, map[string]any{
		"group_id":    groupID,
		"user_count":  len(normalized),
		"member_user": normalized,
	})
	return nil
}
