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
	SubjectType   AccessSubjectType `json:"subject_type"`
	SubjectID     string            `json:"subject_id"`
	Operations    []string          `json:"operations"`
	NotBefore     *time.Time        `json:"not_before,omitempty"`
	ExpiresAt     *time.Time        `json:"expires_at,omitempty"`
	Justification string            `json:"justification,omitempty"`
	TicketID      string            `json:"ticket_id,omitempty"`
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
	UserID              string
	Username            string
	Role                string
	Permissions         []string
	Groups              []string
	ClientID            string
	InterfaceName       string
	SubjectID           string
	WorkloadIdentity    string
	WorkloadTrustDomain string
	AllowedKeyIDs       []string
	Authenticated       bool
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

func normalizeActorKeyIDs(values []string) []string {
	set := map[string]struct{}{}
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		set[value] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func actorPermissionAllowsOperation(perms []string, operation string) bool {
	norm, err := normalizeAccessOperation(operation)
	if err != nil {
		return false
	}
	for _, raw := range perms {
		perm := strings.ToLower(strings.TrimSpace(raw))
		switch perm {
		case "*", norm, "key." + norm, "key.*", "workload-key." + norm, "workload-key.*":
			return true
		}
	}
	return false
}

func workloadKeyAllowed(actor AccessActor, keyID string) bool {
	allowed := normalizeActorKeyIDs(actor.AllowedKeyIDs)
	for _, value := range allowed {
		if value == "*" || strings.EqualFold(value, strings.TrimSpace(keyID)) {
			return true
		}
	}
	return false
}

func (s *Service) enforceKeyAccess(ctx context.Context, key Key, operation string) error {
	normOperation, err := normalizeAccessOperation(operation)
	if err != nil {
		return err
	}
	actor := accessActorFromContext(ctx)
	settings, err := s.store.GetKeyAccessSettings(ctx, key.TenantID)
	if err != nil {
		return err
	}
	grants, err := s.store.ListKeyAccessGrants(ctx, key.TenantID, key.ID)
	if err != nil {
		return err
	}

	if strings.TrimSpace(actor.WorkloadIdentity) != "" {
		if !actor.Authenticated {
			return errors.New("access denied: authenticated workload token required")
		}
		if !actorPermissionAllowsOperation(actor.Permissions, normOperation) {
			return errors.New("access denied: workload token does not permit this operation")
		}
		if !workloadKeyAllowed(actor, key.ID) {
			return errors.New("access denied: key is not bound to workload identity")
		}
		if settings.RequireInterfacePolicies {
			if err := s.enforceInterfaceSubjectPolicy(ctx, key.TenantID, actor, normOperation, normalizeActorGroups(actor.Groups)); err != nil {
				return err
			}
		}
		return nil
	}

	now := time.Now().UTC()
	activeGrants := make([]KeyAccessGrant, 0, len(grants))
	for _, grant := range grants {
		if grantActiveAt(grant, now) {
			activeGrants = append(activeGrants, grant)
		}
	}

	// Backward-compatible default remains creator/admin unless deny-by-default is explicitly enabled.
	grants = activeGrants
	if len(grants) == 0 {
		if settings.DenyByDefault {
			if actor.Authenticated && actorIsAdmin(actor) {
				return nil
			}
			return errors.New("access denied: no active grants and deny-by-default is enabled")
		}
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
	if settings.RequireInterfacePolicies {
		if err := s.enforceInterfaceSubjectPolicy(ctx, key.TenantID, actor, normOperation, groupIDs); err != nil {
			return err
		}
		return nil
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

	settings, err := s.store.GetKeyAccessSettings(ctx, tenantID)
	if err != nil {
		return err
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
		if item.NotBefore != nil && item.ExpiresAt != nil && item.NotBefore.After(item.ExpiresAt.UTC()) {
			return fmt.Errorf("grant %s:%s has not_before later than expires_at", subjectType, subjectID)
		}
		notBefore := item.NotBefore
		if notBefore != nil {
			v := notBefore.UTC()
			notBefore = &v
		}
		expiresAt := item.ExpiresAt
		if expiresAt != nil {
			v := expiresAt.UTC()
			expiresAt = &v
		}
		if expiresAt == nil && settings.GrantDefaultTTLMinutes > 0 {
			v := time.Now().UTC().Add(time.Duration(settings.GrantDefaultTTLMinutes) * time.Minute)
			expiresAt = &v
		}
		if settings.GrantMaxTTLMinutes > 0 {
			if notBefore != nil && expiresAt != nil {
				maxTTL := time.Duration(settings.GrantMaxTTLMinutes) * time.Minute
				if expiresAt.Sub(*notBefore) > maxTTL {
					return fmt.Errorf("grant %s:%s exceeds max ttl of %d minutes", subjectType, subjectID, settings.GrantMaxTTLMinutes)
				}
			} else if expiresAt != nil {
				maxTTL := time.Duration(settings.GrantMaxTTLMinutes) * time.Minute
				if expiresAt.Sub(time.Now().UTC()) > maxTTL {
					return fmt.Errorf("grant %s:%s exceeds max ttl of %d minutes", subjectType, subjectID, settings.GrantMaxTTLMinutes)
				}
			}
		}
		seen[key] = struct{}{}
		normalized = append(normalized, KeyAccessGrant{
			SubjectType:   subjectType,
			SubjectID:     subjectID,
			Operations:    operations,
			NotBefore:     notBefore,
			ExpiresAt:     expiresAt,
			Justification: strings.TrimSpace(item.Justification),
			TicketID:      strings.TrimSpace(item.TicketID),
		})
	}

	if settings.RequireApprovalForPolicyChange {
		if err := s.ensureAccessPolicyApproval(ctx, tenantID, keyID, updatedBy, normalized); err != nil {
			return err
		}
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
