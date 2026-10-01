package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/servicetoken"
)

// Access rules (docs/SECURITY/SECRET_ACCESS.md). The route permission says
// what a caller may do with secrets in general; a rule says which callers
// may do it to the secrets under a path. One decision, decide, is used by
// every route, the Vault-compatible ones included.

const (
	capRead   = "read"   // metadata, versions, change history, listing
	capValue  = "value"  // the value, any version
	capWrite  = "write"  // create, update, rotate, roll back, restore
	capDelete = "delete" // delete, destroy, destroy a version

	effectAllow = "allow"
	effectDeny  = "deny"

	reasonRuleDenied        = "access_rule_denied"
	reasonNotInRule         = "not_in_access_rule"
	reasonNoRule            = "no_access_rule"            // default-deny, and no allow rule covers the path
	reasonGroupsUnavailable = "access_groups_unavailable" // a group rule applies and membership could not be read

	subjectUser     = "user"
	subjectRole     = "role"
	subjectClient   = "client"
	subjectWorkload = "workload"
	subjectGroup    = "group" // a keycore access group (Key Management, Access groups), by ID

	maxVersionCap    = 1000
	maxRetentionDays = 3650

	maxRulesPerTenant = 500
	under             = "/*" // a rule path ending in /* covers everything under the folder
)

var (
	capabilities = []string{capRead, capValue, capWrite, capDelete}
	subjectTypes = map[string]bool{subjectUser: true, subjectRole: true, subjectClient: true, subjectWorkload: true, subjectGroup: true}
)

// VaultSettings are a tenant's vault-wide choices.
type VaultSettings struct {
	TenantID string `json:"tenant_id"`
	// DefaultDeny refuses a capability on a path no allow rule covers.
	DefaultDeny bool `json:"default_deny"`
	// MaxVersions caps the stored versions of a secret; the oldest go when a
	// new one is written. 0: no cap.
	MaxVersions int `json:"max_versions"`
	// DeletedRetentionDays destroys a deleted secret this long after its
	// delete. 0: kept until someone destroys it.
	DeletedRetentionDays int        `json:"deleted_retention_days"`
	UpdatedBy            string     `json:"updated_by"`
	UpdatedAt            *time.Time `json:"updated_at,omitempty"`
}

// caller is the verified token and, read at most once per request and only
// when a group rule applies, the access groups its user belongs to.
type caller struct {
	claims *pkgauth.Claims
	groups func() ([]string, error)

	loaded   bool
	groupIDs []string
	err      error
}

func (c *caller) memberOf(groupID string) (bool, error) {
	if c.claims == nil || strings.TrimSpace(c.claims.UserID) == "" || c.groups == nil {
		return false, nil
	}
	if !c.loaded {
		c.groupIDs, c.err = c.groups()
		c.loaded = true
	}
	for _, id := range c.groupIDs {
		if id == groupID {
			return true, nil
		}
	}
	return false, c.err
}

type AccessRule struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	Path         string    `json:"path"`
	SubjectType  string    `json:"subject_type"`
	SubjectID    string    `json:"subject_id"`
	Capabilities []string  `json:"capabilities"`
	Effect       string    `json:"effect"`
	CreatedBy    string    `json:"created_by"`
	CreatedAt    time.Time `json:"created_at"`
}

// secretPath is where a secret sits: its "path" label (the folder), then its
// name. A Vault KV path such as app/prod/db is already a path.
func secretPath(labels map[string]string, name string) string {
	parts := strings.FieldsFunc(labels["path"]+"/"+name, func(r rune) bool { return r == '/' })
	return "/" + strings.Join(parts, "/")
}

// normalizeRule validates a rule and puts it in canonical form.
func normalizeRule(r AccessRule) (AccessRule, error) {
	r.Path = strings.TrimSpace(r.Path)
	r.SubjectType = strings.ToLower(strings.TrimSpace(r.SubjectType))
	r.SubjectID = strings.TrimSpace(r.SubjectID)
	r.Effect = strings.ToLower(strings.TrimSpace(r.Effect))
	if r.Effect == "" {
		r.Effect = effectAllow
	}
	if r.Effect != effectAllow && r.Effect != effectDeny {
		return r, errors.New("effect must be allow or deny")
	}
	if !subjectTypes[r.SubjectType] {
		return r, errors.New("subject_type must be user, role, group, client or workload")
	}
	if r.SubjectID == "" || len(r.SubjectID) > 256 {
		return r, errors.New("subject_id is required")
	}
	if !strings.HasPrefix(r.Path, "/") || len(r.Path) > 512 || strings.Contains(r.Path, "//") {
		return r, errors.New("path must start with / and name a secret (/team/db) or everything under a folder (/team/*)")
	}
	folder, isFolder := strings.CutSuffix(r.Path, under)
	if strings.Contains(folder, "*") || strings.HasSuffix(folder, "/") || (!isFolder && folder == "") {
		return r, errors.New("* is only allowed as the last segment, as in /team/*, and a path must not end with /")
	}
	seen := map[string]bool{}
	var caps []string
	for _, want := range capabilities { // canonical order, no duplicates
		for _, c := range r.Capabilities {
			if strings.ToLower(strings.TrimSpace(c)) == want && !seen[want] {
				seen[want] = true
				caps = append(caps, want)
			}
		}
	}
	if len(caps) == 0 || len(caps) != len(r.Capabilities) {
		return r, errors.New("capabilities must be one or more of read, value, write, delete")
	}
	r.Capabilities = caps
	return r, nil
}

// covers reports whether the rule's path is this secret or a folder above it.
func (r AccessRule) covers(path string) bool {
	if folder, ok := strings.CutSuffix(r.Path, under); ok {
		return strings.HasPrefix(path, folder+"/")
	}
	return r.Path == path
}

func (r AccessRule) grants(capability string) bool {
	for _, c := range r.Capabilities {
		if c == capability {
			return true
		}
	}
	return false
}

// names reports whether the rule's subject is the verified caller. Every
// field compared comes from the caller's verified token; group membership
// comes from keycore, for the token's user.
func (r AccessRule) names(who *caller) (bool, error) {
	if who == nil || who.claims == nil {
		return false, nil
	}
	var have string
	switch r.SubjectType {
	case subjectGroup:
		return who.memberOf(r.SubjectID)
	case subjectUser:
		have = who.claims.UserID
	case subjectRole:
		have = who.claims.Role
	case subjectClient:
		have = who.claims.ClientID
	case subjectWorkload:
		have = who.claims.WorkloadIdentity
	}
	return have != "" && strings.TrimSpace(have) == r.SubjectID, nil
}

// decide applies the tenant's rules to one capability on one path. A deny
// rule naming the caller wins. If any allow rule covers the path for the
// capability, only the callers those rules name are allowed. A path no allow
// rule covers is governed by the route permission alone, unless the tenant
// is default-deny, when it is refused. If a group rule applies and the
// caller's groups cannot be read, the request is refused: an unknown
// membership never allows and never skips a deny. It returns "" when
// allowed, or the refusal reason.
func decide(rules []AccessRule, defaultDeny bool, who *caller, path, capability string) string {
	covered, named, unknownAllow, unknownDeny := false, false, false, false
	for _, r := range rules {
		if !r.covers(path) || !r.grants(capability) {
			continue
		}
		is, err := r.names(who)
		if r.Effect == effectDeny {
			if is {
				return reasonRuleDenied
			}
			unknownDeny = unknownDeny || err != nil
			continue
		}
		covered = true
		named = named || is
		unknownAllow = unknownAllow || err != nil
	}
	switch {
	case unknownDeny, covered && !named && unknownAllow:
		return reasonGroupsUnavailable
	case covered && !named:
		return reasonNotInRule
	case !covered && defaultDeny:
		return reasonNoRule
	}
	return ""
}

// restricted reports whether an allow rule, or default-deny, limits who may
// read the value.
func restricted(rules []AccessRule, defaultDeny bool, path string) bool {
	if defaultDeny {
		return true
	}
	for _, r := range rules {
		if r.Effect == effectAllow && r.covers(path) && r.grants(capValue) {
			return true
		}
	}
	return false
}

// GroupResolver returns the IDs of the access groups a user belongs to.
type GroupResolver interface {
	GroupsOf(ctx context.Context, tenantID, userID string) ([]string, error)
}

// keycoreGroups reads memberships from keycore, where access groups live,
// under this service's identity. An answer is reused for groupCacheTTL, so a
// membership change takes effect within that time.
type keycoreGroups struct {
	baseURL string
	client  *http.Client

	mu    sync.Mutex
	cache map[string]groupEntry
}

type groupEntry struct {
	ids []string
	at  time.Time
}

const groupCacheTTL = 30 * time.Second

func newKeycoreGroups(baseURL string) *keycoreGroups {
	return &keycoreGroups{baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"), client: &http.Client{Timeout: 5 * time.Second}, cache: map[string]groupEntry{}}
}

func (k *keycoreGroups) GroupsOf(ctx context.Context, tenantID, userID string) ([]string, error) {
	key := tenantID + "\x00" + userID
	k.mu.Lock()
	hit, ok := k.cache[key]
	k.mu.Unlock()
	if ok && time.Since(hit.at) < groupCacheTTL {
		return hit.ids, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.baseURL+"/access/users/"+url.PathEscape(userID)+"/groups?tenant_id="+url.QueryEscape(tenantID), nil)
	if err != nil {
		return nil, err
	}
	servicetoken.Authorize(ctx, req)
	resp, err := k.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("keycore access groups: status %d", resp.StatusCode)
	}
	var out struct {
		GroupIDs []string `json:"group_ids"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	k.mu.Lock()
	if len(k.cache) > 10000 { // bounded: start over rather than grow
		k.cache = map[string]groupEntry{}
	}
	k.cache[key] = groupEntry{ids: out.GroupIDs, at: time.Now()}
	k.mu.Unlock()
	return out.GroupIDs, nil
}
