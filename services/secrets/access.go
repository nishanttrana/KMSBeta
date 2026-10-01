package main

import (
	"errors"
	"strings"
	"time"

	pkgauth "vecta-kms/pkg/auth"
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

	reasonRuleDenied = "access_rule_denied"
	reasonNotInRule  = "not_in_access_rule"

	subjectUser     = "user"
	subjectRole     = "role"
	subjectClient   = "client"
	subjectWorkload = "workload"

	maxRulesPerTenant = 500
	under             = "/*" // a rule path ending in /* covers everything under the folder
)

var (
	capabilities = []string{capRead, capValue, capWrite, capDelete}
	subjectTypes = map[string]bool{subjectUser: true, subjectRole: true, subjectClient: true, subjectWorkload: true}
)

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
		return r, errors.New("subject_type must be user, role, client or workload")
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
// field compared comes from the caller's verified token.
func (r AccessRule) names(claims *pkgauth.Claims) bool {
	if claims == nil {
		return false
	}
	var have string
	switch r.SubjectType {
	case subjectUser:
		have = claims.UserID
	case subjectRole:
		have = claims.Role
	case subjectClient:
		have = claims.ClientID
	case subjectWorkload:
		have = claims.WorkloadIdentity
	}
	return have != "" && strings.TrimSpace(have) == r.SubjectID
}

// decide applies the tenant's rules to one capability on one path. A deny
// rule naming the caller wins. If any allow rule covers the path for the
// capability, only the callers those rules name are allowed. A path no allow
// rule covers is governed by the route permission alone. It returns "" when
// allowed, or the refusal reason.
func decide(rules []AccessRule, claims *pkgauth.Claims, path, capability string) string {
	restricted, named := false, false
	for _, r := range rules {
		if !r.covers(path) || !r.grants(capability) {
			continue
		}
		if r.Effect == effectDeny {
			if r.names(claims) {
				return reasonRuleDenied
			}
			continue
		}
		restricted = true
		named = named || r.names(claims)
	}
	if restricted && !named {
		return reasonNotInRule
	}
	return ""
}

// restricted reports whether an allow rule limits who may read the value.
func restricted(rules []AccessRule, path string) bool {
	for _, r := range rules {
		if r.Effect == effectAllow && r.covers(path) && r.grants(capValue) {
			return true
		}
	}
	return false
}
