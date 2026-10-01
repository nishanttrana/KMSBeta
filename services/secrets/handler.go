package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/mek"
	"vecta-kms/pkg/route"
)

// Handler serves the secrets API. Every route is registered through the
// pkg/route kernel, which authenticates the caller, enforces the tenant and
// the route's permission, and emits one audit.secrets.<action> event per
// request, refusals included. Handlers only add domain details.
type Handler struct {
	svc     *Service
	router  *route.Router
	keyring *mek.Keyring  // nil in tests without a master key
	audit   route.Emitter // for events no request carries (retention.go)
	logger  *log.Logger
	// groups resolves group subjects in access rules; nil refuses them.
	groups GroupResolver
	// directory says whether a rule's subject exists; nil refuses new rules.
	directory SubjectDirectory
}

// Permissions for the secrets domain. kms.read grants the *.read ones and
// kms.write the .write and .delete ones (see route.Allowed); destroying and
// managing access rules are granted only by name, secrets.* or *.
const (
	permRead         = "secrets.read"          // metadata, versions, stats
	permValueRead    = "secrets.value.read"    // reveals a secret value
	permWrite        = "secrets.write"         // create, update, rotate, roll back, restore, generate
	permDelete       = "secrets.delete"        // recoverable delete
	permDestroy      = "secrets.destroy"       // permanent: a secret or one of its versions
	permAccessRead   = "secrets.access.read"   // list access rules
	permAccessManage = "secrets.access.manage" // create and delete access rules
)

var vaultTenantHeaders = []string{"X-Vault-Namespace", "X-Namespace"}

func NewHandler(svc *Service, audit route.Emitter, logger *log.Logger, keyring *mek.Keyring) *Handler {
	h := &Handler{svc: svc, router: route.New("secrets", audit, logger), keyring: keyring, audit: audit, logger: logger}
	h.routes()
	if keyring != nil {
		keyring.Routes(h.router, "secrets") // exposure register, backup re-wrap
	}
	return h
}

// remediate closes the secret's exposure-register entry (it was stored under
// a public key before 1.2.0-beta) once its value is replaced or destroyed.
func (h *Handler) remediate(c *route.Call, secretID, how string) {
	if h.keyring == nil {
		return
	}
	if closed, err := h.keyring.Remediate(c.R.Context(), c.Tenant, "secret", secretID, how, c.Actor()); err == nil && closed {
		c.Detail("exposure_remediated", true)
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.router.ServeHTTP(w, r)
}

func (h *Handler) routes() {
	r := h.router
	secret := func(action, perm string) route.Spec {
		return route.Spec{Action: action, Permission: perm, Resource: "secret", TargetParam: "id"}
	}
	warn := func(spec route.Spec) route.Spec { spec.Severity = "warning"; return spec }
	r.Handle("POST /secrets", route.Spec{Action: "created", Permission: permWrite, Resource: "secret"}, h.createSecret)
	r.Handle("GET /secrets", route.Spec{Action: "listed", Permission: permRead, Resource: "secret"}, h.listSecrets)
	r.Handle("GET /secrets/{id}", secret("read", permRead), h.getSecret)
	r.Handle("GET /secrets/{id}/value", warn(secret("value_read", permValueRead)), h.getSecretValue)
	r.Handle("PUT /secrets/{id}", secret("updated", permWrite), h.updateSecret)
	r.Handle("DELETE /secrets/{id}", warn(secret("deleted", permDelete)), h.deleteSecret)
	r.Handle("POST /secrets/{id}/restore", secret("restored", permWrite), h.restoreSecret)
	r.Handle("POST /secrets/{id}/destroy", warn(route.Spec{Action: "destroyed", Permission: permDestroy, Resource: "secret", TargetParam: "id"}), h.destroySecret)
	r.Handle("POST /secrets/generate/ssh_key", route.Spec{Action: "generated", Permission: permWrite, Resource: "secret"}, h.generateSSHKey)
	r.Handle("POST /secrets/generate/keypair", route.Spec{Action: "generated", Permission: permWrite, Resource: "secret"}, h.generateKeyPair)
	r.Handle("GET /secrets/{id}/versions", secret("versions_listed", permRead), h.listVersions)
	r.Handle("DELETE /secrets/{id}/versions/{version}", warn(secret("version_destroyed", permDestroy)), h.destroyVersion)
	r.Handle("GET /secrets/{id}/audit", secret("audit_log_read", permRead), h.secretAuditLog)
	r.Handle("POST /secrets/{id}/rotate", secret("rotated", permWrite), h.rotateSecret)
	r.Handle("POST /secrets/{id}/rollback", warn(secret("rolled_back", permWrite)), h.rollbackSecret)
	r.Handle("GET /secrets/{id}/access", secret("access_read", permRead), h.secretAccess)
	r.Handle("GET /secrets/stats", route.Spec{Action: "stats_read", Permission: permRead}, h.stats)
	r.Handle("GET /secrets/settings", route.Spec{Action: "settings_read", Permission: permAccessRead, Resource: "secret_vault_settings"}, h.getSettings)
	r.Handle("PUT /secrets/settings", warn(route.Spec{Action: "settings_updated", Permission: permAccessManage, Resource: "secret_vault_settings"}), h.putSettings)
	r.Handle("GET /secrets/version-caps", route.Spec{Action: "version_caps_listed", Permission: permAccessRead, Resource: "secret_version_cap"}, h.listVersionCaps)
	r.Handle("PUT /secrets/version-caps", warn(route.Spec{Action: "version_cap_set", Permission: permAccessManage, Resource: "secret_version_cap"}), h.putVersionCap)
	r.Handle("DELETE /secrets/version-caps/{cap_id}", warn(route.Spec{Action: "version_cap_deleted", Permission: permAccessManage, Resource: "secret_version_cap", TargetParam: "cap_id"}), h.deleteVersionCap)
	r.Handle("GET /secrets/access/rules", route.Spec{Action: "access_rules_listed", Permission: permAccessRead, Resource: "secret_access_rule"}, h.listAccessRules)
	r.Handle("POST /secrets/access/rules", warn(route.Spec{Action: "access_rule_created", Permission: permAccessManage, Resource: "secret_access_rule"}), h.createAccessRule)
	r.Handle("DELETE /secrets/access/rules/{rule_id}", warn(route.Spec{Action: "access_rule_deleted", Permission: permAccessManage, Resource: "secret_access_rule", TargetParam: "rule_id"}), h.deleteAccessRule)

	// HashiCorp Vault / OpenBao compatibility (KV v1 + KV v2 subset). The
	// namespace headers carry the tenant; the kernel enforces it like any other.
	platform := route.Spec{Permission: route.Authenticated, Tenancy: route.PlatformScoped}
	vault := func(action, perm string) route.Spec {
		return route.Spec{Action: action, Permission: perm, Resource: "secret", TenantHeaders: vaultTenantHeaders}
	}
	kv1Write := vault("vault_kv_written", permWrite)
	kv1Write.OpaqueBody = true // a KV v1 body is the secret's own data
	platform.Action = "vault_health_read"
	r.Handle("GET /v1/sys/health", platform, h.vaultSysHealth)
	platform.Action = "vault_seal_status_read"
	r.Handle("GET /v1/sys/seal-status", platform, h.vaultSealStatus)
	r.Handle("POST /v1/auth/token/lookup-self", vault("vault_token_lookup", route.Authenticated), h.vaultTokenLookupSelf)
	r.Handle("GET /v1/{mount}/data/{path...}", vault("vault_kv_read", permValueRead), h.vaultKVRead(true))
	r.Handle("POST /v1/{mount}/data/{path...}", vault("vault_kv_written", permWrite), h.vaultKVWrite(true))
	r.Handle("DELETE /v1/{mount}/data/{path...}", vault("vault_kv_deleted", permDelete), h.vaultKVDelete)
	r.Handle("GET /v1/{mount}/metadata/{path...}", vault("vault_metadata_read", permRead), h.vaultKV2Metadata)
	r.Handle("GET /v1/{mount}/{path...}", vault("vault_kv_read", permValueRead), h.vaultKVRead(false))
	r.Handle("POST /v1/{mount}/{path...}", kv1Write, h.vaultKVWrite(false))
	r.Handle("DELETE /v1/{mount}/{path...}", vault("vault_kv_deleted", permDelete), h.vaultKVDelete)
}

// fail writes a service error with the status and code that say what it was.
// A request the secret's state rules out is a refusal, audited with its
// reason; anything else is a failure under def.
func fail(c *route.Call, err error, def int, code string) {
	switch {
	case errors.Is(err, errNotFound):
		c.Error(http.StatusNotFound, code, err.Error())
	case errors.Is(err, errVersionNotFound):
		c.Error(http.StatusNotFound, "version_not_found", err.Error())
	case errors.Is(err, errExpired):
		c.Refuse(http.StatusGone, "secret_expired", err.Error())
	case errors.Is(err, errDeleted):
		c.Refuse(http.StatusGone, "secret_deleted", err.Error())
	case errors.Is(err, errNotDeleted):
		c.Refuse(http.StatusConflict, "secret_not_deleted", err.Error())
	case errors.Is(err, errVersionConflict):
		c.Refuse(http.StatusConflict, "version_conflict", err.Error())
	case errors.Is(err, errVersionCurrent):
		c.Refuse(http.StatusConflict, "version_is_current", err.Error())
	case errors.Is(err, errAlreadyCurrent):
		c.Refuse(http.StatusConflict, "already_current", err.Error())
	default:
		c.Error(def, code, err.Error())
	}
}

// actorOr records the verified caller as the author; the body's claim is
// only used when there is no verified identity.
func actorOr(c *route.Call, claimed string) string {
	if a := c.Actor(); a != "" {
		return a
	}
	return claimed
}

// policy is what decides access for one request: the tenant's rules, its
// default, and the caller.
type policy struct {
	rules       []AccessRule
	defaultDeny bool
	who         *caller
}

func (p policy) decide(path, capability string) string {
	return decide(p.rules, p.defaultDeny, p.who, path, capability)
}

func (p policy) restricted(path string) bool { return restricted(p.rules, p.defaultDeny, path) }

// policy loads the tenant's rules and settings. Without them no decision can
// be made, so a failure ends the request.
func (h *Handler) policy(c *route.Call) (policy, bool) {
	rules, err := h.svc.AccessRules(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "access_rules_unavailable", err.Error())
		return policy{}, false
	}
	settings, err := h.svc.Settings(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "access_rules_unavailable", err.Error())
		return policy{}, false
	}
	who := &caller{claims: c.Claims}
	if c.Claims != nil {
		who.groups = func() ([]string, error) {
			if h.groups == nil {
				return nil, errors.New("no access group source is configured")
			}
			return h.groups.GroupsOf(c.R.Context(), c.Tenant, c.Claims.UserID)
		}
	}
	return policy{rules: rules, defaultDeny: settings.DefaultDeny, who: who}, true
}

// allowed applies the tenant's access rules to one capability on one path
// (access.go). A refusal is written and audited with its reason, the path
// and the capability. Every route that touches a secret calls it.
func (h *Handler) allowed(c *route.Call, path, capability string) bool {
	p, ok := h.policy(c)
	return ok && permitted(c, p, path, capability)
}

func permitted(c *route.Call, p policy, path, capability string) bool {
	reason := p.decide(path, capability)
	if reason == "" {
		return true
	}
	c.Detail("path", path)
	c.Detail("capability", capability)
	switch reason {
	case reasonGroupsUnavailable: // fail closed, and say it is not a denial
		c.Refuse(http.StatusServiceUnavailable, reason, "a group access rule covers "+path+" and group membership could not be read")
	case reasonNoRule:
		c.Refuse(http.StatusForbidden, reason, "no access rule allows "+capability+" on "+path+", and this tenant denies by default")
	default:
		c.Refuse(http.StatusForbidden, reason, "an access rule on "+path+" does not allow "+capability+" for this caller")
	}
	return false
}

// secretFor loads the secret a route names and applies the access rules.
func (h *Handler) secretFor(c *route.Call, capability string) (Secret, bool) {
	secret, err := h.svc.GetSecret(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if err != nil {
		fail(c, err, http.StatusInternalServerError, "read_failed")
		return Secret{}, false
	}
	p, ok := h.policy(c)
	if !ok {
		return Secret{}, false
	}
	secret.Restricted = p.restricted(secret.Path)
	return secret, permitted(c, p, secret.Path, capability)
}

// visible returns the filter for listings: the secrets the caller may read,
// each marked with whether a rule restricts its value.
func (h *Handler) visible(c *route.Call) (func(*Secret) bool, bool) {
	p, ok := h.policy(c)
	if !ok {
		return nil, false
	}
	return func(s *Secret) bool {
		s.Restricted = p.restricted(s.Path)
		return p.decide(s.Path, capRead) == ""
	}, true
}

func (h *Handler) createSecret(c *route.Call) {
	var req CreateSecretRequest
	if !c.Decode(&req) {
		return
	}
	req.TenantID, req.CreatedBy = c.Tenant, actorOr(c, req.CreatedBy)
	c.Detail("secret_type", req.SecretType)
	if !h.allowed(c, secretPath(req.Labels, req.Name), capWrite) {
		return
	}
	// A deleted secret keeps its name until it is destroyed.
	if held, err := h.svc.GetSecretByName(c.R.Context(), c.Tenant, strings.TrimSpace(req.Name)); err == nil && held.Status != SecretStatusActive {
		c.Detail("held_by", held.ID)
		c.Refuse(http.StatusConflict, "name_held_by_deleted_secret", "a deleted secret has this name; restore or destroy it first")
		return
	}
	out, err := h.svc.CreateSecret(c.R.Context(), req)
	if err != nil {
		c.Error(http.StatusBadRequest, "create_failed", err.Error())
		return
	}
	c.Target(out.ID)
	c.Detail("path", out.Path)
	c.Detail("current_version", out.CurrentVersion)
	c.Detail("expires_at", toRFC3339(out.ExpiresAt))
	c.JSON(http.StatusCreated, map[string]interface{}{"secret": out})
}

func (h *Handler) listSecrets(c *route.Call) {
	q := c.R.URL.Query()
	secretType := strings.TrimSpace(q.Get("secret_type"))
	status := SecretStatusActive
	if q.Get("deleted") == "true" {
		status = SecretStatusDeleted
	}
	see, ok := h.visible(c)
	if !ok {
		return
	}
	marked := map[string]bool{}
	items, err := h.svc.ListVisible(c.R.Context(), c.Tenant, secretType, status, atoi(q.Get("limit")), atoi(q.Get("offset")), func(s Secret) bool {
		ok := see(&s)
		marked[s.ID] = s.Restricted
		return ok
	})
	if err != nil {
		c.Error(http.StatusInternalServerError, "list_failed", err.Error())
		return
	}
	for i := range items {
		items[i].Restricted = marked[items[i].ID]
	}
	c.Detail("count", len(items))
	c.Detail("secret_type", secretType)
	c.Detail("status", status)
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

func (h *Handler) getSecret(c *route.Call) {
	secret, ok := h.secretFor(c, capRead)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"secret": secret})
}

func (h *Handler) getSecretValue(c *route.Call) {
	q := c.R.URL.Query()
	secret, ok := h.secretFor(c, capValue)
	if !ok {
		return
	}
	out, err := h.svc.GetSecretValue(c.R.Context(), c.Tenant, secret.ID, strings.TrimSpace(strings.ToLower(q.Get("format"))), atoi(q.Get("version")))
	if err != nil {
		fail(c, err, http.StatusBadRequest, "value_read_failed")
		return
	}
	c.Detail("format", out.Format)
	c.Detail("version", out.Version)
	c.JSON(http.StatusOK, map[string]interface{}{
		"value":        out.Value,
		"version":      out.Version,
		"format":       out.Format,
		"content_type": out.ContentType,
	})
}

func (h *Handler) updateSecret(c *route.Call) {
	var req UpdateSecretRequest
	if !c.Decode(&req) {
		return
	}
	secret, ok := h.secretFor(c, capWrite)
	if !ok {
		return
	}
	// Renaming or re-labelling moves the secret: the caller needs write
	// where it lands too, or a move would be a way out of a rule.
	name, labels := secret.Name, secret.Labels
	if req.Name != nil {
		name = *req.Name
	}
	if req.Labels != nil {
		labels = *req.Labels
	}
	if moved := secretPath(labels, name); moved != secret.Path {
		c.Detail("moved_to", moved)
		if !h.allowed(c, moved, capWrite) {
			return
		}
	}
	req.UpdatedBy = actorOr(c, req.UpdatedBy)
	out, err := h.svc.UpdateSecret(c.R.Context(), c.Tenant, secret.ID, req)
	if err != nil {
		fail(c, err, http.StatusBadRequest, "update_failed")
		return
	}
	c.Detail("value_changed", req.Value != nil)
	c.Detail("current_version", out.CurrentVersion)
	pruned(c, out)
	if req.Value != nil {
		h.remediate(c, out.ID, "rotated")
	}
	c.JSON(http.StatusOK, map[string]interface{}{"secret": out})
}

func (h *Handler) deleteSecret(c *route.Call) {
	secret, ok := h.secretFor(c, capDelete)
	if !ok {
		return
	}
	if err := h.svc.DeleteSecret(c.R.Context(), c.Tenant, secret.ID, c.Actor()); err != nil {
		fail(c, err, http.StatusInternalServerError, "delete_failed")
		return
	}
	c.Detail("recoverable", true)
	c.JSON(http.StatusOK, map[string]interface{}{"status": "deleted", "recoverable": true})
}

func (h *Handler) restoreSecret(c *route.Call) {
	secret, ok := h.secretFor(c, capWrite)
	if !ok {
		return
	}
	if err := h.svc.RestoreSecret(c.R.Context(), c.Tenant, secret.ID, c.Actor()); err != nil {
		fail(c, err, http.StatusInternalServerError, "restore_failed")
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"status": "active"})
}

func (h *Handler) destroySecret(c *route.Call) {
	secret, ok := h.secretFor(c, capDelete)
	if !ok {
		return
	}
	if err := h.svc.DestroySecret(c.R.Context(), c.Tenant, secret.ID, c.Actor()); err != nil {
		fail(c, err, http.StatusInternalServerError, "destroy_failed")
		return
	}
	c.Detail("versions_destroyed", secret.CurrentVersion)
	h.remediate(c, secret.ID, "deleted")
	c.JSON(http.StatusOK, map[string]interface{}{"status": "destroyed"})
}

func (h *Handler) destroyVersion(c *route.Call) {
	version := atoi(c.R.PathValue("version"))
	c.Detail("version", version)
	secret, ok := h.secretFor(c, capDelete)
	if !ok {
		return
	}
	if version <= 0 {
		c.Error(http.StatusBadRequest, "bad_request", "version must be a positive number")
		return
	}
	if err := h.svc.DestroyVersion(c.R.Context(), c.Tenant, secret.ID, version, c.Actor()); err != nil {
		fail(c, err, http.StatusInternalServerError, "destroy_failed")
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"status": "destroyed", "version": version})
}

func (h *Handler) generateSSHKey(c *route.Call) {
	var req GenerateSSHKeyRequest
	if !c.Decode(&req) {
		return
	}
	req.TenantID, req.CreatedBy = c.Tenant, actorOr(c, req.CreatedBy)
	c.Detail("secret_type", "ssh_private_key")
	if !h.allowed(c, secretPath(req.Labels, req.Name), capWrite) {
		return
	}
	secret, pub, err := h.svc.GenerateSSHKey(c.R.Context(), req)
	if err != nil {
		c.Error(http.StatusBadRequest, "generate_failed", err.Error())
		return
	}
	c.Target(secret.ID)
	c.JSON(http.StatusCreated, map[string]interface{}{"secret": secret, "public_key": pub})
}

func (h *Handler) generateKeyPair(c *route.Call) {
	var req GenerateKeyPairRequest
	if !c.Decode(&req) {
		return
	}
	req.TenantID, req.CreatedBy = c.Tenant, actorOr(c, req.CreatedBy)
	c.Detail("key_type", req.KeyType)
	if !h.allowed(c, secretPath(req.Labels, req.Name), capWrite) {
		return
	}
	secret, pub, keyType, err := h.svc.GenerateKeyPair(c.R.Context(), req)
	if err != nil {
		c.Error(http.StatusBadRequest, "generate_failed", err.Error())
		return
	}
	c.Target(secret.ID)
	c.Detail("secret_type", secret.SecretType)
	c.JSON(http.StatusCreated, map[string]interface{}{
		"secret":      secret,
		"public_key":  pub,
		"key_type":    keyType,
		"contentType": "text/plain",
	})
}

func (h *Handler) listVersions(c *route.Call) {
	secret, ok := h.secretFor(c, capRead)
	if !ok {
		return
	}
	versions, err := h.svc.ListVersions(c.R.Context(), c.Tenant, secret.ID)
	if err != nil {
		fail(c, err, http.StatusInternalServerError, "versions_failed")
		return
	}
	c.Detail("count", len(versions))
	c.JSON(http.StatusOK, map[string]interface{}{"versions": versions})
}

func (h *Handler) secretAuditLog(c *route.Call) {
	limit := atoi(c.R.URL.Query().Get("limit"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	// The history outlives a destroyed secret, so there may be no secret to
	// load; the rules then apply to nothing and the route permission decides.
	if secret, err := h.svc.GetSecret(c.R.Context(), c.Tenant, c.R.PathValue("id")); err == nil && !h.allowed(c, secret.Path, capRead) {
		return
	}
	entries, err := h.svc.GetSecretAuditLog(c.R.Context(), c.Tenant, c.R.PathValue("id"), limit)
	if err != nil {
		c.Error(http.StatusInternalServerError, "audit_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"entries": entries})
}

func (h *Handler) rotateSecret(c *route.Call) {
	var req struct {
		Value           string `json:"value"`
		UpdatedBy       string `json:"updated_by"`
		ExpectedVersion *int   `json:"expected_version"`
	}
	if !c.Decode(&req) {
		return
	}
	if req.Value == "" {
		c.Error(http.StatusBadRequest, "bad_request", "value is required for rotation")
		return
	}
	secret, ok := h.secretFor(c, capWrite)
	if !ok {
		return
	}
	out, err := h.svc.RotateSecret(c.R.Context(), c.Tenant, secret.ID, req.Value, req.ExpectedVersion, actorOr(c, req.UpdatedBy))
	if err != nil {
		fail(c, err, http.StatusBadRequest, "rotate_failed")
		return
	}
	c.Detail("new_version", out.CurrentVersion)
	pruned(c, out)
	h.remediate(c, out.ID, "rotated")
	c.JSON(http.StatusOK, map[string]interface{}{"secret": out})
}

func (h *Handler) rollbackSecret(c *route.Call) {
	var req struct {
		Version         int  `json:"version"`
		ExpectedVersion *int `json:"expected_version"`
	}
	if !c.Decode(&req) {
		return
	}
	c.Detail("from_version", req.Version)
	secret, ok := h.secretFor(c, capWrite)
	if !ok {
		return
	}
	out, err := h.svc.Rollback(c.R.Context(), c.Tenant, secret.ID, req.Version, req.ExpectedVersion, c.Actor())
	if err != nil {
		fail(c, err, http.StatusBadRequest, "rollback_failed")
		return
	}
	c.Detail("new_version", out.CurrentVersion)
	pruned(c, out)
	c.JSON(http.StatusOK, map[string]interface{}{"secret": out})
}

// pruned records the versions the tenant's version cap removed in a write.
func pruned(c *route.Call, s Secret) {
	if s.pruned > 0 {
		c.Detail("versions_pruned", s.pruned)
	}
}

func (h *Handler) stats(c *route.Call) {
	see, ok := h.visible(c)
	if !ok {
		return
	}
	stats, err := h.svc.GetStats(c.R.Context(), c.Tenant, func(s Secret) bool { return see(&s) })
	if err != nil {
		c.Error(http.StatusInternalServerError, "stats_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"stats": stats})
}

// secretAccess answers, for one secret: which rules cover it, and what this
// caller may do to it under them.
func (h *Handler) secretAccess(c *route.Call) {
	secret, ok := h.secretFor(c, capRead)
	if !ok {
		return
	}
	p, ok := h.policy(c)
	if !ok {
		return
	}
	covering := make([]AccessRule, 0)
	for _, r := range p.rules {
		if r.covers(secret.Path) {
			covering = append(covering, r)
		}
	}
	can := map[string]bool{}
	for _, capability := range capabilities {
		can[capability] = p.decide(secret.Path, capability) == ""
	}
	maxVersions, from, err := h.svc.VersionCapFor(c.R.Context(), c.Tenant, secret.Path)
	if err != nil {
		c.Error(http.StatusInternalServerError, "settings_unavailable", err.Error())
		return
	}
	h.annotate(c, covering)
	c.JSON(http.StatusOK, map[string]interface{}{
		"path": secret.Path, "rules": covering, "caller": can, "default_deny": p.defaultDeny,
		"max_versions": maxVersions, "max_versions_from": from,
	})
}

func (h *Handler) listAccessRules(c *route.Call) {
	rules, err := h.svc.AccessRules(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "access_rules_unavailable", err.Error())
		return
	}
	c.Detail("count", len(rules))
	if missing := h.annotate(c, rules); missing > 0 {
		c.Detail("subjects_missing", missing)
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": rules})
}

func (h *Handler) getSettings(c *route.Call) {
	settings, err := h.svc.Settings(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "settings_unavailable", err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"settings": settings})
}

func (h *Handler) putSettings(c *route.Call) {
	var req struct {
		TenantID             string `json:"tenant_id"`
		DefaultDeny          bool   `json:"default_deny"`
		MaxVersions          int    `json:"max_versions"`
		DeletedRetentionDays int    `json:"deleted_retention_days"`
	}
	if !c.Decode(&req) {
		return
	}
	before, err := h.svc.Settings(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "settings_unavailable", err.Error())
		return
	}
	settings, err := h.svc.PutSettings(c.R.Context(), VaultSettings{
		TenantID: c.Tenant, DefaultDeny: req.DefaultDeny, MaxVersions: req.MaxVersions,
		DeletedRetentionDays: req.DeletedRetentionDays, UpdatedBy: c.Actor(),
	})
	if err != nil {
		c.Error(http.StatusBadRequest, "invalid_settings", err.Error())
		return
	}
	c.Detail("default_deny", settings.DefaultDeny)
	c.Detail("max_versions", settings.MaxVersions)
	c.Detail("deleted_retention_days", settings.DeletedRetentionDays)
	c.Detail("previous", map[string]interface{}{"default_deny": before.DefaultDeny, "max_versions": before.MaxVersions, "deleted_retention_days": before.DeletedRetentionDays})
	c.JSON(http.StatusOK, map[string]interface{}{"settings": settings})
}

// annotate marks each rule with whether its subject still exists where it
// is defined, and returns how many do not. A subject whose owner could not
// be asked is "unchecked", never "found".
func (h *Handler) annotate(c *route.Call, rules []AccessRule) int {
	found := map[subject]subjectInfo{}
	if h.directory != nil && len(rules) > 0 {
		subjects := make([]subject, 0, len(rules))
		for _, r := range rules {
			subjects = append(subjects, subject{r.SubjectType, r.SubjectID})
		}
		found, _ = h.directory.Lookup(c.R.Context(), c.Tenant, subjects)
	}
	missing := 0
	for i, r := range rules {
		info, checked := found[subject{r.SubjectType, r.SubjectID}]
		switch {
		case !checked:
			rules[i].SubjectStatus = subjectUnchecked
		case info.Exists:
			rules[i].SubjectStatus, rules[i].SubjectLabel = subjectFound, info.Label
		default:
			rules[i].SubjectStatus = subjectMissing
			missing++
		}
	}
	return missing
}

func (h *Handler) listVersionCaps(c *route.Call) {
	caps, err := h.svc.VersionCaps(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "version_caps_unavailable", err.Error())
		return
	}
	c.Detail("count", len(caps))
	c.JSON(http.StatusOK, map[string]interface{}{"items": caps})
}

func (h *Handler) putVersionCap(c *route.Call) {
	var req struct {
		TenantID    string `json:"tenant_id"`
		Path        string `json:"path"`
		MaxVersions int    `json:"max_versions"`
	}
	if !c.Decode(&req) {
		return
	}
	c.Detail("path", strings.TrimSpace(req.Path))
	c.Detail("max_versions", req.MaxVersions)
	out, err := h.svc.PutVersionCap(c.R.Context(), VersionCap{TenantID: c.Tenant, Path: req.Path, MaxVersions: req.MaxVersions, UpdatedBy: c.Actor()})
	if err != nil {
		c.Error(http.StatusBadRequest, "invalid_version_cap", err.Error())
		return
	}
	c.Target(out.ID)
	c.JSON(http.StatusOK, map[string]interface{}{"cap": out})
}

func (h *Handler) deleteVersionCap(c *route.Call) {
	out, err := h.svc.DeleteVersionCap(c.R.Context(), c.Tenant, c.R.PathValue("cap_id"))
	if err != nil {
		fail(c, err, http.StatusInternalServerError, "delete_failed")
		return
	}
	c.Detail("path", out.Path)
	c.Detail("max_versions", out.MaxVersions)
	c.JSON(http.StatusOK, map[string]interface{}{"status": "deleted"})
}

func ruleDetails(c *route.Call, r AccessRule) {
	c.Detail("path", r.Path)
	c.Detail("subject", r.SubjectType+":"+r.SubjectID)
	c.Detail("capabilities", strings.Join(r.Capabilities, ","))
	c.Detail("effect", r.Effect)
}

func (h *Handler) createAccessRule(c *route.Call) {
	var req struct {
		TenantID     string   `json:"tenant_id"`
		Path         string   `json:"path"`
		SubjectType  string   `json:"subject_type"`
		SubjectID    string   `json:"subject_id"`
		Capabilities []string `json:"capabilities"`
		Effect       string   `json:"effect"`
	}
	if !c.Decode(&req) {
		return
	}
	draft, err := normalizeRule(AccessRule{
		TenantID: c.Tenant, Path: req.Path, SubjectType: req.SubjectType, SubjectID: req.SubjectID,
		Capabilities: req.Capabilities, Effect: req.Effect, CreatedBy: c.Actor(),
	})
	if err != nil {
		c.Error(http.StatusBadRequest, "invalid_access_rule", err.Error())
		return
	}
	// The subject must exist where it is defined. If that cannot be checked,
	// the rule is refused rather than stored unverified.
	who := subject{draft.SubjectType, draft.SubjectID}
	c.Detail("subject", who.Type+":"+who.ID)
	var known map[subject]subjectInfo
	if h.directory != nil {
		known, _ = h.directory.Lookup(c.R.Context(), c.Tenant, []subject{who})
	}
	info, checked := known[who]
	if !checked {
		c.Refuse(http.StatusServiceUnavailable, "subject_check_unavailable", "could not check that "+who.Type+" "+who.ID+" exists; the rule was not stored")
		return
	}
	if !info.Exists {
		c.Refuse(http.StatusBadRequest, "unknown_subject", "no "+who.Type+" "+who.ID+" in this tenant")
		return
	}
	rule, err := h.svc.CreateAccessRule(c.R.Context(), draft)
	if err != nil {
		c.Error(http.StatusBadRequest, "invalid_access_rule", err.Error())
		return
	}
	rule.SubjectStatus, rule.SubjectLabel = subjectFound, info.Label
	c.Target(rule.ID)
	ruleDetails(c, rule)
	c.JSON(http.StatusCreated, map[string]interface{}{"rule": rule})
}

func (h *Handler) deleteAccessRule(c *route.Call) {
	rule, err := h.svc.DeleteAccessRule(c.R.Context(), c.Tenant, c.R.PathValue("rule_id"))
	if err != nil {
		fail(c, err, http.StatusInternalServerError, "delete_failed")
		return
	}
	ruleDetails(c, rule)
	c.JSON(http.StatusOK, map[string]interface{}{"status": "deleted"})
}

// vaultSysHealth and vaultSealStatus answer Vault/OpenBao clients' readiness
// probes with what is true here: the service is up and serving, so it is
// initialized and unsealed. Vecta has no Shamir unseal, replication or
// cluster identity, so none is reported.
func (h *Handler) vaultSysHealth(c *route.Call) {
	c.JSON(http.StatusOK, map[string]interface{}{
		"initialized":     true,
		"sealed":          false,
		"standby":         false,
		"server_time_utc": time.Now().UTC().Unix(),
		"version":         "openbao-compatible-v1",
	})
}

func (h *Handler) vaultSealStatus(c *route.Call) {
	c.JSON(http.StatusOK, map[string]interface{}{
		"initialized": true,
		"sealed":      false,
		"version":     "openbao-compatible-v1",
	})
}

// vaultTokenLookupSelf reports what the verified token says. Vecta has no
// Vault policies or token accessors, so none are invented: policies carries
// the token's own permissions, and the times are the token's.
func (h *Handler) vaultTokenLookupSelf(c *route.Call) {
	data := map[string]interface{}{
		"id":           c.Actor(),
		"display_name": c.Actor(),
		"policies":     []string{},
		"meta":         map[string]interface{}{"tenant_id": c.Tenant},
		"renewable":    false,
	}
	if claims, ok := pkgauth.ClaimsFromContext(c.R.Context()); ok && claims != nil {
		if claims.Permissions != nil {
			data["policies"] = claims.Permissions
		}
		if claims.IssuedAt != nil {
			data["creation_time"] = claims.IssuedAt.Unix()
		}
		if claims.ExpiresAt != nil {
			data["expire_time"] = claims.ExpiresAt.UTC().Format(time.RFC3339)
			data["ttl"] = max(0, int64(time.Until(claims.ExpiresAt.Time).Seconds()))
		}
	}
	c.JSON(http.StatusOK, map[string]interface{}{"data": data})
}

// rootMount is the KV mount whose paths are secret names as they are. Any
// other mount is the first segment of the name, so /v1/a/x and /v1/b/x are
// different secrets (a/x and b/x), and /v1/secret/data/a/x is the first.
const rootMount = "secret"

// vaultPath returns the name of the secret a KV request addresses, recording
// the mount and path in the audit event.
func vaultPath(c *route.Call) (string, bool) {
	mount := strings.Trim(strings.TrimSpace(c.R.PathValue("mount")), "/")
	path := strings.Trim(strings.TrimSpace(c.R.PathValue("path")), "/")
	if path == "" || mount == "" {
		c.Error(http.StatusBadRequest, "bad_request", "mount and path are required")
		return "", false
	}
	c.Detail("mount", mount)
	c.Detail("path", path)
	if mount == rootMount {
		return path, true
	}
	return mount + "/" + path, true
}

// vaultSecret loads the secret a KV path names and applies the access rules,
// the same decision the /secrets routes use.
func (h *Handler) vaultSecret(c *route.Call, capability, code string) (Secret, bool) {
	path, ok := vaultPath(c)
	if !ok {
		return Secret{}, false
	}
	secret, err := h.svc.GetSecretByName(c.R.Context(), c.Tenant, path)
	if err != nil {
		fail(c, err, http.StatusInternalServerError, code)
		return Secret{}, false
	}
	c.Target(secret.ID)
	return secret, h.allowed(c, secret.Path, capability)
}

func (h *Handler) vaultKVRead(kv2 bool) func(*route.Call) {
	return func(c *route.Call) {
		secret, ok := h.vaultSecret(c, capValue, "read_failed")
		if !ok {
			return
		}
		if secret.Status != SecretStatusActive { // Vault answers 404 for a deleted path
			c.Error(http.StatusNotFound, "read_failed", errNotFound.Error())
			return
		}
		valueOut, err := h.svc.GetSecretValue(c.R.Context(), c.Tenant, secret.ID, "raw", atoi(c.R.URL.Query().Get("version")))
		if err != nil {
			fail(c, err, http.StatusBadRequest, "value_read_failed")
			return
		}
		c.Detail("version", valueOut.Version)
		dataMap := parseVaultDataMap(valueOut.Value)
		payload := map[string]interface{}{"lease_id": "", "renewable": false, "lease_duration": 0, "data": dataMap}
		if kv2 {
			payload["data"] = map[string]interface{}{
				"data": dataMap,
				"metadata": map[string]interface{}{
					"created_time":  secret.CreatedAt.UTC().Format(time.RFC3339),
					"updated_time":  secret.UpdatedAt.UTC().Format(time.RFC3339),
					"deletion_time": "",
					"destroyed":     false,
					"version":       valueOut.Version,
				},
			}
		}
		c.JSON(http.StatusOK, payload)
	}
}

func (h *Handler) vaultKVWrite(kv2 bool) func(*route.Call) {
	return func(c *route.Call) {
		path, ok := vaultPath(c)
		if !ok {
			return
		}
		data, err := decodeVaultWriteData(c, kv2)
		if err != nil {
			c.Error(http.StatusBadRequest, "bad_request", err.Error())
			return
		}
		value := encodeVaultDataValue(data)
		author := actorOr(c, "vault-client")
		secret, err := h.svc.GetSecretByName(c.R.Context(), c.Tenant, path)
		var written Secret
		switch {
		case errors.Is(err, errNotFound):
			createReq := CreateSecretRequest{
				TenantID:    c.Tenant,
				Name:        path,
				SecretType:  "api_key",
				Value:       value,
				Description: "vault-compatible secret",
				CreatedBy:   author,
				Metadata:    map[string]interface{}{"vault_compat": true, "mount": strings.TrimSpace(c.R.PathValue("mount"))},
			}
			if !h.allowed(c, secretPath(nil, path), capWrite) {
				return
			}
			created, createErr := h.svc.CreateSecret(c.R.Context(), createReq)
			if createErr != nil {
				c.Error(http.StatusBadRequest, "create_failed", createErr.Error())
				return
			}
			written = created
			c.Target(created.ID)
			c.Detail("created", true)
		case err != nil:
			c.Error(http.StatusInternalServerError, "write_failed", err.Error())
			return
		default:
			c.Target(secret.ID)
			c.Detail("created", false)
			if !h.allowed(c, secret.Path, capWrite) {
				return
			}
			// As in Vault, writing to a deleted path brings it back.
			if secret.Status != SecretStatusActive {
				if err := h.svc.RestoreSecret(c.R.Context(), c.Tenant, secret.ID, author); err != nil {
					fail(c, err, http.StatusInternalServerError, "restore_failed")
					return
				}
				c.Detail("restored", true)
			}
			if written, err = h.svc.UpdateSecret(c.R.Context(), c.Tenant, secret.ID, UpdateSecretRequest{Value: ptrString(value), UpdatedBy: author}); err != nil {
				fail(c, err, http.StatusBadRequest, "update_failed")
				return
			}
			h.remediate(c, secret.ID, "rotated")
		}
		c.Detail("current_version", written.CurrentVersion)
		pruned(c, written)
		// The version this write produced, as KV v2 reports it.
		c.JSON(http.StatusOK, map[string]interface{}{"data": map[string]interface{}{
			"created_time":  written.UpdatedAt.UTC().Format(time.RFC3339),
			"deletion_time": "",
			"destroyed":     false,
			"version":       written.CurrentVersion,
		}})
	}
}

// vaultKVDelete is a recoverable delete, as KV v2's is: the versions stay
// until the secret is destroyed (POST /secrets/{id}/destroy).
func (h *Handler) vaultKVDelete(c *route.Call) {
	secret, ok := h.vaultSecret(c, capDelete, "delete_failed")
	if !ok {
		return
	}
	if err := h.svc.DeleteSecret(c.R.Context(), c.Tenant, secret.ID, c.Actor()); err != nil {
		fail(c, err, http.StatusInternalServerError, "delete_failed")
		return
	}
	c.Detail("recoverable", true)
	c.W.WriteHeader(http.StatusNoContent)
}

func (h *Handler) vaultKV2Metadata(c *route.Call) {
	secret, ok := h.vaultSecret(c, capRead, "read_failed")
	if !ok {
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{
		"data": map[string]interface{}{
			"created_time":         secret.CreatedAt.UTC().Format(time.RFC3339),
			"updated_time":         secret.UpdatedAt.UTC().Format(time.RFC3339),
			"deletion_time":        toRFC3339(secret.DeletedAt),
			"max_versions":         0,
			"current_version":      secret.CurrentVersion,
			"cas_required":         false,
			"delete_version_after": "0s",
		},
	})
}

func decodeVaultWriteData(c *route.Call, kv2 bool) (map[string]interface{}, error) {
	if kv2 {
		var body struct {
			Data map[string]interface{} `json:"data"`
		}
		if err := json.NewDecoder(c.R.Body).Decode(&body); err != nil {
			return nil, err
		}
		if len(body.Data) == 0 {
			return nil, errors.New("data is required")
		}
		return body.Data, nil
	}
	var body map[string]interface{}
	if err := json.NewDecoder(c.R.Body).Decode(&body); err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, errors.New("request body is required")
	}
	return body, nil
}

func atoi(v string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(v))
	return n
}

func parseVaultDataMap(raw string) map[string]interface{} {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return map[string]interface{}{"value": ""}
	}
	var obj map[string]interface{}
	if json.Unmarshal([]byte(trimmed), &obj) == nil && obj != nil {
		return obj
	}
	return map[string]interface{}{"value": raw}
}

func encodeVaultDataValue(data map[string]interface{}) string {
	if len(data) == 1 {
		if v, ok := data["value"]; ok {
			return stringifyVaultValue(v)
		}
	}
	out, err := json.Marshal(data)
	if err != nil {
		return "{}"
	}
	return string(out)
}

func stringifyVaultValue(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case []byte:
		return string(t)
	default:
		raw, err := json.Marshal(v)
		if err != nil {
			return ""
		}
		return string(raw)
	}
}

func ptrString(v string) *string {
	return &v
}
