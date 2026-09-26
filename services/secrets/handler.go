package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"vecta-kms/pkg/route"
)

// Handler serves the secrets API. Every route is registered through the
// pkg/route kernel, which authenticates the caller, enforces the tenant and
// the route's permission, and emits one audit.secrets.<action> event per
// request, refusals included. Handlers only add domain details.
type Handler struct {
	svc    *Service
	router *route.Router
}

// Permissions for the secrets domain. kms.read grants the *.read ones and
// kms.write the rest (see route.Allowed).
const (
	permRead      = "secrets.read"       // metadata, versions, stats
	permValueRead = "secrets.value.read" // reveals a secret value
	permWrite     = "secrets.write"      // create, update, rotate, generate
	permDelete    = "secrets.delete"
)

var vaultTenantHeaders = []string{"X-Vault-Namespace", "X-Namespace"}

func NewHandler(svc *Service, audit route.Emitter, logger *log.Logger) *Handler {
	h := &Handler{svc: svc, router: route.New("secrets", audit, logger)}
	h.routes()
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.router.ServeHTTP(w, r)
}

func (h *Handler) routes() {
	r := h.router
	secret := func(action, perm string) route.Spec {
		return route.Spec{Action: action, Permission: perm, Resource: "secret", TargetParam: "id"}
	}
	r.Handle("POST /secrets", route.Spec{Action: "created", Permission: permWrite, Resource: "secret"}, h.createSecret)
	r.Handle("GET /secrets", route.Spec{Action: "listed", Permission: permRead, Resource: "secret"}, h.listSecrets)
	r.Handle("GET /secrets/{id}", secret("read", permRead), h.getSecret)
	r.Handle("GET /secrets/{id}/value", route.Spec{Action: "value_read", Permission: permValueRead, Resource: "secret", TargetParam: "id", Severity: "warning"}, h.getSecretValue)
	r.Handle("PUT /secrets/{id}", secret("updated", permWrite), h.updateSecret)
	r.Handle("DELETE /secrets/{id}", route.Spec{Action: "deleted", Permission: permDelete, Resource: "secret", TargetParam: "id", Severity: "warning"}, h.deleteSecret)
	r.Handle("POST /secrets/generate/ssh_key", route.Spec{Action: "generated", Permission: permWrite, Resource: "secret"}, h.generateSSHKey)
	r.Handle("POST /secrets/generate/keypair", route.Spec{Action: "generated", Permission: permWrite, Resource: "secret"}, h.generateKeyPair)
	r.Handle("GET /secrets/{id}/versions", secret("versions_listed", permRead), h.listVersions)
	r.Handle("GET /secrets/{id}/audit", secret("audit_log_read", permRead), h.secretAuditLog)
	r.Handle("POST /secrets/{id}/rotate", secret("rotated", permWrite), h.rotateSecret)
	r.Handle("GET /secrets/stats", route.Spec{Action: "stats_read", Permission: permRead}, h.stats)

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

// statusOf maps service errors to HTTP status, def for anything unclassified.
func statusOf(err error, def int) int {
	switch {
	case errors.Is(err, errNotFound):
		return http.StatusNotFound
	case errors.Is(err, errExpired):
		return http.StatusGone
	}
	return def
}

// actorOr records the verified caller as the author; the body's claim is
// only used when there is no verified identity.
func actorOr(c *route.Call, claimed string) string {
	if a := c.Actor(); a != "" {
		return a
	}
	return claimed
}

func (h *Handler) createSecret(c *route.Call) {
	var req CreateSecretRequest
	if !c.Decode(&req) {
		return
	}
	req.TenantID, req.CreatedBy = c.Tenant, actorOr(c, req.CreatedBy)
	c.Detail("secret_type", req.SecretType)
	out, err := h.svc.CreateSecret(c.R.Context(), req)
	if err != nil {
		c.Error(http.StatusBadRequest, "create_failed", err.Error())
		return
	}
	c.Target(out.ID)
	c.Detail("current_version", out.CurrentVersion)
	c.Detail("expires_at", toRFC3339(out.ExpiresAt))
	c.JSON(http.StatusCreated, map[string]interface{}{"secret": out})
}

func (h *Handler) listSecrets(c *route.Call) {
	q := c.R.URL.Query()
	secretType := strings.TrimSpace(q.Get("secret_type"))
	items, err := h.svc.ListSecrets(c.R.Context(), c.Tenant, secretType, atoi(q.Get("limit")), atoi(q.Get("offset")))
	if err != nil {
		c.Error(http.StatusInternalServerError, "list_failed", err.Error())
		return
	}
	c.Detail("count", len(items))
	c.Detail("secret_type", secretType)
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

func (h *Handler) getSecret(c *route.Call) {
	secret, err := h.svc.GetSecret(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if err != nil {
		c.Error(statusOf(err, http.StatusInternalServerError), "read_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"secret": secret})
}

func (h *Handler) getSecretValue(c *route.Call) {
	format := strings.TrimSpace(strings.ToLower(c.R.URL.Query().Get("format")))
	out, err := h.svc.GetSecretValue(c.R.Context(), c.Tenant, c.R.PathValue("id"), format)
	if err != nil {
		status, code := statusOf(err, http.StatusBadRequest), "value_read_failed"
		switch status {
		case http.StatusGone:
			code = "secret_expired"
		case http.StatusNotFound:
			code = "not_found"
		}
		c.Error(status, code, err.Error())
		return
	}
	c.Detail("format", out.Format)
	c.JSON(http.StatusOK, map[string]interface{}{
		"value":        out.Value,
		"format":       out.Format,
		"content_type": out.ContentType,
	})
}

func (h *Handler) updateSecret(c *route.Call) {
	var req UpdateSecretRequest
	if !c.Decode(&req) {
		return
	}
	req.UpdatedBy = actorOr(c, req.UpdatedBy)
	out, err := h.svc.UpdateSecret(c.R.Context(), c.Tenant, c.R.PathValue("id"), req)
	if err != nil {
		c.Error(statusOf(err, http.StatusBadRequest), "update_failed", err.Error())
		return
	}
	c.Detail("value_changed", req.Value != nil)
	c.Detail("current_version", out.CurrentVersion)
	c.JSON(http.StatusOK, map[string]interface{}{"secret": out})
}

func (h *Handler) deleteSecret(c *route.Call) {
	if err := h.svc.DeleteSecret(c.R.Context(), c.Tenant, c.R.PathValue("id")); err != nil {
		c.Error(statusOf(err, http.StatusInternalServerError), "delete_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"status": "deleted"})
}

func (h *Handler) generateSSHKey(c *route.Call) {
	var req GenerateSSHKeyRequest
	if !c.Decode(&req) {
		return
	}
	req.TenantID, req.CreatedBy = c.Tenant, actorOr(c, req.CreatedBy)
	c.Detail("secret_type", "ssh_private_key")
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
	versions, err := h.svc.ListVersions(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if err != nil {
		c.Error(statusOf(err, http.StatusInternalServerError), "versions_failed", err.Error())
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
	entries, err := h.svc.GetSecretAuditLog(c.R.Context(), c.Tenant, c.R.PathValue("id"), limit)
	if err != nil {
		c.Error(http.StatusInternalServerError, "audit_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"entries": entries})
}

func (h *Handler) rotateSecret(c *route.Call) {
	var req struct {
		Value     string `json:"value"`
		UpdatedBy string `json:"updated_by"`
	}
	if !c.Decode(&req) {
		return
	}
	if req.Value == "" {
		c.Error(http.StatusBadRequest, "bad_request", "value is required for rotation")
		return
	}
	out, err := h.svc.RotateSecret(c.R.Context(), c.Tenant, c.R.PathValue("id"), req.Value, actorOr(c, req.UpdatedBy))
	if err != nil {
		c.Error(statusOf(err, http.StatusBadRequest), "rotate_failed", err.Error())
		return
	}
	c.Detail("new_version", out.CurrentVersion)
	c.JSON(http.StatusOK, map[string]interface{}{"secret": out})
}

func (h *Handler) stats(c *route.Call) {
	stats, err := h.svc.GetStats(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "stats_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"stats": stats})
}

func (h *Handler) vaultSysHealth(c *route.Call) {
	c.JSON(http.StatusOK, map[string]interface{}{
		"initialized":                  true,
		"sealed":                       false,
		"standby":                      false,
		"performance_standby":          false,
		"replication_performance_mode": "disabled",
		"replication_dr_mode":          "disabled",
		"server_time_utc":              time.Now().UTC().Unix(),
		"version":                      "openbao-compatible-v1",
		"cluster_name":                 "vecta-kms",
		"cluster_id":                   "vecta-kms-local",
	})
}

func (h *Handler) vaultSealStatus(c *route.Call) {
	c.JSON(http.StatusOK, map[string]interface{}{
		"type":          "shamir",
		"initialized":   true,
		"sealed":        false,
		"t":             1,
		"n":             1,
		"progress":      0,
		"nonce":         "",
		"version":       "openbao-compatible-v1",
		"build_date":    time.Now().UTC().Format(time.RFC3339),
		"recovery_seal": false,
	})
}

func (h *Handler) vaultTokenLookupSelf(c *route.Call) {
	c.JSON(http.StatusOK, map[string]interface{}{
		"data": map[string]interface{}{
			"id":            c.Actor(),
			"display_name":  "token",
			"policies":      []string{"default"},
			"meta":          map[string]interface{}{"tenant_id": c.Tenant},
			"path":          "auth/token/create",
			"orphan":        true,
			"renewable":     false,
			"ttl":           0,
			"creation_time": time.Now().UTC().Unix(),
			"expire_time":   nil,
		},
	})
}

// vaultPath returns the KV path, recording it as the audit target.
func vaultPath(c *route.Call) (string, bool) {
	path := strings.TrimSpace(c.R.PathValue("path"))
	if path == "" {
		c.Error(http.StatusBadRequest, "bad_request", "path is required")
		return "", false
	}
	c.Detail("mount", c.R.PathValue("mount"))
	c.Detail("path", path)
	return path, true
}

func (h *Handler) vaultKVRead(kv2 bool) func(*route.Call) {
	return func(c *route.Call) {
		path, ok := vaultPath(c)
		if !ok {
			return
		}
		secret, err := h.svc.GetSecretByName(c.R.Context(), c.Tenant, path)
		if err != nil {
			c.Error(statusOf(err, http.StatusInternalServerError), "read_failed", err.Error())
			return
		}
		c.Target(secret.ID)
		valueOut, err := h.svc.GetSecretValue(c.R.Context(), c.Tenant, secret.ID, "raw")
		if err != nil {
			if errors.Is(err, errExpired) {
				c.Error(http.StatusGone, "secret_expired", err.Error())
				return
			}
			c.Error(http.StatusBadRequest, "value_read_failed", err.Error())
			return
		}
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
					"version":       secret.CurrentVersion,
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
		switch {
		case errors.Is(err, errNotFound):
			created, createErr := h.svc.CreateSecret(c.R.Context(), CreateSecretRequest{
				TenantID:    c.Tenant,
				Name:        path,
				SecretType:  "api_key",
				Value:       value,
				Description: "vault-compatible secret",
				CreatedBy:   author,
				Metadata:    map[string]interface{}{"vault_compat": true, "mount": strings.TrimSpace(c.R.PathValue("mount"))},
			})
			if createErr != nil {
				c.Error(http.StatusBadRequest, "create_failed", createErr.Error())
				return
			}
			c.Target(created.ID)
			c.Detail("created", true)
		case err != nil:
			c.Error(http.StatusInternalServerError, "write_failed", err.Error())
			return
		default:
			c.Target(secret.ID)
			c.Detail("created", false)
			if _, err := h.svc.UpdateSecret(c.R.Context(), c.Tenant, secret.ID, UpdateSecretRequest{Value: ptrString(value), UpdatedBy: author}); err != nil {
				c.Error(http.StatusBadRequest, "update_failed", err.Error())
				return
			}
		}
		c.JSON(http.StatusOK, map[string]interface{}{"data": map[string]interface{}{"created": true}})
	}
}

func (h *Handler) vaultKVDelete(c *route.Call) {
	path, ok := vaultPath(c)
	if !ok {
		return
	}
	secret, err := h.svc.GetSecretByName(c.R.Context(), c.Tenant, path)
	if err != nil {
		c.Error(statusOf(err, http.StatusInternalServerError), "delete_failed", err.Error())
		return
	}
	c.Target(secret.ID)
	if err := h.svc.DeleteSecret(c.R.Context(), c.Tenant, secret.ID); err != nil {
		c.Error(statusOf(err, http.StatusInternalServerError), "delete_failed", err.Error())
		return
	}
	c.W.WriteHeader(http.StatusNoContent)
}

func (h *Handler) vaultKV2Metadata(c *route.Call) {
	path, ok := vaultPath(c)
	if !ok {
		return
	}
	secret, err := h.svc.GetSecretByName(c.R.Context(), c.Tenant, path)
	if err != nil {
		c.Error(statusOf(err, http.StatusInternalServerError), "read_failed", err.Error())
		return
	}
	c.Target(secret.ID)
	c.JSON(http.StatusOK, map[string]interface{}{
		"data": map[string]interface{}{
			"created_time":         secret.CreatedAt.UTC().Format(time.RFC3339),
			"updated_time":         secret.UpdatedAt.UTC().Format(time.RFC3339),
			"max_versions":         0,
			"current_version":      secret.CurrentVersion,
			"oldest_version":       1,
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
