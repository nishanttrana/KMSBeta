package main

import (
	"context"
	"errors"
	"log"
	"net/http"

	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/tenantcheck"
)

// Administration of REST client credentials (Workbench → REST API). The
// route kernel authenticates, enforces tenant and permission, and audits
// each call and refusal as audit.auth.<action>. Platform service identities
// (kms-*) are provisioned from the bootstrap secret and are never revoked or
// rotated here: auth's next start would re-derive them anyway, and until then
// the service would be locked out.

const reasonClientState = "client_state"

// clientKeyPermissions are what an activated REST client's API key holds.
var clientKeyPermissions = []string{"kms.read", "kms.write"}

func (h *Handler) clientAdminRouter() *route.Router {
	r := route.New("auth", kernelEmitter{h}, h.logger)
	r.Handle("POST /auth/clients/{id}/revoke", route.Spec{Action: "client_revoked", Permission: "auth.client.write", Resource: "client", TargetParam: "id", Severity: "warning"}, h.revokeClient)
	r.Handle("POST /auth/clients/{id}/rotate-key", route.Spec{Action: "client_key_rotated", Permission: "auth.client.write", Resource: "client", TargetParam: "id", Severity: "warning"}, h.rotateClientKey)
	r.Handle("DELETE /auth/api-keys/{id}", route.Spec{Action: "api_key_revoked", Permission: "auth.api_key.write", Resource: "api_key", TargetParam: "id", Severity: "warning"}, h.deleteAPIKey)
	return r
}

// clientForAdmin reads the client and refuses platform service identities.
func (h *Handler) clientForAdmin(c *route.Call) (ClientRegistration, bool) {
	reg, err := h.store.GetClientRegistration(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if errors.Is(err, errNotFound) {
		c.Error(http.StatusNotFound, "not_found", "client not found")
		return reg, false
	} else if err != nil {
		c.Error(http.StatusInternalServerError, "store_error", "failed to read client")
		return reg, false
	}
	c.Detail("client_name", reg.ClientName)
	if serviceIdentityName(reg.ID) || serviceIdentityName(reg.ClientName) {
		c.Refuse(http.StatusConflict, reasonServiceIdentityTarget, "a platform service identity is managed by the platform")
		return reg, false
	}
	return reg, true
}

func (h *Handler) revokeClient(c *route.Call) {
	reg, ok := h.clientForAdmin(c)
	if !ok {
		return
	}
	if err := h.store.RevokeClientRegistration(c.R.Context(), c.Tenant, reg.ID); err != nil {
		c.Error(http.StatusInternalServerError, "store_error", "failed to revoke client")
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"status": "revoked", "client_id": reg.ID})
}

func (h *Handler) rotateClientKey(c *route.Call) {
	reg, ok := h.clientForAdmin(c)
	if !ok {
		return
	}
	if reg.Status != "approved" {
		c.Refuse(http.StatusConflict, reasonClientState, "only an approved client has a key to rotate (status "+reg.Status+")")
		return
	}
	rawKey, hash, prefix, err := GenerateAPIKey()
	if err != nil {
		c.Error(http.StatusInternalServerError, "key_generation_failed", "failed to rotate key")
		return
	}
	defer pkgcrypto.Zeroize(hash)
	key := APIKey{
		ID: NewID("api"), TenantID: c.Tenant, ClientID: reg.ID, KeyHash: hash, KeyPrefix: prefix,
		Name: "client:" + reg.ID, Permissions: clientKeyPermissions,
	}
	if err := h.store.RotateClientAPIKey(c.R.Context(), c.Tenant, reg.ID, key); errors.Is(err, errClientState) {
		c.Refuse(http.StatusConflict, reasonClientState, err.Error())
		return
	} else if err != nil {
		c.Error(http.StatusInternalServerError, "store_error", "failed to rotate key")
		return
	}
	if h.meter != nil {
		_ = h.meter.IncrementOps()
	}
	c.Detail("api_key_prefix", prefix)
	c.JSON(http.StatusOK, map[string]interface{}{"api_key": rawKey, "api_key_prefix": prefix})
}

func (h *Handler) deleteAPIKey(c *route.Call) {
	key, err := h.store.GetAPIKeyByID(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if errors.Is(err, errNotFound) {
		c.Error(http.StatusNotFound, "not_found", "api key not found")
		return
	} else if err != nil {
		c.Error(http.StatusInternalServerError, "store_error", "failed to read api key")
		return
	}
	if serviceIdentityName(key.ClientID) || len(tenantcheck.StripReserved(key.Permissions)) != len(key.Permissions) {
		c.Refuse(http.StatusConflict, reasonServiceIdentityTarget, "a platform service key is managed by the platform")
		return
	}
	if err := h.store.DeleteAPIKey(c.R.Context(), c.Tenant, key.ID); err != nil {
		c.Error(http.StatusInternalServerError, "store_error", "failed to delete api key")
		return
	}
	c.Detail("client_id", key.ClientID)
	c.JSON(http.StatusOK, map[string]interface{}{"status": "revoked", "api_key_id": key.ID})
}

// retireUnboundAPIKeys deletes API keys bound to no client. Only the removed
// POST /auth/api-keys minted them, with whatever permissions its caller
// named; /auth/client-token never accepted them, but a key the product no
// longer issues must not outlive its endpoint (CLAUDE.md rule 3). Runs on
// the node that runs primary jobs; members receive the deletion by
// replication. Idempotent: nothing left, nothing emitted.
func retireUnboundAPIKeys(ctx context.Context, store Store, logger *log.Logger, audit AuditPublisher) {
	tenants, err := store.ListTenants(ctx)
	if err != nil {
		logger.Printf("bootstrap: list tenants for unbound api key retirement: %v", err)
		return
	}
	for _, t := range tenants {
		n, err := store.DeleteUnboundAPIKeys(ctx, t.ID)
		if err != nil {
			logger.Printf("bootstrap: retire unbound api keys tenant=%s: %v", t.ID, err)
			continue
		}
		if n == 0 {
			continue
		}
		logger.Printf("bootstrap: SECURITY retired %d unbound api key(s) tenant=%s", n, t.ID)
		bootstrapAudit(ctx, audit, "audit.auth.unbound_api_keys_retired", t.ID, map[string]any{
			"keys_deleted": n, "reason": "endpoint_removed", "severity": "warning", "result": "success",
			"description": "API keys from the removed POST /auth/api-keys (bound to no client) were deleted",
		})
	}
}
