package main

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"

	pkgaudit "vecta-kms/pkg/audit"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/tenantcheck"
)

// System keys: each platform service that stores encrypted data (secrets,
// certs, cloud, ekm) keeps its master key in keycore. That master key is
// derived through service-derive from one symmetric key per
// (service, purpose), held in the internal service tenant. The service
// calls POST /system-keys/ensure to get that key (created on first use),
// and only a verified service identity may call it, for itself.
//
// Every value the service stores depends on the key, so keycore refuses,
// at the storage layer, anything that would make it unusable: destroy
// (immediate, scheduled, bulk or the purge sweep), disable, deleting a
// version, and allowing export. Rotation is allowed; the service re-wraps
// onto the new version (pkg/mek). docs/SECURITY/SERVICE_MASTER_KEYS.md

var errSystemKeyProtected = errors.New("system key: a platform service's stored data depends on it, so it can't be destroyed, disabled, deleted, have a version deleted or be made exportable")

// SystemKey is the keycore key a service's master key is derived from.
type SystemKey struct {
	KeyID    string `json:"key_id"`
	TenantID string `json:"tenant_id"`
	Version  int    `json:"version"`
	Created  bool   `json:"created"`
}

// EnsureSystemKey returns the calling service's system key for purpose,
// creating it on first use. The service comes from the verified identity.
func (s *Service) EnsureSystemKey(ctx context.Context, purpose string) (SystemKey, error) {
	actor := accessActorFromContext(ctx)
	clientID := strings.TrimSpace(actor.ClientID)
	if !actorIsServicePrincipal(actor) || !strings.HasPrefix(clientID, "kms-") {
		return SystemKey{}, errServiceIdentityRequired
	}
	purpose = strings.ToLower(strings.TrimSpace(purpose))
	if !serviceDerivePurposeRE.MatchString(purpose) {
		return SystemKey{}, errors.New("a purpose of [a-z0-9-] is required")
	}
	tenant := tenantcheck.InternalServiceTenant()
	lookup := func() (SystemKey, bool, error) {
		id, found, err := s.store.GetSystemKey(ctx, clientID, purpose)
		if err != nil || !found {
			return SystemKey{}, found, err
		}
		key, err := s.GetKey(ctx, tenant, id)
		if err != nil {
			return SystemKey{}, true, err
		}
		return SystemKey{KeyID: key.ID, TenantID: tenant, Version: key.CurrentVersion}, true, nil
	}
	if sk, found, err := lookup(); found || err != nil {
		return sk, err
	}
	key, err := s.CreateKey(ctx, CreateKeyRequest{
		TenantID:  tenant,
		Name:      "system/" + clientID + "/" + purpose,
		Algorithm: "AES-256",
		KeyType:   "symmetric",
		Purpose:   "encrypt",
		Owner:     clientID,
		CreatedBy: clientID,
		Labels:    map[string]string{"vecta.system": "true", "vecta.system.service": clientID, "vecta.system.purpose": purpose},
	})
	if err != nil {
		return SystemKey{}, err
	}
	if err := s.store.InsertSystemKey(ctx, clientID, purpose, tenant, key.ID); err != nil {
		return SystemKey{}, err
	}
	sk, _, err := lookup() // another instance may have won the insert
	if err != nil {
		return SystemKey{}, err
	}
	sk.Created = sk.KeyID == key.ID
	if sk.Created {
		_ = s.publishAudit(ctx, "audit.key.system_key_created", tenant, map[string]any{
			"key_id": key.ID, "service": clientID, "purpose": purpose, "severity": "info",
			"description": "platform service master key created (protected from destroy, disable and export)",
		})
	}
	return sk, nil
}

// storage ------------------------------------------------------------------

func (s *SQLStore) GetSystemKey(ctx context.Context, clientID, purpose string) (string, bool, error) {
	var id string
	err := s.db.SQL().QueryRowContext(ctx, `SELECT key_id FROM keycore_system_keys WHERE client_id=$1 AND purpose=$2`, clientID, purpose).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return id, err == nil, err
}

func (s *SQLStore) InsertSystemKey(ctx context.Context, clientID, purpose, tenantID, keyID string) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO keycore_system_keys (client_id, purpose, tenant_id, key_id, created_at)
VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)
ON CONFLICT (client_id, purpose) DO NOTHING`, clientID, purpose, tenantID, keyID)
	return err
}

type rowQueryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// guardSystemKey refuses op on a system key, and audits the refusal.
func (s *SQLStore) guardSystemKey(ctx context.Context, q rowQueryer, tenantID, keyID, op string) error {
	var n int
	if err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM keycore_system_keys WHERE tenant_id=$1 AND key_id=$2`, tenantID, keyID).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	if s.onSystemKeyRefused != nil {
		s.onSystemKeyRefused(ctx, tenantID, keyID, op)
	}
	return errSystemKeyProtected
}

// guardSystemKeyStatus allows the statuses under which service-derive still
// works (active, deactivated) and refuses every other one on a system key.
func (s *SQLStore) guardSystemKeyStatus(ctx context.Context, tenantID, keyID, status string) error {
	switch normalizeLifecycleStatus(status) {
	case "active", "deactivated":
		return nil
	}
	return s.guardSystemKey(ctx, s.db.SQL(), tenantID, keyID, "set_status_"+normalizeLifecycleStatus(status))
}

// HTTP ---------------------------------------------------------------------

// systemKeyRouter serves the system-key route through the pkg/route kernel;
// the legacy mux mounts it (docs/ARCHITECTURE_MIGRATION.md).
func (h *Handler) systemKeyRouter() *route.Router {
	r := route.New("key", kernelEmitter{h}, nil)
	r.Handle("POST /system-keys/ensure", route.Spec{
		Action: "system_key_ensure", Permission: "key.system.ensure", Resource: "key", Tenancy: route.PlatformScoped,
	}, h.ensureSystemKey)
	return r
}

func (h *Handler) ensureSystemKey(c *route.Call) {
	if !tenantcheck.IsServicePrincipal(c.Claims) {
		c.Refuse(http.StatusForbidden, "service_identity_required", errServiceIdentityRequired.Error())
		return
	}
	var req struct {
		Purpose string `json:"purpose"`
	}
	if !c.Decode(&req) {
		return
	}
	c.Detail("purpose", req.Purpose)
	sk, err := h.svc.EnsureSystemKey(c.R.Context(), req.Purpose)
	switch {
	case errors.Is(err, errServiceIdentityRequired):
		c.Refuse(http.StatusForbidden, "service_identity_required", err.Error())
		return
	case err != nil:
		c.Error(http.StatusBadRequest, "system_key_failed", err.Error())
		return
	}
	c.Target(sk.KeyID)
	c.Detail("created", sk.Created)
	c.JSON(http.StatusOK, map[string]interface{}{"key_id": sk.KeyID, "tenant_id": sk.TenantID, "version": sk.Version, "created": sk.Created})
}

// kernelEmitter sends kernel events through keycore's unified audit client,
// resolved per call so it can be wired after the routes are built.
type kernelEmitter struct{ h *Handler }

func (e kernelEmitter) Emit(ctx context.Context, action string, evt pkgaudit.Event) error {
	if e.h.kernelAudit == nil {
		return nil
	}
	return e.h.kernelAudit.Emit(ctx, action, evt)
}

// SetAuditClient wires the unified audit client used by kernel routes.
func (h *Handler) SetAuditClient(c *pkgaudit.Client) {
	if c != nil {
		h.kernelAudit = c
	}
}
