package main

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"vecta-kms/pkg/route"
)

// A canary key is a decoy key ID. It holds no material and resolves to no
// key: an ID a legitimate caller would never use, planted where an attacker
// would find it (a config file, a vault entry, a wiki page). Any reference to
// it through the key API is recorded as a trip at GetKey's not-found branch
// (noteCanaryProbe), raises a critical threat signal and returns not-found,
// so the prober learns nothing. Its ID is minted like a real key ID so it
// can't be told apart.
type CanaryKey struct {
	ID          string     `json:"id"`
	TenantID    string     `json:"tenant_id"`
	Name        string     `json:"name"`
	Active      bool       `json:"active"`
	CreatedAt   time.Time  `json:"created_at"`
	TripCount   int        `json:"trip_count"`
	LastTripped *time.Time `json:"last_tripped,omitempty"`
}

// CanaryTripEvent is one recorded probe of a canary key.
type CanaryTripEvent struct {
	ID         string    `json:"id"`
	CanaryID   string    `json:"canary_id"`
	TenantID   string    `json:"tenant_id"`
	ActorID    string    `json:"actor_id"`
	ActorIP    string    `json:"actor_ip"`
	UserAgent  string    `json:"user_agent"`
	TrippedAt  time.Time `json:"tripped_at"`
	Severity   string    `json:"severity"`
	RawRequest string    `json:"raw_request"`
}

// canaryRouter serves canary keys through the pkg/route kernel (tenant,
// permission and audit by construction); the legacy mux mounts it.
func (h *Handler) canaryRouter(audit route.Emitter) *route.Router {
	r := route.New("key", audit, nil)
	r.Handle("GET /canary/keys", route.Spec{Action: "canary_keys_listed", Permission: "key.canary.read", Resource: "canary_key"}, h.listCanaryKeys)
	r.Handle("POST /canary/keys", route.Spec{Action: "canary_key_created", Permission: "key.canary.write", Resource: "canary_key"}, h.createCanaryKey)
	r.Handle("GET /canary/keys/{id}/trips", route.Spec{Action: "canary_trips_listed", Permission: "key.canary.read", Resource: "canary_key", TargetParam: "id"}, h.listCanaryTrips)
	r.Handle("DELETE /canary/keys/{id}", route.Spec{Action: "canary_key_deactivated", Permission: "key.canary.write", Resource: "canary_key", TargetParam: "id", Severity: "warning"}, h.deactivateCanaryKey)
	return r
}

func (h *Handler) listCanaryKeys(c *route.Call) {
	keys, err := h.svc.store.ListCanaryKeys(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "list_canary_keys_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": keys})
}

func (h *Handler) createCanaryKey(c *route.Call) {
	var req struct {
		TenantID string `json:"tenant_id"` // enforced by the kernel
		Name     string `json:"name"`
	}
	if !c.Decode(&req) {
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		c.Error(http.StatusBadRequest, "bad_request", "name is required")
		return
	}
	key := CanaryKey{ID: newID("key"), TenantID: c.Tenant, Name: name, Active: true}
	if err := h.svc.store.CreateCanaryKey(c.R.Context(), key); err != nil {
		c.Error(http.StatusInternalServerError, "create_canary_key_failed", err.Error())
		return
	}
	created, err := h.svc.store.GetCanaryKey(c.R.Context(), c.Tenant, key.ID)
	if err != nil {
		c.Error(http.StatusInternalServerError, "create_canary_key_failed", err.Error())
		return
	}
	c.Target(created.ID)
	c.Detail("name", created.Name)
	c.JSON(http.StatusCreated, map[string]interface{}{"item": created})
}

func (h *Handler) listCanaryTrips(c *route.Call) {
	id := c.R.PathValue("id")
	if _, err := h.svc.store.GetCanaryKey(c.R.Context(), c.Tenant, id); err != nil {
		h.canaryLookupError(c, err)
		return
	}
	limit, _ := strconv.Atoi(c.R.URL.Query().Get("limit"))
	trips, err := h.svc.store.ListCanaryTrips(c.R.Context(), c.Tenant, id, limit)
	if err != nil {
		c.Error(http.StatusInternalServerError, "list_canary_trips_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": trips})
}

func (h *Handler) deactivateCanaryKey(c *route.Call) {
	if err := h.svc.store.DeactivateCanaryKey(c.R.Context(), c.Tenant, c.R.PathValue("id")); err != nil {
		h.canaryLookupError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"status": "deactivated"})
}

func (h *Handler) canaryLookupError(c *route.Call, err error) {
	if errors.Is(err, errStoreNotFound) {
		c.Error(http.StatusNotFound, "not_found", "canary key not found")
		return
	}
	c.Error(http.StatusInternalServerError, "canary_lookup_failed", err.Error())
}
