package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"vecta-kms/pkg/hsm"
	"vecta-kms/pkg/route"
)

// Destruction check results.
const (
	destructionRemoved    = "removed"          // no material found anywhere checked
	destructionRemains    = "material_remains" // version rows or HSM objects are still there
	destructionIncomplete = "incomplete"       // the HSM could not be asked
)

// destructionNotCovered is what the check cannot see, stated on every answer
// so a reviewer never reads it as proof of media or memory overwrite.
const destructionNotCovered = "database pages until vacuumed (the rows held material encrypted under the MEK or wrapped by the HSM), backups, and process memory"

var errKeyNotDestroyed = errors.New("key is not destroyed")

// DestructionCheck is what keycore found where it keeps a destroyed key's
// material: the key_versions rows (the only table that holds material) and
// the key's objects in the HSM.
type DestructionCheck struct {
	KeyID       string   `json:"key_id"`
	Status      string   `json:"status"`
	VersionRows int      `json:"version_rows"`
	HSM         string   `json:"hsm"` // checked | not_configured | unreachable
	HSMObjects  []string `json:"hsm_objects"`
	HSMError    string   `json:"hsm_error,omitempty"`
	Result      string   `json:"result"`
	NotCovered  string   `json:"not_covered"`
	CheckedAt   string   `json:"checked_at"`
}

// CheckKeyDestruction looks for a destroyed key's material. It reads the raw
// row: GetKey treats a destroyed key as not found. The HSM is asked for every
// object under the key's label prefix, because destroy clears the row's HSM
// labels and version count.
func (s *Service) CheckKeyDestruction(ctx context.Context, tenantID, keyID string) (DestructionCheck, error) {
	key, err := s.store.GetKey(ctx, tenantID, keyID)
	if err != nil {
		return DestructionCheck{}, err
	}
	out := DestructionCheck{KeyID: keyID, Status: key.Status, HSMObjects: []string{}, NotCovered: destructionNotCovered,
		CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	if normalizeLifecycleStatus(key.Status) != "deleted" {
		return out, errKeyNotDestroyed
	}
	versions, err := s.store.ListVersions(ctx, tenantID, keyID)
	if err != nil {
		return DestructionCheck{}, err
	}
	out.VersionRows = len(versions)
	out.HSM = "not_configured"
	if s.hsm != nil {
		objs, _, err := s.hsm.Objects(ctx, tenantID)
		if err != nil {
			out.HSM, out.HSMError = "unreachable", err.Error()
		} else {
			out.HSM = "checked"
			prefix := hsm.TenantPrefix(tenantID) + "key:" + keyID + ":v" // hsm.KeyLabel without the version
			for _, o := range objs {
				if strings.HasPrefix(o.Label, prefix) {
					out.HSMObjects = append(out.HSMObjects, o.Label)
				}
			}
		}
	}
	switch {
	case out.VersionRows > 0 || len(out.HSMObjects) > 0:
		out.Result = destructionRemains
	case out.HSM == "unreachable":
		out.Result = destructionIncomplete
	default:
		out.Result = destructionRemoved
	}
	return out, nil
}

// POST /keys/{id}/destruction-check
func (h *Handler) handleDestructionCheck(c *route.Call) {
	if !h.visibleKey(c) {
		return
	}
	out, err := h.svc.CheckKeyDestruction(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	switch {
	case errors.Is(err, errKeyNotDestroyed):
		c.Detail("status", out.Status)
		c.Refuse(http.StatusConflict, "key_not_destroyed", "the key is not destroyed; only a destroyed key can be checked for remaining material")
		return
	case errors.Is(err, errStoreNotFound):
		c.Error(http.StatusNotFound, "not_found", "key not found")
		return
	case err != nil:
		c.Error(http.StatusInternalServerError, "destruction_check_failed", "failed to check the key's stored material")
		return
	}
	c.Detail("result", out.Result)
	c.Detail("version_rows", out.VersionRows)
	c.Detail("hsm", out.HSM)
	c.Detail("hsm_objects", len(out.HSMObjects))
	if out.Result == destructionRemains {
		c.Detail("severity", "critical")
		c.Detail("description", "a destroyed key still has stored material: remove it")
	}
	c.JSON(http.StatusOK, map[string]any{"check": out})
}
