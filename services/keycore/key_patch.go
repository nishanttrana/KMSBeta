package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"unicode/utf8"

	"vecta-kms/pkg/route"
)

// PATCH /keys/{id} (13.56.0-beta): a partial metadata update. Only the fields
// the body names change; every other stays as stored. PUT /keys/{id} replaces
// name, purpose, owner, cloud, region, compliance, tags and labels at once,
// and an API client (an SDK, Terraform) can't read all of them back, so a PUT
// it builds clears the ones it doesn't know.
//
// Both routes now require the caller to see the key and to manage it: its
// creator, a key-access administrator, a platform service, or a holder of a
// grant of "all" (as for changing its grants). Before, key.update alone let a
// caller change any key's metadata in the tenant.

type keyPatch struct {
	Name        *string            `json:"name"`
	Description *string            `json:"description"`
	Purpose     *string            `json:"purpose"`
	Owner       *string            `json:"owner"`
	Cloud       *string            `json:"cloud"`
	Region      *string            `json:"region"`
	Compliance  *[]string          `json:"compliance"`
	Tags        *[]string          `json:"tags"`
	Labels      *map[string]string `json:"labels"`
}

// authorizeKeyUpdate is the per-key decision both update routes make: the
// key must be visible (else not found) and the caller must manage it.
func (s *Service) authorizeKeyUpdate(ctx context.Context, tenantID, id string) (Key, error) {
	key, err := s.store.GetKey(ctx, tenantID, strings.TrimSpace(id))
	if err != nil {
		return Key{}, err
	}
	if err := s.ensureKeyVisible(ctx, key); err != nil {
		return Key{}, err
	}
	if authorizeAccessPolicyChange(accessActorFromContext(ctx), key) == nil {
		return key, nil
	}
	// Otherwise a grant of "all"; a refusal is audited as access_refused.
	if err := s.enforceKeyAccess(ctx, key, "all"); err != nil {
		return Key{}, err
	}
	return key, nil
}

func (h *Handler) keyPatchRoutes(r *route.Router) {
	r.Handle("PATCH /keys/{id}", route.Spec{Action: "metadata_patched", Permission: "key.update", Resource: "key", TargetParam: "id"}, h.patchKey)
}

func (h *Handler) patchKey(c *route.Call) {
	var in keyPatch
	if !c.Decode(&in) {
		return
	}
	ctx := c.R.Context()
	if !accessActorFromContext(ctx).Authenticated {
		ctx = contextWithAccessActor(ctx, accessActorFromHTTPRequest(c.R))
	}
	key, err := h.svc.authorizeKeyUpdate(ctx, c.Tenant, c.R.PathValue("id"))
	var refusal *accessRefusal
	switch {
	case errors.Is(err, errStoreNotFound):
		c.Error(http.StatusNotFound, "not_found", "key not found")
		return
	case errors.As(err, &refusal):
		c.Refuse(http.StatusForbidden, refusal.reason, refusal.Error())
		return
	case err != nil:
		c.Error(http.StatusInternalServerError, "get_failed", "failed to retrieve key")
		return
	}
	if isDeletedLike(key.Status) {
		c.Refuse(http.StatusConflict, "key_deleted", "a deleted key's metadata can't change")
		return
	}
	changed := []string{}
	if in.Description != nil {
		text, ok := cleanText(*in.Description, maxKeyDescription)
		if !ok {
			c.Refuse(http.StatusBadRequest, "description_invalid", errKeyDescriptionInvalid.Error())
			return
		}
		in.Description = &text
	}
	req := UpdateKeyRequest{Name: key.Name, Purpose: key.Purpose, Owner: key.Owner, Cloud: key.Cloud, Region: key.Region,
		Compliance: key.Compliance, Tags: key.Tags, Labels: map[string]string(key.Labels), IVMode: key.IVMode}
	set := func(name string, apply func()) {
		apply()
		changed = append(changed, name)
	}
	if in.Name != nil {
		if strings.TrimSpace(*in.Name) == "" {
			c.Refuse(http.StatusBadRequest, "invalid_name", "name can't be empty")
			return
		}
		set("name", func() { req.Name = strings.TrimSpace(*in.Name) })
	}
	if in.Purpose != nil {
		set("purpose", func() { req.Purpose = strings.TrimSpace(*in.Purpose) })
	}
	if in.Owner != nil {
		set("owner", func() { req.Owner = strings.TrimSpace(*in.Owner) })
	}
	if in.Cloud != nil {
		set("cloud", func() { req.Cloud = strings.TrimSpace(*in.Cloud) })
	}
	if in.Region != nil {
		set("region", func() { req.Region = strings.TrimSpace(*in.Region) })
	}
	if in.Compliance != nil {
		set("compliance", func() { req.Compliance = *in.Compliance })
	}
	if in.Tags != nil {
		set("tags", func() { req.Tags = *in.Tags })
	}
	if in.Labels != nil {
		set("labels", func() { req.Labels = *in.Labels })
	}
	if len(changed) > 0 {
		if err := h.svc.UpdateKey(ctx, c.Tenant, key.ID, req); err != nil {
			var v *MetadataViolation
			if errors.As(err, &v) {
				c.Detail("problems", v.Problems)
				c.Refuse(http.StatusBadRequest, "metadata_profile_violation", v.Error())
				return
			}
			c.Error(http.StatusInternalServerError, "update_failed", "failed to update key")
			return
		}
	}
	if in.Description != nil {
		if err := h.svc.store.SetKeyDescription(ctx, c.Tenant, key.ID, *in.Description); err != nil {
			c.Error(http.StatusInternalServerError, "description_update_failed", "failed to update the description")
			return
		}
		_ = h.svc.cache.Delete(ctx, c.Tenant, key.ID)
		changed = append(changed, "description")
		c.Detail("description_length", utf8.RuneCountInString(*in.Description))
	}
	c.Target(key.ID)
	c.Detail("changed", changed)
	updated, err := h.svc.store.GetKey(ctx, c.Tenant, key.ID)
	if err != nil {
		c.Error(http.StatusInternalServerError, "get_failed", "failed to retrieve key")
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"key": renderKey(updated)})
}
