package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"vecta-kms/pkg/route"
)

// Free text a caller attaches to a key (its description) or to an export
// (its reason). It is display and audit text: no access decision reads it
// (docs/SECURITY/KEY_ACCESS_MODEL.md section 6).

const (
	maxKeyDescription = 512
	maxExportReason   = 256
)

var (
	errKeyDescriptionInvalid = errors.New("description must be at most 512 characters, with no control characters")
	errExportReasonRequired  = errors.New("reason is required to export key material")
	errExportReasonInvalid   = errors.New("reason must be at most 256 characters, with no control characters")
)

// cleanText trims v and reports whether it is valid UTF-8 of at most max
// characters with no control characters.
func cleanText(v string, max int) (string, bool) {
	v = strings.TrimSpace(v)
	if !utf8.ValidString(v) || utf8.RuneCountInString(v) > max {
		return "", false
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return "", false
		}
	}
	return v, true
}

// keyDescription returns the description to store, or refuses it and audits
// the refusal under subject (details name the key or the request).
func (s *Service) keyDescription(ctx context.Context, tenantID, subject string, details map[string]any, v string) (string, error) {
	if out, ok := cleanText(v, maxKeyDescription); ok {
		return out, nil
	}
	details["result"], details["reason"] = "refused", "description_invalid"
	_ = s.publishAudit(ctx, subject, tenantID, details)
	return "", errKeyDescriptionInvalid
}

// exportReason returns the reason to record with an export, or refuses the
// export: key material (required) never leaves without a stated reason.
// The refusal is audited as audit.key.export_refused.
func (s *Service) exportReason(ctx context.Context, tenantID, keyID, mode, v string, required bool) (string, error) {
	out, ok := cleanText(v, maxExportReason)
	var err error
	code := ""
	switch {
	case !ok:
		err, code = errExportReasonInvalid, "export_reason_invalid"
	case out == "" && required:
		err, code = errExportReasonRequired, "export_reason_required"
	default:
		return out, nil
	}
	_ = s.publishAudit(ctx, "audit.key.export_refused", tenantID, map[string]any{
		"key_id": keyID, "export_mode": mode, "result": "refused", "reason": code, "severity": "warning",
	})
	return "", err
}

// setKeyDescription replaces a key's description (PUT /keys/{id}/description).
// Its own route, because the metadata update replaces every field it names.
// The event records that the text changed and its length, never the text,
// which may name people or systems.
func (h *Handler) setKeyDescription(c *route.Call) {
	var req struct {
		Description string `json:"description"`
	}
	if !c.Decode(&req) {
		return
	}
	text, ok := cleanText(req.Description, maxKeyDescription)
	if !ok {
		c.Refuse(http.StatusBadRequest, "description_invalid", errKeyDescriptionInvalid.Error())
		return
	}
	if !h.visibleKey(c) {
		return
	}
	ctx, id := c.R.Context(), strings.TrimSpace(c.R.PathValue("id"))
	key, err := h.svc.store.GetKey(ctx, c.Tenant, id)
	if err != nil {
		c.Error(http.StatusInternalServerError, "get_failed", "failed to retrieve key")
		return
	}
	if isDeletedLike(key.Status) {
		c.Refuse(http.StatusConflict, "key_deleted", "a deleted key's description can't change")
		return
	}
	if err := h.svc.store.SetKeyDescription(ctx, c.Tenant, id, text); err != nil {
		c.Error(http.StatusInternalServerError, "description_update_failed", "failed to update the description")
		return
	}
	_ = h.svc.cache.Delete(ctx, c.Tenant, id)
	c.Detail("changed", text != key.Description)
	c.Detail("length", utf8.RuneCountInString(text))
	c.JSON(http.StatusOK, map[string]interface{}{"status": "ok", "description": text})
}
