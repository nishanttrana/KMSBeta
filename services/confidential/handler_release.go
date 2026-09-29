package main

import (
	"errors"
	"net/http"
	"strings"

	"vecta-kms/pkg/route"
)

// handleRelease registers POST /confidential/release (audited as
// audit.confidential.key_release, refusals included).
func (h *Handler) handleRelease(r *route.Router) {
	r.Handle("POST /confidential/release", route.Spec{
		Action: "key_release", Permission: permRelease, Resource: "key", Severity: "warning",
	}, h.releaseKey)
}

func (h *Handler) releaseKey(c *route.Call) {
	var req AttestedReleaseRequest
	if !c.Decode(&req) {
		return
	}
	req.TenantID = c.Tenant
	req.Requester = c.Actor()
	c.Target(req.KeyID)
	out, err := h.svc.ReleaseKey(c.R.Context(), req)
	if err != nil {
		var se serviceError
		if errors.As(err, &se) {
			c.Error(se.HTTPStatus, se.Code, se.Message)
			return
		}
		c.Error(http.StatusInternalServerError, "release_failed", "release could not be recorded")
		return
	}
	c.Detail("release_id", out.ReleaseID)
	c.Detail("decision", out.Decision)
	if !out.Released {
		c.Detail("reasons", out.Reasons)
		c.Refuse(http.StatusForbidden, "release_refused", "key not released (release "+out.ReleaseID+"): "+strings.Join(out.Reasons, "; "))
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"decision": out})
}
