package mek

import (
	"net/http"
	"strings"

	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/tenantcheck"
)

// GovernanceClient is the only identity allowed to re-wrap backup contents.
const GovernanceClient = "kms-governance"

// maxRewrapEntries bounds one re-wrap call.
const maxRewrapEntries = 1000

// RewrapEntry is one wrapped DEK from a backup, base64 of the raw bytes.
type RewrapEntry struct {
	IV  string `json:"iv"`
	DEK string `json:"dek"`
}

// RewrapResult is the entry after re-wrap. Status: "rewrapped" (it was under
// a legacy key, now under the service key; Source names which), "current"
// (already under the service key, unchanged) or "unknown" (no known key
// opens it, unchanged).
type RewrapResult struct {
	IV     string `json:"iv"`
	DEK    string `json:"dek"`
	Status string `json:"status"`
	Source string `json:"source,omitempty"`
}

// Routes registers the master-key routes on r. domain is the service's
// permission domain (e.g. "secrets"):
//
//	GET  /mek/exposure                                  <domain>.read
//	POST /mek/exposure/{item_type}/{item_id}/acknowledge <domain>.exposure.acknowledge
//	POST /mek/rewrap-legacy                             kms-governance only
func (k *Keyring) Routes(r *route.Router, domain string) {
	r.Handle("GET /mek/exposure", route.Spec{Action: "mek_exposure_listed", Permission: domain + ".read", Resource: "mek_exposure"}, k.listExposure)
	r.Handle("POST /mek/exposure/{item_type}/{item_id}/acknowledge", route.Spec{
		Action: "mek_exposure_acknowledged", Permission: domain + ".exposure.acknowledge", Resource: "mek_exposure",
		TargetParam: "item_id", Severity: "warning",
	}, k.acknowledge)
	r.Handle("POST /mek/rewrap-legacy", route.Spec{
		Action: "mek_backup_rewrap", Permission: route.Authenticated, Tenancy: route.PlatformScoped, Severity: "warning",
	}, k.rewrapLegacy)
}

func (k *Keyring) listExposure(c *route.Call) {
	openOnly := c.R.URL.Query().Get("open") != "false"
	items, err := k.Exposures(c.R.Context(), c.Tenant, openOnly)
	if err != nil {
		c.Error(http.StatusInternalServerError, "exposure_failed", err.Error())
		return
	}
	open := 0
	for _, e := range items {
		if e.RemediatedAt == nil {
			open++
		}
	}
	c.Detail("open", open)
	c.JSON(http.StatusOK, map[string]interface{}{"service": k.opts.Tables.Service, "items": items, "open": open})
}

func (k *Keyring) acknowledge(c *route.Call) {
	var req struct {
		Reason string `json:"reason"`
	}
	if !c.Decode(&req) {
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if len(reason) < 10 {
		c.Error(http.StatusBadRequest, "reason_required", "a reason of at least 10 characters is required to acknowledge an exposure")
		return
	}
	c.Detail("reason", reason)
	closed, err := k.Remediate(c.R.Context(), c.Tenant, c.R.PathValue("item_type"), c.R.PathValue("item_id"), "acknowledged: "+reason, c.Actor())
	switch {
	case err != nil:
		c.Error(http.StatusInternalServerError, "acknowledge_failed", err.Error())
	case !closed:
		c.Error(http.StatusNotFound, "not_found", "no open exposure for this item")
	default:
		c.JSON(http.StatusOK, map[string]interface{}{"status": "acknowledged"})
	}
}

func (k *Keyring) rewrapLegacy(c *route.Call) {
	if !tenantcheck.IsServicePrincipal(c.Claims) || c.Claims.ClientID != GovernanceClient {
		c.Refuse(http.StatusForbidden, "governance_identity_required", "only the governance service may re-wrap backup contents")
		return
	}
	var req struct {
		Entries []RewrapEntry `json:"entries"`
	}
	if !c.Decode(&req) {
		return
	}
	if len(req.Entries) > maxRewrapEntries {
		c.Error(http.StatusBadRequest, "too_many_entries", "at most 1000 entries per call")
		return
	}
	out := make([]RewrapResult, len(req.Entries))
	counts := map[string]int{}
	for i, e := range req.Entries {
		out[i] = RewrapResult{IV: e.IV, DEK: e.DEK, Status: "unknown"}
		iv, err1 := unb64(e.IV)
		dek, err2 := unb64(e.DEK)
		if err1 != nil || err2 != nil {
			counts["unknown"]++
			continue
		}
		env := &pkgcrypto.EnvelopeCiphertext{WrappedDEKIV: iv, WrappedDEK: dek}
		if pkgcrypto.EnvelopeWrappedUnder(k.current, env) {
			out[i].Status = "current"
			counts["current"]++
			continue
		}
		for _, l := range k.legacy {
			if !pkgcrypto.EnvelopeWrappedUnder(l.Key, env) {
				continue
			}
			moved, err := pkgcrypto.RewrapEnvelope(l.Key, k.current, env)
			if err != nil {
				break
			}
			out[i] = RewrapResult{IV: b64(moved.WrappedDEKIV), DEK: b64(moved.WrappedDEK), Status: "rewrapped", Source: l.Name}
			counts["rewrapped"]++
			break
		}
		if out[i].Status == "unknown" {
			counts["unknown"]++
		}
	}
	for s, n := range counts {
		c.Detail(s, n)
	}
	c.JSON(http.StatusOK, map[string]interface{}{"entries": out})
}
