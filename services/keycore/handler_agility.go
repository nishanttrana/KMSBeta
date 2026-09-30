package main

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"vecta-kms/pkg/cryptocatalog"
	"vecta-kms/pkg/route"
)

// agilityRouter serves the crypto-agility posture, inventory, the tenant's
// migration policy through the pkg/route kernel (tenant,
// permission and audit by construction); the legacy mux mounts it. Counts
// come from the tenant's keys table, technical facts from pkg/cryptocatalog,
// and every status and date from the tenant's own policy rules.
func (h *Handler) agilityRouter(audit route.Emitter) *route.Router {
	r := route.New("key", audit, nil)
	r.Handle("GET /agility/posture", route.Spec{Action: "agility_posture_read", Permission: "key.agility.read", Resource: "agility"}, h.getAgilityPosture)
	r.Handle("GET /agility/algorithms", route.Spec{Action: "agility_inventory_read", Permission: "key.agility.read", Resource: "agility"}, h.getAlgorithmInventory)
	r.Handle("GET /agility/keys-by-algorithm", route.Spec{Action: "agility_keys_by_algorithm_read", Permission: "key.agility.read", Resource: "agility"}, h.getKeysByAlgorithm)
	r.Handle("GET /agility/policy/rules", route.Spec{Action: "agility_policy_rules_listed", Permission: "key.agility.read", Resource: "agility_policy_rule"}, h.listAgilityRules)
	r.Handle("POST /agility/policy/rules", route.Spec{Action: "agility_policy_rule_created", Permission: "key.agility.write", Resource: "agility_policy_rule"}, h.createAgilityRule)
	r.Handle("PUT /agility/policy/rules/{id}", route.Spec{Action: "agility_policy_rule_updated", Permission: "key.agility.write", Resource: "agility_policy_rule", TargetParam: "id"}, h.updateAgilityRule)
	r.Handle("DELETE /agility/policy/rules/{id}", route.Spec{Action: "agility_policy_rule_deleted", Permission: "key.agility.write", Resource: "agility_policy_rule", TargetParam: "id"}, h.deleteAgilityRule)
	h.carafRoutes(r)
	h.drillRoutes(r)
	return r
}

// posture measures live keys against the tenant's rules.
func (h *Handler) posture(c *route.Call, code string) (AgilityPosture, bool) {
	ctx := c.R.Context()
	algos, err := h.svc.store.GetAlgorithmDistribution(ctx, c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, code, err.Error())
		return AgilityPosture{}, false
	}
	rules, err := h.svc.store.ListAgilityRules(ctx, c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, code, err.Error())
		return AgilityPosture{}, false
	}
	return computeAgilityPosture(algos, rules, time.Now()), true
}

func (h *Handler) getAgilityPosture(c *route.Call) {
	p, ok := h.posture(c, "agility_posture_failed")
	if !ok {
		return
	}
	c.Detail("total_keys", p.TotalKeys)
	c.Detail("quantum_vulnerable_keys", p.QuantumVulnerableKeys)
	c.Detail("not_assessed_keys", p.NotAssessedKeys)
	c.Detail("uncovered_keys", p.UncoveredKeys)
	c.JSON(http.StatusOK, map[string]interface{}{"data": p})
}

func (h *Handler) getAlgorithmInventory(c *route.Call) {
	p, ok := h.posture(c, "algorithm_inventory_failed")
	if !ok {
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"data": p.Algorithms, "total_keys": p.TotalKeys})
}

func (h *Handler) getKeysByAlgorithm(c *route.Call) {
	algorithm := strings.TrimSpace(c.R.URL.Query().Get("algorithm"))
	if algorithm == "" {
		c.Error(http.StatusBadRequest, "bad_request", "algorithm query parameter is required")
		return
	}
	c.Detail("algorithm", algorithm)
	keys, err := h.svc.store.ListKeysByAlgorithm(c.R.Context(), c.Tenant, algorithm)
	if err != nil {
		c.Error(http.StatusInternalServerError, "keys_by_algorithm_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"data": KeysByAlgorithm{Algorithm: algorithm, Keys: keys}})
}

// parsePlanDate accepts a calendar date (the dashboard's date input) or RFC3339.
func parsePlanDate(s string) (*time.Time, bool) {
	for _, layout := range []string{"2006-01-02", time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			t = t.UTC()
			return &t, true
		}
	}
	return nil, false
}

// ---- Customer migration policy ----

type agilityRuleRequest struct {
	TenantID        string `json:"tenant_id"` // enforced by the kernel
	Name            string `json:"name"`
	MatchKind       string `json:"match_kind"`
	MatchValue      string `json:"match_value"`
	Action          string `json:"action"`
	EffectiveDate   string `json:"effective_date"`
	TargetAlgorithm string `json:"target_algorithm"`
	Note            string `json:"note"`
}

// validateMatch checks a match kind and value (rules and CARAF threats share
// them) and returns the value to store.
func validateMatch(kind, value string) (string, string) {
	switch kind {
	case MatchAlgorithm, MatchFamily:
		if value == "" {
			return value, "match_value names the " + kind
		}
	case MatchBelowStrength:
		if n, err := strconv.Atoi(value); err != nil || n < 1 || n > 512 {
			return value, "match_value for below_strength is a number of bits"
		}
	case MatchQuantumVulnerable, MatchWeak:
		return "", ""
	default:
		return value, "match_kind must be algorithm, family, quantum_vulnerable, weak or below_strength"
	}
	return value, ""
}

// ruleFromRequest validates a rule. The customer chooses every value; the
// only refusals are for rules that can't mean anything.
func ruleFromRequest(req agilityRuleRequest) (AgilityRule, string) {
	r := AgilityRule{
		Name: strings.TrimSpace(req.Name), MatchKind: strings.TrimSpace(req.MatchKind), MatchValue: strings.TrimSpace(req.MatchValue),
		Action: strings.TrimSpace(req.Action), TargetAlgorithm: strings.TrimSpace(req.TargetAlgorithm), Note: strings.TrimSpace(req.Note),
	}
	if r.Name == "" || len(r.Name) > 120 {
		return r, "name is required (at most 120 characters)"
	}
	if len(r.Note) > 500 {
		return r, "note is at most 500 characters"
	}
	value, problem := validateMatch(r.MatchKind, r.MatchValue)
	if problem != "" {
		return r, problem
	}
	r.MatchValue = value
	if _, ok := actionRank[r.Action]; !ok {
		return r, "action must be deprecated, decrypt_only or disallowed"
	}
	d, ok := parsePlanDate(strings.TrimSpace(req.EffectiveDate))
	if !ok {
		return r, "effective_date is required (YYYY-MM-DD or RFC3339)"
	}
	r.EffectiveDate = *d
	if r.TargetAlgorithm != "" {
		e, known := cryptocatalog.Lookup(r.TargetAlgorithm)
		if !known || e.Weak {
			return r, "target_algorithm must name a parameter set that is not weak (for example ML-DSA-65 or AES-256)"
		}
		if r.MatchKind == MatchAlgorithm && strings.EqualFold(e.Algorithm, r.MatchValue) {
			return r, "target_algorithm is the algorithm the rule migrates away from"
		}
	}
	return r, ""
}

func (h *Handler) auditRule(c *route.Call, r AgilityRule) {
	c.Target(r.ID)
	c.Detail("name", r.Name)
	c.Detail("match_kind", r.MatchKind)
	c.Detail("match_value", r.MatchValue)
	c.Detail("action", r.Action)
	c.Detail("effective_date", r.EffectiveDate.Format("2006-01-02"))
	c.Detail("target_algorithm", r.TargetAlgorithm)
}

func (h *Handler) listAgilityRules(c *route.Call) {
	rules, err := h.svc.store.ListAgilityRules(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "list_agility_rules_failed", err.Error())
		return
	}
	c.Detail("count", len(rules))
	c.JSON(http.StatusOK, map[string]interface{}{"data": rules})
}

func (h *Handler) createAgilityRule(c *route.Call) {
	var req agilityRuleRequest
	if !c.Decode(&req) {
		return
	}
	r, problem := ruleFromRequest(req)
	if problem != "" {
		c.Error(http.StatusBadRequest, "bad_request", problem)
		return
	}
	r.ID, r.TenantID, r.CreatedBy = newID("agrule"), c.Tenant, c.Actor()
	created, err := h.svc.store.CreateAgilityRule(c.R.Context(), r)
	if err != nil {
		c.Error(http.StatusInternalServerError, "create_agility_rule_failed", err.Error())
		return
	}
	h.svc.invalidateAgilityRules(c.Tenant)
	h.auditRule(c, created)
	c.JSON(http.StatusCreated, map[string]interface{}{"data": created})
}

func (h *Handler) updateAgilityRule(c *route.Call) {
	var req agilityRuleRequest
	if !c.Decode(&req) {
		return
	}
	r, problem := ruleFromRequest(req)
	if problem != "" {
		c.Error(http.StatusBadRequest, "bad_request", problem)
		return
	}
	r.ID, r.TenantID = c.R.PathValue("id"), c.Tenant
	updated, err := h.svc.store.UpdateAgilityRule(c.R.Context(), r)
	if err == errStoreNotFound {
		c.Error(http.StatusNotFound, "not_found", "migration policy rule not found")
		return
	}
	if err != nil {
		c.Error(http.StatusInternalServerError, "update_agility_rule_failed", err.Error())
		return
	}
	h.svc.invalidateAgilityRules(c.Tenant)
	h.auditRule(c, updated)
	c.JSON(http.StatusOK, map[string]interface{}{"data": updated})
}

func (h *Handler) deleteAgilityRule(c *route.Call) {
	err := h.svc.store.DeleteAgilityRule(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if err == errStoreNotFound {
		c.Error(http.StatusNotFound, "not_found", "migration policy rule not found")
		return
	}
	if err != nil {
		c.Error(http.StatusInternalServerError, "delete_agility_rule_failed", err.Error())
		return
	}
	h.svc.invalidateAgilityRules(c.Tenant)
	c.JSON(http.StatusOK, map[string]interface{}{"deleted": true})
}
