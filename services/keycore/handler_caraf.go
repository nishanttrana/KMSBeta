package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"vecta-kms/pkg/route"
)

// carafRoutes registers the crypto agility risk assessment on the agility
// router: threats, assets, decisions and the computed assessment.
func (h *Handler) carafRoutes(r *route.Router) {
	read := func(action, resource string) route.Spec {
		return route.Spec{Action: action, Permission: "key.agility.read", Resource: resource}
	}
	write := func(action, resource, target string) route.Spec {
		return route.Spec{Action: action, Permission: "key.agility.write", Resource: resource, TargetParam: target}
	}
	r.Handle("GET /agility/caraf/assessment", read("caraf_assessment_read", "caraf"), h.getCarafAssessment)
	r.Handle("GET /agility/caraf/threats", read("caraf_threats_listed", "caraf_threat"), h.listCarafThreats)
	r.Handle("POST /agility/caraf/threats", write("caraf_threat_created", "caraf_threat", ""), h.createCarafThreat)
	r.Handle("PUT /agility/caraf/threats/{id}", write("caraf_threat_updated", "caraf_threat", "id"), h.updateCarafThreat)
	r.Handle("DELETE /agility/caraf/threats/{id}", write("caraf_threat_deleted", "caraf_threat", "id"), h.deleteCarafThreat)
	r.Handle("GET /agility/caraf/assets", read("caraf_assets_listed", "caraf_asset"), h.listCarafAssets)
	r.Handle("POST /agility/caraf/assets", write("caraf_asset_created", "caraf_asset", ""), h.createCarafAsset)
	r.Handle("PUT /agility/caraf/assets/{id}", write("caraf_asset_updated", "caraf_asset", "id"), h.updateCarafAsset)
	r.Handle("DELETE /agility/caraf/assets/{id}", write("caraf_asset_deleted", "caraf_asset", "id"), h.deleteCarafAsset)
	r.Handle("PUT /agility/caraf/assets/{id}/decision", route.Spec{Action: "caraf_decision_recorded", Permission: "key.agility.write", Resource: "caraf_asset", TargetParam: "id", Severity: "warning"}, h.setCarafDecision)
}

func (h *Handler) getCarafAssessment(c *route.Call) {
	ctx := c.R.Context()
	assets, err := h.svc.store.ListCarafAssets(ctx, c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "caraf_assessment_failed", err.Error())
		return
	}
	threats, err := h.svc.store.ListCarafThreats(ctx, c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "caraf_assessment_failed", err.Error())
		return
	}
	live := map[string]string{}
	for _, a := range assets {
		for _, id := range a.KeyIDs {
			if _, done := live[id]; done {
				continue
			}
			if k, err := h.svc.store.GetKey(ctx, c.Tenant, id); err == nil && k.Status != "deleted" && k.Status != "destroyed" {
				live[id] = k.Algorithm
			}
		}
	}
	out := computeCarafAssessment(assets, threats, live, time.Now())
	dist, err := h.svc.store.GetAlgorithmDistribution(ctx, c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "caraf_assessment_failed", err.Error())
		return
	}
	out.Unlinked = unlinkedThreatenedKeys(threats, dist, live)
	for _, u := range out.Unlinked {
		out.Findings = append(out.Findings, fmt.Sprintf("%s on %s (%s) belong to no asset: link them so their exposure is assessed.", keysN(u.Keys), u.Algorithm, strings.Join(u.Threats, ", ")))
	}
	since := time.Now().UTC().Add(-usageRetention)
	for i := range out.Assets {
		seen := map[string]bool{}
		out.Assets[i].Consumers = []string{}
		for _, id := range out.Assets[i].Asset.KeyIDs {
			if _, ok := live[id]; !ok {
				continue
			}
			consumers, err := h.svc.store.ListKeyConsumers(ctx, c.Tenant, id, since)
			if err != nil {
				c.Error(http.StatusInternalServerError, "caraf_assessment_failed", err.Error())
				return
			}
			for _, k := range consumers {
				if name := k.ActorID + " via " + k.Interface; !seen[name] {
					seen[name] = true
					out.Assets[i].Consumers = append(out.Assets[i].Consumers, name)
				}
			}
		}
	}
	c.Detail("assets", out.Summary.Assets)
	c.Detail("exposed", out.Summary.Exposed)
	c.Detail("unlinked_algorithms", len(out.Unlinked))
	c.Detail("undecided_at_risk", out.Summary.UndecidedAtRisk)
	c.JSON(http.StatusOK, map[string]interface{}{"data": out})
}

// ---- threats ----

type carafThreatRequest struct {
	TenantID      string `json:"tenant_id"` // enforced by the kernel
	Name          string `json:"name"`
	Category      string `json:"category"`
	MatchKind     string `json:"match_kind"`
	MatchValue    string `json:"match_value"`
	YearsToThreat *int   `json:"years_to_threat"`
	Note          string `json:"note"`
}

func threatFromRequest(req carafThreatRequest) (CarafThreat, string) {
	t := CarafThreat{Name: strings.TrimSpace(req.Name), Category: strings.TrimSpace(req.Category),
		MatchKind: strings.TrimSpace(req.MatchKind), MatchValue: strings.TrimSpace(req.MatchValue), Note: strings.TrimSpace(req.Note)}
	if t.Name == "" || len(t.Name) > 120 {
		return t, "name is required (at most 120 characters)"
	}
	if !carafCategories[t.Category] {
		return t, "category must be quantum, cryptanalytic, regulatory, business or other"
	}
	value, problem := validateMatch(t.MatchKind, t.MatchValue)
	if problem != "" {
		return t, problem
	}
	t.MatchValue = value
	if req.YearsToThreat == nil || *req.YearsToThreat < 0 || *req.YearsToThreat > 100 {
		return t, "years_to_threat is required: the years until you expect the threat (0 to 100)"
	}
	t.YearsToThreat = *req.YearsToThreat
	if len(t.Note) > 500 {
		return t, "note is at most 500 characters"
	}
	return t, ""
}

func (h *Handler) listCarafThreats(c *route.Call) {
	items, err := h.svc.store.ListCarafThreats(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "list_caraf_threats_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"data": items})
}

func (h *Handler) createCarafThreat(c *route.Call) {
	var req carafThreatRequest
	if !c.Decode(&req) {
		return
	}
	t, problem := threatFromRequest(req)
	if problem != "" {
		c.Error(http.StatusBadRequest, "bad_request", problem)
		return
	}
	t.ID, t.TenantID, t.CreatedBy = newID("cthreat"), c.Tenant, c.Actor()
	out, err := h.svc.store.CreateCarafThreat(c.R.Context(), t)
	if err != nil {
		c.Error(http.StatusInternalServerError, "create_caraf_threat_failed", err.Error())
		return
	}
	auditThreat(c, out)
	c.JSON(http.StatusCreated, map[string]interface{}{"data": out})
}

func (h *Handler) updateCarafThreat(c *route.Call) {
	var req carafThreatRequest
	if !c.Decode(&req) {
		return
	}
	t, problem := threatFromRequest(req)
	if problem != "" {
		c.Error(http.StatusBadRequest, "bad_request", problem)
		return
	}
	t.ID, t.TenantID = c.R.PathValue("id"), c.Tenant
	out, err := h.svc.store.UpdateCarafThreat(c.R.Context(), t)
	if !storeOK(c, err, "caraf threat") {
		return
	}
	auditThreat(c, out)
	c.JSON(http.StatusOK, map[string]interface{}{"data": out})
}

func (h *Handler) deleteCarafThreat(c *route.Call) {
	if !storeOK(c, h.svc.store.DeleteCarafThreat(c.R.Context(), c.Tenant, c.R.PathValue("id")), "caraf threat") {
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"deleted": true})
}

func auditThreat(c *route.Call, t CarafThreat) {
	c.Target(t.ID)
	c.Detail("name", t.Name)
	c.Detail("category", t.Category)
	c.Detail("match_kind", t.MatchKind)
	c.Detail("match_value", t.MatchValue)
	c.Detail("years_to_threat", t.YearsToThreat)
}

// ---- assets ----

type carafAssetRequest struct {
	TenantID       string   `json:"tenant_id"` // enforced by the kernel
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	Owner          string   `json:"owner"`
	Ownership      string   `json:"ownership"`
	Implementation string   `json:"implementation"`
	PQCSupport     string   `json:"pqc_support"`
	Location       string   `json:"location"`
	Jurisdiction   string   `json:"jurisdiction"`
	Sensitivity    string   `json:"sensitivity"`
	ShelfLifeYears *int     `json:"shelf_life_years"`
	MigrationYears *int     `json:"migration_years"`
	Cost           string   `json:"cost"`
	Algorithms     []string `json:"algorithms"`
	KeyIDs         []string `json:"key_ids"`
}

func orUnknown(v string) string {
	if v = strings.TrimSpace(v); v == "" {
		return "unknown"
	}
	return v
}

func (h *Handler) assetFromRequest(c *route.Call, req carafAssetRequest) (CarafAsset, string) {
	a := CarafAsset{
		Name: strings.TrimSpace(req.Name), Description: strings.TrimSpace(req.Description), Owner: strings.TrimSpace(req.Owner),
		Ownership: orUnknown(req.Ownership), Implementation: orUnknown(req.Implementation), PQCSupport: orUnknown(req.PQCSupport),
		Location: orUnknown(req.Location), Jurisdiction: strings.TrimSpace(req.Jurisdiction), Sensitivity: orUnknown(req.Sensitivity),
		ShelfLifeYears: req.ShelfLifeYears, MigrationYears: req.MigrationYears, Cost: orUnknown(req.Cost),
		Algorithms: []string{}, KeyIDs: []string{},
	}
	if a.Name == "" || len(a.Name) > 120 {
		return a, "name is required (at most 120 characters)"
	}
	if len(a.Description) > 1000 || len(a.Owner) > 120 || len(a.Jurisdiction) > 120 {
		return a, "description is at most 1000 characters, owner and jurisdiction at most 120"
	}
	for field, ok := range map[string]bool{
		"ownership": carafOwnership[a.Ownership], "implementation": carafImpl[a.Implementation], "pqc_support": carafPQC[a.PQCSupport],
		"location": carafLocation[a.Location], "sensitivity": carafLevels[a.Sensitivity], "cost": carafCost[a.Cost],
	} {
		if !ok {
			return a, field + " has an unknown value"
		}
	}
	for _, v := range []*int{a.ShelfLifeYears, a.MigrationYears} {
		if v != nil && (*v < 0 || *v > 100) {
			return a, "shelf_life_years and migration_years are 0 to 100"
		}
	}
	if len(req.Algorithms) > 50 || len(req.KeyIDs) > 200 {
		return a, "at most 50 algorithms and 200 linked keys"
	}
	for _, alg := range req.Algorithms {
		if alg = strings.TrimSpace(alg); alg != "" {
			a.Algorithms = append(a.Algorithms, alg)
		}
	}
	for _, id := range req.KeyIDs {
		if id = strings.TrimSpace(id); id == "" {
			continue
		}
		if _, err := h.svc.store.GetKey(c.R.Context(), c.Tenant, id); err != nil {
			return a, "key_ids: " + id + " is not a key of this tenant"
		}
		a.KeyIDs = append(a.KeyIDs, id)
	}
	return a, ""
}

func (h *Handler) listCarafAssets(c *route.Call) {
	items, err := h.svc.store.ListCarafAssets(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "list_caraf_assets_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"data": items})
}

func (h *Handler) createCarafAsset(c *route.Call) {
	var req carafAssetRequest
	if !c.Decode(&req) {
		return
	}
	a, problem := h.assetFromRequest(c, req)
	if problem != "" {
		c.Error(http.StatusBadRequest, "bad_request", problem)
		return
	}
	a.ID, a.TenantID, a.CreatedBy = newID("casset"), c.Tenant, c.Actor()
	out, err := h.svc.store.CreateCarafAsset(c.R.Context(), a)
	if err != nil {
		c.Error(http.StatusInternalServerError, "create_caraf_asset_failed", err.Error())
		return
	}
	auditAsset(c, out)
	c.JSON(http.StatusCreated, map[string]interface{}{"data": out})
}

func (h *Handler) updateCarafAsset(c *route.Call) {
	var req carafAssetRequest
	if !c.Decode(&req) {
		return
	}
	a, problem := h.assetFromRequest(c, req)
	if problem != "" {
		c.Error(http.StatusBadRequest, "bad_request", problem)
		return
	}
	a.ID, a.TenantID = c.R.PathValue("id"), c.Tenant
	out, err := h.svc.store.UpdateCarafAsset(c.R.Context(), a)
	if !storeOK(c, err, "caraf asset") {
		return
	}
	auditAsset(c, out)
	c.JSON(http.StatusOK, map[string]interface{}{"data": out})
}

func (h *Handler) deleteCarafAsset(c *route.Call) {
	if !storeOK(c, h.svc.store.DeleteCarafAsset(c.R.Context(), c.Tenant, c.R.PathValue("id")), "caraf asset") {
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"deleted": true})
}

func auditAsset(c *route.Call, a CarafAsset) {
	c.Target(a.ID)
	c.Detail("name", a.Name)
	c.Detail("ownership", a.Ownership)
	c.Detail("sensitivity", a.Sensitivity)
	c.Detail("shelf_life_years", a.ShelfLifeYears)
	c.Detail("migration_years", a.MigrationYears)
	c.Detail("cost", a.Cost)
	c.Detail("key_ids", len(a.KeyIDs))
}

// ---- decisions ----

type carafDecisionRequest struct {
	TenantID string `json:"tenant_id"` // enforced by the kernel
	Decision string `json:"decision"`  // "" clears it
	Owner    string `json:"owner"`
	Due      string `json:"due"`
	ReviewBy string `json:"review_by"`
	Status   string `json:"status"`
	Note     string `json:"note"`
}

// decisionFromRequest validates a decision. Accepting a risk needs a review
// date in the future, so every acceptance lapses; the other decisions need
// an owner and a due date.
func decisionFromRequest(req carafDecisionRequest, now time.Time) (CarafDecision, string) {
	d := CarafDecision{Decision: strings.TrimSpace(req.Decision), Owner: strings.TrimSpace(req.Owner),
		Status: strings.TrimSpace(req.Status), Note: strings.TrimSpace(req.Note)}
	if d.Decision == "" {
		return CarafDecision{}, ""
	}
	if !carafDecisions[d.Decision] {
		return d, "decision must be secure, accept, phase_out or compensating_control"
	}
	if d.Owner == "" || len(d.Owner) > 120 {
		return d, "owner is required (at most 120 characters)"
	}
	if len(d.Note) > 500 {
		return d, "note is at most 500 characters"
	}
	if d.Status == "" {
		d.Status = "open"
	}
	if !carafStatuses[d.Status] {
		return d, "status must be open, in_progress or done"
	}
	if d.Decision == "accept" {
		t, ok := parsePlanDate(strings.TrimSpace(req.ReviewBy))
		if !ok || !t.After(now) {
			return d, "review_by is required for an accepted risk and must be in the future"
		}
		d.ReviewBy = t
		return d, ""
	}
	t, ok := parsePlanDate(strings.TrimSpace(req.Due))
	if !ok {
		return d, "due is required (YYYY-MM-DD)"
	}
	d.Due = t
	return d, ""
}

func (h *Handler) setCarafDecision(c *route.Call) {
	var req carafDecisionRequest
	if !c.Decode(&req) {
		return
	}
	now := time.Now().UTC()
	d, problem := decisionFromRequest(req, now)
	if problem != "" {
		c.Error(http.StatusBadRequest, "bad_request", problem)
		return
	}
	if d.Decision != "" {
		d.DecidedBy, d.DecidedAt = c.Actor(), &now
	}
	out, err := h.svc.store.SetCarafDecision(c.R.Context(), c.Tenant, c.R.PathValue("id"), d)
	if !storeOK(c, err, "caraf asset") {
		return
	}
	c.Detail("asset", out.Name)
	c.Detail("decision", d.Decision)
	c.Detail("owner", d.Owner)
	c.Detail("status", d.Status)
	if d.Due != nil {
		c.Detail("due", d.Due.Format("2006-01-02"))
	}
	if d.ReviewBy != nil {
		c.Detail("review_by", d.ReviewBy.Format("2006-01-02"))
	}
	c.JSON(http.StatusOK, map[string]interface{}{"data": out})
}

func storeOK(c *route.Call, err error, what string) bool {
	switch {
	case err == nil:
		return true
	case err == errStoreNotFound:
		c.Error(http.StatusNotFound, "not_found", what+" not found")
	default:
		c.Error(http.StatusInternalServerError, "store_failed", err.Error())
	}
	return false
}
