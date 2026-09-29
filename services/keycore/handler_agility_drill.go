package main

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"vecta-kms/pkg/route"
)

// drillSlot allows one drill at a time per keycore process: a drill is CPU
// work (RSA-4096 key generation, SLH-DSA signing) that must not starve key
// operations.
var drillSlot = make(chan struct{}, 1)

func (h *Handler) drillRoutes(r *route.Router) {
	r.Handle("GET /agility/drills", route.Spec{Action: "agility_drills_listed", Permission: "key.agility.read", Resource: "agility_drill"}, h.listAgilityDrills)
	r.Handle("POST /agility/drills", route.Spec{Action: "agility_drill_run", Permission: "key.agility.write", Resource: "agility_drill"}, h.runAgilityDrill)
}

func (h *Handler) listAgilityDrills(c *route.Call) {
	items, err := h.svc.store.ListAgilityDrills(c.R.Context(), c.Tenant, 50)
	if err != nil {
		c.Error(http.StatusInternalServerError, "list_drills_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

type agilityDrillRequest struct {
	TenantID      string `json:"tenant_id"` // enforced by the kernel
	FromAlgorithm string `json:"from_algorithm"`
	ToAlgorithm   string `json:"to_algorithm"`
	Iterations    int    `json:"iterations"`
}

func (h *Handler) runAgilityDrill(c *route.Call) {
	var req agilityDrillRequest
	if !c.Decode(&req) {
		return
	}
	from, to := strings.TrimSpace(req.FromAlgorithm), strings.TrimSpace(req.ToAlgorithm)
	n := req.Iterations
	if n == 0 {
		n = drillDefaultIterations
	}
	c.Detail("from_algorithm", from)
	c.Detail("to_algorithm", to)
	c.Detail("iterations", n)
	switch {
	case from == "" || to == "":
		c.Error(http.StatusBadRequest, "bad_request", "from_algorithm and to_algorithm are required")
		return
	case strings.EqualFold(from, to):
		c.Error(http.StatusBadRequest, "bad_request", "from_algorithm and to_algorithm must differ")
		return
	case n < 1 || n > drillMaxIterations:
		c.Error(http.StatusBadRequest, "bad_request", "iterations must be between 1 and 10")
		return
	}
	for _, alg := range []string{from, to} {
		if _, err := drillOperation(alg); err != nil {
			msg := err.Error()
			if errors.Is(err, errDrillUnsupported) {
				msg = alg + ": keycore has no operation it can round-trip for this algorithm"
			}
			c.Error(http.StatusBadRequest, "drill_unsupported", msg)
			return
		}
	}
	ctx := c.R.Context()
	// The drill runs the same crypto a key would, so it obeys the same FIPS
	// mode; the target must also be one the tenant's policy lets new keys use.
	for _, alg := range []string{from, to} {
		if err := h.svc.enforceFIPSKeyAlgorithm(ctx, c.Tenant, alg, "key.agility_drill"); err != nil {
			var v fipsModeViolationError
			if errors.As(err, &v) {
				c.Refuse(http.StatusForbidden, "fips_mode_violation", err.Error())
				return
			}
			c.Error(http.StatusInternalServerError, "fips_check_failed", err.Error())
			return
		}
	}
	rules, err := h.svc.agilityRules(ctx, c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "crypto_policy_check_failed", err.Error())
		return
	}
	if refusal := policyRefusal(rules, to, "key.create", time.Now()); refusal != nil {
		c.Detail("rule_id", refusal.Rule.ID)
		c.Refuse(http.StatusForbidden, refusal.Reason, "target "+refusal.Message)
		return
	}
	select {
	case drillSlot <- struct{}{}:
		defer func() { <-drillSlot }()
	default:
		c.Error(http.StatusConflict, "drill_in_progress", "another drill is running on this node; try again when it finishes")
		return
	}

	d := AgilityDrill{ID: newID("drill"), TenantID: c.Tenant, Iterations: n, RunBy: c.Actor(), Result: "passed"}
	var ferr, terr error
	d.From, ferr = measureAlgorithm(from, n, drillBudget)
	if ferr == nil {
		d.To, terr = measureAlgorithm(to, n, drillBudget)
	}
	switch {
	case ferr != nil:
		d.Result, d.Error = "failed", from+": "+ferr.Error()
	case terr != nil:
		d.Result, d.Error = "failed", to+": "+terr.Error()
	default:
		d.Comparison = compareDrill(d.From, d.To)
	}
	d.From.Algorithm, d.To.Algorithm = from, to
	saved, err := h.svc.store.CreateAgilityDrill(ctx, d)
	if err != nil {
		c.Error(http.StatusInternalServerError, "store_failed", err.Error())
		return
	}
	c.Target(saved.ID)
	c.Detail("drill_result", saved.Result)
	if saved.Error != "" {
		c.Detail("drill_error", saved.Error)
	}
	c.JSON(http.StatusCreated, map[string]interface{}{"data": saved})
}
