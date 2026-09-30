package main

import (
	"net/http"
	"strings"
	"time"

	"vecta-kms/pkg/route"
)

const maxCryptoperiodDays = 3650

type cryptoperiodView struct {
	Category    string `json:"category"`
	DefaultDays int    `json:"default_days"`
	Days        int    `json:"days"`
	Custom      bool   `json:"custom"`
}

func days(d time.Duration) int { return int(d / (24 * time.Hour)) }

func (h *Handler) cryptoperiodTable() *CryptoperiodPolicy {
	if h.svc.cryptoperiod != nil {
		return h.svc.cryptoperiod
	}
	return NewCryptoperiodPolicy()
}

// listCryptoperiods shows each category's built-in period and the tenant's
// own, which the lifecycle scan uses for rotation.
func (h *Handler) listCryptoperiods(c *route.Call) {
	ov, err := h.svc.store.ListCryptoperiodOverrides(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "list_cryptoperiods_failed", err.Error())
		return
	}
	cp := h.cryptoperiodTable()
	out := []cryptoperiodView{}
	for _, cat := range cp.Categories() {
		def, _ := cp.Default(cat)
		v := cryptoperiodView{Category: cat, DefaultDays: days(def), Days: days(def)}
		if d, ok := ov[cat]; ok {
			v.Days, v.Custom = days(d), true
		}
		out = append(out, v)
	}
	c.Detail("custom", len(ov))
	c.JSON(http.StatusOK, map[string]interface{}{"data": out})
}

// cryptoperiodCategory refuses a category the table doesn't have.
func (h *Handler) cryptoperiodCategory(c *route.Call) (string, bool) {
	cat := strings.ToLower(strings.TrimSpace(c.R.PathValue("category")))
	if _, ok := h.cryptoperiodTable().Default(cat); !ok {
		c.Refuse(http.StatusBadRequest, "unknown_category", "unknown cryptoperiod category")
		return "", false
	}
	return cat, true
}

func (h *Handler) setCryptoperiod(c *route.Call) {
	cat, ok := h.cryptoperiodCategory(c)
	if !ok {
		return
	}
	var req struct {
		Days int `json:"days"`
	}
	if !c.Decode(&req) {
		return
	}
	if req.Days < 1 || req.Days > maxCryptoperiodDays {
		c.Detail("days", req.Days)
		c.Refuse(http.StatusBadRequest, "invalid_days", "days must be between 1 and 3650")
		return
	}
	if err := h.svc.store.SetCryptoperiodOverride(c.R.Context(), c.Tenant, cat, req.Days, c.Actor()); err != nil {
		c.Error(http.StatusInternalServerError, "set_cryptoperiod_failed", err.Error())
		return
	}
	def, _ := h.cryptoperiodTable().Default(cat)
	c.Detail("days", req.Days)
	c.Detail("default_days", days(def))
	c.JSON(http.StatusOK, map[string]interface{}{"data": cryptoperiodView{Category: cat, DefaultDays: days(def), Days: req.Days, Custom: true}})
}

func (h *Handler) resetCryptoperiod(c *route.Call) {
	cat, ok := h.cryptoperiodCategory(c)
	if !ok {
		return
	}
	removed, err := h.svc.store.DeleteCryptoperiodOverride(c.R.Context(), c.Tenant, cat)
	if err != nil {
		c.Error(http.StatusInternalServerError, "reset_cryptoperiod_failed", err.Error())
		return
	}
	if !removed {
		c.Refuse(http.StatusNotFound, "not_custom", "category already uses the built-in period")
		return
	}
	def, _ := h.cryptoperiodTable().Default(cat)
	c.JSON(http.StatusOK, map[string]interface{}{"data": cryptoperiodView{Category: cat, DefaultDays: days(def), Days: days(def)}})
}
