package main

import (
	"log"
	"net/http"
	"sort"

	"vecta-kms/pkg/route"
)

// permHealthRead guards the platform health read API (watchdog heartbeats and
// incidents, reconciler status). Only administrators ("*") hold it by
// default; it is platform data, not any one tenant's.
const permHealthRead = "health.read"

// newRouter serves the watchdog's read API through the route kernel, so every
// call is authenticated, needs health.read and is audited as
// audit.watchdog.<action>, refusals included.
func newRouter(heartbeats func() []ServiceState, incidents func() []Incident, audit route.Emitter, logger *log.Logger) *route.Router {
	r := route.New("watchdog", audit, logger)
	spec := func(action, resource string) route.Spec {
		return route.Spec{Action: action, Permission: permHealthRead, Resource: resource, Tenancy: route.PlatformScoped}
	}
	r.Handle("GET /watchdog/heartbeats", spec("heartbeats_listed", "service_heartbeat"), func(c *route.Call) {
		items := heartbeats()
		sort.Slice(items, func(i, j int) bool { return items[i].Service < items[j].Service })
		c.Detail("count", len(items))
		c.JSON(http.StatusOK, map[string]interface{}{"items": items})
	})
	r.Handle("GET /watchdog/incidents", spec("incidents_listed", "watchdog_incident"), func(c *route.Call) {
		items := incidents()
		c.Detail("count", len(items))
		c.JSON(http.StatusOK, map[string]interface{}{"items": items})
	})
	return r
}
