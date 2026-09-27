package main

import (
	"log"
	"net/http"

	pkgreconciler "vecta-kms/pkg/reconciler"
	"vecta-kms/pkg/route"
)

// permHealthRead guards the platform health read API; see the watchdog's
// permission of the same name.
const permHealthRead = "health.read"

// newRouter serves the reconciler's status through the route kernel: every
// call is authenticated, needs health.read and is audited as
// audit.reconciler.status_read, refusals included.
func newRouter(status func() []pkgreconciler.Status, audit route.Emitter, logger *log.Logger) *route.Router {
	r := route.New("reconciler", audit, logger)
	r.Handle("GET /reconciler/status", route.Spec{
		Action: "status_read", Permission: permHealthRead, Resource: "reconciler", Tenancy: route.PlatformScoped,
	}, func(c *route.Call) {
		items := status()
		c.Detail("count", len(items))
		c.JSON(http.StatusOK, map[string]interface{}{"items": items})
	})
	return r
}
