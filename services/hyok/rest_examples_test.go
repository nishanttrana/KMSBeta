package main

import (
	"net/http"
	"testing"

	"vecta-kms/pkg/route/routetest"
)

// The REST API tab's examples for this service, sent to its real handlers.
// HYOK verifies the bearer token itself; the test verifier reads
// "jwt:<tenant>:<role>".
func TestRESTExamplesMatchTheService(t *testing.T) {
	h, _, _, _, _, _ := newHYOKHandler(t)
	routetest.Examples(t, routetest.ExampleSet{Service: "hyok", Serve: func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("Authorization", "Bearer jwt:t1:admin")
		h.ServeHTTP(w, r)
	}})
}
