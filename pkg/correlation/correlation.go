// Package correlation carries one request's correlation ID from the service
// that first received it to every service it calls, so the audit events of
// one console action share an ID across services (docs/SECURITY/REQUEST_ORIGIN.md).
//
// The route kernel puts the ID in the request context (With). Internal
// clients send it on every call through servicetoken.Authorize, which every
// internal call already makes (conformance service-token). The edge removes
// the header from outside requests (infra/envoy/envoy.yaml), so a value a
// service receives was set by another platform service, never by a caller
// splicing its events into someone else's request.
package correlation

import "context"

// Header is the request header that carries the ID between services.
const Header = "X-Correlation-ID"

type key struct{}

// With returns ctx carrying id. An empty id leaves ctx unchanged.
func With(ctx context.Context, id string) context.Context {
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, key{}, id)
}

// From returns the ID ctx carries, or "".
func From(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	id, _ := ctx.Value(key{}).(string)
	return id
}
