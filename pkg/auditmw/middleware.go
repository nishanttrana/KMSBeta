package auditmw

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	pkgauth "vecta-kms/pkg/auth"
)

// EventPublisher matches the interface used by all services for NATS audit publishing.
type EventPublisher interface {
	Publish(ctx context.Context, subject string, payload []byte) error
}

// responseCapture wraps http.ResponseWriter to capture status code and bytes written.
type responseCapture struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (rc *responseCapture) WriteHeader(code int) {
	rc.status = code
	rc.ResponseWriter.WriteHeader(code)
}

func (rc *responseCapture) Write(b []byte) (int, error) {
	n, err := rc.ResponseWriter.Write(b)
	rc.bytes += n
	return n, err
}

// Wrap returns an http.Handler that publishes an audit event for every HTTP request.
// This acts as a safety net — no request can bypass audit logging regardless of whether
// the individual service handler publishes its own detailed event.
//
// Events are published asynchronously after the response is written to avoid adding
// latency to the request path.
func Wrap(next http.Handler, publisher EventPublisher, serviceName string) http.Handler {
	if publisher == nil {
		return next
	}
	subject := "audit." + serviceName + ".http_request"

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rc := &responseCapture{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(rc, r)

		// Fire-and-forget — publish in background goroutine so it never blocks the response.
		go func() {
			duration := time.Since(start)

			tenantID := r.URL.Query().Get("tenant_id")
			if tenantID == "" {
				tenantID = r.Header.Get("X-Tenant-ID")
			}

			actorID := ""
			actorRole := ""
			clientID := ""
			if claims, ok := pkgauth.ClaimsFromContext(r.Context()); ok {
				if tenantID == "" {
					tenantID = claims.TenantID
				}
				actorID = claims.UserID
				actorRole = claims.Role
				clientID = claims.ClientID
			}

			result := "success"
			if rc.status >= 400 {
				result = "failure"
			}

			sourceIP := r.RemoteAddr
			if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
				sourceIP = strings.SplitN(fwd, ",", 2)[0]
			}

			evt := map[string]interface{}{
				"tenant_id":      tenantID,
				"service":        serviceName,
				"action":         subject,
				"method":         r.Method,
				"endpoint":       r.URL.Path,
				"query":          sanitizeQuery(r.URL.RawQuery),
				"source_ip":      strings.TrimSpace(sourceIP),
				"user_agent":     r.UserAgent(),
				"actor_id":       actorID,
				"actor_role":     actorRole,
				"client_id":      clientID,
				"status_code":    rc.status,
				"result":         result,
				"response_bytes": rc.bytes,
				"duration_ms":    duration.Milliseconds(),
				"timestamp":      time.Now().UTC().Format(time.RFC3339Nano),
			}

			payload, err := json.Marshal(evt)
			if err != nil {
				return
			}

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = publisher.Publish(ctx, subject, payload)
		}()
	})
}

// sanitizeQuery removes sensitive query parameters from the audit log.
func sanitizeQuery(raw string) string {
	if raw == "" {
		return ""
	}
	parts := strings.Split(raw, "&")
	var clean []string
	for _, p := range parts {
		kv := strings.SplitN(p, "=", 2)
		key := strings.ToLower(kv[0])
		if strings.Contains(key, "password") || strings.Contains(key, "secret") ||
			strings.Contains(key, "token") || strings.Contains(key, "key") ||
			strings.Contains(key, "credential") {
			clean = append(clean, kv[0]+"=***")
		} else {
			clean = append(clean, p)
		}
	}
	return strings.Join(clean, "&")
}
