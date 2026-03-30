package geofence

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Enforcement modes control whether violations block requests or only log them.
const (
	EnforcementEnforce = "enforce"
	EnforcementAudit   = "audit"
)

// Policy defines a geo-fencing rule for data residency compliance.
type Policy struct {
	ID             string
	TenantID       string
	KeyPattern     string
	AllowedRegions []string
	DeniedRegions  []string
	Enforcement    string // "enforce" or "audit"
	CreatedAt      time.Time
}

// CheckRequest carries the context for a geo-fence evaluation.
type CheckRequest struct {
	TenantID    string
	KeyID       string
	SourceRegion string
	Operation   string
}

// CheckResult is the outcome of a geo-fence evaluation.
type CheckResult struct {
	Allowed     bool
	Reason      string
	PolicyID    string
	Enforcement string
}

// Engine evaluates geo-fencing policies against key operations.
type Engine struct {
	mu       sync.RWMutex
	policies map[string][]Policy // keyed by TenantID
}

// NewEngine creates a geo-fence engine with an empty policy cache.
func NewEngine() *Engine {
	return &Engine{
		policies: make(map[string][]Policy),
	}
}

// LoadPolicies replaces the in-memory policy cache with the given set.
func (e *Engine) LoadPolicies(policies []Policy) {
	grouped := make(map[string][]Policy, len(policies))
	for _, p := range policies {
		grouped[p.TenantID] = append(grouped[p.TenantID], p)
	}
	e.mu.Lock()
	e.policies = grouped
	e.mu.Unlock()
}

// Check evaluates whether a key operation is permitted from the given source region.
// It returns early on the first matching deny or allow-list violation.
func (e *Engine) Check(_ context.Context, req CheckRequest) (*CheckResult, error) {
	if req.SourceRegion == "" {
		return &CheckResult{Allowed: true, Reason: "no source region provided; skipping geo-fence"}, nil
	}

	e.mu.RLock()
	tenantPolicies := e.policies[req.TenantID]
	e.mu.RUnlock()

	for _, p := range tenantPolicies {
		if !matchPattern(p.KeyPattern, req.KeyID) {
			continue
		}

		// Check denied regions first — explicit deny wins.
		for _, denied := range p.DeniedRegions {
			if matchRegion(denied, req.SourceRegion) {
				return &CheckResult{
					Allowed:     false,
					Reason:      "source region " + req.SourceRegion + " is denied by policy",
					PolicyID:    p.ID,
					Enforcement: p.Enforcement,
				}, nil
			}
		}

		// If allowed regions are specified, source must match at least one.
		if len(p.AllowedRegions) > 0 {
			matched := false
			for _, allowed := range p.AllowedRegions {
				if matchRegion(allowed, req.SourceRegion) {
					matched = true
					break
				}
			}
			if !matched {
				return &CheckResult{
					Allowed:     false,
					Reason:      "source region " + req.SourceRegion + " is not in allowed regions",
					PolicyID:    p.ID,
					Enforcement: p.Enforcement,
				}, nil
			}
		}
	}

	return &CheckResult{Allowed: true, Reason: "no geo-fence restriction matched"}, nil
}

// matchRegion supports wildcard patterns such as "eu-*" matching "eu-west-1".
func matchRegion(pattern, region string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(region, prefix)
	}
	return strings.EqualFold(pattern, region)
}

// matchPattern matches a key ID against a policy key pattern with wildcard support.
func matchPattern(pattern, keyID string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(keyID, prefix)
	}
	return pattern == keyID
}

// contextKey is an unexported type for context keys in this package.
type contextKey string

const regionContextKey contextKey = "geofence_source_region"

// RegionFromContext extracts the source region stored by HTTPMiddleware.
func RegionFromContext(ctx context.Context) string {
	v, _ := ctx.Value(regionContextKey).(string)
	return v
}

// HTTPMiddleware extracts the source region from the X-Source-Region header
// (falling back to a geographic lookup of the client IP) and stores it in the
// request context. Downstream handlers can retrieve it with RegionFromContext.
func (e *Engine) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		region := r.Header.Get("X-Source-Region")
		if region == "" {
			region = resolveRegionFromIP(r.RemoteAddr)
		}
		ctx := context.WithValue(r.Context(), regionContextKey, region)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// resolveRegionFromIP is a stub for IP-to-region geolocation.
// In production this would call a MaxMind GeoIP database or similar service.
func resolveRegionFromIP(remoteAddr string) string {
	// Strip port if present.
	if idx := strings.LastIndex(remoteAddr, ":"); idx != -1 {
		remoteAddr = remoteAddr[:idx]
	}

	// Private/loopback ranges map to a default region for local development.
	if remoteAddr == "127.0.0.1" || remoteAddr == "::1" || strings.HasPrefix(remoteAddr, "10.") ||
		strings.HasPrefix(remoteAddr, "192.168.") || strings.HasPrefix(remoteAddr, "172.") {
		return "local"
	}

	// Placeholder — integrate with a real geolocation provider.
	return ""
}
