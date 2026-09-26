// Package route is the feature kernel every HTTP endpoint registers through.
//
// A route declares what it is (Spec), and the kernel applies the
// platform-wide rules to it on every request, in one place:
//
//  1. authentication: the verified JWT claims must be present (pkg/jwtauth
//     sets them), unless the route is explicitly Public;
//  2. tenancy: one tenant is resolved from the query, headers and JSON body.
//     Conflicting sources are refused, and the tenant must match the token
//     (service principals and tenant-less root tokens excepted, as in
//     pkg/tenantcheck);
//  3. authorization: the caller must hold Spec.Permission;
//  4. audit: exactly one specific event, audit.<service>.<Spec.Action>, is
//     emitted for every request. It carries the actor, tenant, target,
//     correlation ID, outcome and, for refusals, the reason.
//
// Handlers receive a *Call that holds the resolved tenant and caller, so a
// handler can't read an unchecked tenant or forget to audit. Registering a
// route without an action or a permission fails at startup. This is how
// cross-cutting rules reach new features by construction rather than by
// reminder (docs/PLATFORM_CONTRACT.md, docs/DECISIONS.md 2026-09-26).
package route

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	pkgaudit "vecta-kms/pkg/audit"
	pkgauth "vecta-kms/pkg/auth"
	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/tenantcheck"
)

// Emitter is the audit sink; *pkgaudit.Client satisfies it.
type Emitter interface {
	Emit(ctx context.Context, action string, evt pkgaudit.Event) error
}

// Tenancy says whether a route acts inside one tenant.
type Tenancy int

const (
	// TenantScoped (the default) resolves and enforces exactly one tenant.
	TenantScoped Tenancy = iota
	// PlatformScoped routes act on no tenant's data (health, version).
	PlatformScoped
)

// Authenticated is the Permission for routes any verified identity may call.
const Authenticated = "authenticated"

// Result values carried on audit events.
const (
	ResultSuccess = "success"
	ResultFailure = "failure"
	ResultRefused = "refused"
)

// Refusal reasons the kernel itself produces.
const (
	ReasonUnauthenticated  = "unauthenticated"
	ReasonPermissionDenied = "permission_denied"
	ReasonTenantMismatch   = "tenant_mismatch"
	ReasonTenantConflict   = "tenant_conflict"
)

// MaxBody bounds request bodies read by the kernel.
const MaxBody = 16 << 20

// Spec declares a route's contract. Action and Permission are required.
type Spec struct {
	// Action is the audit action: the event is audit.<service>.<Action>.
	Action string
	// Permission the caller must hold, as <domain>.<verb> (e.g.
	// "secrets.write"), or Authenticated. Ignored when Public.
	Permission string
	// Resource is the audit target type (e.g. "secret").
	Resource string
	// TargetParam names the path wildcard holding the target ID (e.g. "id").
	TargetParam string
	// Tenancy defaults to TenantScoped.
	Tenancy Tenancy
	// TenantHeaders are extra headers a protocol uses to carry the tenant
	// (e.g. X-Vault-Namespace), read after tenant_id and X-Tenant-ID.
	TenantHeaders []string
	// OpaqueBody marks a body that is the caller's own data (e.g. a Vault
	// KV v1 write), so a tenant_id key in it is data, not a tenant.
	OpaqueBody bool
	// Public routes need no identity. They are still audited.
	Public bool
	// Severity is info (default), warning or critical. Refusals are at
	// least warning.
	Severity string
}

// Route is one registered pattern with its contract.
type Route struct {
	Pattern string
	Spec    Spec
}

// Router is an http.Handler whose every route goes through the kernel.
type Router struct {
	service string
	audit   Emitter
	logger  *log.Logger
	mux     *http.ServeMux
	routes  []Route
}

// New returns a router for service. audit may be nil (no bus, or tests); a
// nil *pkgaudit.Client is treated as nil.
func New(service string, audit Emitter, logger *log.Logger) *Router {
	if c, ok := audit.(*pkgaudit.Client); ok && c == nil {
		audit = nil
	}
	if logger == nil {
		logger = log.Default()
	}
	return &Router{service: service, audit: audit, logger: logger, mux: http.NewServeMux()}
}

var actionRE = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$`)

// Handle registers pattern ("METHOD /path") under spec. An invalid spec
// panics: it's a programming error, and it must stop the service at startup
// rather than serve an unguarded route.
func (rt *Router) Handle(pattern string, spec Spec, h func(*Call)) {
	if err := spec.validate(pattern); err != nil {
		panic("route: " + pattern + ": " + err.Error())
	}
	rt.routes = append(rt.routes, Route{Pattern: pattern, Spec: spec})
	rt.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) { rt.serve(w, r, spec, h) })
}

// Routes returns the registered contracts, sorted by pattern.
func (rt *Router) Routes() []Route {
	out := append([]Route(nil), rt.routes...)
	sort.Slice(out, func(i, j int) bool { return out[i].Pattern < out[j].Pattern })
	return out
}

func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) { rt.mux.ServeHTTP(w, r) }

// MountOn registers every route on a legacy mux, delegating to the kernel.
// A service still on the route-kernel burn-down list uses it to add routes
// that get the kernel's guarantees before its handler is migrated.
func (rt *Router) MountOn(mux *http.ServeMux) {
	for _, r := range rt.routes {
		mux.Handle(r.Pattern, rt)
	}
}

func (s Spec) validate(pattern string) error {
	method, _, ok := strings.Cut(pattern, " ")
	if !ok || method == "" || strings.ToUpper(method) != method {
		return errors.New(`pattern must be "METHOD /path"`)
	}
	if !actionRE.MatchString(s.Action) {
		return errors.New("Action is required (lowercase, dot-separated)")
	}
	if !s.Public && s.Permission == "" {
		return errors.New("Permission is required (or route.Authenticated, or Public)")
	}
	if s.TargetParam != "" && !strings.Contains(pattern, "{"+s.TargetParam) {
		return fmt.Errorf("TargetParam %q is not a wildcard in the pattern", s.TargetParam)
	}
	switch s.Severity {
	case "", "info", "warning", "critical":
	default:
		return fmt.Errorf("unknown Severity %q", s.Severity)
	}
	return nil
}

// Call is one request as the kernel has checked it.
type Call struct {
	W         http.ResponseWriter
	R         *http.Request
	Tenant    string          // resolved and enforced; "" on PlatformScoped routes
	Claims    *pkgauth.Claims // nil only on Public routes without a token
	RequestID string

	status  int
	result  string
	reason  string
	errCode string
	errMsg  string
	target  string
	details map[string]interface{}
}

// Target records the audit target ID (overrides Spec.TargetParam).
func (c *Call) Target(id string) { c.target = strings.TrimSpace(id) }

// Detail adds a field to the audit event's details. Never pass secret values.
func (c *Call) Detail(key string, value interface{}) {
	if c.details == nil {
		c.details = map[string]interface{}{}
	}
	c.details[key] = value
}

// Actor is the verified caller's identity, "" when unauthenticated.
func (c *Call) Actor() string {
	if c.Claims == nil {
		return ""
	}
	for _, v := range []string{c.Claims.UserID, c.Claims.ClientID, c.Claims.Subject} {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

// Decode reads the JSON body into out, rejecting unknown fields. On failure
// it writes a 400 and returns false.
func (c *Call) Decode(out interface{}) bool {
	d := json.NewDecoder(c.R.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		c.Error(http.StatusBadRequest, "bad_request", err.Error())
		return false
	}
	return true
}

// JSON writes a success (or any non-error) payload with the request ID.
func (c *Call) JSON(status int, payload map[string]interface{}) {
	if payload == nil {
		payload = map[string]interface{}{}
	}
	if _, ok := payload["request_id"]; !ok {
		payload["request_id"] = c.RequestID
	}
	c.write(status, payload)
}

// Error writes the standard error envelope. The event records a failure.
func (c *Call) Error(status int, code, msg string) {
	c.errCode, c.errMsg = code, msg
	c.write(status, map[string]interface{}{"error": map[string]interface{}{
		"code": code, "message": msg, "request_id": c.RequestID, "tenant_id": c.Tenant,
	}})
}

// Refuse writes an error and records the event as refused with reason:
// denied permission, integrity or tamper failures, preview or FIPS refusals.
func (c *Call) Refuse(status int, reason, msg string) {
	c.Error(status, reason, msg)
	c.result, c.reason = ResultRefused, reason
}

func (c *Call) write(status int, payload map[string]interface{}) {
	c.W.Header().Set("Content-Type", "application/json")
	c.W.WriteHeader(status)
	_ = json.NewEncoder(c.W).Encode(payload)
}

type capture struct {
	http.ResponseWriter
	status int
}

func (w *capture) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *capture) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (rt *Router) serve(w http.ResponseWriter, r *http.Request, spec Spec, h func(*Call)) {
	start := time.Now()
	cw := &capture{ResponseWriter: w}
	c := &Call{W: cw, R: r, RequestID: headerOr(r, "X-Request-ID", "")}
	if c.RequestID == "" {
		c.RequestID = newRequestID()
	}
	if claims, ok := pkgauth.ClaimsFromContext(r.Context()); ok {
		c.Claims = claims
	}
	defer func() { rt.emit(c, spec, cw.status, time.Since(start)) }()

	if c.Claims == nil && !spec.Public {
		c.Refuse(http.StatusUnauthorized, ReasonUnauthenticated, "authentication required")
		return
	}
	if !spec.Public && !Allowed(c.Claims, spec.Permission) {
		c.Refuse(http.StatusForbidden, ReasonPermissionDenied, "missing permission "+spec.Permission)
		return
	}
	if spec.Tenancy == TenantScoped {
		tenant, reason, err := resolveTenant(r, spec, c.Claims)
		if err != nil {
			c.Error(http.StatusBadRequest, "bad_request", err.Error())
			return
		}
		if reason != "" {
			// Recorded under the caller's own tenant; the tenant it tried to
			// reach goes in the details.
			c.Detail("requested_tenant", tenant)
			c.Refuse(http.StatusForbidden, reason, "tenant_id does not match the authenticated token")
			return
		}
		c.Tenant = tenant
		if tenant == "" {
			c.Error(http.StatusBadRequest, "tenant_required", "tenant_id is required (query, X-Tenant-ID or body)")
			return
		}
	}
	if spec.TargetParam != "" {
		c.target = strings.TrimSpace(r.PathValue(spec.TargetParam))
	}
	h(c)
}

// CoarseDomains are the data-plane domains covered by the coarse grants that
// activated API clients hold (kms.read, kms.write). A domain joins only by an
// explicit decision when its service migrates. Administrative domains (auth,
// cluster, governance, audit) never do.
var CoarseDomains = map[string]bool{"secrets": true}

// Allowed reports whether claims grant perm. A grant matches exactly, as "*",
// or as a "<domain>.*" prefix. In a CoarseDomains domain, kms.read grants any
// *.read, and kms.write any *.write or *.delete. Internal service principals
// (unforgeable, see tenantcheck) are allowed.
func Allowed(claims *pkgauth.Claims, perm string) bool {
	if claims == nil {
		return false
	}
	if perm == Authenticated || tenantcheck.IsServicePrincipal(claims) {
		return true
	}
	domain, _, _ := strings.Cut(perm, ".")
	for _, g := range claims.Permissions {
		g = strings.TrimSpace(g)
		switch {
		case g == "*", g == perm:
			return true
		case strings.HasSuffix(g, ".*") && strings.HasPrefix(perm, strings.TrimSuffix(g, "*")):
			return true
		case !CoarseDomains[domain]:
		case g == "kms.read" && strings.HasSuffix(perm, ".read"):
			return true
		case g == "kms.write" && (strings.HasSuffix(perm, ".write") || strings.HasSuffix(perm, ".delete")):
			return true
		}
	}
	return false
}

// resolveTenant finds the one tenant a request names. Every explicit source
// (query tenant_id, X-Tenant-ID, spec.TenantHeaders, top-level JSON
// tenant_id) must agree; a disagreement is a smuggling attempt and refused.
// With no explicit source, the token's tenant applies. It returns the
// tenant, a refusal reason ("" if allowed), or a request error.
func resolveTenant(r *http.Request, spec Spec, claims *pkgauth.Claims) (string, string, error) {
	sources := []string{r.URL.Query().Get("tenant_id"), r.Header.Get("X-Tenant-ID")}
	for _, h := range spec.TenantHeaders {
		sources = append(sources, r.Header.Get(h))
	}
	if !spec.OpaqueBody {
		body, err := peekBodyTenant(r)
		if err != nil {
			return "", "", err
		}
		sources = append(sources, body)
	}

	tenant := ""
	for _, s := range sources {
		s = strings.TrimSpace(s)
		switch {
		case s == "":
		case tenant == "":
			tenant = s
		case !strings.EqualFold(tenant, s):
			return tenant, ReasonTenantConflict, nil
		}
	}
	if claims == nil {
		return tenant, "", nil
	}
	claimTenant := strings.TrimSpace(claims.TenantID)
	if tenant == "" && !tenantcheck.IsServicePrincipal(claims) {
		tenant = claimTenant
	}
	if claimTenant != "" && !tenantcheck.IsServicePrincipal(claims) && !strings.EqualFold(claimTenant, tenant) {
		return tenant, ReasonTenantMismatch, nil
	}
	return tenant, "", nil
}

// peekBodyTenant reads a JSON body's top-level tenant_id and restores the
// body for the handler. Non-JSON or non-object bodies carry no tenant.
func peekBodyTenant(r *http.Request) (string, error) {
	if r.Body == nil || r.Body == http.NoBody {
		return "", nil
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
	_ = r.Body.Close()
	if err != nil {
		return "", errors.New("unreadable request body")
	}
	if len(raw) > MaxBody {
		return "", errors.New("request body too large")
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	var probe struct {
		TenantID json.RawMessage `json:"tenant_id"`
	}
	if json.Unmarshal(raw, &probe) != nil || len(probe.TenantID) == 0 {
		return "", nil
	}
	var s string
	if json.Unmarshal(probe.TenantID, &s) != nil {
		return "", errors.New("tenant_id must be a string")
	}
	return s, nil
}

func (rt *Router) emit(c *Call, spec Spec, status int, took time.Duration) {
	if rt.audit == nil {
		return
	}
	if status == 0 {
		status = http.StatusOK
	}
	result := c.result
	if result == "" {
		result = ResultSuccess
		if status >= 400 {
			result = ResultFailure
		}
	}
	severity := spec.Severity
	if severity == "" {
		severity = "info"
	}
	if result == ResultRefused && severity == "info" {
		severity = "warning"
	}
	details := map[string]interface{}{"severity": severity}
	for k, v := range c.details {
		details[k] = v
	}
	if c.reason != "" {
		details["reason"] = c.reason
	}
	if c.errCode != "" && result == ResultFailure {
		details["error_code"] = c.errCode
	}
	r := c.R
	evt := pkgaudit.Event{
		TenantID:      c.Tenant,
		ActorID:       c.Actor(),
		ActorType:     actorType(c.Claims),
		TargetType:    spec.Resource,
		TargetID:      c.target,
		Result:        result,
		StatusCode:    status,
		ErrorMessage:  c.errMsg,
		SourceIP:      sourceIP(r),
		UserAgent:     r.UserAgent(),
		Method:        r.Method,
		Endpoint:      r.URL.Path,
		CorrelationID: headerOr(r, "X-Correlation-ID", c.RequestID),
		DurationMS:    float64(took.Milliseconds()),
		Details:       details,
	}
	if c.Claims != nil {
		evt.ActorRole = c.Claims.Role
		if evt.TenantID == "" {
			evt.TenantID = c.Claims.TenantID
		}
	}
	// A detached context: the request's may already be cancelled, and the
	// event must still be published.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer cancel()
	if err := rt.audit.Emit(ctx, spec.Action, evt); err != nil {
		rt.logger.Printf("route: audit emit %s.%s failed: %v", rt.service, spec.Action, err)
	}
}

func actorType(claims *pkgauth.Claims) string {
	switch {
	case claims == nil:
		return ""
	case tenantcheck.IsServicePrincipal(claims):
		return "service"
	case strings.TrimSpace(claims.UserID) != "":
		return "user"
	default:
		return "client"
	}
}

func sourceIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		first, _, _ := strings.Cut(fwd, ",")
		return strings.TrimSpace(first)
	}
	return r.RemoteAddr
}

func headerOr(r *http.Request, name, def string) string {
	if v := strings.TrimSpace(r.Header.Get(name)); v != "" {
		return v
	}
	return def
}

func newRequestID() string {
	b, err := pkgcrypto.RandomBytes(8)
	if err != nil {
		panic("route: system randomness unavailable: " + err.Error())
	}
	return "req_" + hex.EncodeToString(b)
}
