package config

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	pkgaudit "vecta-kms/pkg/audit"
	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/clusterroute"
	"vecta-kms/pkg/clusterstate"
	pkgevents "vecta-kms/pkg/events"
	"vecta-kms/pkg/jwtauth"
)

// Cluster write forwarding (docs/CLUSTERING.md, slice 3), applied to every
// service by NewHTTPServer. On a member, a request that can change shared
// state (pkg/clusterroute) goes to the primary's cluster-manager instead of
// the local handler: the member verifies the caller's token, and the primary
// mints an equivalent token for its own services. Standalone nodes and the
// primary are unaffected.

const (
	HeaderClusterNode       = "X-Vecta-Cluster-Node"
	HeaderClusterCredential = "X-Vecta-Cluster-Credential"
	HeaderForwardClaims     = "X-Vecta-Forward-Claims"
	HeaderForwardedTo       = "X-Vecta-Forwarded-To"
)

var hopByHop = map[string]bool{
	"Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true, "Proxy-Authorization": true,
	"Te": true, "Trailer": true, "Transfer-Encoding": true, "Upgrade": true, "Host": true,
}

type clusterForwarder struct {
	service string
	state   func(*http.Request) clusterstate.State
	parser  func(string) (*pkgauth.Claims, error)
	client  func(clusterstate.State) *http.Client
	emit    func(ctx context.Context, action string, evt pkgaudit.Event)
	next    http.Handler
}

var (
	forwardParserOnce sync.Once
	forwardParser     func(string) (*pkgauth.Claims, error)
	forwardAuditOnce  sync.Once
	forwardAudit      *pkgaudit.Client
)

// emitForwardAudit sends a member-side forwarding event through the single
// audit pipeline. The NATS connection is made on first use, so standalone
// nodes and primaries never open it. If NATS is unreachable the event is
// logged instead (the primary's audit.cluster.* events still record it).
func emitForwardAudit(ctx context.Context, service, action string, evt pkgaudit.Event) {
	forwardAuditOnce.Do(func() {
		nc, err := pkgevents.Connect(get("NATS_URL", "nats://localhost:4222"), service+"-cluster-forward", log.Printf)
		if err != nil {
			log.Printf("cluster forward: audit unavailable: %v", err)
			return
		}
		js, err := nc.JetStream()
		if err == nil {
			forwardAudit, err = pkgaudit.NewClient(js, strings.TrimPrefix(service, "kms-"))
		}
		if err != nil {
			log.Printf("cluster forward: audit unavailable: %v", err)
		}
	})
	if forwardAudit == nil || forwardAudit.Emit(ctx, action, evt) != nil {
		log.Printf("cluster forward audit (not delivered): %s %s %s %s result=%s %s", action, evt.ActorID, evt.Method, evt.Endpoint, evt.Result, evt.ErrorMessage)
	}
}

// withClusterForwarding wraps a service's handler.
func withClusterForwarding(next http.Handler) http.Handler {
	service := fipsServiceName()
	return &clusterForwarder{
		service: service,
		emit: func(ctx context.Context, action string, evt pkgaudit.Event) {
			emitForwardAudit(ctx, service, action, evt)
		},
		state: func(r *http.Request) clusterstate.State { return clusterstate.Default().Get(r.Context()) },
		parser: func(raw string) (*pkgauth.Claims, error) {
			forwardParserOnce.Do(func() {
				cfg := Config{JWTIssuer: get("JWT_ISSUER", "vecta-auth"), JWTAudience: get("JWT_AUDIENCE", "vecta-services")}
				p, err := jwtauth.LoadParser(jwtauth.Config{Prefix: "CLUSTER_FORWARD", Issuer: cfg.JWTIssuer, Audience: cfg.JWTAudience})
				if err != nil {
					log.Printf("cluster forward: token parser unavailable: %v", err)
				}
				forwardParser = p
			})
			if forwardParser == nil {
				return nil, errNoForwardParser
			}
			return forwardParser(raw)
		},
		client: func(st clusterstate.State) *http.Client {
			if strings.HasPrefix(st.PrimaryURL, "https://") {
				return clusterstate.PinnedHTTPClient(st.PrimaryFingerprint, 60*time.Second)
			}
			return &http.Client{Timeout: 60 * time.Second} // lab only (CLUSTER_JOIN_ALLOW_HTTP)
		},
		next: next,
	}
}

type forwardError string

func (e forwardError) Error() string { return string(e) }

const errNoForwardParser = forwardError("no JWT verification key configured")

func writeForwardErr(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

func (f *clusterForwarder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	st := f.state(r)
	if !st.IsMember() {
		f.next.ServeHTTP(w, r)
		return
	}
	switch clusterroute.Decide(f.service, r.Method, r.URL.Path) {
	case clusterroute.RunLocal:
		f.next.ServeHTTP(w, r)
		return
	case clusterroute.Refuse:
		f.audit(r, st, nil, "cluster_write_refused", http.StatusConflict, "primary_write_required")
		writeForwardErr(w, http.StatusConflict, "primary_write_required", "this node is a cluster member; this change must be made on the primary")
		return
	}
	f.forward(w, r, st)
}

func (f *clusterForwarder) forward(w http.ResponseWriter, r *http.Request, st clusterstate.State) {
	// Verify the caller here; the primary trusts this member's word for it.
	var claimsHeader string
	var claims *pkgauth.Claims
	if raw := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer")); raw != "" {
		var err error
		claims, err = f.parser(raw)
		if err != nil {
			f.audit(r, st, nil, "cluster_write_refused", http.StatusUnauthorized, "invalid_token")
			writeForwardErr(w, http.StatusUnauthorized, "unauthorized", "invalid token")
			return
		}
		b, _ := json.Marshal(claims)
		claimsHeader = base64.RawURLEncoding.EncodeToString(b)
	}
	target := strings.TrimRight(st.PrimaryURL, "/") + "/cluster/forward/" + f.service + r.URL.Path
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, target, r.Body)
	if err != nil {
		writeForwardErr(w, http.StatusInternalServerError, "forward_failed", err.Error())
		return
	}
	for k, vs := range r.Header {
		if hopByHop[k] || k == "Authorization" || strings.HasPrefix(k, "X-Vecta-Cluster-") || k == HeaderForwardClaims {
			continue
		}
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set(HeaderClusterNode, st.NodeID)
	req.Header.Set(HeaderClusterCredential, st.ForwardCredential)
	if claimsHeader != "" {
		req.Header.Set(HeaderForwardClaims, claimsHeader)
	}
	resp, err := f.client(st).Do(req)
	if err != nil {
		f.audit(r, st, claims, "cluster_write_refused", http.StatusBadGateway, "primary_unreachable")
		writeForwardErr(w, http.StatusBadGateway, "primary_unreachable", "this change must be made on the primary, which is unreachable: "+err.Error())
		return
	}
	defer resp.Body.Close() //nolint:errcheck
	f.audit(r, st, claims, "cluster_write_forwarded", resp.StatusCode, "")
	for k, vs := range resp.Header {
		if hopByHop[k] {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set(HeaderForwardedTo, st.PrimaryNodeID)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// audit records a member-side forwarding outcome: which write, by whom, to
// which primary, and why it was refused.
func (f *clusterForwarder) audit(r *http.Request, st clusterstate.State, c *pkgauth.Claims, action string, status int, reason string) {
	if f.emit == nil {
		return
	}
	evt := pkgaudit.Event{
		Method: r.Method, Endpoint: r.URL.Path, StatusCode: status,
		SourceIP: r.RemoteAddr, UserAgent: r.UserAgent(), NodeID: st.NodeID,
		CorrelationID: r.Header.Get("X-Request-ID"),
		TargetType:    "cluster_primary", TargetID: st.PrimaryNodeID,
		Result:  "success",
		Details: map[string]interface{}{"service": f.service, "primary_node_id": st.PrimaryNodeID, "severity": "info"},
	}
	if c != nil {
		evt.TenantID, evt.ActorID, evt.ActorRole = c.TenantID, c.UserID, c.Role
		evt.ActorType = "user"
		if c.UserID == "" {
			evt.ActorID, evt.ActorType = c.ClientID, "service"
		}
	}
	if reason != "" {
		evt.Result, evt.ErrorMessage = "refused", reason
		evt.Details["reason"], evt.Details["severity"] = reason, "warning"
	}
	f.emit(r.Context(), action, evt)
}
