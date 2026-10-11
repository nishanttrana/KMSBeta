package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/route"
)

// EKM database clients (dashboard: EKM → EKM for DBs).
//
// A client is the agent on one database host, an ekm_agents row. An
// administrator creates it as "pending" and issues a one-time registration
// token. The agent presents the token once and receives its own client key,
// which it sends with every check-in. Nothing in this file marks a client
// registered or seen except a credential the service has verified, and
// health is judged from the time of the last such check-in alone.

const (
	registrationPending    = "pending"
	registrationRegistered = "registered"
	// clientStatusPending is the status of a client no agent has contacted.
	// It is not "connected", which other services count as a live agent.
	clientStatusPending = "pending"

	clientHealthPending  = "pending"
	clientHealthHealthy  = "healthy"
	clientHealthDegraded = "degraded"
	clientHealthOffline  = "offline"

	clientHealthyWithin  = 5 * time.Minute
	clientDegradedWithin = 60 * time.Minute

	registrationTokenTTL    = 24 * time.Hour
	registrationTokenPrefix = "vekm-reg"

	// clientKeyHeader carries the client key. It is not the Authorization
	// header: that one holds auth-service tokens, and a cluster member
	// verifies it as one before forwarding a write to the primary.
	clientKeyHeader = "X-EKM-Client-Key"

	credentialClientKey    = "client_key"
	credentialServiceToken = "service_token"
)

var (
	clientNameRE = regexp.MustCompile(`^[A-Za-z0-9._-]{3,40}$`)
	clientHostRE = regexp.MustCompile(`^[A-Za-z0-9._:-]{0,253}$`)
)

// clientRecord is a client as stored. It holds verifier hashes and is never
// serialized; ClientView is what leaves the service.
type clientRecord struct {
	TenantID, ID, Name, DBEngine, Host, Version, Status, TDEState string
	HeartbeatIntervalSec                                          int
	LastSeenAt                                                    time.Time
	AssignedKeyID, AssignedKeyVersion, MetadataJSON               string
	CreatedAt                                                     time.Time
	Registration                                                  string
	RegisteredAt                                                  time.Time
	SourceIP                                                      string
	TokenHash                                                     string
	TokenExpiresAt                                                time.Time
	CredentialHash                                                string
}

type ClientView struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	DBEngine       string     `json:"db_engine"`
	Host           string     `json:"host"`
	Registration   string     `json:"registration"`
	Health         string     `json:"health"`
	LastSeenAt     *time.Time `json:"last_seen_at,omitempty"`
	LastSeenAgeSec *int64     `json:"last_seen_age_sec,omitempty"`
	RegisteredAt   *time.Time `json:"registered_at,omitempty"`
	CreatedAt      *time.Time `json:"created_at,omitempty"`
	SourceIP       string     `json:"source_ip"`
	Version        string     `json:"version"`
	TDEState       string     `json:"tde_state"`
	// HeartbeatIntervalSec is how often the agent is configured to check in.
	HeartbeatIntervalSec int    `json:"heartbeat_interval_sec"`
	AssignedKeyID        string `json:"assigned_key_id"`
	AssignedKeyVersion   string `json:"assigned_key_version"`
	// Credential is how the client proves itself at check-in: "client_key"
	// (issued at enrolment), "service_token" (registered before 11.6.0-beta)
	// or "" while pending.
	Credential string `json:"credential"`
	// TokenExpiresAt is set while an unused registration token is outstanding.
	TokenExpiresAt *time.Time `json:"token_expires_at,omitempty"`
}

type ClientCheckIn struct {
	TenantID string    `json:"-"`
	ClientID string    `json:"-"`
	At       time.Time `json:"at"`
	SourceIP string    `json:"source_ip"`
	Version  string    `json:"version"`
	// Status is what the agent reported at this check-in.
	Status string `json:"status"`
}

type ClientKey struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Algorithm string `json:"algorithm"`
	Version   string `json:"version"`
	Status    string `json:"status"`
}

type ClientKeyRequest struct {
	At        time.Time `json:"at"`
	Operation string    `json:"operation"`
	Status    string    `json:"status"`
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

func clientHealth(c clientRecord, now time.Time) string {
	switch age := now.Sub(c.LastSeenAt); {
	case c.Registration == registrationPending:
		return clientHealthPending
	case c.LastSeenAt.IsZero():
		return clientHealthOffline
	case age <= clientHealthyWithin:
		return clientHealthHealthy
	case age <= clientDegradedWithin:
		return clientHealthDegraded
	}
	return clientHealthOffline
}

func clientView(c clientRecord, now time.Time) ClientView {
	v := ClientView{
		ID: c.ID, Name: c.Name, DBEngine: c.DBEngine, Host: c.Host,
		Registration: c.Registration, Health: clientHealth(c, now),
		CreatedAt: timePtr(c.CreatedAt), SourceIP: c.SourceIP, Version: c.Version, TDEState: c.TDEState,
		HeartbeatIntervalSec: defaultInt(c.HeartbeatIntervalSec, DefaultHeartbeatSec),
		AssignedKeyID:        c.AssignedKeyID, AssignedKeyVersion: c.AssignedKeyVersion,
	}
	if c.TokenHash != "" && now.Before(c.TokenExpiresAt) {
		v.TokenExpiresAt = timePtr(c.TokenExpiresAt)
	}
	if c.Registration == registrationPending {
		return v
	}
	v.Credential = credentialServiceToken
	if c.CredentialHash != "" {
		v.Credential = credentialClientKey
	}
	v.RegisteredAt = timePtr(c.RegisteredAt)
	if v.RegisteredAt == nil {
		v.RegisteredAt = v.CreatedAt
	}
	if v.LastSeenAt = timePtr(c.LastSeenAt); v.LastSeenAt != nil {
		age := int64(now.Sub(c.LastSeenAt).Seconds())
		if age < 0 {
			age = 0
		}
		v.LastSeenAgeSec = &age
	}
	return v
}

func clientThresholds() map[string]interface{} {
	return map[string]interface{}{
		"healthy_within_sec":  int(clientHealthyWithin.Seconds()),
		"degraded_within_sec": int(clientDegradedWithin.Seconds()),
	}
}

// verifierHash is what is stored for a registration token or a client key:
// both are 256 random bits, so their SHA-256 can't be searched.
func verifierHash(secret string) string {
	return hex.EncodeToString(pkgcrypto.SHA256([]byte(secret)))
}

func newClientSecret() (string, error) {
	raw, err := pkgcrypto.RandomBytes(32)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// sameVerifier compares in constant time. An empty stored verifier matches
// nothing.
func sameVerifier(stored, presented string) bool {
	ok := pkgcrypto.ConstantTimeEqual([]byte(stored), []byte(verifierHash(presented)))
	return ok && stored != ""
}

// parseRegistrationToken splits "vekm-reg.<tenant>.<client>.<secret>".
func parseRegistrationToken(token string) (tenantID, clientID string, ok bool) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 4 || parts[0] != registrationTokenPrefix || parts[2] == "" || parts[3] == "" {
		return "", "", false
	}
	tenant, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(tenant) == 0 {
		return "", "", false
	}
	return string(tenant), parts[2], true
}

// clientIP is the address the request came from. Behind the edge proxy that
// is the last X-Forwarded-For entry, the one the proxy appended; earlier
// entries are the caller's own claim.
func clientIP(r *http.Request) string {
	if fwd := strings.Join(r.Header.Values("X-Forwarded-For"), ","); strings.TrimSpace(fwd) != "" {
		parts := strings.Split(fwd, ",")
		return strings.TrimSpace(parts[len(parts)-1])
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

type sourceIPKey struct{}

func withSourceIP(ctx context.Context, r *http.Request) context.Context {
	return context.WithValue(ctx, sourceIPKey{}, clientIP(r))
}

func sourceIPFrom(ctx context.Context) string { v, _ := ctx.Value(sourceIPKey{}).(string); return v }

// guardLegacyContact refuses the token-authenticated register, heartbeat and
// validate calls for a client that is pending or holds a client key. Those
// calls accept any token of the tenant, so they must not be able to register
// such a client or make it look alive.
func (s *Service) guardLegacyContact(ctx context.Context, tenantID, clientID string) error {
	c, err := s.store.GetClient(ctx, tenantID, clientID)
	if errors.Is(err, errNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if c.Registration == registrationPending {
		return newServiceError(http.StatusForbidden, "client_enrollment_required", "this client is awaiting registration: its agent must present the registration token")
	}
	if c.CredentialHash != "" {
		return newServiceError(http.StatusForbidden, "client_key_required", "this client checks in with the client key it was issued at registration")
	}
	return nil
}

// noteCheckIn records a verified contact made through the token-authenticated
// calls, so those clients have a check-in history too.
func (s *Service) noteCheckIn(ctx context.Context, a Agent, at time.Time) {
	_ = s.store.RecordClientCheckIn(ctx, ClientCheckIn{
		TenantID: a.TenantID, ClientID: a.ID, At: at, SourceIP: sourceIPFrom(ctx), Version: a.Version, Status: a.Status,
	})
}

func (h *Handler) clientRoutes(rt *route.Router) {
	rt.Handle("GET /ekm/clients", route.Spec{Action: "client_list", Permission: "ekm.read", Resource: "ekm_client"}, h.listClients)
	rt.Handle("POST /ekm/clients", route.Spec{Action: "client_created", Permission: "ekm.write", Resource: "ekm_client"}, h.createClient)
	rt.Handle("GET /ekm/clients/{id}", route.Spec{Action: "client_read", Permission: "ekm.read", Resource: "ekm_client", TargetParam: "id"}, h.getClient)
	rt.Handle("POST /ekm/clients/{id}/registration-token", route.Spec{Action: "client_token_issued", Permission: "ekm.write", Resource: "ekm_client", TargetParam: "id", Severity: "warning"}, h.issueClientToken)
	// The agent has no auth-service token: these two verify its own credential.
	rt.Handle("POST /ekm/clients/enroll", route.Spec{Action: "client_enrolled", Public: true, Resource: "ekm_client", Severity: "warning"}, h.enrollClient)
	rt.Handle("POST /ekm/clients/{id}/check-in", route.Spec{Action: "client_check_in", Public: true, Resource: "ekm_client", TargetParam: "id"}, h.clientCheckIn)
}

// clientError answers a store or service error on a kernel route.
func clientError(c *route.Call, err error) {
	var se serviceError
	switch {
	case errors.Is(err, errNotFound):
		c.Error(http.StatusNotFound, "client_not_found", "no such client")
	case errors.As(err, &se):
		c.Error(se.HTTPStatus, se.Code, se.Message)
	default:
		c.Error(http.StatusInternalServerError, "internal_error", "internal server error")
	}
}

func (h *Handler) listClients(c *route.Call) {
	rows, err := h.svc.store.ListClients(c.R.Context(), c.Tenant)
	if err != nil {
		clientError(c, err)
		return
	}
	now := time.Now().UTC()
	items := make([]ClientView, 0, len(rows))
	for _, r := range rows {
		items = append(items, clientView(r, now))
	}
	c.Detail("count", len(items))
	c.JSON(http.StatusOK, map[string]interface{}{"items": items, "thresholds": clientThresholds(), "server_time": now})
}

func (h *Handler) getClient(c *route.Call) {
	ctx, id := c.R.Context(), c.R.PathValue("id")
	rec, err := h.svc.store.GetClient(ctx, c.Tenant, id)
	if err != nil {
		clientError(c, err)
		return
	}
	checkIns, err := h.svc.store.ListClientCheckIns(ctx, c.Tenant, id, 60)
	if err != nil {
		clientError(c, err)
		return
	}
	now := time.Now().UTC()
	out := map[string]interface{}{
		"client": clientView(rec, now), "check_ins": checkIns, "thresholds": clientThresholds(), "server_time": now,
	}
	if rec.AssignedKeyID != "" {
		if key, err := h.svc.store.GetTDEKey(ctx, c.Tenant, rec.AssignedKeyID); err == nil {
			out["key"] = ClientKey{ID: key.ID, Name: key.Name, Algorithm: key.Algorithm, Version: key.CurrentVersion, Status: key.Status}
		}
	}
	if logs, err := h.svc.store.ListKeyAccessByAgent(ctx, c.Tenant, id, 1); err == nil && len(logs) > 0 {
		out["last_key_request"] = ClientKeyRequest{At: logs[0].CreatedAt.UTC(), Operation: logs[0].Operation, Status: logs[0].Status}
	}
	// OS metrics exactly as the agent last reported them; absent if it sent none.
	if meta := parseJSONMap(rec.MetadataJSON); reportedOSMetrics(meta) {
		out["metrics"] = agentOSMetrics(meta, rec.Host)
	}
	if dbs, err := h.svc.store.ListDatabases(ctx, c.Tenant, id); err == nil {
		tde := 0
		for _, d := range dbs {
			if d.TDEEnabled {
				tde++
			}
		}
		out["databases"], out["tde_enabled_databases"] = len(dbs), tde
	}
	c.JSON(http.StatusOK, out)
}

type createClientRequest struct {
	TenantID             string `json:"tenant_id"`
	Name                 string `json:"name"`
	DBEngine             string `json:"db_engine"`
	Host                 string `json:"host"`
	HeartbeatIntervalSec int    `json:"heartbeat_interval_sec"`
	AutoProvisionTDE     *bool  `json:"auto_provision_tde"`
}

func (h *Handler) createClient(c *route.Call) {
	var req createClientRequest
	if !c.Decode(&req) {
		return
	}
	ctx := c.R.Context()
	name, host := strings.TrimSpace(req.Name), strings.TrimSpace(req.Host)
	engine := normalizeDBEngine(req.DBEngine)
	switch {
	case !clientNameRE.MatchString(name):
		c.Error(http.StatusBadRequest, "invalid_name", "name must be 3 to 40 letters, digits, dots, dashes or underscores")
		return
	case !isSupportedTDEEngine(engine):
		c.Error(http.StatusBadRequest, "invalid_db_engine", "db_engine must be mssql, oracle, postgresql, mysql, db2 or mariadb")
		return
	case !clientHostRE.MatchString(host):
		c.Error(http.StatusBadRequest, "invalid_host", "host must be a host name or an IP address")
		return
	case req.HeartbeatIntervalSec != 0 && (req.HeartbeatIntervalSec < 5 || req.HeartbeatIntervalSec > 3600):
		c.Error(http.StatusBadRequest, "invalid_heartbeat_interval", "heartbeat_interval_sec must be between 5 and 3600")
		return
	}
	existing, err := h.svc.store.ListClients(ctx, c.Tenant)
	if err != nil {
		clientError(c, err)
		return
	}
	for _, e := range existing {
		if strings.EqualFold(e.Name, name) {
			c.Error(http.StatusConflict, "client_name_taken", "a client named "+e.Name+" already exists")
			return
		}
	}
	rec := clientRecord{
		TenantID: c.Tenant, ID: newID("ekm"), Name: name, DBEngine: engine, Host: host,
		HeartbeatIntervalSec: req.HeartbeatIntervalSec, MetadataJSON: `{"created_from":"clients"}`,
	}
	c.Target(rec.ID)
	c.Detail("name", name)
	c.Detail("db_engine", engine)
	c.Detail("host", host)
	if err := h.svc.store.CreatePendingClient(ctx, rec); err != nil {
		clientError(c, err)
		return
	}
	// The TDE key is created for the administrator making this request (their
	// token is in ctx). If keycore refuses or fails, no client is left behind.
	if shouldAuto(req.AutoProvisionTDE, true) {
		key, err := h.svc.createTDEKey(ctx, CreateTDEKeyRequest{
			TenantID: c.Tenant, Name: "tde-agent-" + rec.ID, Algorithm: DefaultTDEAlgorithm,
			CreatedBy: "ekm-auto-agent", AgentID: rec.ID, AutoProvisioned: true,
		})
		if err != nil {
			_, _, _, _ = h.svc.store.PurgeAgent(ctx, c.Tenant, rec.ID, nil)
			clientError(c, err)
			return
		}
		c.Detail("assigned_key_id", key.ID)
	}
	out, err := h.svc.store.GetClient(ctx, c.Tenant, rec.ID)
	if err != nil {
		clientError(c, err)
		return
	}
	c.JSON(http.StatusCreated, map[string]interface{}{"client": clientView(out, time.Now().UTC())})
}

// issueClientToken mints the one-time registration token. It is returned
// once and only its hash is kept. For a client that is already registered
// the token re-enrols it: when used, the client key is replaced.
func (h *Handler) issueClientToken(c *route.Call) {
	ctx, id := c.R.Context(), c.R.PathValue("id")
	rec, err := h.svc.store.GetClient(ctx, c.Tenant, id)
	if err != nil {
		clientError(c, err)
		return
	}
	secret, err := newClientSecret()
	if err != nil {
		clientError(c, err)
		return
	}
	token := strings.Join([]string{registrationTokenPrefix, base64.RawURLEncoding.EncodeToString([]byte(c.Tenant)), rec.ID, secret}, ".")
	expires := time.Now().UTC().Add(registrationTokenTTL)
	if err := h.svc.store.SetClientToken(ctx, c.Tenant, rec.ID, verifierHash(token), expires); err != nil {
		clientError(c, err)
		return
	}
	c.Detail("name", rec.Name)
	c.Detail("expires_at", expires.Format(time.RFC3339))
	c.Detail("reenrolment", rec.Registration == registrationRegistered)
	c.W.Header().Set("Cache-Control", "no-store")
	c.JSON(http.StatusCreated, map[string]interface{}{
		"token": token, "expires_at": expires, "client_id": rec.ID, "enroll_path": "/ekm/clients/enroll",
	})
}

type enrollClientRequest struct {
	TenantID string `json:"tenant_id"`
	Token    string `json:"token"`
	Version  string `json:"version"`
	Host     string `json:"host"`
}

func (h *Handler) enrollClient(c *route.Call) {
	var req enrollClientRequest
	if !c.Decode(&req) {
		return
	}
	ctx := c.R.Context()
	refuse := func(reason, msg string) { c.Refuse(http.StatusUnauthorized, reason, msg) }
	tokenTenant, id, ok := parseRegistrationToken(req.Token)
	var rec clientRecord
	if ok && tokenTenant == c.Tenant {
		rec, _ = h.svc.store.GetClient(ctx, c.Tenant, id)
	}
	// Compared even when no client was found, so the answer takes as long.
	if !sameVerifier(rec.TokenHash, strings.TrimSpace(req.Token)) {
		refuse("invalid_registration_token", "the registration token was not accepted")
		return
	}
	c.Target(rec.ID)
	c.Detail("name", rec.Name)
	now := time.Now().UTC()
	if !now.Before(rec.TokenExpiresAt) {
		refuse("registration_token_expired", "the registration token has expired: issue a new one")
		return
	}
	version, host, ip := strings.TrimSpace(req.Version), strings.TrimSpace(req.Host), clientIP(c.R)
	if len(version) > 64 || !clientHostRE.MatchString(host) {
		c.Error(http.StatusBadRequest, "bad_request", "version or host is not valid")
		return
	}
	clientKey, err := newClientSecret()
	if err != nil {
		clientError(c, err)
		return
	}
	used, err := h.svc.store.ConsumeClientToken(ctx, c.Tenant, rec.ID, rec.TokenHash, verifierHash(clientKey), ip, version, host, now)
	if err != nil {
		clientError(c, err)
		return
	}
	if !used {
		refuse("invalid_registration_token", "the registration token was not accepted")
		return
	}
	c.Authenticated(rec.ID, "ekm_client")
	c.Detail("client_source_ip", ip)
	c.Detail("version", version)
	c.Detail("reenrolment", rec.Registration == registrationRegistered)
	_ = h.svc.store.RecordClientCheckIn(ctx, ClientCheckIn{TenantID: c.Tenant, ClientID: rec.ID, At: now, SourceIP: ip, Version: version, Status: AgentStatusConnected})
	out, err := h.svc.store.GetClient(ctx, c.Tenant, rec.ID)
	if err != nil {
		clientError(c, err)
		return
	}
	c.W.Header().Set("Cache-Control", "no-store")
	c.JSON(http.StatusOK, map[string]interface{}{
		"client": clientView(out, now), "tenant_id": c.Tenant, "client_key": clientKey,
		"client_key_header": clientKeyHeader, "check_in_path": "/ekm/clients/" + rec.ID + "/check-in",
	})
}

type clientCheckInRequest struct {
	TenantID         string `json:"tenant_id"`
	Status           string `json:"status"`
	TDEState         string `json:"tde_state"`
	ActiveKeyID      string `json:"active_key_id"`
	ActiveKeyVersion string `json:"active_key_version"`
	ConfigVersionAck int    `json:"config_version_ack"`
	MetadataJSON     string `json:"metadata_json"`
	Version          string `json:"version"`
}

func (h *Handler) clientCheckIn(c *route.Call) {
	ctx, id := c.R.Context(), c.R.PathValue("id")
	rec, _ := h.svc.store.GetClient(ctx, c.Tenant, id)
	if !sameVerifier(rec.CredentialHash, strings.TrimSpace(c.R.Header.Get(clientKeyHeader))) {
		c.Refuse(http.StatusUnauthorized, "invalid_client_key", "the client key was not accepted")
		return
	}
	c.Authenticated(rec.ID, "ekm_client")
	var req clientCheckInRequest
	if !c.Decode(&req) {
		return
	}
	// "disconnected" is the service's own verdict; an agent can't report it.
	status := normalizeAgentStatus(req.Status)
	if status != AgentStatusDegraded {
		status = AgentStatusConnected
	}
	version := strings.TrimSpace(req.Version)
	if len(version) > 64 {
		c.Error(http.StatusBadRequest, "bad_request", "version is not valid")
		return
	}
	now, ip := time.Now().UTC(), clientIP(c.R)
	if err := h.svc.store.UpdateAgentHeartbeat(ctx, c.Tenant, rec.ID, status, normalizeTDEState(req.TDEState),
		strings.TrimSpace(req.ActiveKeyID), strings.TrimSpace(req.ActiveKeyVersion), req.ConfigVersionAck, validJSONOr(req.MetadataJSON, "{}"), now); err != nil {
		clientError(c, err)
		return
	}
	if err := h.svc.store.RecordClientCheckIn(ctx, ClientCheckIn{TenantID: c.Tenant, ClientID: rec.ID, At: now, SourceIP: ip, Version: version, Status: status}); err != nil {
		clientError(c, err)
		return
	}
	c.Detail("status", status)
	c.Detail("client_source_ip", ip)
	out, err := h.svc.store.GetClient(ctx, c.Tenant, rec.ID)
	if err != nil {
		clientError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"client": clientView(out, now), "server_time": now})
}
