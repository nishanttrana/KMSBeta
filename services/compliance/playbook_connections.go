package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	neturl "net/url"
	"sort"
	"strings"
	"sync"
	"time"

	pkgaudit "vecta-kms/pkg/audit"
	"vecta-kms/pkg/clusterstate"
	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/mek"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/siem"
	"vecta-kms/pkg/tenantcheck"
)

// Connections hold the endpoints and credentials the platform sends through:
// Slack, Teams, webhooks, Jira, ServiceNow and SIEMs (pkg/siem). They are the
// only store of them: playbook actions, the audit event stream and
// governance approval notices all name a connection (docs/SECURITY/CONNECTIONS.md). Every field is sealed as one
// envelope under the compliance master key from keycore (pkg/mek,
// docs/SECURITY/SERVICE_MASTER_KEYS.md); only the name, type and endpoint
// host are stored in plaintext. The API never returns a field value.
// Actions name a connection_id, so a playbook definition holds no secret.

const connectionItemType = "playbook_connection"

// ConnectionSpec describes one connection type's fields.
type ConnectionSpec struct {
	Type   string   `json:"type"`
	Label  string   `json:"label"`
	Fields []string `json:"fields"`
	// URLField is the endpoint; its host is shown, and it must be public https.
	URLField string   `json:"url_field"`
	Optional []string `json:"optional,omitempty"`
	// Category groups types: notify, ticketing or siem.
	Category string `json:"category"`
	// Secrets are credential fields (the form masks them). No field value
	// is ever returned, secret or not.
	Secrets []string `json:"secrets"`
	// Stream types can carry the audit event stream (audit service).
	Stream bool `json:"stream"`
}

const (
	categoryNotify    = "notify"
	categoryTicketing = "ticketing"
	categorySIEM      = "siem"
)

var connectionTypes = func() []ConnectionSpec {
	out := []ConnectionSpec{
		{Type: "slack", Label: "Slack incoming webhook", Fields: []string{"webhook_url"}, URLField: "webhook_url", Category: categoryNotify, Secrets: []string{"webhook_url"}, Stream: true},
		{Type: "teams", Label: "Microsoft Teams webhook", Fields: []string{"webhook_url"}, URLField: "webhook_url", Category: categoryNotify, Secrets: []string{"webhook_url"}, Stream: true},
		{Type: "webhook", Label: "HTTPS webhook", Fields: []string{"url"}, URLField: "url", Optional: []string{"headers", "signing_secret"}, Category: categoryNotify, Secrets: []string{"headers", "signing_secret"}, Stream: true},
		{Type: "jira", Label: "Jira", Fields: []string{"base_url"}, URLField: "base_url", Optional: []string{"api_token"}, Category: categoryTicketing, Secrets: []string{"api_token"}},
		{Type: "servicenow", Label: "ServiceNow", Fields: []string{"instance_url"}, URLField: "instance_url", Optional: []string{"auth_token"}, Category: categoryTicketing, Secrets: []string{"auth_token"}},
	}
	for _, s := range siem.Specs {
		out = append(out, ConnectionSpec{Type: s.Kind, Label: s.Label, Fields: s.Required, URLField: s.URLField, Optional: s.Optional,
			Category: categorySIEM, Secrets: s.Secrets, Stream: true})
	}
	return out
}()

var connectionByType = map[string]ConnectionSpec{}

func init() {
	for _, c := range connectionTypes {
		connectionByType[c.Type] = c
	}
}

// connectionFits reports whether a connection of type typ serves an action
// or use that asks for want: the same type, or any SIEM type for "siem".
func connectionFits(want, typ string) bool {
	return want == typ || (want == categorySIEM && connectionByType[typ].Category == categorySIEM)
}

// minSigningSecret: HMAC keys under 112 bits are not approved (SP 800-131A).
const minSigningSecret = 16

// Connection is a stored connection. Fields hold plaintext only in memory.
type Connection struct {
	ID        string                        `json:"id"`
	TenantID  string                        `json:"tenant_id"`
	Name      string                        `json:"name"`
	Type      string                        `json:"type"`
	Endpoint  string                        `json:"endpoint"` // host only
	FieldSet  []string                      `json:"fields_set"`
	CreatedBy string                        `json:"created_by"`
	CreatedAt time.Time                     `json:"created_at"`
	UpdatedAt time.Time                     `json:"updated_at"`
	Fields    map[string]string             `json:"-"`
	Sealed    *pkgcrypto.EnvelopeCiphertext `json:"-"`
}

var errConnKeyUnavailable = errors.New("connections unavailable: the compliance master key has not been opened from keycore")

type sealedFields struct {
	TenantID     string            `json:"tenant_id"`
	ConnectionID string            `json:"connection_id"`
	Fields       map[string]string `json:"fields"`
}

// connVault holds the compliance keyring once it is open.
type connVault struct {
	mu      sync.RWMutex
	keyring *mek.Keyring
	err     error
}

func (v *connVault) set(k *mek.Keyring) {
	v.mu.Lock()
	v.keyring, v.err = k, nil
	v.mu.Unlock()
}

func (v *connVault) fail(err error) {
	v.mu.Lock()
	v.err = err
	v.mu.Unlock()
}

func (v *connVault) current() (*mek.Keyring, error) {
	if v == nil {
		return nil, errConnKeyUnavailable
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.keyring == nil {
		if v.err != nil {
			return nil, fmt.Errorf("%w: %v", errConnKeyUnavailable, v.err)
		}
		return nil, errConnKeyUnavailable
	}
	return v.keyring, nil
}

// Seal puts c.Fields into c.Sealed. The envelope names its tenant and
// connection, so a blob copied onto another row does not open there.
func (v *connVault) Seal(c *Connection) error {
	k, err := v.current()
	if err != nil {
		return err
	}
	raw, err := json.Marshal(sealedFields{TenantID: c.TenantID, ConnectionID: c.ID, Fields: c.Fields})
	if err != nil {
		return err
	}
	defer pkgcrypto.Zeroize(raw)
	env, err := pkgcrypto.EncryptEnvelope(k.Current(), raw)
	if err != nil {
		return err
	}
	c.Sealed = env
	c.FieldSet = fieldNames(c.Fields)
	return nil
}

// Open fills c.Fields from c.Sealed.
func (v *connVault) Open(c Connection) (Connection, error) {
	if c.Sealed == nil {
		return c, errors.New("connection has no sealed fields")
	}
	k, err := v.current()
	if err != nil {
		return c, err
	}
	raw, err := pkgcrypto.DecryptEnvelope(k.Current(), c.Sealed)
	if err != nil {
		return c, fmt.Errorf("connection fields do not open under the compliance master key: %w", err)
	}
	defer pkgcrypto.Zeroize(raw)
	var sf sealedFields
	if err := json.Unmarshal(raw, &sf); err != nil {
		return c, err
	}
	if sf.TenantID != c.TenantID || sf.ConnectionID != c.ID {
		return c, errors.New("connection fields belong to a different connection")
	}
	c.Fields = sf.Fields
	return c, nil
}

func fieldNames(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		if v != "" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// validateConnection checks type, fields and the endpoint.
func validateConnection(c Connection) error {
	spec, ok := connectionByType[c.Type]
	if !ok {
		return fmt.Errorf("unsupported connection type %q", c.Type)
	}
	if strings.TrimSpace(c.Name) == "" {
		return errors.New("name is required")
	}
	allowed := map[string]bool{}
	for _, f := range append(append([]string{}, spec.Fields...), spec.Optional...) {
		allowed[f] = true
	}
	for k := range c.Fields {
		if !allowed[k] {
			return fmt.Errorf("unknown field %q for %s", k, c.Type)
		}
	}
	for _, f := range spec.Fields {
		if strings.TrimSpace(c.Fields[f]) == "" {
			return fmt.Errorf("%s is required", f)
		}
	}
	if h := strings.TrimSpace(c.Fields["headers"]); h != "" {
		var headers map[string]string
		if json.Unmarshal([]byte(h), &headers) != nil {
			return errors.New("headers must be a JSON object of strings")
		}
	}
	if s := c.Fields["signing_secret"]; s != "" && len(s) < minSigningSecret {
		return errors.New("signing_secret must be at least 16 characters (HMAC keys under 112 bits are not approved)")
	}
	if spec.Category == categorySIEM {
		// Build it: the destination checks its own fields (https, DCR and
		// stream names, the syslog address and CA).
		if _, err := siem.New(c.Type, c.Fields, siem.Options{Client: http.DefaultClient}); err != nil {
			return err
		}
		return checkOutboundURL(siem.ValidationURL(c.Type, c.Fields))
	}
	return checkOutboundURL(c.Fields[spec.URLField])
}

// connectionEndpoint is the host shown for a connection.
func connectionEndpoint(c Connection) string {
	spec := connectionByType[c.Type]
	if spec.Category == categorySIEM {
		return endpointHost(siem.ValidationURL(c.Type, c.Fields))
	}
	return endpointHost(c.Fields[spec.URLField])
}

func endpointHost(raw string) string {
	u, err := neturl.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// ---- routes ----

type connectionInput struct {
	TenantID string            `json:"tenant_id"` // verified by the kernel
	Name     string            `json:"name"`
	Type     string            `json:"type"`
	Fields   map[string]string `json:"fields"`
}

const keepField = "********"

func (h *Handler) connectionRoutes(rt *route.Router) {
	spec := func(action, perm, target string, sev string) route.Spec {
		return route.Spec{Action: action, Permission: perm, Resource: "playbook_connection", TargetParam: target, Severity: sev}
	}
	rt.Handle("GET /compliance/playbooks/connections", spec("connections_listed", permPlaybookRead, "", ""), h.listConnections)
	rt.Handle("POST /compliance/playbooks/connections", spec("connection_created", permPlaybookWrite, "", "warning"), h.createConnection)
	rt.Handle("PUT /compliance/playbooks/connections/{id}", spec("connection_updated", permPlaybookWrite, "id", "warning"), h.updateConnection)
	rt.Handle("DELETE /compliance/playbooks/connections/{id}", spec("connection_deleted", permPlaybookDelete, "id", "warning"), h.deleteConnection)
	rt.Handle("POST /compliance/playbooks/connections/{id}/test", spec("connection_tested", permPlaybookWrite, "id", ""), h.testConnection)
}

func (h *Handler) listConnections(c *route.Call) {
	items, err := h.svc.store.ListConnections(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "internal_error", "list connections failed")
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"data": items, "types": connectionTypes})
}

func (h *Handler) createConnection(c *route.Call) {
	var in connectionInput
	if !c.Decode(&in) {
		return
	}
	conn := Connection{ID: newID("pbconn"), TenantID: c.Tenant, Name: strings.TrimSpace(in.Name), Type: in.Type, Fields: in.Fields, CreatedBy: c.Actor()}
	c.Target(conn.ID)
	if !h.sealConnection(c, &conn) {
		return
	}
	created, err := h.svc.store.CreateConnection(c.R.Context(), conn)
	if err != nil {
		c.Error(http.StatusInternalServerError, "internal_error", "create connection failed")
		return
	}
	c.JSON(http.StatusCreated, map[string]interface{}{"data": created})
}

// updateConnection replaces fields. A field sent as ******** keeps its
// stored value; replacing every stored credential retires an exposure the
// migration recorded.
func (h *Handler) updateConnection(c *route.Call) {
	stored, err := h.svc.store.GetConnection(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if errors.Is(err, errNotFound) {
		c.Error(http.StatusNotFound, "not_found", "connection not found")
		return
	} else if err != nil {
		c.Error(http.StatusInternalServerError, "internal_error", "read connection failed")
		return
	}
	var in connectionInput
	if !c.Decode(&in) {
		return
	}
	if in.Type != stored.Type {
		c.Error(http.StatusBadRequest, "bad_request", "a connection's type can't change")
		return
	}
	opened, err := h.connVault.Open(stored)
	if err != nil {
		c.Error(http.StatusServiceUnavailable, "connections_unavailable", err.Error())
		return
	}
	replacedAll := true
	for k, v := range in.Fields {
		if v == keepField {
			in.Fields[k] = opened.Fields[k]
			replacedAll = false
		}
	}
	stored.Name, stored.Fields = strings.TrimSpace(in.Name), in.Fields
	if !h.sealConnection(c, &stored) {
		return
	}
	updated, err := h.svc.store.UpdateConnection(c.R.Context(), stored)
	if err != nil {
		c.Error(http.StatusInternalServerError, "internal_error", "update connection failed")
		return
	}
	if replacedAll {
		if k, err := h.connVault.current(); err == nil {
			if ok, _ := k.Remediate(c.R.Context(), c.Tenant, connectionItemType, stored.ID, "credentials_replaced", c.Actor()); ok {
				c.Detail("exposure_remediated", true)
			}
		}
	}
	c.JSON(http.StatusOK, map[string]interface{}{"data": updated})
}

func (h *Handler) sealConnection(c *route.Call, conn *Connection) bool {
	c.Detail("name", conn.Name)
	c.Detail("type", conn.Type)
	if err := validateConnection(*conn); err != nil {
		var ue urlError
		if errors.As(err, &ue) {
			c.Refuse(http.StatusBadRequest, reasonURLBlocked, err.Error())
		} else {
			c.Error(http.StatusBadRequest, "bad_request", err.Error())
		}
		return false
	}
	conn.Endpoint = connectionEndpoint(*conn)
	c.Detail("endpoint", conn.Endpoint)
	if err := h.connVault.Seal(conn); err != nil {
		c.Error(http.StatusServiceUnavailable, "connections_unavailable", err.Error())
		return false
	}
	return true
}

func (h *Handler) deleteConnection(c *route.Call) {
	id := c.R.PathValue("id")
	pbs, err := h.svc.store.ListPlaybooks(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "internal_error", "list playbooks failed")
		return
	}
	var users []string
	for _, pb := range pbs {
		for _, a := range pb.Actions {
			if a.Parameters["connection_id"] == id {
				users = append(users, pb.ID)
				break
			}
		}
	}
	if h.usage != nil {
		others, err := h.usage.Users(c.R.Context(), c.Tenant, id)
		if err != nil {
			// Fail closed: deleting a connection a stream still uses would
			// silently stop the tenant's SIEM feed.
			c.Detail("error", err.Error())
			c.Refuse(http.StatusServiceUnavailable, "connection_usage_unverified", "can't confirm the connection is unused: "+err.Error())
			return
		}
		users = append(users, others...)
	}
	if len(users) > 0 {
		c.Detail("used_by", users)
		c.Refuse(http.StatusConflict, "connection_in_use", "remove it from these first: "+strings.Join(users, ", "))
		return
	}
	switch err := h.svc.store.DeleteConnection(c.R.Context(), c.Tenant, id); {
	case errors.Is(err, errNotFound):
		c.Error(http.StatusNotFound, "not_found", "connection not found")
	case err != nil:
		c.Error(http.StatusInternalServerError, "internal_error", "delete connection failed")
	default:
		if k, err := h.connVault.current(); err == nil {
			if ok, _ := k.Remediate(c.R.Context(), c.Tenant, connectionItemType, id, "connection_deleted", c.Actor()); ok {
				c.Detail("exposure_remediated", true)
			}
		}
		c.JSON(http.StatusOK, map[string]interface{}{"data": map[string]string{"status": "deleted"}})
	}
}

// testConnection makes a real call: a test message for Slack, Teams and
// webhooks, and an authenticated read for Jira and ServiceNow.
func (h *Handler) testConnection(c *route.Call) {
	conn, err := h.svc.store.GetConnection(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if errors.Is(err, errNotFound) {
		c.Error(http.StatusNotFound, "not_found", "connection not found")
		return
	} else if err != nil {
		c.Error(http.StatusInternalServerError, "internal_error", "read connection failed")
		return
	}
	if h.executor == nil {
		c.Error(http.StatusServiceUnavailable, "unavailable", "playbook executor not initialized")
		return
	}
	c.Detail("type", conn.Type)
	if err := h.executor.testConnection(c.R.Context(), conn); err != nil {
		c.Error(http.StatusBadGateway, "connection_test_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"data": map[string]string{"status": "ok", "endpoint": conn.Endpoint}})
}

// ---- legacy inline secrets ----

// Before 2.5.0-beta a playbook action held its endpoint and credentials in
// its own parameters, in plaintext. migrateInlineSecrets moves each into a
// sealed connection, rewrites the action to name it, and records the
// credentials in the exposure register (a database copy made before still
// holds them). Primary only: the tables are replicated.
var legacyConnParams = map[string]map[string]string{
	"send_slack":                 {"webhook_url": "webhook_url"},
	"send_teams":                 {"webhook_url": "webhook_url"},
	"send_webhook":               {"url": "url", "headers": "headers"},
	"create_jira_ticket":         {"base_url": "base_url", "api_token": "api_token"},
	"create_servicenow_incident": {"instance_url": "instance_url", "auth_token": "auth_token"},
}

var actionConnectionType = map[string]string{
	"send_slack": "slack", "send_teams": "teams", "send_webhook": "webhook",
	"create_jira_ticket": "jira", "create_servicenow_incident": "servicenow",
}

// hasInlineSecrets reports whether a stored action still carries the
// pre-2.5 inline endpoint parameters.
func hasInlineSecrets(a PlaybookAction) bool {
	for k := range legacyConnParams[a.Type] {
		if a.Parameters[k] != "" {
			return true
		}
	}
	return false
}

// redactInline blanks pre-2.5 inline secrets in API output until the
// migration has moved them.
func redactInline(p Playbook) Playbook {
	actions := make([]PlaybookAction, len(p.Actions))
	for i, a := range p.Actions {
		params := make(map[string]string, len(a.Parameters))
		for k, v := range a.Parameters {
			if _, secret := legacyConnParams[a.Type][k]; secret && v != "" {
				v = keepField
			}
			params[k] = v
		}
		a.Parameters = params
		actions[i] = a
	}
	p.Actions = actions
	return p
}

func (s *Service) migrateInlineSecrets(ctx context.Context, vault *connVault, primary func(context.Context) bool, emit func(string, map[string]interface{}, string)) (int, error) {
	if !primary(ctx) {
		return 0, nil
	}
	k, err := vault.current()
	if err != nil {
		return 0, err
	}
	pbs, err := s.store.ListAllPlaybooks(ctx)
	if err != nil {
		return 0, err
	}
	moved := map[string][]string{}
	var failed []string
	for _, pb := range pbs {
		changed := false
		for i, a := range pb.Actions {
			if !hasInlineSecrets(a) {
				continue
			}
			conn := Connection{
				ID: newID("pbconn"), TenantID: pb.TenantID, Type: actionConnectionType[a.Type],
				Name: fmt.Sprintf("%s #%d (migrated)", pb.Name, i+1), CreatedBy: "migration", Fields: map[string]string{},
			}
			for from, to := range legacyConnParams[a.Type] {
				if v := a.Parameters[from]; v != "" {
					conn.Fields[to] = v
				}
			}
			conn.Endpoint = connectionEndpoint(conn)
			if err := k.RecordExposure(ctx, pb.TenantID, connectionItemType, conn.ID, "plaintext_storage"); err != nil {
				failed = append(failed, pb.ID)
				continue
			}
			if err := vault.Seal(&conn); err != nil {
				failed = append(failed, pb.ID)
				continue
			}
			if _, err := s.store.CreateConnection(ctx, conn); err != nil {
				failed = append(failed, pb.ID)
				continue
			}
			for from := range legacyConnParams[a.Type] {
				delete(pb.Actions[i].Parameters, from)
			}
			pb.Actions[i].Parameters["connection_id"] = conn.ID
			moved[pb.TenantID] = append(moved[pb.TenantID], conn.ID)
			changed = true
		}
		if changed {
			if _, err := s.store.UpdatePlaybook(ctx, pb); err != nil {
				failed = append(failed, pb.ID)
			}
		}
	}
	total := 0
	for tenant, ids := range moved {
		total += len(ids)
		emit(tenant, map[string]interface{}{
			"severity": "warning", "count": len(ids), "connection_ids": ids,
			"exposure": "stored in plaintext in playbook actions by an earlier release; rotate these webhook URLs and tokens",
		}, route.ResultSuccess)
	}
	if len(failed) > 0 {
		emit("", map[string]interface{}{"severity": "critical", "reason": "seal_failed", "playbook_ids": failed}, route.ResultRefused)
		return total, fmt.Errorf("%d playbook(s) still hold plaintext credentials", len(failed))
	}
	return total, nil
}

// migrateInlineSecretsLoop moves inline credentials now and every interval,
// which catches rows a restore brings back from an earlier release.
func (s *Service) migrateInlineSecretsLoop(ctx context.Context, vault *connVault, e *PlaybookExecutor, interval time.Duration, logf func(string, ...interface{})) {
	emit := func(tenant string, details map[string]interface{}, result string) {
		e.emit("playbook_connections_migrated", pkgaudit.Event{
			TenantID: firstNonEmpty(tenant, tenantcheck.InternalServiceTenant()), ActorID: executorClientID, ActorType: "service",
			TargetType: connectionItemType, Result: result, Details: details,
		})
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if n, err := s.migrateInlineSecrets(ctx, vault, clusterstate.RunsPrimaryJobs, emit); err != nil {
			logf("playbook connections: %v", err)
		} else if n > 0 {
			logf("playbook connections: moved %d inline credential set(s) into sealed connections; recorded in the exposure register", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// openConnectionKeyring opens the compliance keyring in the background and
// retries while keycore is unreachable. Until it opens, connections can't be
// created, changed or used (503), and notification actions fail with the
// reason. A key that doesn't match the stored data stops it (fail closed).
func openConnectionKeyring(ctx context.Context, vault *connVault, open func(context.Context) (*mek.Keyring, error), onOpen func(*mek.Keyring), logf func(string, ...interface{})) {
	for {
		k, err := open(ctx)
		if err == nil {
			vault.set(k)
			logf("playbook connections: master key open (keycore key %s v%d)", k.KeyID(), k.Version())
			if onOpen != nil {
				onOpen(k)
			}
			return
		}
		vault.fail(err)
		if errors.Is(err, mek.ErrMismatch) || ctx.Err() != nil {
			logf("playbook connections unavailable: %v", err)
			return
		}
		logf("playbook connections: master key not open yet, retrying in 1m: %v", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Minute):
		}
	}
}
