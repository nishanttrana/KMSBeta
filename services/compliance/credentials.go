package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	neturl "net/url"
	"sort"
	"strings"
	"time"

	pkgaudit "vecta-kms/pkg/audit"
	"vecta-kms/pkg/clusterstate"
	"vecta-kms/pkg/deployed"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/smtpmail"
	"vecta-kms/pkg/ssrfguard"
)

// What turns the connection store into the platform's credential store
// (docs/SECURITY/CONNECTIONS.md): who may attach a credential to a feature,
// where each one is used, the result of its last real test, and reminders
// before it expires or is due for rotation.

// permConnectionUse lets a person attach a credential to a feature (a cloud
// account, an HSM key, a mail relay) without being able to create, read or
// change one. Managing credentials stays with the playbook permissions.
const permConnectionUse = "compliance.connection.use"

func (h *Handler) credentialRoutes(rt *route.Router) {
	spec := func(action, perm, target, sev string) route.Spec {
		return route.Spec{Action: action, Permission: perm, Resource: "playbook_connection", TargetParam: target, Severity: sev}
	}
	rt.Handle("GET /compliance/connections", spec("connection_choices_listed", permConnectionUse, "", ""), h.listConnectionChoices)
	rt.Handle("GET /compliance/connections/{id}", spec("connection_use_checked", permConnectionUse, "id", ""), h.checkConnectionUse)
	rt.Handle("GET /compliance/connections/{id}/usage", spec("connection_usage_read", permPlaybookRead, "id", ""), h.connectionUsage)
	rt.Handle("POST /compliance/connections/{id}/tested", spec("connection_test_reported", route.Authenticated, "id", ""), h.reportConnectionTest)
}

// listConnectionChoices lists the credentials a feature's picker offers:
// those of one type (?type=) or category (?category=). It needs only the
// use permission, and like every listing it returns no field value.
func (h *Handler) listConnectionChoices(c *route.Call) {
	typ, category := strings.TrimSpace(c.R.URL.Query().Get("type")), strings.TrimSpace(c.R.URL.Query().Get("category"))
	if typ == "" && category == "" {
		c.Error(http.StatusBadRequest, "bad_request", "type or category is required")
		return
	}
	c.Detail("type", typ)
	c.Detail("category", category)
	all, err := h.svc.store.ListConnections(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "internal_error", "list credentials failed")
		return
	}
	items := []Connection{}
	for _, conn := range all {
		if (typ == "" || conn.Type == typ) && (category == "" || connectionByType[conn.Type].Category == category) {
			items = append(items, conn)
		}
	}
	c.JSON(http.StatusOK, map[string]interface{}{"data": items})
}

// checkConnectionUse answers a service that is about to attach a credential
// to a feature for a person: it forwards that person's verified token, so
// the kernel has already checked they hold compliance.connection.use in the
// credential's tenant. The answer carries no field value.
func (h *Handler) checkConnectionUse(c *route.Call) {
	conn, err := h.svc.store.GetConnection(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if errors.Is(err, errNotFound) {
		c.Error(http.StatusNotFound, "not_found", "credential not found")
		return
	} else if err != nil {
		c.Error(http.StatusInternalServerError, "internal_error", "read credential failed")
		return
	}
	c.Detail("type", conn.Type)
	conn.Sealed = nil
	c.JSON(http.StatusOK, map[string]interface{}{"data": conn})
}

// ---- where a credential is used ----

// CredentialUsage names the cloud accounts and HSM keys
// that use a credential. An error means usage could not be verified.
type CredentialUsage func(ctx context.Context, tenantID string, conn Connection) ([]string, error)

// usersOf names everything that uses conn. It fails closed: if a service
// that could be using it can't answer, the error says which.
func (h *Handler) usersOf(ctx context.Context, tenantID string, conn Connection) ([]string, error) {
	pbs, err := h.svc.store.ListPlaybooks(ctx, tenantID)
	if err != nil {
		return nil, errors.New("list playbooks failed")
	}
	var users []string
	for _, pb := range pbs {
		for _, a := range pb.Actions {
			if a.Parameters["connection_id"] == conn.ID {
				users = append(users, "playbook "+pb.Name)
				break
			}
		}
	}
	if h.usage != nil {
		others, err := h.usage.Users(ctx, tenantID, conn.ID)
		if err != nil {
			return nil, err
		}
		users = append(users, others...)
	}
	// A source connection's users are discovery's repositories and
	// buckets. Discovery is asked only for those types, so a deployment
	// without it can still delete every other connection.
	if connectionByType[conn.Type].Category == categorySource && h.sourceUsage != nil {
		repos, err := h.sourceUsage(ctx, tenantID, conn.ID)
		if err != nil {
			return nil, err
		}
		users = append(users, repos...)
	}
	if h.credUsage != nil {
		others, err := h.credUsage(ctx, tenantID, conn)
		if err != nil {
			return nil, err
		}
		users = append(users, others...)
	}
	sort.Strings(users)
	return users, nil
}

func (h *Handler) connectionUsage(c *route.Call) {
	conn, err := h.svc.store.GetConnection(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if errors.Is(err, errNotFound) {
		c.Error(http.StatusNotFound, "not_found", "credential not found")
		return
	} else if err != nil {
		c.Error(http.StatusInternalServerError, "internal_error", "read credential failed")
		return
	}
	users, err := h.usersOf(c.R.Context(), c.Tenant, conn)
	if err != nil {
		// "unavailable", never an empty list: no answer is not "unused".
		c.Detail("error", err.Error())
		c.Error(http.StatusServiceUnavailable, "connection_usage_unverified", "usage unavailable: "+err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"data": map[string]interface{}{"used_by": users}})
}

// Credentials names what uses a cloud or HSM credential, asking
// the service that owns each: only the services a type can serve are asked.
func (p platformUsage) Credentials(ctx context.Context, tenantID string, conn Connection) ([]string, error) {
	ask := func(base, path, noun string) ([]string, error) {
		var list struct {
			Items []struct {
				ConnectionID string `json:"connection_id"`
				Label        string `json:"label"`
			} `json:"items"`
		}
		if base == "" {
			return nil, nil
		}
		if _, err := callJSON(ctx, p.http, http.MethodGet, base+path+"?tenant_id="+neturl.QueryEscape(tenantID), tenantID, "", nil, &list); err != nil {
			return nil, fmt.Errorf("%s: %w", noun, err)
		}
		var out []string
		for _, it := range list.Items {
			if it.ConnectionID == conn.ID {
				out = append(out, it.Label)
			}
		}
		return out, nil
	}
	var users []string
	add := func(base, path, noun string) error {
		got, err := ask(base, path, noun)
		users = append(users, got...)
		return err
	}
	// A service the deployment leaves out holds nothing, so it isn't asked
	// (pkg/deployed: an unknown deployment asks, and fails closed).
	if usable("cloud_account", conn.Type) && deployed.Has("cloud_byok") {
		if err := add(p.cloudURL, "/cloud/credential-usage", "cloud accounts"); err != nil {
			return nil, err
		}
	}
	if usable("database_engine", conn.Type) && deployed.Has("secrets") {
		if err := add(p.secretsURL, "/secrets/credential-usage", "database roles"); err != nil {
			return nil, err
		}
	}
	if usable("hyok_proxy", conn.Type) && deployed.Has("hyok_proxy") {
		if err := add(p.hyokURL, "/hyok/credential-usage", "HYOK endpoints"); err != nil {
			return nil, err
		}
	}
	if conn.Type == "pkcs11_hsm" {
		if err := add(p.keycoreURL, "/keys/hsm/credential-usage", "HSM keys"); err != nil {
			return nil, err
		}
	}
	return users, nil
}

// ---- test results ----

// recordTest stores a real test's result and, on a failure, raises
// audit.compliance.credential_test_failed for playbooks to respond to.
func (h *Handler) recordTest(ctx context.Context, conn Connection, by string, testErr error) {
	msg := ""
	if testErr != nil {
		msg = testErr.Error()
	}
	_ = h.svc.store.RecordConnectionTest(ctx, conn.TenantID, conn.ID, testErr == nil, msg)
	if testErr != nil && h.executor != nil {
		h.executor.emit("credential_test_failed", pkgaudit.Event{
			TenantID: conn.TenantID, ActorID: by, TargetType: connectionItemType, TargetID: conn.ID, Result: route.ResultFailure,
			Details: map[string]interface{}{"name": conn.Name, "type": conn.Type, "endpoint": conn.Endpoint, "reason": "test_failed", "error": msg, "severity": "warning"},
		})
	}
}

// reportConnectionTest records a test the using service ran where the
// credential is used (a cloud account's inventory read). Only that service may report it, and only for its own types.
func (h *Handler) reportConnectionTest(c *route.Call) {
	use, ok := connectionCaller(c)
	if !ok {
		return
	}
	var in struct {
		TenantID string `json:"tenant_id"` // verified by the kernel
		OK       bool   `json:"ok"`
		Error    string `json:"error"`
	}
	if !c.Decode(&in) {
		return
	}
	conn, err := h.svc.store.GetConnection(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if errors.Is(err, errNotFound) {
		c.Error(http.StatusNotFound, "not_found", "credential not found")
		return
	} else if err != nil {
		c.Error(http.StatusInternalServerError, "internal_error", "read credential failed")
		return
	}
	c.Detail("type", conn.Type)
	if !usable(use, conn.Type) {
		c.Refuse(http.StatusConflict, reasonConnectionUse, fmt.Sprintf("%s does not use %s credentials", c.Claims.ClientID, conn.Type))
		return
	}
	c.Detail("ok", in.OK)
	var testErr error
	if !in.OK {
		testErr = errors.New(firstNonEmpty(strings.TrimSpace(in.Error), "the test failed"))
	}
	h.recordTest(c.R.Context(), conn, c.Claims.ClientID, testErr)
	c.JSON(http.StatusOK, map[string]interface{}{"data": map[string]string{"status": "recorded"}})
}

// CredentialTester runs the real test for a credential another service
// uses: the cloud service reads the provider's key inventory, and the HSM
// connector opens a logged-in session on the token.
type CredentialTester func(ctx context.Context, conn Connection) error

// Test asks the owning service to test conn.
func (p platformUsage) Test(ctx context.Context, conn Connection) error {
	tenant := neturl.QueryEscape(conn.TenantID)
	switch {
	case conn.Type == "pkcs11_hsm":
		var out struct {
			Status struct {
				Connected bool   `json:"connected"`
				Error     string `json:"error"`
			} `json:"status"`
		}
		if _, err := callJSON(ctx, p.http, http.MethodGet, p.hsmURL+"/hsm/status?tenant_id="+tenant+"&connection_id="+neturl.QueryEscape(conn.ID), conn.TenantID, "", nil, &out); err != nil {
			return err
		}
		if !out.Status.Connected {
			return errors.New(firstNonEmpty(out.Status.Error, "the HSM connector could not open a session on the token"))
		}
		return nil
	case usable("cloud_account", conn.Type):
		_, err := callJSON(ctx, p.http, http.MethodPost, p.cloudURL+"/cloud/credentials/"+neturl.PathEscape(conn.ID)+"/test?tenant_id="+tenant, conn.TenantID, "", map[string]string{}, nil)
		return err
	}
	return fmt.Errorf("no test for %s credentials", conn.Type)
}

// testSMTP signs in to the relay over TLS and leaves; no mail is sent.
func (e *PlaybookExecutor) testSMTP(ctx context.Context, conn Connection) error {
	opened, err := e.vault.Open(conn)
	if err != nil {
		return err
	}
	f := opened.Fields
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	return smtpmail.Check(ctx, smtpmail.Config{Host: f["host"], Port: f["port"], Username: f["username"], Password: f["password"], From: f["from"], CAPEM: f["ca_pem"]},
		approvedAllow(ctx, e.store, conn.TenantID, conn.Type).DialContext)
}

// privateCapable: a credential type whose host the customer names, so it may
// sit on the customer's own network: scan sources, mail relays and, from
// 8.1.0-beta, notification, ticketing and SIEM destinations. Cloud accounts
// reach the provider's public endpoints and an HSM is not dialled from here.
func privateCapable(typ string) bool {
	switch connectionByType[typ].Category {
	case categorySource, categoryMail, categoryNotify, categoryTicketing, categorySIEM:
		return true
	}
	return false
}

// approvedAllow is the outbound allowance for a credential of type typ that
// compliance, audit or governance dials: the private ranges a root
// administrator approved for the tenant (private_endpoints.go). A scan
// source has none here: discovery dials it, and its save has its own check
// (privateSourceAllowed). On a store error it is none too (fail closed).
func approvedAllow(ctx context.Context, store Store, tenantID, typ string) ssrfguard.Allow {
	if !privateCapable(typ) || connectionByType[typ].Category == categorySource {
		return nil
	}
	items, err := store.ListPrivateEndpoints(ctx, tenantID)
	if err != nil {
		return nil
	}
	var out ssrfguard.Allow
	for _, it := range items {
		if n, err := ssrfguard.ParseCIDR(it.CIDR); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// ---- expiry and rotation reminders ----

// A reminder is raised once per secret: 30 and 7 days before the expiry the
// operator recorded, when it passes, and when the secret is older than its
// rotation interval. Replacing the secret, or changing the dates, clears the
// record so the new one is reminded afresh.
const (
	remindExpiring30 = "expiring_30"
	remindExpiring7  = "expiring_7"
	remindExpired    = "expired"
	remindRotation   = "rotation_due"
)

// dueReminders returns the reminders c has reached at now, most urgent of
// the expiry ones only (a credential first seen 3 days from expiry raises
// expiring_7, not expiring_30 as well).
func dueReminders(c Connection, now time.Time) []string {
	var due []string
	if c.ExpiresAt != nil {
		switch left := c.ExpiresAt.Sub(now); {
		case left <= 0:
			due = append(due, remindExpired)
		case left <= 7*24*time.Hour:
			due = append(due, remindExpiring7)
		case left <= 30*24*time.Hour:
			due = append(due, remindExpiring30)
		}
	}
	if c.RotateAfterDays > 0 && now.Sub(c.CredentialsChangedAt) >= time.Duration(c.RotateAfterDays)*24*time.Hour {
		due = append(due, remindRotation)
	}
	return due
}

// remindCredentials raises each due reminder once. Primary only: the table
// is replicated.
func (s *Service) remindCredentials(ctx context.Context, now time.Time, primary func(context.Context) bool, emit func(string, pkgaudit.Event)) (int, error) {
	if !primary(ctx) {
		return 0, nil
	}
	conns, err := s.store.ListAllConnections(ctx)
	if err != nil {
		return 0, err
	}
	raised := 0
	for _, c := range conns {
		notified := append([]string{}, c.Notified...)
		for _, r := range dueReminders(c, now) {
			if contains(notified, r) {
				continue
			}
			details := map[string]interface{}{"name": c.Name, "type": c.Type, "endpoint": c.Endpoint, "reminder": r,
				"age_days": int(now.Sub(c.CredentialsChangedAt).Hours() / 24), "severity": "warning"}
			if c.ExpiresAt != nil {
				details["expires_at"] = c.ExpiresAt.Format(time.RFC3339)
				details["days_left"] = int(c.ExpiresAt.Sub(now).Hours() / 24)
			}
			if r == remindRotation {
				details["rotate_after_days"] = c.RotateAfterDays
			}
			if r == remindExpired {
				details["severity"] = "critical"
			}
			notified = append(notified, r)
			// Stored before it is raised: a failed write must not repeat
			// the reminder every sweep.
			if err := s.store.SetConnectionNotified(ctx, c.TenantID, c.ID, notified); err != nil {
				return raised, err
			}
			evt := pkgaudit.Event{TenantID: c.TenantID, ActorID: executorClientID, ActorType: "service",
				TargetType: connectionItemType, TargetID: c.ID, Result: route.ResultSuccess, Details: details}
			switch r {
			case remindExpired:
				emit("credential_expired", evt)
			case remindRotation:
				emit("credential_rotation_due", evt)
			default:
				emit("credential_expiring", evt)
			}
			raised++
		}
	}
	return raised, nil
}

func (s *Service) remindCredentialsLoop(ctx context.Context, e *PlaybookExecutor, interval time.Duration, logf func(string, ...interface{})) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if n, err := s.remindCredentials(ctx, time.Now().UTC(), clusterstate.RunsPrimaryJobs, e.emit); err != nil {
			logf("credential reminders: %v", err)
		} else if n > 0 {
			logf("credential reminders: raised %d", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
