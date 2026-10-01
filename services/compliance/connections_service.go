package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	neturl "net/url"
	"regexp"
	"strings"

	"vecta-kms/pkg/route"
	"vecta-kms/pkg/tenantcheck"
)

// Connections are the platform's one store of outbound credentials. The
// audit service (event streams) and governance (approval notices) hold only
// a connection ID. Before each use they ask compliance to open it:
// POST /compliance/connections/{id}/resolve returns its fields over internal
// mTLS to those two service identities and no one else, and each release is
// audited as connection_resolved. POST /compliance/connections/import is how
// they moved the credentials they used to keep themselves into connections
// (2.10.0-beta), keeping the exposure register entry when the credentials
// were once stored in plaintext.

// connectionUsers are the service identities that may open or import
// connections, and the use each makes of them.
var connectionUsers = map[string]string{
	"kms-audit":      "stream",
	"kms-governance": "approval_notice",
	"kms-discovery":  "scan_source",
}

const (
	reasonConnectionCaller = "service_identity_required"
	reasonConnectionUse    = "connection_use_unsupported"
)

// connectionCaller admits only the services in connectionUsers.
func connectionCaller(c *route.Call) (string, bool) {
	if tenantcheck.IsServicePrincipal(c.Claims) {
		if use, ok := connectionUsers[c.Claims.ClientID]; ok {
			c.Detail("caller", c.Claims.ClientID)
			return use, true
		}
	}
	c.Refuse(http.StatusForbidden, reasonConnectionCaller, "only the audit, governance and discovery services may open connections")
	return "", false
}

// usable reports whether connection type typ serves a caller's use: event
// streams take any stream type; approval notices go to Slack or Teams.
func usable(use, typ string) bool {
	switch use {
	case "stream":
		return connectionByType[typ].Stream
	case "approval_notice":
		return typ == "slack" || typ == "teams"
	case "scan_source":
		return connectionByType[typ].Category == categorySource
	}
	return false
}

func (h *Handler) serviceConnectionRoutes(rt *route.Router) {
	rt.Handle("POST /compliance/connections/{id}/resolve", route.Spec{Action: "connection_resolved", Permission: route.Authenticated, Resource: "playbook_connection", TargetParam: "id"}, h.resolveConnection)
	rt.Handle("POST /compliance/connections/import", route.Spec{Action: "connection_imported", Permission: route.Authenticated, Resource: "playbook_connection", Severity: "warning"}, h.importConnection)
}

type resolvedConnection struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Type     string            `json:"type"`
	Endpoint string            `json:"endpoint"`
	Fields   map[string]string `json:"fields"`
}

func (h *Handler) resolveConnection(c *route.Call) {
	use, ok := connectionCaller(c)
	if !ok {
		return
	}
	c.Detail("use", use)
	conn, err := h.svc.store.GetConnection(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if errors.Is(err, errNotFound) {
		c.Error(http.StatusNotFound, "not_found", "connection not found")
		return
	} else if err != nil {
		c.Error(http.StatusInternalServerError, "internal_error", "read connection failed")
		return
	}
	c.Detail("type", conn.Type)
	if !usable(use, conn.Type) {
		c.Refuse(http.StatusConflict, reasonConnectionUse, fmt.Sprintf("a %s connection can't be used for %s", conn.Type, use))
		return
	}
	opened, err := h.connVault.Open(conn)
	if err != nil {
		c.Error(http.StatusServiceUnavailable, "connections_unavailable", err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"data": resolvedConnection{ID: conn.ID, Name: conn.Name, Type: conn.Type, Endpoint: conn.Endpoint, Fields: opened.Fields}})
}

type importInput struct {
	TenantID string            `json:"tenant_id"` // verified by the kernel
	SourceID string            `json:"source_id"` // the caller's record, e.g. an audit webhook ID
	Name     string            `json:"name"`
	Type     string            `json:"type"`
	Fields   map[string]string `json:"fields"`
	// Exposed carries an open exposure register entry over: the credentials
	// were once stored in plaintext and are still readable in old copies.
	Exposed bool `json:"exposed"`
}

var importSourceRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,80}$`)

// importConnection creates a connection from credentials another service
// held. Its ID is derived from the caller and source record, so a retried
// migration finds the connection it already made instead of adding one.
func (h *Handler) importConnection(c *route.Call) {
	use, ok := connectionCaller(c)
	if !ok {
		return
	}
	var in importInput
	if !c.Decode(&in) {
		return
	}
	if !importSourceRE.MatchString(in.SourceID) {
		c.Error(http.StatusBadRequest, "bad_request", "source_id is required ([A-Za-z0-9_.-])")
		return
	}
	c.Detail("source_id", in.SourceID)
	c.Detail("type", in.Type)
	if !usable(use, in.Type) {
		c.Refuse(http.StatusConflict, reasonConnectionUse, fmt.Sprintf("a %s connection can't be used for %s", in.Type, use))
		return
	}
	id := "pbconn_" + strings.TrimPrefix(c.Claims.ClientID, "kms-") + "_" + in.SourceID
	c.Target(id)
	if existing, err := h.svc.store.GetConnection(c.R.Context(), c.Tenant, id); err == nil {
		c.Detail("already_imported", true)
		existing.Sealed = nil
		c.JSON(http.StatusOK, map[string]interface{}{"data": existing})
		return
	}
	conn := Connection{ID: id, TenantID: c.Tenant, Name: strings.TrimSpace(in.Name), Type: in.Type, Fields: in.Fields, CreatedBy: c.Claims.ClientID}
	if in.Exposed {
		// Register first: once sealed nothing shows it was plaintext.
		k, err := h.connVault.current()
		if err == nil {
			err = k.RecordExposure(c.R.Context(), c.Tenant, connectionItemType, id, "plaintext_storage")
		}
		if err != nil {
			c.Error(http.StatusServiceUnavailable, "connections_unavailable", err.Error())
			return
		}
		c.Detail("exposure_recorded", true)
	}
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

// ConnectionUsage finds where a connection is used outside playbooks.
type ConnectionUsage interface {
	// Users names the audit streams and governance settings that use the
	// connection. An error means usage could not be verified.
	Users(ctx context.Context, tenantID, connID string) ([]string, error)
}

// platformUsage asks the audit service and governance, as the compliance
// service identity.
type platformUsage struct {
	auditURL, governanceURL, discoveryURL string
	http                                  *http.Client
}

// Sources names discovery's repositories and buckets that read with the
// connection.
func (p platformUsage) Sources(ctx context.Context, tenantID, connID string) ([]string, error) {
	var users []string
	for _, kind := range []string{"repositories", "buckets"} {
		var list struct {
			Items []struct {
				URL          string `json:"url"`      // a repository
				Endpoint     string `json:"endpoint"` // a bucket
				Bucket       string `json:"bucket"`
				ConnectionID string `json:"connection_id"`
			} `json:"items"`
		}
		if _, err := callJSON(ctx, p.http, http.MethodGet, p.discoveryURL+"/discovery/"+kind+"?tenant_id="+neturl.QueryEscape(tenantID), tenantID, "", nil, &list); err != nil {
			return nil, fmt.Errorf("discovery %s: %w", kind, err)
		}
		for _, it := range list.Items {
			switch {
			case it.ConnectionID != connID:
			case kind == "buckets":
				users = append(users, "bucket "+it.Endpoint+"/"+it.Bucket)
			default:
				users = append(users, "repository "+it.URL)
			}
		}
	}
	return users, nil
}

func (p platformUsage) Users(ctx context.Context, tenantID, connID string) ([]string, error) {
	var streams struct {
		Items []struct {
			ID           string `json:"id"`
			Name         string `json:"name"`
			ConnectionID string `json:"connection_id"`
		} `json:"items"`
	}
	if _, err := callJSON(ctx, p.http, http.MethodGet, p.auditURL+"/webhooks", tenantID, "", nil, &streams); err != nil {
		return nil, fmt.Errorf("audit event streams: %w", err)
	}
	var users []string
	for _, s := range streams.Items {
		if s.ConnectionID == connID {
			users = append(users, "event stream "+s.Name)
		}
	}
	if tenantID != tenantcheck.InternalServiceTenant() {
		// Governance settings (approval notices) exist for the root tenant
		// only: system administration.
		return users, nil
	}
	var gov struct {
		Settings struct {
			SlackConnectionID string `json:"slack_connection_id"`
			TeamsConnectionID string `json:"teams_connection_id"`
		} `json:"settings"`
	}
	if _, err := callJSON(ctx, p.http, http.MethodGet, p.governanceURL+"/governance/settings?tenant_id="+neturl.QueryEscape(tenantID), tenantID, "", nil, &gov); err != nil {
		return nil, fmt.Errorf("governance settings: %w", err)
	}
	if gov.Settings.SlackConnectionID == connID || gov.Settings.TeamsConnectionID == connID {
		users = append(users, "governance approval notices")
	}
	return users, nil
}
