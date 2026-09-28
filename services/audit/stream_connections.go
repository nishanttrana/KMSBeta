package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"strings"
	"sync"
	"time"

	"vecta-kms/pkg/servicetoken"
	"vecta-kms/pkg/siem"
)

// Event streams send through compliance connections, the platform's one
// store of outbound credentials (docs/SECURITY/CONNECTIONS.md). The audit
// service keeps only the connection ID. Before delivering, it asks
// compliance to open the connection (POST /compliance/connections/{id}/resolve,
// which only the kms-audit and kms-governance identities may call) and holds
// the fields in memory for connCacheTTL. A connection changed or deleted in
// compliance takes effect on the next resolve.

const connCacheTTL = 60 * time.Second

// streamConnection is an opened connection.
type streamConnection struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Type     string            `json:"type"`
	Endpoint string            `json:"endpoint"`
	Fields   map[string]string `json:"fields"`
}

// connImport moves a legacy stream's credentials into a connection.
type connImport struct {
	SourceID string            `json:"source_id"`
	Name     string            `json:"name"`
	Type     string            `json:"type"`
	Fields   map[string]string `json:"fields"`
	Exposed  bool              `json:"exposed"`
}

// connectionSource opens and imports connections.
type connectionSource interface {
	Resolve(ctx context.Context, tenantID, id string) (streamConnection, error)
	Import(ctx context.Context, tenantID string, in connImport) (string, error)
}

// connError is compliance's answer to a refused call.
type connError struct {
	Status int
	Code   string
	Msg    string
}

func (e connError) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return fmt.Sprintf("compliance HTTP %d %s", e.Status, e.Code)
}

// complianceConnections calls compliance as the kms-audit identity over
// internal mTLS (http.DefaultTransport is svctls's router).
type complianceConnections struct {
	base string
	http *http.Client
}

func (c complianceConnections) call(ctx context.Context, tenantID, path string, body, out interface{}) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", tenantID)
	servicetoken.Authorize(ctx, req)
	resp, err := c.http.Do(req)
	if err != nil {
		var ue *neturl.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("compliance unreachable: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	ans, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		var e struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(ans, &e)
		return connError{Status: resp.StatusCode, Code: e.Error.Code, Msg: e.Error.Message}
	}
	return json.Unmarshal(ans, out)
}

func (c complianceConnections) Resolve(ctx context.Context, tenantID, id string) (streamConnection, error) {
	var out struct {
		Data streamConnection `json:"data"`
	}
	err := c.call(ctx, tenantID, "/compliance/connections/"+neturl.PathEscape(id)+"/resolve", map[string]string{"tenant_id": tenantID}, &out)
	return out.Data, err
}

func (c complianceConnections) Import(ctx context.Context, tenantID string, in connImport) (string, error) {
	var out struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	body := map[string]interface{}{"tenant_id": tenantID, "source_id": in.SourceID, "name": in.Name, "type": in.Type, "fields": in.Fields, "exposed": in.Exposed}
	if err := c.call(ctx, tenantID, "/compliance/connections/import", body, &out); err != nil {
		return "", err
	}
	if out.Data.ID == "" {
		return "", errors.New("compliance returned no connection id")
	}
	return out.Data.ID, nil
}

// connCache holds opened connections, and the SIEM destination built from
// each (so a Sentinel token is reused), for connCacheTTL.
type connCache struct {
	src connectionSource
	ttl time.Duration

	mu    sync.Mutex
	items map[string]cachedConn
}

type cachedConn struct {
	at   time.Time
	conn streamConnection
	dest siem.Destination
}

func newConnCache(src connectionSource) *connCache {
	return &connCache{src: src, ttl: connCacheTTL, items: map[string]cachedConn{}}
}

// get returns the opened connection and, for a SIEM type, its destination
// built with client (the outbound client every delivery uses).
func (c *connCache) get(ctx context.Context, tenantID, id string, client *http.Client) (streamConnection, siem.Destination, error) {
	key := tenantID + "/" + id
	c.mu.Lock()
	it, ok := c.items[key]
	c.mu.Unlock()
	if ok && time.Since(it.at) < c.ttl {
		return it.conn, it.dest, nil
	}
	if c.src == nil {
		return streamConnection{}, nil, errors.New("connections are not wired")
	}
	conn, err := c.src.Resolve(ctx, tenantID, id)
	if err != nil {
		return streamConnection{}, nil, err
	}
	var dest siem.Destination
	if _, isSIEM := siem.SpecFor(conn.Type); isSIEM {
		if dest, err = siem.New(conn.Type, conn.Fields, siem.Options{Client: client}); err != nil {
			return streamConnection{}, nil, err
		}
	}
	c.mu.Lock()
	c.items[key] = cachedConn{at: time.Now(), conn: conn, dest: dest}
	c.mu.Unlock()
	return conn, dest, nil
}

// siemEvent is an audit event as pkg/siem sends it; the whole event is the
// record, as the legacy formats sent it.
func siemEvent(ev AuditEvent) siem.Event {
	sev, _ := ev.Details["severity"].(string)
	return siem.Event{
		ID: ev.ID, Timestamp: ev.Timestamp, TenantID: ev.TenantID, Service: ev.Service, Action: ev.Action,
		ActorID: ev.ActorID, TargetType: ev.TargetType, TargetID: ev.TargetID, Result: ev.Result,
		Severity: strings.ToLower(sev), SourceIP: ev.SourceIP, NodeID: ev.NodeID, Record: ev,
	}
}
