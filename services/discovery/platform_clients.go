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
	"time"

	"vecta-kms/pkg/servicetoken"
)

// ResolvedConnection is a sealed connection opened by compliance for one use.
// Its fields are credentials: they are held in memory for one scan and never
// stored, logged or put in an error.
type ResolvedConnection struct {
	Type     string            `json:"type"`
	Endpoint string            `json:"endpoint"` // the host the connection is for
	Fields   map[string]string `json:"fields"`
}

// ConnectionResolver opens a git connection as the discovery service
// (POST /compliance/connections/{id}/resolve; compliance admits kms-discovery
// for git connections only and audits every release).
type ConnectionResolver interface {
	Resolve(ctx context.Context, tenantID, id string) (ResolvedConnection, error)
}

// AuthorityChecker asks auth whether a user is active and holds permissions
// now (POST /auth/delegated/authority).
type AuthorityChecker interface {
	Authority(ctx context.Context, tenantID, userID string, perms []string) (active bool, missing []string, err error)
}

// platformClient calls compliance and auth over internal mTLS as
// kms-discovery.
type platformClient struct {
	complianceURL, authURL string
	http                   *http.Client
}

func newPlatformClient(complianceURL, authURL string) platformClient {
	return platformClient{
		complianceURL: strings.TrimRight(complianceURL, "/"), authURL: strings.TrimRight(authURL, "/"),
		http: &http.Client{Timeout: 10 * time.Second},
	}
}

func (p platformClient) post(ctx context.Context, url, tenantID string, body, out interface{}) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", tenantID)
	servicetoken.Authorize(ctx, req)
	resp, err := p.http.Do(req)
	if err != nil {
		var ue *neturl.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("%s unreachable: %v", req.URL.Hostname(), err)
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
		return fmt.Errorf("%s HTTP %d %s: %s", req.URL.Hostname(), resp.StatusCode, e.Error.Code, e.Error.Message)
	}
	return json.Unmarshal(ans, out)
}

func (p platformClient) Resolve(ctx context.Context, tenantID, id string) (ResolvedConnection, error) {
	var out struct {
		Data ResolvedConnection `json:"data"`
	}
	err := p.post(ctx, p.complianceURL+"/compliance/connections/"+neturl.PathEscape(id)+"/resolve?tenant_id="+neturl.QueryEscape(tenantID), tenantID, map[string]string{"tenant_id": tenantID}, &out)
	return out.Data, err
}

func (p platformClient) Authority(ctx context.Context, tenantID, userID string, perms []string) (bool, []string, error) {
	var out struct {
		Active  bool     `json:"active"`
		Missing []string `json:"missing"`
	}
	err := p.post(ctx, p.authURL+"/auth/delegated/authority?tenant_id="+neturl.QueryEscape(tenantID), tenantID, map[string]interface{}{"tenant_id": tenantID, "user_id": userID, "permissions": perms}, &out)
	return out.Active, out.Missing, err
}
