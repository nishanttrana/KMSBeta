// Package credstore is a service's client for the platform's credential
// store: the sealed connections the compliance service keeps (Playbooks →
// Credentials, docs/SECURITY/CONNECTIONS.md). A service that uses an
// external credential holds only its ID and opens it here for each use, as
// its own service identity over internal mTLS. Compliance admits only the
// identity that uses that credential type and audits every release.
package credstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"strings"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/deployed"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/servicetoken"
)

// PermissionUse lets a person attach a credential to a feature.
const PermissionUse = "compliance.connection.use"

// Profile is the compose profile that deploys the credential store.
const Profile = "compliance_dashboard"

var (
	// ErrNotDeployed: this deployment has no credential store.
	ErrNotDeployed = errors.New("this deployment has no credential store (the compliance service, Playbooks): add it to use external credentials")
	// ErrNotFound: no such credential in the tenant.
	ErrNotFound = errors.New("no such credential for this tenant")
	// ErrWrongType: the credential exists but this service doesn't use its type.
	ErrWrongType = errors.New("the credential is of a type this feature doesn't use")
	// ErrUnavailable: the store could not answer.
	ErrUnavailable = errors.New("the credential store is unavailable")
)

// Credential is an opened credential. Fields are secrets: hold them in
// memory for one use, and never log them or put them in an error.
type Credential struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Type     string            `json:"type"`
	Endpoint string            `json:"endpoint"`
	Fields   map[string]string `json:"fields"`
	// PrivateRanges are the private ranges a root administrator approved
	// for the tenant (compliance returns them for scan sources and mail
	// relays), for the caller's outbound guard (ssrfguard.ParseAllow).
	PrivateRanges []string `json:"private_ranges"`
}

// Store is what a service needs from the credential store.
type Store interface {
	// Resolve opens a credential for one use.
	Resolve(ctx context.Context, tenantID, id string) (Credential, error)
	// Import moves credentials the service used to keep itself into the
	// store. The ID derives from the caller and sourceID, so a retry finds
	// the credential it already made. exposed records that they were once
	// stored in plaintext.
	Import(ctx context.Context, tenantID, sourceID, name, typ string, fields map[string]string, exposed bool) (string, error)
	// ReportTest records the result of a real test the service ran with
	// the credential (nil: it worked).
	ReportTest(ctx context.Context, tenantID, id string, testErr error) error
}

// Client calls compliance (http.DefaultTransport is svctls's router).
type Client struct {
	base string
	http *http.Client
}

// New returns a client for the compliance service at base.
func New(base string) *Client {
	return &Client{base: strings.TrimRight(strings.TrimSpace(base), "/"), http: &http.Client{Timeout: 10 * time.Second}}
}

// FromEnv reads COMPLIANCE_URL (default https://compliance:8110). It returns
// nil, whose every method answers ErrNotDeployed, when the deployment
// leaves the credential store out.
func FromEnv() *Client {
	if !deployed.Has(Profile) {
		return nil
	}
	base := strings.TrimSpace(os.Getenv("COMPLIANCE_URL"))
	if base == "" {
		base = "https://compliance:8110"
	}
	return New(base)
}

func (c *Client) post(ctx context.Context, tenantID, path string, body, out interface{}) error {
	if c == nil {
		return ErrNotDeployed
	}
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
		// Never the *url.Error: it quotes the request URL.
		return fmt.Errorf("%w: unreachable", ErrUnavailable)
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
		switch {
		case resp.StatusCode == http.StatusNotFound:
			return ErrNotFound
		case e.Error.Code == "connection_use_unsupported":
			return ErrWrongType
		case resp.StatusCode == http.StatusBadRequest:
			return errors.New(strings.TrimSpace(e.Error.Message))
		}
		return fmt.Errorf("%w: HTTP %d %s", ErrUnavailable, resp.StatusCode, strings.TrimSpace(e.Error.Message))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(ans, out)
}

// Resolve opens credential id for one use.
func (c *Client) Resolve(ctx context.Context, tenantID, id string) (Credential, error) {
	var out struct {
		Data Credential `json:"data"`
	}
	err := c.post(ctx, tenantID, "/compliance/connections/"+neturl.PathEscape(strings.TrimSpace(id))+"/resolve?tenant_id="+neturl.QueryEscape(tenantID), map[string]string{}, &out)
	return out.Data, err
}

// Import creates a credential from ones the caller held itself.
func (c *Client) Import(ctx context.Context, tenantID, sourceID, name, typ string, fields map[string]string, exposed bool) (string, error) {
	var out struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	body := map[string]interface{}{"tenant_id": tenantID, "source_id": sourceID, "name": name, "type": typ, "fields": fields, "exposed": exposed}
	if err := c.post(ctx, tenantID, "/compliance/connections/import", body, &out); err != nil {
		return "", err
	}
	if out.Data.ID == "" {
		return "", fmt.Errorf("%w: no credential id returned", ErrUnavailable)
	}
	return out.Data.ID, nil
}

// ReportTest records a test's result on the credential.
func (c *Client) ReportTest(ctx context.Context, tenantID, id string, testErr error) error {
	body := map[string]interface{}{"tenant_id": tenantID, "ok": testErr == nil}
	if testErr != nil {
		body["error"] = testErr.Error()
	}
	return c.post(ctx, tenantID, "/compliance/connections/"+neturl.PathEscape(id)+"/tested?tenant_id="+neturl.QueryEscape(tenantID), body, nil)
}

// MayAttach reports whether the verified caller may attach a credential to
// a feature: a person holding PermissionUse, or a platform service acting
// for one. It reads only the verified token's claims.
func MayAttach(ctx context.Context) bool {
	claims, _ := pkgauth.ClaimsFromContext(ctx)
	return route.Allowed(claims, PermissionUse)
}
