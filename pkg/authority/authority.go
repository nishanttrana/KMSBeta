// Package authority asks auth whether the person behind unattended work (a
// schedule, a playbook) is still active and still holds the permissions the
// work needs, at the moment it runs (POST /auth/delegated/authority).
//
// Work that runs with nobody present acts only on the authority of the
// person who set it up (CLAUDE.md, "Unattended work re-checks the person's
// authority"). Every scheduler uses this one client; auth admits only the
// service identities in its authorityCallers list.
package authority

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"vecta-kms/pkg/servicetoken"
)

// Answer is auth's answer. Missing lists the asked permissions the person no
// longer holds; Role is their role now, for checks that also match on role
// (the vault's access rules).
type Answer struct {
	Active  bool     `json:"active"`
	Missing []string `json:"missing"`
	Role    string   `json:"role"`
}

// Refusal reasons a scheduler records and audits.
const (
	// ReasonUnknown: auth did not answer. The work neither runs on
	// unverified authority nor pauses for good.
	ReasonUnknown = "authority_unknown"
	// ReasonRevoked: the person is inactive or lost a permission. The work
	// pauses until someone with the authority saves it again.
	ReasonRevoked = "authority_revoked"
)

// Checker is what a scheduler holds; tests answer it directly.
type Checker interface {
	Authority(ctx context.Context, tenantID, userID string, perms []string) (Answer, error)
}

// Client calls auth over internal mTLS with the service's own token.
type Client struct {
	url  string
	http *http.Client
}

func New(authURL string) Client {
	return Client{url: strings.TrimRight(authURL, "/"), http: &http.Client{Timeout: 10 * time.Second}}
}

func (c Client) Authority(ctx context.Context, tenantID, userID string, perms []string) (Answer, error) {
	raw, err := json.Marshal(map[string]interface{}{"tenant_id": tenantID, "user_id": userID, "permissions": perms})
	if err != nil {
		return Answer{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url+"/auth/delegated/authority?tenant_id="+url.QueryEscape(tenantID), bytes.NewReader(raw))
	if err != nil {
		return Answer{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", tenantID)
	servicetoken.Authorize(ctx, req)
	resp, err := c.http.Do(req)
	if err != nil {
		return Answer{}, fmt.Errorf("%s unreachable: %w", req.URL.Hostname(), err)
	}
	defer resp.Body.Close() //nolint:errcheck
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return Answer{}, fmt.Errorf("%s HTTP %d", req.URL.Hostname(), resp.StatusCode)
	}
	var out Answer
	if err := json.Unmarshal(body, &out); err != nil || out.Missing == nil {
		return Answer{}, fmt.Errorf("%s answered without an authority", req.URL.Hostname())
	}
	return out, nil
}

// Check asks and reduces the answer to what a scheduler does: "" to run,
// or a refusal reason with its detail. Work saved before it recorded who
// authorized it has no one to ask: that is revoked (it pauses until someone
// saves it again), never a retry that waits forever.
func Check(ctx context.Context, c Checker, tenantID, userID string, required []string) (Answer, string, string) {
	if strings.TrimSpace(userID) == "" {
		return Answer{}, ReasonRevoked, "no one is on record as authorizing this; save it again to resume"
	}
	if c == nil {
		return Answer{}, ReasonUnknown, "auth is not wired"
	}
	a, err := c.Authority(ctx, tenantID, userID, required)
	switch {
	case err != nil:
		return a, ReasonUnknown, err.Error()
	case !a.Active:
		return a, ReasonRevoked, userID + " is no longer an active user"
	case len(a.Missing) > 0:
		return a, ReasonRevoked, userID + " no longer holds " + strings.Join(a.Missing, ", ")
	}
	return a, "", ""
}

// Held is the asked permissions minus those the answer says are missing.
func Held(asked []string, a Answer) []string {
	missing := map[string]bool{}
	for _, m := range a.Missing {
		missing[m] = true
	}
	var out []string
	for _, p := range asked {
		if !missing[p] {
			out = append(out, p)
		}
	}
	return out
}
