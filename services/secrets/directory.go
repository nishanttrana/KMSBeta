package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"vecta-kms/pkg/servicetoken"
)

// A rule's subject is checked against the service that owns it before the
// rule is stored, and again whenever rules are listed, so a rule for a
// subject that does not exist (a typo, a deleted user) is refused or
// flagged instead of sitting there naming nobody.

const (
	subjectFound     = "found"
	subjectMissing   = "missing"
	subjectUnchecked = "unchecked" // the owning service could not be asked
)

type subject struct{ Type, ID string }

type subjectInfo struct {
	Exists bool
	Label  string // username, client or group name, for display
}

// SubjectDirectory says which subjects exist in a tenant. A subject absent
// from the result could not be checked.
type SubjectDirectory interface {
	Lookup(ctx context.Context, tenantID string, subjects []subject) (map[subject]subjectInfo, error)
}

// platformDirectory asks the owners: auth for users, roles and clients,
// keycore for access groups, workload identity for registered workloads.
// Every call carries this service's token.
type platformDirectory struct {
	authURL, keycoreURL, workloadURL string
	client                           *http.Client
}

func newPlatformDirectory(authURL, keycoreURL, workloadURL string) *platformDirectory {
	trim := func(s string) string { return strings.TrimRight(strings.TrimSpace(s), "/") }
	return &platformDirectory{authURL: trim(authURL), keycoreURL: trim(keycoreURL), workloadURL: trim(workloadURL), client: &http.Client{Timeout: 5 * time.Second}}
}

func (d *platformDirectory) do(ctx context.Context, method, target string, body, out interface{}) error {
	var payload bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&payload).Encode(body); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, target, &payload)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	servicetoken.Authorize(ctx, req)
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s %s: status %d", method, req.URL.Path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Lookup returns what it could check. If one owner fails, its subjects are
// left out and the error is returned alongside the rest.
func (d *platformDirectory) Lookup(ctx context.Context, tenantID string, subjects []subject) (map[subject]subjectInfo, error) {
	out := map[subject]subjectInfo{}
	var fromAuth []map[string]string
	wantGroups, wantWorkloads := false, false
	for _, s := range subjects {
		switch s.Type {
		case subjectUser, subjectRole, subjectClient:
			fromAuth = append(fromAuth, map[string]string{"type": s.Type, "id": s.ID})
		case subjectGroup:
			wantGroups = true
		case subjectWorkload:
			wantWorkloads = true
		}
	}
	var firstErr error
	fail := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}
	if len(fromAuth) > 0 {
		var res struct {
			Subjects []struct {
				Type, ID, Label string
				Exists          bool
			} `json:"subjects"`
		}
		if err := d.do(ctx, http.MethodPost, d.authURL+"/internal/subjects/check", map[string]interface{}{"tenant_id": tenantID, "subjects": fromAuth}, &res); err != nil {
			fail(err)
		}
		for _, r := range res.Subjects {
			out[subject{r.Type, r.ID}] = subjectInfo{Exists: r.Exists, Label: r.Label}
		}
	}
	q := "?tenant_id=" + url.QueryEscape(tenantID)
	if wantGroups {
		var res struct {
			Items []struct{ ID, Name string } `json:"items"`
		}
		if err := d.do(ctx, http.MethodGet, d.keycoreURL+"/access/groups"+q, nil, &res); err != nil {
			fail(err)
		} else {
			names := map[string]string{}
			for _, g := range res.Items {
				names[g.ID] = g.Name
			}
			for _, s := range subjects {
				if s.Type == subjectGroup {
					name, ok := names[s.ID]
					out[s] = subjectInfo{Exists: ok, Label: name}
				}
			}
		}
	}
	if wantWorkloads {
		var res struct {
			Items []struct {
				Name     string `json:"name"`
				SpiffeID string `json:"spiffe_id"`
			} `json:"items"`
		}
		if err := d.do(ctx, http.MethodGet, d.workloadURL+"/workload-identity/registrations"+q, nil, &res); err != nil {
			fail(err)
		} else {
			names := map[string]string{}
			for _, w := range res.Items {
				names[w.SpiffeID] = w.Name
			}
			for _, s := range subjects {
				if s.Type == subjectWorkload {
					name, ok := names[s.ID]
					out[s] = subjectInfo{Exists: ok, Label: name}
				}
			}
		}
	}
	return out, firstErr
}
