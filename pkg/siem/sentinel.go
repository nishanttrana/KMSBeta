package siem

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// sentinel sends to a Log Analytics workspace through the Azure Monitor
// Logs Ingestion API: a data collection endpoint (DCE) and rule (DCR) the
// customer creates, authenticated with a Microsoft Entra app registration
// (client credentials). The older HTTP Data Collector API (shared key) was
// retired by Microsoft on 14 September 2026 and is not used.
//
// Each record carries the columns the DCR stream must declare:
// TimeGenerated, EventId, Action, TenantId, Service, Actor, TargetType,
// TargetId, Result, Severity, SourceIp and Event (dynamic, the full event).
type sentinel struct {
	ingestURL, azureTenant, clientID, clientSecret string
	client                                         *http.Client

	mu      sync.Mutex
	token   string
	expires time.Time
}

// azureLogin is Microsoft Entra's token host (public cloud). Tests point it
// at their own TLS server.
var azureLogin = "https://login.microsoftonline.com"

var (
	azureTenantRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,127}$`)
	dcrRE         = regexp.MustCompile(`^dcr-[a-f0-9]{32}$`)
	streamRE      = regexp.MustCompile(`^Custom-[A-Za-z0-9_]{1,200}$`)
)

func newSentinel(u *neturl.URL, f map[string]string, client *http.Client) (*sentinel, error) {
	switch {
	case !azureTenantRE.MatchString(f["azure_tenant_id"]):
		return nil, errors.New("azure_tenant_id must be the directory (tenant) ID or domain")
	case !dcrRE.MatchString(f["dcr_immutable_id"]):
		return nil, errors.New("dcr_immutable_id must look like dcr-<32 hex>")
	case !streamRE.MatchString(f["stream_name"]):
		return nil, errors.New("stream_name must be the DCR's Custom-<table> stream")
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/dataCollectionRules/" + f["dcr_immutable_id"] + "/streams/" + f["stream_name"]
	u.RawQuery = "api-version=2023-01-01"
	return &sentinel{ingestURL: u.String(), azureTenant: f["azure_tenant_id"], clientID: f["client_id"], clientSecret: f["client_secret"], client: client}, nil
}

func (s *sentinel) Send(ctx context.Context, events []Event) (int, error) {
	token, err := s.accessToken(ctx)
	if err != nil {
		return 0, err
	}
	rows := make([]map[string]any, 0, len(events))
	for _, e := range events {
		rows = append(rows, map[string]any{
			"TimeGenerated": e.Timestamp.UTC().Format(time.RFC3339Nano), "EventId": e.ID, "Action": e.Action,
			"TenantId": e.TenantID, "Service": e.Service, "Actor": e.ActorID, "TargetType": e.TargetType,
			"TargetId": e.TargetID, "Result": e.Result, "Severity": e.Severity, "SourceIp": e.SourceIP, "Event": e.record(),
		})
	}
	body, err := json.Marshal(rows)
	if err != nil {
		return 0, err
	}
	status, _, err := post(ctx, s.client, s.ingestURL, "application/json", body, map[string]string{"Authorization": "Bearer " + token})
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		s.mu.Lock()
		s.token = "" // fetch a fresh one next time
		s.mu.Unlock()
	}
	return status, err
}

// accessToken returns a cached Entra token for the Azure Monitor audience,
// fetching one with the client credentials when needed.
func (s *sentinel) accessToken(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != "" && time.Now().Before(s.expires) {
		return s.token, nil
	}
	form := neturl.Values{
		"grant_type": {"client_credentials"}, "client_id": {s.clientID}, "client_secret": {s.clientSecret},
		"scope": {"https://monitor.azure.com//.default"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, azureLogin+"/"+neturl.PathEscape(s.azureTenant)+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", errors.New("invalid token request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.client.Do(req)
	if err != nil {
		var ue *neturl.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return "", fmt.Errorf("entra token: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var ans struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
	}
	_ = json.Unmarshal(raw, &ans)
	if resp.StatusCode != http.StatusOK || ans.AccessToken == "" {
		// The error code (invalid_client, unauthorized_client …) names the
		// problem without echoing anything sent.
		return "", fmt.Errorf("entra token refused: HTTP %d %s", resp.StatusCode, ans.Error)
	}
	life := time.Duration(ans.ExpiresIn) * time.Second
	if life <= 2*time.Minute {
		life = 2 * time.Minute
	}
	s.token, s.expires = ans.AccessToken, time.Now().Add(life-time.Minute)
	return s.token, nil
}
