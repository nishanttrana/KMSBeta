package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

const (
	identityProviderAD    = "ad"
	identityProviderEntra = "entra"
)

type ExternalDirectoryUser struct {
	ExternalID  string `json:"external_id"`
	Username    string `json:"username"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name,omitempty"`
	Source      string `json:"source,omitempty"`
	DN          string `json:"dn,omitempty"`
}

type ExternalDirectoryGroup struct {
	ExternalID   string `json:"external_id"`
	Name         string `json:"name"`
	Description  string `json:"description,omitempty"`
	Source       string `json:"source,omitempty"`
	DN           string `json:"dn,omitempty"`
	MemberCount  int    `json:"member_count,omitempty"`
	ProviderName string `json:"provider_name,omitempty"`
}

type IdentityProviderConfigView struct {
	TenantID       string         `json:"tenant_id"`
	Provider       string         `json:"provider"`
	Enabled        bool           `json:"enabled"`
	Config         map[string]any `json:"config,omitempty"`
	SecretPresence map[string]any `json:"secret_presence,omitempty"`
	UpdatedBy      string         `json:"updated_by"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

type directoryClient interface {
	Test(ctx context.Context) (map[string]any, error)
	ListUsers(ctx context.Context, query string, limit int) ([]ExternalDirectoryUser, error)
	ListGroups(ctx context.Context, query string, limit int) ([]ExternalDirectoryGroup, error)
	ListGroupMembers(ctx context.Context, groupID string, limit int) ([]ExternalDirectoryUser, error)
}

func normalizeIdentityProvider(provider string) (string, bool) {
	switch strings.TrimSpace(strings.ToLower(provider)) {
	case identityProviderAD:
		return identityProviderAD, true
	case identityProviderEntra:
		return identityProviderEntra, true
	default:
		return "", false
	}
}

func defaultIdentityProviderConfig(tenantID string, provider string) IdentityProviderConfig {
	p, ok := normalizeIdentityProvider(provider)
	if !ok {
		p = identityProviderAD
	}
	cfg := IdentityProviderConfig{
		TenantID:  strings.TrimSpace(tenantID),
		Provider:  p,
		Enabled:   false,
		Config:    map[string]any{},
		Secrets:   map[string]any{},
		UpdatedBy: "system",
	}
	switch p {
	case identityProviderAD:
		cfg.Config = map[string]any{
			"ldap_url":             "ldaps://dc01.example.local:636",
			"base_dn":              "",
			"bind_dn":              "",
			"user_login_attr":      "sAMAccountName",
			"user_email_attr":      "mail",
			"user_display_attr":    "displayName",
			"user_object_filter":   "(objectClass=user)",
			"group_name_attr":      "cn",
			"group_object_filter":  "(objectClass=group)",
			"use_start_tls":        false,
			"insecure_skip_verify": false,
			"timeout_sec":          10,
		}
	case identityProviderEntra:
		cfg.Config = map[string]any{
			"tenant_id":      "",
			"client_id":      "",
			"authority_host": "https://login.microsoftonline.com",
			"graph_base":     "https://graph.microsoft.com/v1.0",
			"timeout_sec":    10,
		}
	}
	return cfg
}

func normalizeIdentityProviderConfig(cfg IdentityProviderConfig) IdentityProviderConfig {
	out := cfg
	out.TenantID = strings.TrimSpace(out.TenantID)
	if p, ok := normalizeIdentityProvider(out.Provider); ok {
		out.Provider = p
	}
	if out.Config == nil {
		out.Config = map[string]any{}
	}
	if out.Secrets == nil {
		out.Secrets = map[string]any{}
	}
	if strings.TrimSpace(out.UpdatedBy) == "" {
		out.UpdatedBy = "system"
	}
	return out
}

func identityProviderConfigView(cfg IdentityProviderConfig) IdentityProviderConfigView {
	view := IdentityProviderConfigView{
		TenantID:       cfg.TenantID,
		Provider:       cfg.Provider,
		Enabled:        cfg.Enabled,
		Config:         cfg.Config,
		SecretPresence: map[string]any{},
		UpdatedBy:      cfg.UpdatedBy,
		CreatedAt:      cfg.CreatedAt,
		UpdatedAt:      cfg.UpdatedAt,
	}
	switch cfg.Provider {
	case identityProviderAD:
		view.SecretPresence["bind_password_set"] = strings.TrimSpace(anyString(cfg.Secrets["bind_password"])) != ""
	case identityProviderEntra:
		view.SecretPresence["client_secret_set"] = strings.TrimSpace(anyString(cfg.Secrets["client_secret"])) != ""
	}
	return view
}

func identityProviderConfigMapString(m map[string]any, key string, d string) string {
	if m == nil {
		return d
	}
	v := strings.TrimSpace(anyString(m[key]))
	if v == "" {
		return d
	}
	return v
}

func identityProviderConfigMapBool(m map[string]any, key string, d bool) bool {
	if m == nil {
		return d
	}
	raw := strings.TrimSpace(strings.ToLower(anyString(m[key])))
	switch raw {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return d
	}
}

func identityProviderConfigMapInt(m map[string]any, key string, d int) int {
	if m == nil {
		return d
	}
	raw := strings.TrimSpace(anyString(m[key]))
	if raw == "" {
		return d
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return d
	}
	return n
}

func clampIdentityLimit(raw int, d int, max int) int {
	if raw <= 0 {
		raw = d
	}
	if raw > max {
		raw = max
	}
	if raw < 1 {
		raw = 1
	}
	return raw
}

func sanitizeImportedUsername(raw string) string {
	v := strings.TrimSpace(strings.ToLower(raw))
	if v == "" {
		return ""
	}
	out := make([]rune, 0, len(v))
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			out = append(out, r)
		}
	}
	return strings.Trim(strings.ReplaceAll(string(out), "..", "."), ".-_")
}

func fallbackIdentityUsername(email string, displayName string, externalID string) string {
	if local := strings.TrimSpace(strings.SplitN(strings.ToLower(strings.TrimSpace(email)), "@", 2)[0]); local != "" {
		return sanitizeImportedUsername(local)
	}
	if display := sanitizeImportedUsername(strings.ReplaceAll(strings.TrimSpace(displayName), " ", ".")); display != "" {
		return display
	}
	if ext := sanitizeImportedUsername(strings.ReplaceAll(strings.TrimSpace(externalID), " ", ".")); ext != "" {
		return ext
	}
	return ""
}

func generateImportedUserPassword() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "V!" + base64.RawURLEncoding.EncodeToString(buf) + "a1", nil
}

func newDirectoryClient(cfg IdentityProviderConfig) (directoryClient, error) {
	normalized := normalizeIdentityProviderConfig(cfg)
	switch normalized.Provider {
	case identityProviderAD:
		return newADDirectoryClient(normalized), nil
	case identityProviderEntra:
		return newEntraDirectoryClient(normalized), nil
	default:
		return nil, fmt.Errorf("unsupported identity provider: %s", normalized.Provider)
	}
}

type adDirectoryClient struct {
	URL                string
	BaseDN             string
	BindDN             string
	BindPassword       string
	UserLoginAttr      string
	UserEmailAttr      string
	UserDisplayAttr    string
	UserObjectFilter   string
	GroupNameAttr      string
	GroupObjectFilter  string
	InsecureSkipVerify bool
	UseStartTLS        bool
	Timeout            time.Duration
}

func newADDirectoryClient(cfg IdentityProviderConfig) *adDirectoryClient {
	timeoutSec := identityProviderConfigMapInt(cfg.Config, "timeout_sec", 10)
	if timeoutSec < 3 {
		timeoutSec = 3
	}
	if timeoutSec > 60 {
		timeoutSec = 60
	}
	return &adDirectoryClient{
		URL:                identityProviderConfigMapString(cfg.Config, "ldap_url", ""),
		BaseDN:             identityProviderConfigMapString(cfg.Config, "base_dn", ""),
		BindDN:             identityProviderConfigMapString(cfg.Config, "bind_dn", ""),
		BindPassword:       identityProviderConfigMapString(cfg.Secrets, "bind_password", ""),
		UserLoginAttr:      identityProviderConfigMapString(cfg.Config, "user_login_attr", "sAMAccountName"),
		UserEmailAttr:      identityProviderConfigMapString(cfg.Config, "user_email_attr", "mail"),
		UserDisplayAttr:    identityProviderConfigMapString(cfg.Config, "user_display_attr", "displayName"),
		UserObjectFilter:   identityProviderConfigMapString(cfg.Config, "user_object_filter", "(objectClass=user)"),
		GroupNameAttr:      identityProviderConfigMapString(cfg.Config, "group_name_attr", "cn"),
		GroupObjectFilter:  identityProviderConfigMapString(cfg.Config, "group_object_filter", "(objectClass=group)"),
		InsecureSkipVerify: identityProviderConfigMapBool(cfg.Config, "insecure_skip_verify", false),
		UseStartTLS:        identityProviderConfigMapBool(cfg.Config, "use_start_tls", false),
		Timeout:            time.Duration(timeoutSec) * time.Second,
	}
}

func (c *adDirectoryClient) dial(_ context.Context) (*ldap.Conn, error) {
	if strings.TrimSpace(c.URL) == "" {
		return nil, errors.New("ad ldap_url is required")
	}
	if strings.TrimSpace(c.BaseDN) == "" {
		return nil, errors.New("ad base_dn is required")
	}
	dialer := &net.Dialer{Timeout: c.Timeout}
	conn, err := ldap.DialURL(c.URL, ldap.DialWithDialer(dialer))
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(c.URL)), "ldap://") && c.UseStartTLS {
		if err := conn.StartTLS(&tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: c.InsecureSkipVerify, //nolint:gosec
		}); err != nil {
			conn.Close()
			return nil, err
		}
	}
	if strings.TrimSpace(c.BindDN) != "" {
		if err := conn.Bind(c.BindDN, c.BindPassword); err != nil {
			conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

func (c *adDirectoryClient) Test(ctx context.Context) (map[string]any, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close() //nolint:errcheck

	req := ldap.NewSearchRequest(
		c.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		c.UserObjectFilter,
		[]string{"distinguishedName"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"provider":      identityProviderAD,
		"directory_url": c.URL,
		"base_dn":       c.BaseDN,
		"sample_users":  len(res.Entries),
	}, nil
}

func (c *adDirectoryClient) ListUsers(ctx context.Context, query string, limit int) ([]ExternalDirectoryUser, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close() //nolint:errcheck

	limit = clampIdentityLimit(limit, 50, 200)
	filter := strings.TrimSpace(c.UserObjectFilter)
	if filter == "" {
		filter = "(objectClass=user)"
	}
	q := strings.TrimSpace(query)
	if q != "" {
		escaped := ldap.EscapeFilter(q)
		match := fmt.Sprintf("(|(%s=*%s*)(%s=*%s*)(%s=*%s*))", c.UserLoginAttr, escaped, c.UserEmailAttr, escaped, c.UserDisplayAttr, escaped)
		filter = fmt.Sprintf("(&%s%s)", filter, match)
	}
	req := ldap.NewSearchRequest(
		c.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		limit,
		0,
		false,
		filter,
		[]string{c.UserLoginAttr, c.UserEmailAttr, c.UserDisplayAttr, "distinguishedName"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return nil, err
	}
	items := make([]ExternalDirectoryUser, 0, len(res.Entries))
	for _, entry := range res.Entries {
		username := sanitizeImportedUsername(entry.GetAttributeValue(c.UserLoginAttr))
		email := strings.TrimSpace(entry.GetAttributeValue(c.UserEmailAttr))
		displayName := strings.TrimSpace(entry.GetAttributeValue(c.UserDisplayAttr))
		if username == "" {
			username = fallbackIdentityUsername(email, displayName, entry.DN)
		}
		if username == "" {
			continue
		}
		if strings.TrimSpace(email) == "" {
			email = fmt.Sprintf("%s@directory.local", username)
		}
		items = append(items, ExternalDirectoryUser{
			ExternalID:  entry.DN,
			Username:    username,
			Email:       email,
			DisplayName: displayName,
			Source:      identityProviderAD,
			DN:          entry.DN,
		})
	}
	return items, nil
}

func (c *adDirectoryClient) ListGroups(ctx context.Context, query string, limit int) ([]ExternalDirectoryGroup, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close() //nolint:errcheck

	limit = clampIdentityLimit(limit, 50, 200)
	filter := strings.TrimSpace(c.GroupObjectFilter)
	if filter == "" {
		filter = "(objectClass=group)"
	}
	q := strings.TrimSpace(query)
	if q != "" {
		escaped := ldap.EscapeFilter(q)
		match := fmt.Sprintf("(%s=*%s*)", c.GroupNameAttr, escaped)
		filter = fmt.Sprintf("(&%s%s)", filter, match)
	}
	req := ldap.NewSearchRequest(
		c.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		limit,
		0,
		false,
		filter,
		[]string{c.GroupNameAttr, "description", "member", "distinguishedName"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return nil, err
	}
	items := make([]ExternalDirectoryGroup, 0, len(res.Entries))
	for _, entry := range res.Entries {
		name := strings.TrimSpace(entry.GetAttributeValue(c.GroupNameAttr))
		if name == "" {
			continue
		}
		items = append(items, ExternalDirectoryGroup{
			ExternalID:  entry.DN,
			Name:        name,
			Description: strings.TrimSpace(entry.GetAttributeValue("description")),
			Source:      identityProviderAD,
			DN:          entry.DN,
			MemberCount: len(entry.GetAttributeValues("member")),
		})
	}
	return items, nil
}

func (c *adDirectoryClient) ListGroupMembers(ctx context.Context, groupID string, limit int) ([]ExternalDirectoryUser, error) {
	groupDN := strings.TrimSpace(groupID)
	if groupDN == "" {
		return nil, errors.New("group id is required")
	}
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close() //nolint:errcheck

	limit = clampIdentityLimit(limit, 100, 500)
	groupReq := ldap.NewSearchRequest(
		groupDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=group)",
		[]string{"member"},
		nil,
	)
	groupRes, err := conn.Search(groupReq)
	if err != nil {
		return nil, err
	}
	if len(groupRes.Entries) == 0 {
		return []ExternalDirectoryUser{}, nil
	}
	memberDNs := groupRes.Entries[0].GetAttributeValues("member")
	if len(memberDNs) > limit {
		memberDNs = memberDNs[:limit]
	}
	out := make([]ExternalDirectoryUser, 0, len(memberDNs))
	seen := map[string]struct{}{}
	for _, memberDN := range memberDNs {
		memberDN = strings.TrimSpace(memberDN)
		if memberDN == "" {
			continue
		}
		if _, ok := seen[memberDN]; ok {
			continue
		}
		seen[memberDN] = struct{}{}
		userReq := ldap.NewSearchRequest(
			memberDN,
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			1,
			0,
			false,
			"(objectClass=*)",
			[]string{c.UserLoginAttr, c.UserEmailAttr, c.UserDisplayAttr, "distinguishedName"},
			nil,
		)
		userRes, userErr := conn.Search(userReq)
		if userErr != nil || len(userRes.Entries) == 0 {
			continue
		}
		entry := userRes.Entries[0]
		username := sanitizeImportedUsername(entry.GetAttributeValue(c.UserLoginAttr))
		email := strings.TrimSpace(entry.GetAttributeValue(c.UserEmailAttr))
		displayName := strings.TrimSpace(entry.GetAttributeValue(c.UserDisplayAttr))
		if username == "" {
			username = fallbackIdentityUsername(email, displayName, entry.DN)
		}
		if username == "" {
			continue
		}
		if strings.TrimSpace(email) == "" {
			email = fmt.Sprintf("%s@directory.local", username)
		}
		out = append(out, ExternalDirectoryUser{
			ExternalID:  entry.DN,
			Username:    username,
			Email:       email,
			DisplayName: displayName,
			Source:      identityProviderAD,
			DN:          entry.DN,
		})
	}
	return out, nil
}

type entraDirectoryClient struct {
	TenantID      string
	ClientID      string
	ClientSecret  string
	AuthorityHost string
	GraphBase     string
	Timeout       time.Duration
}

func newEntraDirectoryClient(cfg IdentityProviderConfig) *entraDirectoryClient {
	timeoutSec := identityProviderConfigMapInt(cfg.Config, "timeout_sec", 10)
	if timeoutSec < 3 {
		timeoutSec = 3
	}
	if timeoutSec > 60 {
		timeoutSec = 60
	}
	return &entraDirectoryClient{
		TenantID:      identityProviderConfigMapString(cfg.Config, "tenant_id", ""),
		ClientID:      identityProviderConfigMapString(cfg.Config, "client_id", ""),
		ClientSecret:  identityProviderConfigMapString(cfg.Secrets, "client_secret", ""),
		AuthorityHost: strings.TrimRight(identityProviderConfigMapString(cfg.Config, "authority_host", "https://login.microsoftonline.com"), "/"),
		GraphBase:     strings.TrimRight(identityProviderConfigMapString(cfg.Config, "graph_base", "https://graph.microsoft.com/v1.0"), "/"),
		Timeout:       time.Duration(timeoutSec) * time.Second,
	}
}

func (c *entraDirectoryClient) httpClient() *http.Client {
	return &http.Client{Timeout: c.Timeout}
}

func (c *entraDirectoryClient) acquireToken(ctx context.Context) (string, error) {
	if strings.TrimSpace(c.TenantID) == "" {
		return "", errors.New("entra tenant_id is required")
	}
	if strings.TrimSpace(c.ClientID) == "" {
		return "", errors.New("entra client_id is required")
	}
	if strings.TrimSpace(c.ClientSecret) == "" {
		return "", errors.New("entra client_secret is required")
	}
	values := url.Values{}
	values.Set("grant_type", "client_credentials")
	values.Set("client_id", c.ClientID)
	values.Set("client_secret", c.ClientSecret)
	values.Set("scope", "https://graph.microsoft.com/.default")
	tokenURL := fmt.Sprintf("%s/%s/oauth2/v2.0/token", c.AuthorityHost, url.PathEscape(c.TenantID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(values.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() //nolint:errcheck
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("entra token request failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var payload struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", err
	}
	if strings.TrimSpace(payload.AccessToken) == "" {
		return "", errors.New("entra access_token is empty")
	}
	return payload.AccessToken, nil
}

func (c *entraDirectoryClient) graphGet(ctx context.Context, token string, path string, query url.Values) ([]byte, error) {
	endpoint := c.GraphBase + path
	if query != nil {
		qs := strings.TrimSpace(query.Encode())
		if qs != "" {
			endpoint += "?" + qs
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("ConsistencyLevel", "eventual")
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("entra graph request failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}

func (c *entraDirectoryClient) Test(ctx context.Context) (map[string]any, error) {
	token, err := c.acquireToken(ctx)
	if err != nil {
		return nil, err
	}
	query := url.Values{}
	query.Set("$top", "1")
	body, err := c.graphGet(ctx, token, "/organization", query)
	if err != nil {
		return nil, err
	}
	var out struct {
		Value []map[string]any `json:"value"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return map[string]any{
		"provider":      identityProviderEntra,
		"tenant_id":     c.TenantID,
		"graph_base":    c.GraphBase,
		"organizations": len(out.Value),
	}, nil
}

func escapeODataString(v string) string {
	return strings.ReplaceAll(v, "'", "''")
}

func (c *entraDirectoryClient) ListUsers(ctx context.Context, query string, limit int) ([]ExternalDirectoryUser, error) {
	token, err := c.acquireToken(ctx)
	if err != nil {
		return nil, err
	}
	limit = clampIdentityLimit(limit, 50, 200)
	q := strings.TrimSpace(query)
	params := url.Values{}
	params.Set("$top", strconv.Itoa(limit))
	params.Set("$select", "id,displayName,userPrincipalName,mail,onPremisesSamAccountName")
	if q != "" {
		escaped := escapeODataString(q)
		params.Set("$filter", fmt.Sprintf("startswith(displayName,'%s') or startswith(mail,'%s') or startswith(userPrincipalName,'%s')", escaped, escaped, escaped))
	}
	body, err := c.graphGet(ctx, token, "/users", params)
	if err != nil {
		return nil, err
	}
	var payload struct {
		Value []struct {
			ID                   string `json:"id"`
			DisplayName          string `json:"displayName"`
			UserPrincipalName    string `json:"userPrincipalName"`
			Mail                 string `json:"mail"`
			OnPremisesSamAccount string `json:"onPremisesSamAccountName"`
		} `json:"value"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	out := make([]ExternalDirectoryUser, 0, len(payload.Value))
	for _, item := range payload.Value {
		username := sanitizeImportedUsername(item.OnPremisesSamAccount)
		if username == "" {
			upn := strings.TrimSpace(item.UserPrincipalName)
			if local := strings.TrimSpace(strings.SplitN(strings.ToLower(upn), "@", 2)[0]); local != "" {
				username = sanitizeImportedUsername(local)
			}
		}
		email := strings.TrimSpace(item.Mail)
		if email == "" {
			email = strings.TrimSpace(item.UserPrincipalName)
		}
		if username == "" {
			username = fallbackIdentityUsername(email, item.DisplayName, item.ID)
		}
		if username == "" {
			continue
		}
		if email == "" {
			email = fmt.Sprintf("%s@entra.local", username)
		}
		out = append(out, ExternalDirectoryUser{
			ExternalID:  strings.TrimSpace(item.ID),
			Username:    username,
			Email:       email,
			DisplayName: strings.TrimSpace(item.DisplayName),
			Source:      identityProviderEntra,
		})
	}
	return out, nil
}

func (c *entraDirectoryClient) ListGroups(ctx context.Context, query string, limit int) ([]ExternalDirectoryGroup, error) {
	token, err := c.acquireToken(ctx)
	if err != nil {
		return nil, err
	}
	limit = clampIdentityLimit(limit, 50, 200)
	q := strings.TrimSpace(query)
	params := url.Values{}
	params.Set("$top", strconv.Itoa(limit))
	params.Set("$select", "id,displayName,description")
	if q != "" {
		escaped := escapeODataString(q)
		params.Set("$filter", fmt.Sprintf("startswith(displayName,'%s')", escaped))
	}
	body, err := c.graphGet(ctx, token, "/groups", params)
	if err != nil {
		return nil, err
	}
	var payload struct {
		Value []struct {
			ID          string `json:"id"`
			DisplayName string `json:"displayName"`
			Description string `json:"description"`
		} `json:"value"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	out := make([]ExternalDirectoryGroup, 0, len(payload.Value))
	for _, item := range payload.Value {
		name := strings.TrimSpace(item.DisplayName)
		if name == "" {
			continue
		}
		out = append(out, ExternalDirectoryGroup{
			ExternalID:  strings.TrimSpace(item.ID),
			Name:        name,
			Description: strings.TrimSpace(item.Description),
			Source:      identityProviderEntra,
		})
	}
	return out, nil
}

func (c *entraDirectoryClient) ListGroupMembers(ctx context.Context, groupID string, limit int) ([]ExternalDirectoryUser, error) {
	groupID = strings.TrimSpace(groupID)
	if groupID == "" {
		return nil, errors.New("group id is required")
	}
	token, err := c.acquireToken(ctx)
	if err != nil {
		return nil, err
	}
	limit = clampIdentityLimit(limit, 100, 500)
	params := url.Values{}
	params.Set("$top", strconv.Itoa(limit))
	params.Set("$select", "id,displayName,userPrincipalName,mail,onPremisesSamAccountName")
	body, err := c.graphGet(ctx, token, "/groups/"+url.PathEscape(groupID)+"/members", params)
	if err != nil {
		return nil, err
	}
	var payload struct {
		Value []map[string]any `json:"value"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	out := make([]ExternalDirectoryUser, 0, len(payload.Value))
	for _, item := range payload.Value {
		id := strings.TrimSpace(anyString(item["id"]))
		if id == "" {
			continue
		}
		email := strings.TrimSpace(anyString(item["mail"]))
		upn := strings.TrimSpace(anyString(item["userPrincipalName"]))
		display := strings.TrimSpace(anyString(item["displayName"]))
		sam := strings.TrimSpace(anyString(item["onPremisesSamAccountName"]))
		username := sanitizeImportedUsername(sam)
		if username == "" && upn != "" {
			username = sanitizeImportedUsername(strings.SplitN(strings.ToLower(upn), "@", 2)[0])
		}
		if username == "" {
			username = fallbackIdentityUsername(email, display, id)
		}
		if username == "" {
			continue
		}
		if email == "" {
			email = upn
		}
		if email == "" {
			email = fmt.Sprintf("%s@entra.local", username)
		}
		out = append(out, ExternalDirectoryUser{
			ExternalID:  id,
			Username:    username,
			Email:       email,
			DisplayName: display,
			Source:      identityProviderEntra,
		})
	}
	return out, nil
}
