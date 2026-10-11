package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/credstore"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/tenantcheck"
)

// A cloud account's credentials are a credential in the platform's store
// (Playbooks → Credentials, docs/SECURITY/CONNECTIONS.md). The account holds
// its ID; every provider call opens it as the kms-cloud identity and keeps
// the fields in memory for that call only. An account an earlier release
// registered with its own sealed credentials keeps working from that copy
// until the primary has moved it into the store (migrateAccountCredentials).

// credentialType is the credential type each provider's account uses. The
// names are the providers' own, so the two match.
var credentialType = map[string]string{
	ProviderAWS: "aws", ProviderAzure: "azure", ProviderGCP: "gcp", ProviderOCI: "oci",
	ProviderAlibaba: "alibaba", ProviderSalesforce: "salesforce",
}

var providerOfCredential = func() map[string]string {
	out := map[string]string{}
	for provider, typ := range credentialType {
		out[typ] = provider
	}
	return out
}()

const optionsField = "options_json"

// SetCredentials wires the credential store.
func (s *Service) SetCredentials(c credstore.Store) { s.creds = c }

// credentialMap turns an opened credential into the map the providers
// read: its fields, under the provider options in options_json. A Google
// service account key file is passed whole, as the client library wants it.
func credentialMap(cred credstore.Credential) (map[string]interface{}, error) {
	out := map[string]interface{}{}
	if raw := strings.TrimSpace(cred.Fields[optionsField]); raw != "" {
		var opts map[string]string
		if err := json.Unmarshal([]byte(raw), &opts); err != nil {
			return nil, errors.New("the credential's options_json is not a JSON object of strings")
		}
		for k, v := range opts {
			out[k] = v
		}
	}
	for k, v := range cred.Fields {
		if k != optionsField && v != "" {
			out[k] = v
		}
	}
	if cred.Type == "gcp" {
		out["_raw_json"] = cred.Fields["service_account_json"]
		delete(out, "service_account_json")
	}
	return out, nil
}

// credentialError says what went wrong opening an account's credential,
// without naming more than its ID.
func credentialError(id string, err error) error {
	switch {
	case errors.Is(err, credstore.ErrNotDeployed):
		return newServiceError(http.StatusConflict, "credentials_not_deployed", err.Error())
	case errors.Is(err, credstore.ErrNotFound):
		return newServiceError(http.StatusConflict, "credential_not_found", "credential "+id+" does not exist: add it in Playbooks, Credentials")
	case errors.Is(err, credstore.ErrWrongType):
		return newServiceError(http.StatusConflict, "credential_wrong_type", "credential "+id+" is not a cloud provider credential")
	}
	return newServiceError(http.StatusServiceUnavailable, "credentials_unavailable", "credential "+id+" could not be opened: "+err.Error())
}

// accountCredentials opens the account's credential for one provider call.
func (s *Service) accountCredentials(ctx context.Context, account CloudAccount) (map[string]interface{}, error) {
	if account.ConnectionID == "" {
		// Registered by an earlier release and not migrated yet.
		return s.decryptAccountCredentials(account)
	}
	if s.creds == nil {
		return nil, credentialError(account.ConnectionID, credstore.ErrNotDeployed)
	}
	cred, err := s.creds.Resolve(ctx, account.TenantID, account.ConnectionID)
	if err != nil {
		return nil, credentialError(account.ConnectionID, err)
	}
	if providerOfCredential[cred.Type] != account.Provider {
		return nil, newServiceError(http.StatusConflict, "credential_wrong_type",
			fmt.Sprintf("credential %s is a %s credential; this account is %s", account.ConnectionID, cred.Type, account.Provider))
	}
	return credentialMap(cred)
}

// checkAccountCredential verifies, before an account is saved, that its
// credential exists in the tenant and is the provider's type.
func (s *Service) checkAccountCredential(ctx context.Context, tenantID, provider, connectionID string) error {
	if s.creds == nil {
		return credentialError(connectionID, credstore.ErrNotDeployed)
	}
	cred, err := s.creds.Resolve(ctx, tenantID, connectionID)
	if err != nil {
		return credentialError(connectionID, err)
	}
	if providerOfCredential[cred.Type] != provider {
		return newServiceError(http.StatusBadRequest, "credential_wrong_type",
			fmt.Sprintf("credential %s is a %s credential; a %s account needs a %s credential", connectionID, cred.Type, provider, credentialType[provider]))
	}
	return nil
}

// testCredentials makes one real, read-only provider call with creds: it
// lists the provider's keys.
func (s *Service) testCredentials(ctx context.Context, tenantID, provider, region string, creds map[string]interface{}) error {
	p, err := s.providers.Get(provider)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	account := CloudAccount{TenantID: tenantID, Provider: provider, DefaultRegion: region}
	_, err = p.Inventory(ctx, InventoryInput{TenantID: tenantID, Account: account, Region: region, Credentials: creds})
	return err
}

// TestAccount tests the account's credential against its provider and
// records the result on the credential.
func (s *Service) TestAccount(ctx context.Context, tenantID, accountID string) (CloudAccount, error) {
	account, err := s.store.GetAccount(ctx, tenantID, accountID)
	if err != nil {
		return CloudAccount{}, err
	}
	creds, err := s.accountCredentials(ctx, account)
	if err != nil {
		return account, err
	}
	testErr := s.testCredentials(ctx, tenantID, account.Provider, account.DefaultRegion, creds)
	if account.ConnectionID != "" && s.creds != nil {
		_ = s.creds.ReportTest(ctx, tenantID, account.ConnectionID, testErr)
	}
	result := "success"
	details := map[string]interface{}{"account_id": account.ID, "provider": account.Provider, "connection_id": account.ConnectionID}
	if testErr != nil {
		result, details["error"], details["severity"] = "failure", testErr.Error(), "warning"
	}
	details["result"] = result
	_ = s.publishAudit(ctx, "audit.cloud.account_tested", tenantID, details)
	if testErr != nil {
		return account, newServiceError(http.StatusBadGateway, "account_test_failed", testErr.Error())
	}
	return account, nil
}

// ---- routes (route kernel) ----

func complianceOnly(c *route.Call) bool {
	if tenantcheck.IsServicePrincipal(c.Claims) && c.Claims.ClientID == "kms-compliance" {
		return true
	}
	c.Refuse(http.StatusForbidden, "caller_not_allowed", "only the credential store may call this")
	return false
}

func (h *Handler) credentialRoutes(rt *route.Router) {
	rt.Handle("POST /cloud/accounts/{id}/test", route.Spec{Action: "account_test_requested", Permission: "cloud.write", Resource: "cloud_account", TargetParam: "id"}, h.testAccount)
	rt.Handle("POST /cloud/credentials/{id}/test", route.Spec{Action: "credential_tested", Permission: route.Authenticated, Resource: "credential", TargetParam: "id"}, h.testCredential)
	rt.Handle("GET /cloud/credential-usage", route.Spec{Action: "credential_usage_read", Permission: route.Authenticated, Resource: "credential"}, h.credentialUsage)
}

func (h *Handler) testAccount(c *route.Call) {
	account, err := h.svc.TestAccount(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	c.Detail("provider", account.Provider)
	var se serviceError
	switch {
	case errors.Is(err, errNotFound):
		c.Error(http.StatusNotFound, "not_found", "cloud account not found")
	case errors.As(err, &se):
		c.Error(se.status, se.code, se.message)
	case err != nil:
		c.Error(http.StatusInternalServerError, "internal_error", "test failed")
	default:
		c.JSON(http.StatusOK, map[string]interface{}{"status": "ok", "account_id": account.ID})
	}
}

// testCredential is the credential store's Test for a cloud credential: the
// same provider call an account makes, before any account uses it.
func (h *Handler) testCredential(c *route.Call) {
	if !complianceOnly(c) {
		return
	}
	id := c.R.PathValue("id")
	if h.svc.creds == nil {
		c.Error(http.StatusConflict, "credentials_not_deployed", credstore.ErrNotDeployed.Error())
		return
	}
	cred, err := h.svc.creds.Resolve(c.R.Context(), c.Tenant, id)
	if err != nil {
		se := credentialError(id, err).(serviceError)
		c.Error(se.status, se.code, se.message)
		return
	}
	c.Detail("type", cred.Type)
	provider := providerOfCredential[cred.Type]
	creds, err := credentialMap(cred)
	if err != nil {
		c.Error(http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if err := h.svc.testCredentials(c.R.Context(), c.Tenant, provider, strings.TrimSpace(cred.Fields["region"]), creds); err != nil {
		c.Error(http.StatusBadGateway, "credential_test_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"status": "ok"})
}

// credentialUsage names the cloud accounts on each credential, for the
// credential store's "used by" and its delete guard.
func (h *Handler) credentialUsage(c *route.Call) {
	if !complianceOnly(c) {
		return
	}
	accounts, err := h.svc.store.ListAccounts(c.R.Context(), c.Tenant, "")
	if err != nil {
		c.Error(http.StatusInternalServerError, "internal_error", "list accounts failed")
		return
	}
	items := []map[string]string{}
	for _, a := range accounts {
		if a.ConnectionID != "" {
			items = append(items, map[string]string{"connection_id": a.ConnectionID, "label": "cloud account " + a.Name + " (" + a.Provider + ")"})
		}
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

// mayAttach: registering an account attaches a credential to it, which
// needs compliance.connection.use on the caller's own verified token.
func mayAttach(ctx context.Context) bool { return credstore.MayAttach(ctx) }

func actorOf(ctx context.Context) string {
	if claims, ok := pkgauth.ClaimsFromContext(ctx); ok && claims != nil {
		return firstNonEmpty(claims.UserID, claims.ClientID, claims.Subject)
	}
	return ""
}

// ---- migration of accounts that hold their own credentials ----

// aliases maps the key names earlier releases accepted in an account's
// credentials JSON onto the credential type's fields. Anything else goes
// into options_json unchanged, so nothing an account relied on is dropped.
var aliases = map[string]map[string]string{
	"aws": {"access_key_id": "access_key_id", "aws_access_key_id": "access_key_id", "secret_access_key": "secret_access_key",
		"aws_secret_access_key": "secret_access_key", "session_token": "session_token", "aws_session_token": "session_token",
		"region": "region", "endpoint_url": "endpoint_url", "endpoint": "endpoint_url", "role_arn": "role_arn", "external_id": "external_id"},
	"azure": {"tenant_id": "tenant_id", "client_id": "client_id", "app_id": "client_id", "client_secret": "client_secret",
		"app_secret": "client_secret", "vault_url": "vault_url", "vault_name": "vault_name"},
	"gcp": {"project_id": "project_id", "project": "project_id", "location": "location", "key_ring": "key_ring"},
	"oci": {"tenancy_ocid": "tenancy_ocid", "tenancy": "tenancy_ocid", "user_ocid": "user_ocid", "user": "user_ocid", "fingerprint": "fingerprint",
		"private_key_pem": "private_key_pem", "private_key": "private_key_pem", "private_key_passphrase": "private_key_passphrase",
		"region": "region", "compartment_id": "compartment_id", "management_endpoint": "management_endpoint", "kms_management_endpoint": "management_endpoint"},
	"alibaba":    {"access_key_id": "access_key_id", "access_key_secret": "access_key_secret", "region": "region", "endpoint_url": "endpoint_url"},
	"salesforce": {"instance_url": "instance_url", "client_id": "client_id", "client_secret": "client_secret", "username": "username", "password": "password", "security_token": "security_token", "login_url": "login_url"},
}

// credentialFields turns a legacy credentials document into the fields of
// credential type typ.
func credentialFields(typ string, legacy map[string]interface{}) map[string]string {
	fields, options := map[string]string{}, map[string]string{}
	keys := make([]string, 0, len(legacy))
	for k := range legacy {
		keys = append(keys, k)
	}
	sort.Strings(keys) // an alias never overrides the canonical name
	for _, k := range keys {
		if k == "_raw_json" {
			continue
		}
		v := strings.TrimSpace(anyToString(legacy[k]))
		if v == "" {
			continue
		}
		if to, ok := aliases[typ][k]; ok {
			if k == to || fields[to] == "" {
				fields[to] = v
			}
			continue
		}
		if typ != "gcp" { // a Google key file's own members stay in the file
			options[k] = v
		}
	}
	if typ == "gcp" {
		fields["service_account_json"] = anyToString(legacy["_raw_json"])
	}
	if len(options) > 0 {
		raw, _ := json.Marshal(options)
		fields[optionsField] = string(raw)
	}
	return fields
}

// migrateAccountCredentials moves each account's own sealed credentials
// into the credential store, points the account at the new credential and
// clears its copy. Primary only: the table is replicated. An account the
// store won't take keeps working from its own copy and is retried.
func (s *Service) migrateAccountCredentials(ctx context.Context, primary func(context.Context) bool) (int, error) {
	if !primary(ctx) || s.creds == nil {
		return 0, nil
	}
	accounts, err := s.store.ListLegacyCredentialAccounts(ctx)
	if err != nil {
		return 0, err
	}
	moved := 0
	var failed []string
	for _, a := range accounts {
		legacy, err := s.decryptAccountCredentials(a)
		if err != nil {
			failed = append(failed, a.ID+" (unreadable)")
			continue
		}
		typ := credentialType[a.Provider]
		id, err := s.creds.Import(ctx, a.TenantID, a.ID, a.Name+" (cloud account)", typ, credentialFields(typ, legacy), s.accountExposed(ctx, a))
		if err == nil {
			err = s.store.SetAccountConnection(ctx, a.TenantID, a.ID, id)
		}
		if err != nil {
			failed = append(failed, a.ID)
			if !s.migrationReported[a.ID] {
				s.migrationReported[a.ID] = true
				_ = s.publishAudit(ctx, "audit.cloud.credentials_migration_refused", a.TenantID, map[string]interface{}{
					"account_id": a.ID, "provider": a.Provider, "result": "refused", "reason": "credential_store_refused", "severity": "warning",
					"error": err.Error(), "description": "the account keeps using its own sealed credentials; add a credential in Playbooks, Credentials and re-register the account",
				})
			}
			continue
		}
		moved++
		s.exposure.Retire(ctx, a.TenantID, "cloud_account_credentials", a.ID, "moved_to_credential_store")
		_ = s.publishAudit(ctx, "audit.cloud.credentials_migrated", a.TenantID, map[string]interface{}{
			"account_id": a.ID, "provider": a.Provider, "connection_id": id, "result": "success",
		})
	}
	if len(failed) > 0 {
		return moved, errors.New("cloud account credentials not moved yet, retrying: " + strings.Join(failed, ", "))
	}
	return moved, nil
}

// accountExposed reports whether the account's credentials are in the
// exposure register: wrapped under a public key by an earlier release.
func (s *Service) accountExposed(ctx context.Context, a CloudAccount) bool {
	if s.exposure == nil {
		return false
	}
	open, err := s.exposure.Exposures(ctx, a.TenantID, true)
	if err != nil {
		return false
	}
	for _, e := range open {
		if e.ItemType == "cloud_account_credentials" && e.ItemID == a.ID {
			return true
		}
	}
	return false
}

func (s *Service) migrateAccountCredentialsLoop(ctx context.Context, primary func(context.Context) bool, interval time.Duration, logf func(string, ...interface{})) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if n, err := s.migrateAccountCredentials(ctx, primary); err != nil {
			logf("cloud account credentials: %v", err)
		} else if n > 0 {
			logf("cloud account credentials: moved %d account(s) into the credential store", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
