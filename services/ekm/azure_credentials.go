package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"vecta-kms/pkg/credstore"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/tenantcheck"
)

// An Azure EKM vault's app registration (Entra tenant, client ID and client
// secret) is an "azure" credential in the platform's store (Playbooks →
// Credentials, docs/SECURITY/CONNECTIONS.md). The vault configuration holds
// its ID; each call to Azure opens it as the kms-ekm identity and keeps the
// secret in memory for that call. Before 8.0.0-beta the client secret was a
// plaintext column here; migrateAzureSecrets moves it out.

const azureCredentialType = "azure"

// SetCredentials wires the credential store.
func (s *Service) SetCredentials(c credstore.Store) { s.creds = c }

func credentialServiceError(id string, err error) error {
	switch {
	case errors.Is(err, credstore.ErrNotDeployed):
		return newServiceError(http.StatusConflict, "credentials_not_deployed", err.Error())
	case errors.Is(err, credstore.ErrNotFound):
		return newServiceError(http.StatusConflict, "credential_not_found", "credential "+id+" does not exist: add it in Playbooks, Credentials")
	case errors.Is(err, credstore.ErrWrongType):
		return newServiceError(http.StatusConflict, "credential_wrong_type", "credential "+id+" is not a Microsoft Entra app registration credential")
	}
	return newServiceError(http.StatusServiceUnavailable, "credentials_unavailable", "credential "+id+" could not be opened: "+err.Error())
}

// refuseAzureConfig audits a refused vault configuration and returns the
// refusal.
func (h *Handler) refuseAzureConfig(ctx context.Context, tenantID string, status int, reason, msg, connectionID string) error {
	h.emitAzure(ctx, "audit.ekm.azure_config_refused", tenantID, map[string]interface{}{
		"connection_id": connectionID, "result": "refused", "reason": reason, "severity": "warning", "description": msg,
	})
	return newServiceError(status, reason, msg)
}

func (h *Handler) emitAzure(ctx context.Context, subject, tenantID string, details map[string]interface{}) {
	_ = h.svc.publishAudit(ctx, subject, tenantID, details)
}

// azureCredentialFor checks the credential a vault configuration names: it
// is required unless the vault uses a managed identity, the secret may not
// be sent inline, the caller must be allowed to attach it, and it must be
// an "azure" credential in the tenant.
func (h *Handler) azureCredentialFor(ctx context.Context, tenantID string, req CreateAzureEKMConfigRequest) (credstore.Credential, error) {
	id := strings.TrimSpace(req.ConnectionID)
	if strings.TrimSpace(req.ClientSecret) != "" {
		return credstore.Credential{}, h.refuseAzureConfig(ctx, tenantID, http.StatusBadRequest, "inline_credentials_not_accepted",
			"the client secret is no longer sent with the vault: add the app registration in Playbooks, Credentials and pass its connection_id", id)
	}
	if req.AuthMode == "managed_identity" {
		return credstore.Credential{}, nil
	}
	if id == "" {
		return credstore.Credential{}, h.refuseAzureConfig(ctx, tenantID, http.StatusBadRequest, "credential_required",
			"connection_id is required: add the Microsoft Entra app registration in Playbooks, Credentials first", id)
	}
	if !credstore.MayAttach(ctx) {
		return credstore.Credential{}, h.refuseAzureConfig(ctx, tenantID, http.StatusForbidden, "credential_use_not_permitted",
			"attaching a credential to a vault needs the compliance.connection.use permission", id)
	}
	if h.svc.creds == nil {
		return credstore.Credential{}, h.refuseAzureConfig(ctx, tenantID, http.StatusConflict, "credentials_not_deployed", credstore.ErrNotDeployed.Error(), id)
	}
	cred, err := h.svc.creds.Resolve(ctx, tenantID, id)
	if err == nil && cred.Type != azureCredentialType {
		err = credstore.ErrWrongType
	}
	if err != nil {
		se := credentialServiceError(id, err).(serviceError)
		return credstore.Credential{}, h.refuseAzureConfig(ctx, tenantID, se.HTTPStatus, se.Code, se.Message, id)
	}
	return cred, nil
}

// azureConfigForUse loads a vault configuration for a call to Azure, with
// the app registration filled in from its credential, in memory only.
func (h *Handler) azureConfigForUse(ctx context.Context, tenantID, configID string) (AzureEKMConfig, error) {
	cfg, err := h.svc.store.GetAzureEKMConfig(ctx, tenantID, configID)
	if err != nil || cfg.AuthMode == "managed_identity" || cfg.ConnectionID == "" {
		// No connection: registered by an earlier release, not migrated yet.
		return cfg, err
	}
	if h.svc.creds == nil {
		return cfg, credentialServiceError(cfg.ConnectionID, credstore.ErrNotDeployed)
	}
	cred, err := h.svc.creds.Resolve(ctx, tenantID, cfg.ConnectionID)
	if err == nil && cred.Type != azureCredentialType {
		err = credstore.ErrWrongType
	}
	if err != nil {
		return cfg, credentialServiceError(cfg.ConnectionID, err)
	}
	cfg.AzureTenantID, cfg.ClientID, cfg.ClientSecret = cred.Fields["tenant_id"], cred.Fields["client_id"], cred.Fields["client_secret"]
	return cfg, nil
}

// reportAzureTest records a vault test's result on its credential.
func (h *Handler) reportAzureTest(ctx context.Context, cfg AzureEKMConfig, testErr error) {
	if cfg.ConnectionID != "" && h.svc.creds != nil {
		_ = h.svc.creds.ReportTest(ctx, cfg.TenantID, cfg.ConnectionID, testErr)
	}
}

func (h *Handler) azureCredentialRoutes(rt *route.Router) {
	rt.Handle("GET /ekm/credential-usage", route.Spec{Action: "credential_usage_read", Permission: route.Authenticated, Resource: "credential"}, h.azureCredentialUsage)
}

// azureCredentialUsage names the vaults on each credential, for the
// credential store's "used by" and its delete guard.
func (h *Handler) azureCredentialUsage(c *route.Call) {
	if !tenantcheck.IsServicePrincipal(c.Claims) || c.Claims.ClientID != "kms-compliance" {
		c.Refuse(http.StatusForbidden, "caller_not_allowed", "only the credential store may call this")
		return
	}
	configs, err := h.svc.store.ListAzureEKMConfigs(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "internal_error", "list vaults failed")
		return
	}
	items := []map[string]string{}
	for _, cfg := range configs {
		if cfg.ConnectionID != "" {
			items = append(items, map[string]string{"connection_id": cfg.ConnectionID, "label": "Azure EKM vault " + cfg.VaultName})
		}
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

// migrateAzureSecrets moves each plaintext client secret into the
// credential store as an exposed "azure" credential, points the vault at it
// and empties the column. Primary only: the table is replicated.
func (s *Service) migrateAzureSecrets(ctx context.Context, primary func(context.Context) bool) (int, error) {
	if !primary(ctx) || s.creds == nil {
		return 0, nil
	}
	configs, err := s.store.ListLegacyAzureSecrets(ctx)
	if err != nil {
		return 0, err
	}
	moved := 0
	var failed []string
	for _, cfg := range configs {
		fields := map[string]string{"tenant_id": cfg.AzureTenantID, "client_id": cfg.ClientID, "client_secret": cfg.ClientSecret}
		// exposed: the secret was stored in plaintext; old database copies
		// and backups still hold it.
		id, err := s.creds.Import(ctx, cfg.TenantID, cfg.ID, cfg.VaultName+" (Azure EKM)", azureCredentialType, fields, true)
		if err == nil {
			err = s.store.SetAzureConfigConnection(ctx, cfg.TenantID, cfg.ID, id)
		}
		if err != nil {
			failed = append(failed, cfg.ID)
			continue
		}
		moved++
		_ = s.publishAudit(ctx, "audit.ekm.azure_credentials_migrated", cfg.TenantID, map[string]interface{}{
			"config_id": cfg.ID, "connection_id": id, "result": "success", "severity": "warning",
			"exposure": "the client secret was stored in plaintext by an earlier release; rotate it in Microsoft Entra and enter the new one on the credential",
		})
	}
	if len(failed) > 0 {
		return moved, errors.New("Azure EKM client secrets not moved yet, retrying: " + strings.Join(failed, ", "))
	}
	return moved, nil
}

func (s *Service) migrateAzureSecretsLoop(ctx context.Context, primary func(context.Context) bool, interval time.Duration, logf func(string, ...interface{})) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if n, err := s.migrateAzureSecrets(ctx, primary); err != nil {
			logf("azure ekm: %v", err)
		} else if n > 0 {
			logf("azure ekm: moved %d plaintext client secret(s) into the credential store; recorded as exposed", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
