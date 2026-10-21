package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"vecta-kms/pkg/credstore"
	pkgcrypto "vecta-kms/pkg/crypto"
	pkgkeyaccess "vecta-kms/pkg/keyaccess"
	"vecta-kms/pkg/mek"
	"vecta-kms/pkg/route"
)

type EventPublisher interface {
	Publish(ctx context.Context, subject string, payload []byte) error
}

type Service struct {
	store     Store
	providers *ProviderRegistry
	events    EventPublisher
	mek       []byte
	keyAccess pkgkeyaccess.Gate
	exposure  *mek.Keyring // exposure register; nil in tests
	// creds is the credential store (credentials.go); nil when the
	// deployment has none.
	creds credstore.Store
	// migrationReported: accounts whose migration refusal was audited, so
	// the 15-minute retry does not repeat the event.
	migrationReported map[string]bool
	// The BYOK engine (byok_engine.go).
	byokStore     BYOKStore
	byokKeycore   BYOKKeycore
	byokProviders map[string]BYOKProvider
	// audit emits events no request carries (BYOK automation sweep).
	audit route.Emitter
}

func NewService(store Store, providers *ProviderRegistry, events EventPublisher, mek []byte) *Service {
	if providers == nil {
		providers = defaultProviderRegistry()
	}
	// The master key comes from keycore (pkg/mek); there is no fallback.
	if len(mek) != 32 {
		panic("cloud: a 32-byte master key from pkg/mek is required")
	}
	return &Service{
		store:     store,
		providers: providers,
		events:    events,
		mek:       append([]byte{}, mek[:32]...),

		migrationReported: map[string]bool{},
	}
}

// SetKeyring wires the exposure register: credentials stored under a public
// key before 1.2.0-beta stay listed until the account is deleted.
func (s *Service) SetKeyring(k *mek.Keyring) { s.exposure = k }

// SetKeyAccess wires the key access gate. Until it is set the zero gate
// refuses every key operation (fail closed).
func (s *Service) SetKeyAccess(g pkgkeyaccess.Gate) {
	s.keyAccess = g
}

func (s *Service) RegisterAccount(ctx context.Context, req RegisterCloudAccountRequest) (CloudAccount, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	rawProvider := strings.TrimSpace(req.Provider)
	req.Provider = normalizeProvider(rawProvider)
	req.Name = strings.TrimSpace(req.Name)
	req.DefaultRegion = strings.TrimSpace(req.DefaultRegion)
	req.ConnectionID = strings.TrimSpace(req.ConnectionID)
	if rawProvider != "" && req.Provider == "" {
		return CloudAccount{}, errors.New("unsupported provider")
	}
	if req.TenantID == "" || req.Provider == "" || req.Name == "" {
		return CloudAccount{}, errors.New("tenant_id, provider, name are required")
	}
	// Credentials are added once, in the credential store, and an account
	// names one (owner directive 2026-10-10). The account holds no secret.
	if strings.TrimSpace(req.CredentialsJSON) != "" {
		return CloudAccount{}, s.refuseAccount(ctx, req, "inline_credentials_not_accepted",
			"credentials are no longer sent with the account: add the credential in Playbooks, Credentials and pass its connection_id")
	}
	if req.ConnectionID == "" {
		return CloudAccount{}, s.refuseAccount(ctx, req, "credential_required",
			"connection_id is required: add the provider's credential in Playbooks, Credentials first")
	}
	if !mayAttach(ctx) {
		return CloudAccount{}, s.refuseAccountStatus(ctx, req, http.StatusForbidden, "credential_use_not_permitted",
			"attaching a credential to a cloud account needs the compliance.connection.use permission")
	}
	if err := s.checkAccountCredential(ctx, req.TenantID, req.Provider, req.ConnectionID); err != nil {
		var se serviceError
		if errors.As(err, &se) {
			return CloudAccount{}, s.refuseAccountStatus(ctx, req, se.status, se.code, se.message)
		}
		return CloudAccount{}, err
	}
	account := CloudAccount{
		ID:            newID("ca"),
		TenantID:      req.TenantID,
		Provider:      req.Provider,
		Name:          req.Name,
		DefaultRegion: req.DefaultRegion,
		Status:        "configured",
		ConnectionID:  req.ConnectionID,
	}
	if err := s.store.CreateAccount(ctx, account); err != nil {
		return CloudAccount{}, err
	}
	out, err := s.store.GetAccount(ctx, req.TenantID, account.ID)
	if err != nil {
		return CloudAccount{}, err
	}
	_ = s.publishAudit(ctx, "audit.cloud.connector_configured", req.TenantID, map[string]interface{}{
		"account_id":    out.ID,
		"provider":      out.Provider,
		"name":          out.Name,
		"connection_id": out.ConnectionID,
		"action":        "register",
	})
	return out, nil
}

// refuseAccount audits a refused account registration and returns the
// refusal (400 unless refuseAccountStatus is used).
func (s *Service) refuseAccount(ctx context.Context, req RegisterCloudAccountRequest, reason, msg string) error {
	return s.refuseAccountStatus(ctx, req, http.StatusBadRequest, reason, msg)
}

func (s *Service) refuseAccountStatus(ctx context.Context, req RegisterCloudAccountRequest, status int, reason, msg string) error {
	_ = s.publishAudit(ctx, "audit.cloud.account_refused", req.TenantID, map[string]interface{}{
		"provider": req.Provider, "name": req.Name, "connection_id": req.ConnectionID, "actor": actorOf(ctx),
		"result": "refused", "reason": reason, "severity": "warning", "description": msg,
	})
	return newServiceError(status, reason, msg)
}

func (s *Service) ListAccounts(ctx context.Context, tenantID string, provider string) ([]CloudAccount, error) {
	tenantID = strings.TrimSpace(tenantID)
	rawProvider := strings.TrimSpace(provider)
	provider = normalizeProvider(rawProvider)
	if rawProvider != "" && provider == "" {
		return nil, errors.New("unsupported provider")
	}
	if tenantID == "" {
		return nil, errors.New("tenant_id is required")
	}
	return s.store.ListAccounts(ctx, tenantID, provider)
}

func (s *Service) DeleteAccount(ctx context.Context, tenantID string, accountID string) (DeleteCloudAccountResult, error) {
	tenantID = strings.TrimSpace(tenantID)
	accountID = strings.TrimSpace(accountID)
	if tenantID == "" || accountID == "" {
		return DeleteCloudAccountResult{}, errors.New("tenant_id and account_id are required")
	}
	out, err := s.store.DeleteAccountCascade(ctx, tenantID, accountID)
	if err != nil {
		return DeleteCloudAccountResult{}, err
	}
	s.exposure.Retire(ctx, tenantID, "cloud_account_credentials", accountID, "deleted")
	_ = s.publishAudit(ctx, "audit.cloud.connector_deleted", tenantID, map[string]interface{}{
		"account_id":              out.AccountID,
		"provider":                out.Provider,
		"deleted_bindings":        out.DeletedBindings,
		"deleted_sync_jobs":       out.DeletedSyncJobs,
		"deleted_region_mappings": out.DeletedRegionMappings,
		"action":                  "delete_connector",
	})
	return out, nil
}

func (s *Service) SetRegionMapping(ctx context.Context, req SetRegionMappingRequest) (RegionMapping, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	rawProvider := strings.TrimSpace(req.Provider)
	req.Provider = normalizeProvider(rawProvider)
	req.VectaRegion = strings.TrimSpace(req.VectaRegion)
	req.CloudRegion = strings.TrimSpace(req.CloudRegion)
	if rawProvider != "" && req.Provider == "" {
		return RegionMapping{}, errors.New("unsupported provider")
	}
	if req.TenantID == "" || req.Provider == "" || req.VectaRegion == "" || req.CloudRegion == "" {
		return RegionMapping{}, errors.New("tenant_id, provider, vecta_region, cloud_region are required")
	}
	m := RegionMapping{
		TenantID:    req.TenantID,
		Provider:    req.Provider,
		VectaRegion: req.VectaRegion,
		CloudRegion: req.CloudRegion,
	}
	if err := s.store.SetRegionMapping(ctx, m); err != nil {
		return RegionMapping{}, err
	}
	out, err := s.store.GetRegionMapping(ctx, req.TenantID, req.Provider, req.VectaRegion)
	if err != nil {
		return RegionMapping{}, err
	}
	_ = s.publishAudit(ctx, "audit.cloud.connector_configured", req.TenantID, map[string]interface{}{
		"provider":     req.Provider,
		"vecta_region": req.VectaRegion,
		"cloud_region": req.CloudRegion,
		"action":       "region_mapping",
	})
	return out, nil
}

func (s *Service) ListRegionMappings(ctx context.Context, tenantID string, provider string) ([]RegionMapping, error) {
	tenantID = strings.TrimSpace(tenantID)
	rawProvider := strings.TrimSpace(provider)
	provider = normalizeProvider(rawProvider)
	if rawProvider != "" && provider == "" {
		return nil, errors.New("unsupported provider")
	}
	if tenantID == "" {
		return nil, errors.New("tenant_id is required")
	}
	return s.store.ListRegionMappings(ctx, tenantID, provider)
}

func (s *Service) SyncCloudKeys(ctx context.Context, req SyncCloudKeysRequest) (SyncJob, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	rawProvider := strings.TrimSpace(req.Provider)
	req.Provider = normalizeProvider(rawProvider)
	req.AccountID = strings.TrimSpace(req.AccountID)
	req.Mode = strings.TrimSpace(strings.ToLower(req.Mode))
	if req.TenantID == "" {
		return SyncJob{}, errors.New("tenant_id is required")
	}
	if rawProvider != "" && req.Provider == "" {
		return SyncJob{}, errors.New("unsupported provider")
	}
	if req.Mode == "" {
		req.Mode = "full"
	}
	if req.Provider != "" && !supportedProvider(req.Provider) {
		return SyncJob{}, errors.New("unsupported provider")
	}
	keyAccessResult, err := s.evaluateKeyAccess(ctx, pkgkeyaccess.EvaluateRequest{
		TenantID:          req.TenantID,
		Service:           "cloud",
		Connector:         req.Provider,
		Operation:         "sync",
		ResourceID:        firstNonEmpty(req.AccountID, req.Provider, req.Mode),
		TargetType:        "cloud_sync",
		RequestID:         newID("cloudreq"),
		RequesterID:       strings.TrimSpace(req.RequesterID),
		RequesterEmail:    strings.TrimSpace(req.RequesterEmail),
		RequesterIP:       strings.TrimSpace(req.RequesterIP),
		JustificationCode: strings.TrimSpace(req.JustificationCode),
		JustificationText: strings.TrimSpace(req.JustificationText),
		Metadata: map[string]interface{}{
			"provider":   req.Provider,
			"account_id": req.AccountID,
			"mode":       req.Mode,
		},
	})
	if err != nil {
		return SyncJob{}, err
	}
	if strings.EqualFold(keyAccessResult.Action, "deny") {
		reason := firstNonEmpty(keyAccessResult.Reason, "blocked by key access justification policy")
		_ = s.publishAudit(ctx, "audit.cloud.key_access_denied", req.TenantID, map[string]interface{}{
			"provider":           req.Provider,
			"account_id":         req.AccountID,
			"operation":          "sync",
			"mode":               req.Mode,
			"justification_code": req.JustificationCode,
			"reason":             reason,
			"result":             "refused",
		})
		return SyncJob{}, newServiceError(http.StatusForbidden, "key_access_denied", reason)
	}
	if keyAccessResult.ApprovalRequired {
		job := SyncJob{
			ID:                newID("cjob"),
			TenantID:          req.TenantID,
			Provider:          req.Provider,
			AccountID:         req.AccountID,
			Mode:              req.Mode,
			Status:            "pending_approval",
			SummaryJSON:       "{}",
			ApprovalRequestID: keyAccessResult.ApprovalRequestID,
			StartedAt:         nowUTC(),
			CreatedAt:         nowUTC(),
		}
		_ = s.publishAudit(ctx, "audit.cloud.approval_required", req.TenantID, map[string]interface{}{
			"provider":            req.Provider,
			"account_id":          req.AccountID,
			"operation":           "sync",
			"mode":                req.Mode,
			"approval_request_id": keyAccessResult.ApprovalRequestID,
			"justification_code":  req.JustificationCode,
		})
		return job, nil
	}
	job := SyncJob{
		ID:          newID("cjob"),
		TenantID:    req.TenantID,
		Provider:    req.Provider,
		AccountID:   req.AccountID,
		Mode:        req.Mode,
		Status:      "running",
		SummaryJSON: "{}",
		StartedAt:   nowUTC(),
	}
	if err := s.store.CreateSyncJob(ctx, job); err != nil {
		return SyncJob{}, err
	}
	_ = s.publishAudit(ctx, "audit.cloud.sync_started", req.TenantID, map[string]interface{}{
		"job_id":            job.ID,
		"provider":          job.Provider,
		"account_id":        job.AccountID,
		"mode":              job.Mode,
		"key_access_reason": keyAccessResult.Reason,
	})

	bindings, err := s.store.ListBindings(ctx, req.TenantID, req.Provider, req.AccountID, "", 10_000, 0)
	if err != nil {
		_ = s.store.CompleteSyncJob(ctx, req.TenantID, job.ID, "failed", `{"total":0,"success":0,"failed":1}`, err.Error())
		_ = s.publishAudit(ctx, "audit.cloud.sync_failed", req.TenantID, map[string]interface{}{"job_id": job.ID, "error": err.Error()})
		return SyncJob{}, err
	}
	total := len(bindings)
	success := 0
	failed := 0
	failMsgs := make([]string, 0)
	for _, b := range bindings {
		account, err := s.store.GetAccount(ctx, req.TenantID, b.AccountID)
		if err != nil {
			failed++
			failMsgs = append(failMsgs, b.ID+": "+err.Error())
			continue
		}
		creds, err := s.accountCredentials(ctx, account)
		if err != nil {
			failed++
			failMsgs = append(failMsgs, b.ID+": "+err.Error())
			continue
		}
		provider, err := s.providers.Get(b.Provider)
		if err != nil {
			failed++
			failMsgs = append(failMsgs, b.ID+": "+err.Error())
			continue
		}
		result, err := provider.SyncBinding(ctx, SyncInput{
			TenantID:    req.TenantID,
			Binding:     b,
			Account:     account,
			Credentials: creds,
		})
		if err != nil {
			b.SyncStatus = "failed"
			b.LastSyncedAt = nowUTC()
			_ = s.store.UpdateBinding(ctx, b)
			failed++
			failMsgs = append(failMsgs, b.ID+": "+err.Error())
			continue
		}
		b.SyncStatus = "synced"
		b.LastSyncedAt = nowUTC()
		b.CloudKeyID = defaultString(result.CloudKeyID, b.CloudKeyID)
		b.CloudKeyRef = defaultString(result.CloudKeyRef, b.CloudKeyRef)
		b.MetadataJSON = mergeMetadata(b.MetadataJSON, result.Metadata)
		_ = s.store.UpdateBinding(ctx, b)
		success++
	}
	summary := map[string]interface{}{
		"total":   total,
		"success": success,
		"failed":  failed,
	}
	summaryRaw, _ := json.Marshal(summary)
	status := "completed"
	errorMessage := ""
	if failed > 0 {
		status = "failed"
		errorMessage = strings.Join(failMsgs, "; ")
	}
	if err := s.store.CompleteSyncJob(ctx, req.TenantID, job.ID, status, string(summaryRaw), errorMessage); err != nil {
		return SyncJob{}, err
	}
	out, err := s.store.GetSyncJob(ctx, req.TenantID, job.ID)
	if err != nil {
		return SyncJob{}, err
	}
	auditSubject := "audit.cloud.sync_completed"
	if status != "completed" {
		auditSubject = "audit.cloud.sync_failed"
	}
	_ = s.publishAudit(ctx, auditSubject, req.TenantID, map[string]interface{}{
		"job_id":     out.ID,
		"provider":   out.Provider,
		"account_id": out.AccountID,
		"mode":       out.Mode,
		"summary":    summary,
		"error":      errorMessage,
	})
	return out, nil
}

func (s *Service) DiscoverInventory(ctx context.Context, req DiscoverInventoryRequest) ([]InventoryItem, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	rawProvider := strings.TrimSpace(req.Provider)
	req.Provider = normalizeProvider(rawProvider)
	req.AccountID = strings.TrimSpace(req.AccountID)
	req.CloudRegion = strings.TrimSpace(req.CloudRegion)
	if req.TenantID == "" {
		return nil, errors.New("tenant_id is required")
	}
	if rawProvider != "" && req.Provider == "" {
		return nil, errors.New("unsupported provider")
	}
	account, provider, err := s.resolveAccountProvider(ctx, req.TenantID, req.Provider, req.AccountID)
	if err != nil {
		return nil, err
	}
	creds, err := s.accountCredentials(ctx, account)
	if err != nil {
		return nil, err
	}
	region := req.CloudRegion
	if region == "" {
		region = defaultString(account.DefaultRegion, provider.DefaultRegion())
	}
	items, err := provider.Inventory(ctx, InventoryInput{
		TenantID:    req.TenantID,
		Account:     account,
		Region:      region,
		Credentials: creds,
	})
	if err != nil {
		_ = s.store.UpdateAccountStatus(ctx, req.TenantID, account.ID, "auth_failed")
		return nil, err
	}
	_ = s.store.UpdateAccountStatus(ctx, req.TenantID, account.ID, "connected")
	bindings, _ := s.store.ListBindings(ctx, req.TenantID, provider.Name(), account.ID, "", 10_000, 0)
	managed := map[string]struct{}{}
	for _, b := range bindings {
		managed[b.CloudKeyID] = struct{}{}
	}
	for i := range items {
		if _, ok := managed[items[i].CloudKeyID]; ok {
			items[i].ManagedByVecta = true
		}
	}
	return items, nil
}

func (s *Service) ListBindings(ctx context.Context, tenantID string, provider string, accountID string, keyID string, limit int, offset int) ([]CloudKeyBinding, error) {
	tenantID = strings.TrimSpace(tenantID)
	rawProvider := strings.TrimSpace(provider)
	provider = normalizeProvider(rawProvider)
	accountID = strings.TrimSpace(accountID)
	keyID = strings.TrimSpace(keyID)
	if tenantID == "" {
		return nil, errors.New("tenant_id is required")
	}
	if rawProvider != "" && provider == "" {
		return nil, errors.New("unsupported provider")
	}
	return s.store.ListBindings(ctx, tenantID, provider, accountID, keyID, limit, offset)
}

func (s *Service) GetBinding(ctx context.Context, tenantID string, bindingID string) (CloudKeyBinding, error) {
	tenantID = strings.TrimSpace(tenantID)
	bindingID = strings.TrimSpace(bindingID)
	if tenantID == "" || bindingID == "" {
		return CloudKeyBinding{}, errors.New("tenant_id and binding_id are required")
	}
	return s.store.GetBinding(ctx, tenantID, bindingID)
}

func (s *Service) resolveAccountProvider(ctx context.Context, tenantID string, provider string, accountID string) (CloudAccount, CloudProvider, error) {
	if strings.TrimSpace(accountID) != "" {
		account, err := s.store.GetAccount(ctx, tenantID, accountID)
		if err != nil {
			return CloudAccount{}, nil, err
		}
		if provider != "" && provider != account.Provider {
			return CloudAccount{}, nil, errors.New("provider/account mismatch")
		}
		p, err := s.providers.Get(account.Provider)
		if err != nil {
			return CloudAccount{}, nil, err
		}
		return account, p, nil
	}
	if provider == "" {
		return CloudAccount{}, nil, errors.New("provider or account_id is required")
	}
	accounts, err := s.store.ListAccounts(ctx, tenantID, provider)
	if err != nil {
		return CloudAccount{}, nil, err
	}
	if len(accounts) == 0 {
		return CloudAccount{}, nil, errors.New("no cloud account found for provider")
	}
	var account CloudAccount
	found := false
	for _, a := range accounts {
		if strings.EqualFold(a.Status, "connected") || strings.EqualFold(a.Status, "configured") || strings.EqualFold(a.Status, "active") {
			account = a
			found = true
			break
		}
	}
	if !found {
		account = accounts[0]
	}
	p, err := s.providers.Get(account.Provider)
	if err != nil {
		return CloudAccount{}, nil, err
	}
	return account, p, nil
}

func (s *Service) decryptAccountCredentials(account CloudAccount) (map[string]interface{}, error) {
	env := &pkgcrypto.EnvelopeCiphertext{
		WrappedDEK:   append([]byte{}, account.CredentialsWrappedDEK...),
		WrappedDEKIV: append([]byte{}, account.CredentialsWrappedDEKIV...),
		Ciphertext:   append([]byte{}, account.CredentialsCiphertext...),
		DataIV:       append([]byte{}, account.CredentialsDataIV...),
	}
	plain, err := pkgcrypto.DecryptEnvelope(s.mek, env)
	if err != nil {
		return nil, err
	}
	defer pkgcrypto.Zeroize(plain)
	out := map[string]interface{}{}
	if len(strings.TrimSpace(string(plain))) == 0 {
		return out, nil
	}
	if err := json.Unmarshal(plain, &out); err != nil {
		return nil, errors.New("invalid cloud credentials json")
	}
	out["_raw_json"] = string(plain)
	return out, nil
}

func (s *Service) publishAudit(ctx context.Context, subject string, tenantID string, data map[string]interface{}) error {
	if s.events == nil {
		return nil
	}
	payload, err := json.Marshal(map[string]interface{}{
		"tenant_id": tenantID,
		"service":   "cloud",
		"action":    subject,
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"data":      data,
	})
	if err != nil {
		return err
	}
	return s.events.Publish(ctx, subject, payload)
}

func mergeMetadata(existing string, updates map[string]interface{}) string {
	current := map[string]interface{}{}
	if strings.TrimSpace(existing) != "" {
		_ = json.Unmarshal([]byte(existing), &current)
	}
	if current == nil {
		current = map[string]interface{}{}
	}
	for k, v := range updates {
		current[k] = v
	}
	raw, _ := json.Marshal(current)
	return string(raw)
}

// evaluateKeyAccess asks the key access gate. When key access is deployed
// (or its deployment is unknown) and gives no decision, the operation is
// refused with 424 key_access_unavailable and audited; it never falls back
// to allow. Without the service the decision reason is key_access_not_deployed.
func (s *Service) evaluateKeyAccess(ctx context.Context, req pkgkeyaccess.EvaluateRequest) (pkgkeyaccess.EvaluateResponse, error) {
	out, err := s.keyAccess.Evaluate(ctx, req)
	if err != nil {
		_ = s.publishAudit(ctx, "audit.cloud.key_access_denied", req.TenantID, map[string]interface{}{
			"provider":           req.Connector,
			"key_id":             req.KeyID,
			"resource_id":        req.ResourceID,
			"operation":          req.Operation,
			"justification_code": req.JustificationCode,
			"reason":             pkgkeyaccess.ReasonUnavailable,
			"error":              err.Error(),
			"result":             "refused",
			"severity":           "warning",
		})
		return pkgkeyaccess.EvaluateResponse{}, newServiceError(http.StatusFailedDependency, pkgkeyaccess.ReasonUnavailable, pkgkeyaccess.ErrUnavailable.Error())
	}
	return out, nil
}
