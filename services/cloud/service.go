package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
)

type EventPublisher interface {
	Publish(ctx context.Context, subject string, payload []byte) error
}

type Service struct {
	store     Store
	keycore   KeyCoreClient
	providers *ProviderRegistry
	events    EventPublisher
	mek       []byte
}

func NewService(store Store, keycore KeyCoreClient, providers *ProviderRegistry, events EventPublisher, mek []byte) *Service {
	if providers == nil {
		providers = defaultProviderRegistry()
	}
	if len(mek) < 32 {
		mek = []byte("0123456789ABCDEF0123456789ABCDEF")
	}
	return &Service{
		store:     store,
		keycore:   keycore,
		providers: providers,
		events:    events,
		mek:       append([]byte{}, mek[:32]...),
	}
}

func (s *Service) RegisterAccount(ctx context.Context, req RegisterCloudAccountRequest) (CloudAccount, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	rawProvider := strings.TrimSpace(req.Provider)
	req.Provider = normalizeProvider(rawProvider)
	req.Name = strings.TrimSpace(req.Name)
	req.DefaultRegion = strings.TrimSpace(req.DefaultRegion)
	req.CredentialsJSON = validJSONOr(req.CredentialsJSON, "{}")
	if rawProvider != "" && req.Provider == "" {
		return CloudAccount{}, errors.New("unsupported provider")
	}
	if req.TenantID == "" || req.Provider == "" || req.Name == "" {
		return CloudAccount{}, errors.New("tenant_id, provider, name are required")
	}
	// Security: cloud credentials are envelope-encrypted before persistence and plaintext is zeroized.
	raw := []byte(req.CredentialsJSON)
	defer pkgcrypto.Zeroize(raw)
	env, err := pkgcrypto.EncryptEnvelope(s.mek, raw)
	if err != nil {
		return CloudAccount{}, err
	}
	account := CloudAccount{
		ID:                      newID("ca"),
		TenantID:                req.TenantID,
		Provider:                req.Provider,
		Name:                    req.Name,
		DefaultRegion:           req.DefaultRegion,
		Status:                  "active",
		CredentialsWrappedDEK:   env.WrappedDEK,
		CredentialsWrappedDEKIV: env.WrappedDEKIV,
		CredentialsCiphertext:   env.Ciphertext,
		CredentialsDataIV:       env.DataIV,
	}
	if err := s.store.CreateAccount(ctx, account); err != nil {
		return CloudAccount{}, err
	}
	out, err := s.store.GetAccount(ctx, req.TenantID, account.ID)
	if err != nil {
		return CloudAccount{}, err
	}
	_ = s.publishAudit(ctx, "audit.cloud.connector_configured", req.TenantID, map[string]interface{}{
		"account_id": out.ID,
		"provider":   out.Provider,
		"name":       out.Name,
		"action":     "register",
	})
	return out, nil
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

func (s *Service) ImportKeyToCloud(ctx context.Context, req ImportKeyToCloudRequest) (CloudKeyBinding, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.KeyID = strings.TrimSpace(req.KeyID)
	rawProvider := strings.TrimSpace(req.Provider)
	req.Provider = normalizeProvider(rawProvider)
	req.AccountID = strings.TrimSpace(req.AccountID)
	req.VectaRegion = strings.TrimSpace(req.VectaRegion)
	req.CloudRegion = strings.TrimSpace(req.CloudRegion)
	req.MetadataJSON = validJSONOr(req.MetadataJSON, "{}")
	if rawProvider != "" && req.Provider == "" {
		return CloudKeyBinding{}, errors.New("unsupported provider")
	}
	if req.TenantID == "" || req.KeyID == "" {
		return CloudKeyBinding{}, errors.New("tenant_id and key_id are required")
	}

	account, provider, err := s.resolveAccountProvider(ctx, req.TenantID, req.Provider, req.AccountID)
	if err != nil {
		return CloudKeyBinding{}, err
	}
	creds, err := s.decryptAccountCredentials(account)
	if err != nil {
		return CloudKeyBinding{}, err
	}
	region, err := s.resolveRegion(ctx, req.TenantID, provider, account, req.VectaRegion, req.CloudRegion)
	if err != nil {
		return CloudKeyBinding{}, err
	}
	keyMeta, err := s.keycore.GetKey(ctx, req.TenantID, req.KeyID)
	if err != nil {
		return CloudKeyBinding{}, err
	}
	exportData, err := s.keycore.ExportKey(ctx, req.TenantID, req.KeyID)
	if err != nil {
		return CloudKeyBinding{}, err
	}
	meta := map[string]interface{}{}
	_ = json.Unmarshal([]byte(req.MetadataJSON), &meta)
	result, err := provider.ImportKey(ctx, ImportInput{
		TenantID:    req.TenantID,
		KeyID:       req.KeyID,
		Account:     account,
		Region:      region,
		Credentials: creds,
		KeyMeta:     keyMeta,
		Export:      exportData,
		Metadata:    meta,
	})
	if err != nil {
		return CloudKeyBinding{}, err
	}
	metaRaw, _ := json.Marshal(result.Metadata)
	b := CloudKeyBinding{
		ID:           newID("cbk"),
		TenantID:     req.TenantID,
		KeyID:        req.KeyID,
		Provider:     provider.Name(),
		AccountID:    account.ID,
		CloudKeyID:   result.CloudKeyID,
		CloudKeyRef:  result.CloudKeyRef,
		Region:       region,
		SyncStatus:   "synced",
		LastSyncedAt: nowUTC(),
		MetadataJSON: string(metaRaw),
	}
	if err := s.store.CreateBinding(ctx, b); err != nil {
		return CloudKeyBinding{}, err
	}
	out, err := s.store.GetBinding(ctx, req.TenantID, b.ID)
	if err != nil {
		return CloudKeyBinding{}, err
	}
	_ = s.publishAudit(ctx, "audit.cloud.key_imported", req.TenantID, map[string]interface{}{
		"binding_id":    out.ID,
		"key_id":        out.KeyID,
		"provider":      out.Provider,
		"account_id":    out.AccountID,
		"cloud_key_id":  out.CloudKeyID,
		"cloud_key_ref": out.CloudKeyRef,
		"region":        out.Region,
	})
	return out, nil
}

func (s *Service) RotateCloudKey(ctx context.Context, req RotateCloudKeyRequest) (CloudKeyBinding, string, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.BindingID = strings.TrimSpace(req.BindingID)
	req.Reason = strings.TrimSpace(req.Reason)
	if req.TenantID == "" || req.BindingID == "" {
		return CloudKeyBinding{}, "", errors.New("tenant_id and binding_id are required")
	}
	binding, err := s.store.GetBinding(ctx, req.TenantID, req.BindingID)
	if err != nil {
		return CloudKeyBinding{}, "", err
	}
	account, err := s.store.GetAccount(ctx, req.TenantID, binding.AccountID)
	if err != nil {
		return CloudKeyBinding{}, "", err
	}
	creds, err := s.decryptAccountCredentials(account)
	if err != nil {
		return CloudKeyBinding{}, "", err
	}
	provider, err := s.providers.Get(binding.Provider)
	if err != nil {
		return CloudKeyBinding{}, "", err
	}

	_ = s.publishAudit(ctx, "audit.cloud.sync_started", req.TenantID, map[string]interface{}{
		"binding_id": binding.ID,
		"provider":   binding.Provider,
		"reason":     defaultString(req.Reason, "manual"),
		"mode":       "rotate",
	})
	rot, err := s.keycore.RotateKey(ctx, req.TenantID, binding.KeyID, defaultString(req.Reason, "byok-rotate"))
	if err != nil {
		_ = s.publishAudit(ctx, "audit.cloud.sync_failed", req.TenantID, map[string]interface{}{
			"binding_id": binding.ID,
			"provider":   binding.Provider,
			"error":      err.Error(),
			"mode":       "rotate",
		})
		return CloudKeyBinding{}, "", err
	}
	keyMeta, err := s.keycore.GetKey(ctx, req.TenantID, binding.KeyID)
	if err != nil {
		_ = s.publishAudit(ctx, "audit.cloud.sync_failed", req.TenantID, map[string]interface{}{
			"binding_id": binding.ID,
			"provider":   binding.Provider,
			"error":      err.Error(),
			"mode":       "rotate",
		})
		return CloudKeyBinding{}, "", err
	}
	exportData, err := s.keycore.ExportKey(ctx, req.TenantID, binding.KeyID)
	if err != nil {
		_ = s.publishAudit(ctx, "audit.cloud.sync_failed", req.TenantID, map[string]interface{}{
			"binding_id": binding.ID,
			"provider":   binding.Provider,
			"error":      err.Error(),
			"mode":       "rotate",
		})
		return CloudKeyBinding{}, "", err
	}
	result, err := provider.RotateKey(ctx, RotateInput{
		TenantID:    req.TenantID,
		Binding:     binding,
		Account:     account,
		Credentials: creds,
		KeyMeta:     keyMeta,
		Export:      exportData,
		Reason:      req.Reason,
	})
	if err != nil {
		_ = s.publishAudit(ctx, "audit.cloud.sync_failed", req.TenantID, map[string]interface{}{
			"binding_id": binding.ID,
			"provider":   binding.Provider,
			"error":      err.Error(),
			"mode":       "rotate",
		})
		return CloudKeyBinding{}, "", err
	}
	meta := mergeMetadata(binding.MetadataJSON, result.Metadata)
	binding.CloudKeyID = defaultString(result.CloudKeyID, binding.CloudKeyID)
	binding.CloudKeyRef = defaultString(result.CloudKeyRef, binding.CloudKeyRef)
	binding.SyncStatus = "synced"
	binding.LastSyncedAt = nowUTC()
	binding.MetadataJSON = meta
	if err := s.store.UpdateBinding(ctx, binding); err != nil {
		return CloudKeyBinding{}, "", err
	}
	out, err := s.store.GetBinding(ctx, req.TenantID, binding.ID)
	if err != nil {
		return CloudKeyBinding{}, "", err
	}
	_ = s.publishAudit(ctx, "audit.cloud.sync_completed", req.TenantID, map[string]interface{}{
		"binding_id": out.ID,
		"provider":   out.Provider,
		"mode":       "rotate",
		"cloud_key":  out.CloudKeyID,
	})
	_ = s.publishAudit(ctx, "audit.cloud.key_rotated", req.TenantID, map[string]interface{}{
		"binding_id": out.ID,
		"provider":   out.Provider,
		"key_id":     out.KeyID,
		"cloud_key":  out.CloudKeyID,
	})
	versionID, _ := rot["version_id"].(string)
	return out, strings.TrimSpace(versionID), nil
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
		"job_id":     job.ID,
		"provider":   job.Provider,
		"account_id": job.AccountID,
		"mode":       job.Mode,
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
		creds, err := s.decryptAccountCredentials(account)
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
	creds, err := s.decryptAccountCredentials(account)
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
		return nil, err
	}
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
		if strings.EqualFold(a.Status, "active") {
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

func (s *Service) resolveRegion(ctx context.Context, tenantID string, provider CloudProvider, account CloudAccount, vectaRegion string, cloudRegion string) (string, error) {
	if strings.TrimSpace(cloudRegion) != "" {
		return strings.TrimSpace(cloudRegion), nil
	}
	if strings.TrimSpace(vectaRegion) != "" {
		if mapping, err := s.store.GetRegionMapping(ctx, tenantID, provider.Name(), vectaRegion); err == nil && strings.TrimSpace(mapping.CloudRegion) != "" {
			return strings.TrimSpace(mapping.CloudRegion), nil
		}
	}
	if strings.TrimSpace(account.DefaultRegion) != "" {
		return strings.TrimSpace(account.DefaultRegion), nil
	}
	return provider.DefaultRegion(), nil
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
