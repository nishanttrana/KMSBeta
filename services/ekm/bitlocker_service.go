package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
)

func (s *Service) RegisterBitLockerClient(ctx context.Context, req RegisterBitLockerClientRequest, tlsClientCN string, jwtSubject string) (BitLockerClient, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.ClientID = strings.TrimSpace(req.ClientID)
	req.Name = strings.TrimSpace(req.Name)
	req.Host = strings.TrimSpace(req.Host)
	req.OSVersion = strings.TrimSpace(req.OSVersion)
	req.MountPoint = strings.TrimSpace(req.MountPoint)
	req.MetadataJSON = validJSONOr(req.MetadataJSON, "{}")
	if req.TenantID == "" {
		return BitLockerClient{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	if req.ClientID == "" {
		req.ClientID = newID("blc")
	}
	if req.Name == "" {
		req.Name = req.ClientID
	}
	if req.Host == "" {
		req.Host = req.Name
	}
	if req.OSVersion == "" {
		req.OSVersion = "windows"
	}
	if req.MountPoint == "" {
		req.MountPoint = "C:"
	}
	client := BitLockerClient{
		ID:                   req.ClientID,
		TenantID:             req.TenantID,
		Name:                 req.Name,
		Host:                 req.Host,
		OSVersion:            req.OSVersion,
		Status:               AgentStatusConnected,
		Health:               "healthy",
		ProtectionStatus:     "unknown",
		EncryptionPercentage: 0,
		MountPoint:           req.MountPoint,
		HeartbeatIntervalSec: defaultInt(req.HeartbeatIntervalSec, DefaultHeartbeatSec),
		LastHeartbeatAt:      time.Now().UTC(),
		JWTSubject:           strings.TrimSpace(jwtSubject),
		TLSClientCN:          strings.TrimSpace(tlsClientCN),
		MetadataJSON:         req.MetadataJSON,
	}
	if err := s.store.UpsertBitLockerClient(ctx, client); err != nil {
		return BitLockerClient{}, err
	}
	out, err := s.store.GetBitLockerClient(ctx, req.TenantID, req.ClientID)
	if err != nil {
		return BitLockerClient{}, err
	}
	_ = s.publishAudit(ctx, "audit.ekm.bitlocker_client_registered", req.TenantID, map[string]interface{}{
		"client_id":   out.ID,
		"name":        out.Name,
		"host":        out.Host,
		"os_version":  out.OSVersion,
		"mount_point": out.MountPoint,
		"jwt_subject": out.JWTSubject,
	})
	return out, nil
}

func (s *Service) ListBitLockerClients(ctx context.Context, tenantID string, limit int) ([]BitLockerClient, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	items, err := s.store.ListBitLockerClients(ctx, tenantID, limit)
	if err != nil {
		return nil, err
	}
	out := make([]BitLockerClient, 0, len(items))
	for _, item := range items {
		refreshed, refreshErr := s.refreshBitLockerConnectivity(ctx, item)
		if refreshErr != nil {
			return nil, refreshErr
		}
		out = append(out, refreshed)
	}
	return out, nil
}

func (s *Service) GetBitLockerClient(ctx context.Context, tenantID string, clientID string) (BitLockerClient, error) {
	tenantID = strings.TrimSpace(tenantID)
	clientID = strings.TrimSpace(clientID)
	if tenantID == "" || clientID == "" {
		return BitLockerClient{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and client id are required")
	}
	item, err := s.store.GetBitLockerClient(ctx, tenantID, clientID)
	if err != nil {
		return BitLockerClient{}, err
	}
	return s.refreshBitLockerConnectivity(ctx, item)
}

func (s *Service) BitLockerHeartbeat(ctx context.Context, clientID string, req BitLockerHeartbeatRequest, tlsClientCN string, jwtSubject string) (BitLockerClient, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	clientID = strings.TrimSpace(clientID)
	if req.TenantID == "" || clientID == "" {
		return BitLockerClient{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and client id are required")
	}
	status := normalizeBitLockerStatus(req.Status)
	health := normalizeBitLockerHealth(req.Health)
	protection := normalizeBitLockerProtection(req.ProtectionStatus)
	encryptionPct := req.EncryptionPercentage
	if encryptionPct < 0 {
		encryptionPct = 0
	}
	if encryptionPct > 100 {
		encryptionPct = 100
	}
	mountPoint := strings.TrimSpace(req.MountPoint)
	if mountPoint == "" {
		mountPoint = "C:"
	}
	meta := parseJSONMap(req.MetadataJSON)
	if strings.TrimSpace(jwtSubject) != "" {
		meta["jwt_subject"] = strings.TrimSpace(jwtSubject)
	}
	if strings.TrimSpace(tlsClientCN) != "" {
		meta["tls_client_cn"] = strings.TrimSpace(tlsClientCN)
	}
	if err := s.store.UpdateBitLockerHeartbeat(
		ctx,
		req.TenantID,
		clientID,
		status,
		health,
		protection,
		encryptionPct,
		mountPoint,
		req.TPMPresent,
		req.TPMReady,
		mustJSON(meta),
		time.Now().UTC(),
	); err != nil {
		return BitLockerClient{}, err
	}
	out, err := s.store.GetBitLockerClient(ctx, req.TenantID, clientID)
	if err != nil {
		return BitLockerClient{}, err
	}
	if strings.TrimSpace(jwtSubject) != "" || strings.TrimSpace(tlsClientCN) != "" {
		if strings.TrimSpace(jwtSubject) != "" {
			out.JWTSubject = strings.TrimSpace(jwtSubject)
		}
		if strings.TrimSpace(tlsClientCN) != "" {
			out.TLSClientCN = strings.TrimSpace(tlsClientCN)
		}
		_ = s.store.UpsertBitLockerClient(ctx, out)
	}
	_ = s.publishAudit(ctx, "audit.ekm.bitlocker_heartbeat", req.TenantID, map[string]interface{}{
		"client_id":              clientID,
		"status":                 status,
		"health":                 health,
		"protection_status":      protection,
		"encryption_percentage":  encryptionPct,
		"mount_point":            mountPoint,
		"tpm_present":            req.TPMPresent,
		"tpm_ready":              req.TPMReady,
		"auth_subject":           strings.TrimSpace(jwtSubject),
		"auth_client_commonname": strings.TrimSpace(tlsClientCN),
	})
	return out, nil
}

func (s *Service) QueueBitLockerOperation(ctx context.Context, clientID string, req BitLockerOperationRequest) (BitLockerJob, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	clientID = strings.TrimSpace(clientID)
	if req.TenantID == "" || clientID == "" {
		return BitLockerJob{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and client id are required")
	}
	op := normalizeBitLockerOperation(req.Operation)
	if op == "" {
		return BitLockerJob{}, newServiceError(http.StatusBadRequest, "bad_request", "unsupported operation")
	}
	client, err := s.store.GetBitLockerClient(ctx, req.TenantID, clientID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			return BitLockerJob{}, newServiceError(http.StatusNotFound, "client_not_found", "bitlocker client is not registered")
		}
		return BitLockerJob{}, err
	}
	paramsJSON := "{}"
	if req.Params != nil {
		paramsJSON = mustJSON(req.Params)
	}
	requestID := strings.TrimSpace(req.RequestID)
	if requestID == "" {
		requestID = newID("blop")
	}
	requestedBy := strings.TrimSpace(req.RequestedBy)
	if requestedBy == "" {
		requestedBy = "dashboard"
	}
	job := BitLockerJob{
		ID:          newID("bljob"),
		TenantID:    req.TenantID,
		ClientID:    client.ID,
		Operation:   op,
		ParamsJSON:  paramsJSON,
		Status:      "pending",
		RequestedBy: requestedBy,
		RequestID:   requestID,
		RequestedAt: time.Now().UTC(),
		ResultJSON:  "{}",
	}
	if err := s.store.CreateBitLockerJob(ctx, job); err != nil {
		return BitLockerJob{}, err
	}
	out, err := s.store.GetBitLockerJob(ctx, req.TenantID, client.ID, job.ID)
	if err != nil {
		return BitLockerJob{}, err
	}
	_ = s.publishAudit(ctx, "audit.ekm.bitlocker_job_queued", req.TenantID, map[string]interface{}{
		"client_id":    client.ID,
		"operation":    out.Operation,
		"job_id":       out.ID,
		"requested_by": out.RequestedBy,
		"request_id":   out.RequestID,
	})
	return out, nil
}

func (s *Service) PollBitLockerJob(ctx context.Context, tenantID string, clientID string) (BitLockerJob, error) {
	tenantID = strings.TrimSpace(tenantID)
	clientID = strings.TrimSpace(clientID)
	if tenantID == "" || clientID == "" {
		return BitLockerJob{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and client id are required")
	}
	if _, err := s.store.GetBitLockerClient(ctx, tenantID, clientID); err != nil {
		if errors.Is(err, errNotFound) {
			return BitLockerJob{}, newServiceError(http.StatusNotFound, "client_not_found", "bitlocker client is not registered")
		}
		return BitLockerJob{}, err
	}
	out, err := s.store.DispatchNextBitLockerJob(ctx, tenantID, clientID, time.Now().UTC())
	if err != nil {
		if errors.Is(err, errNotFound) {
			return BitLockerJob{}, newServiceError(http.StatusNotFound, "no_pending_job", "no pending operation jobs")
		}
		return BitLockerJob{}, err
	}
	_ = s.publishAudit(ctx, "audit.ekm.bitlocker_job_dispatched", tenantID, map[string]interface{}{
		"client_id":  clientID,
		"job_id":     out.ID,
		"operation":  out.Operation,
		"request_id": out.RequestID,
	})
	return out, nil
}

func (s *Service) SubmitBitLockerJobResult(ctx context.Context, clientID string, jobID string, req BitLockerJobResultRequest) (BitLockerJob, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	clientID = strings.TrimSpace(clientID)
	jobID = strings.TrimSpace(jobID)
	if req.TenantID == "" || clientID == "" || jobID == "" {
		return BitLockerJob{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id, client id and job id are required")
	}
	job, err := s.store.GetBitLockerJob(ctx, req.TenantID, clientID, jobID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			return BitLockerJob{}, newServiceError(http.StatusNotFound, "job_not_found", "job does not exist")
		}
		return BitLockerJob{}, err
	}
	status := normalizeBitLockerJobStatus(req.Status)
	if status != "succeeded" && status != "failed" {
		return BitLockerJob{}, newServiceError(http.StatusBadRequest, "bad_request", "status must be succeeded or failed")
	}

	resultJSON := "{}"
	if req.Result != nil {
		resultJSON = mustJSON(req.Result)
	}
	recoveryRef := ""
	if status == "succeeded" {
		recovery := strings.TrimSpace(req.RecoveryKey)
		if recovery == "" && req.Result != nil {
			recovery = mapStringAny(req.Result, "recovery_key", "recovery_password", "recoveryPassword")
		}
		if recovery != "" {
			raw := []byte(recovery)
			env, encErr := pkgcrypto.EncryptEnvelope(s.mek, raw)
			pkgcrypto.Zeroize(raw)
			if encErr != nil {
				return BitLockerJob{}, newServiceError(http.StatusInternalServerError, "encryption_failed", encErr.Error())
			}
			rec := BitLockerRecoveryKeyRecord{
				ID:               newID("blrec"),
				TenantID:         req.TenantID,
				ClientID:         clientID,
				JobID:            jobID,
				VolumeMountPoint: defaultString(strings.TrimSpace(req.VolumeMountPoint), defaultString(mapStringAny(req.Result, "volume_mount_point", "mount_point"), "C:")),
				ProtectorID:      defaultString(strings.TrimSpace(req.ProtectorID), mapStringAny(req.Result, "protector_id", "key_protector_id")),
				KeyFingerprint:   fingerprintBitLockerKey(recovery),
				KeyMasked:        maskBitLockerKey(recovery),
				WrappedDEK:       base64.StdEncoding.EncodeToString(env.WrappedDEK),
				WrappedDEKIV:     base64.StdEncoding.EncodeToString(env.WrappedDEKIV),
				Ciphertext:       base64.StdEncoding.EncodeToString(env.Ciphertext),
				DataIV:           base64.StdEncoding.EncodeToString(env.DataIV),
				Source:           "agent",
				CreatedAt:        time.Now().UTC(),
			}
			if saveErr := s.store.SaveBitLockerRecoveryKey(ctx, rec); saveErr != nil {
				return BitLockerJob{}, saveErr
			}
			recoveryRef = rec.ID
		}
	}

	if err := s.store.CompleteBitLockerJob(
		ctx,
		req.TenantID,
		clientID,
		jobID,
		status,
		resultJSON,
		strings.TrimSpace(req.ErrorMessage),
		recoveryRef,
		time.Now().UTC(),
	); err != nil {
		return BitLockerJob{}, err
	}

	protectionStatus := defaultString(strings.TrimSpace(req.ProtectionStatus), normalizeBitLockerProtection(mapStringAny(req.Result, "protection_status", "status")))
	encryptionPct := mapFloatAny(req.Result, "encryption_percentage", "encryption_pct")
	health := "healthy"
	if status == "failed" {
		health = "degraded"
	}
	meta := map[string]interface{}{
		"last_job_id":          jobID,
		"last_job_operation":   job.Operation,
		"last_job_status":      status,
		"last_job_completed_at": time.Now().UTC().Format(time.RFC3339Nano),
	}
	if req.Result != nil {
		meta["last_job_result"] = req.Result
	}
	if req.ErrorMessage != "" {
		meta["last_job_error"] = req.ErrorMessage
	}
	_ = s.store.UpdateBitLockerHeartbeat(
		ctx,
		req.TenantID,
		clientID,
		AgentStatusConnected,
		health,
		defaultString(protectionStatus, "unknown"),
		encryptionPct,
		defaultString(strings.TrimSpace(req.VolumeMountPoint), "C:"),
		false,
		false,
		mustJSON(meta),
		time.Now().UTC(),
	)

	out, err := s.store.GetBitLockerJob(ctx, req.TenantID, clientID, jobID)
	if err != nil {
		return BitLockerJob{}, err
	}
	_ = s.publishAudit(ctx, "audit.ekm.bitlocker_job_completed", req.TenantID, map[string]interface{}{
		"client_id":      clientID,
		"job_id":         jobID,
		"operation":      job.Operation,
		"status":         status,
		"error_message":  strings.TrimSpace(req.ErrorMessage),
		"recovery_saved": recoveryRef != "",
		"recovery_ref":   recoveryRef,
	})
	return out, nil
}

func (s *Service) ListBitLockerJobs(ctx context.Context, tenantID string, clientID string, limit int) ([]BitLockerJob, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	return s.store.ListBitLockerJobs(ctx, tenantID, strings.TrimSpace(clientID), limit)
}

func (s *Service) ListBitLockerRecoveryKeys(ctx context.Context, tenantID string, clientID string, limit int) ([]BitLockerRecoveryKeyView, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	items, err := s.store.ListBitLockerRecoveryKeys(ctx, tenantID, strings.TrimSpace(clientID), limit)
	if err != nil {
		return nil, err
	}
	out := make([]BitLockerRecoveryKeyView, 0, len(items))
	for _, item := range items {
		out = append(out, BitLockerRecoveryKeyView{
			ID:               item.ID,
			ClientID:         item.ClientID,
			VolumeMountPoint: item.VolumeMountPoint,
			ProtectorID:      item.ProtectorID,
			KeyFingerprint:   item.KeyFingerprint,
			KeyMasked:        item.KeyMasked,
			Source:           item.Source,
			CreatedAt:        item.CreatedAt,
		})
	}
	return out, nil
}

func (s *Service) BuildBitLockerDeployPackage(ctx context.Context, tenantID string, clientID string, targetOS string) (DeployPackage, error) {
	tenantID = strings.TrimSpace(tenantID)
	clientID = strings.TrimSpace(clientID)
	targetOS = normalizeTargetOS(targetOS)
	if tenantID == "" || clientID == "" || targetOS == "" {
		return DeployPackage{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id, client id and target os are required")
	}
	client, err := s.store.GetBitLockerClient(ctx, tenantID, clientID)
	if err != nil {
		return DeployPackage{}, err
	}
	if targetOS != "windows" {
		return DeployPackage{}, newServiceError(http.StatusBadRequest, "bad_request", "bitlocker agent currently supports windows target only")
	}
	cfg := map[string]interface{}{
		"tenant_id":                tenantID,
		"agent_id":                 client.ID,
		"agent_name":               client.Name,
		"agent_mode":               "bitlocker",
		"role":                     "bitlocker-agent",
		"db_engine":                "mssql",
		"host":                     client.Host,
		"version":                  defaultString(client.OSVersion, "windows"),
		"api_base_url":             "https://kms.example.com/svc/ekm",
		"register_path":            "/ekm/bitlocker/clients/register",
		"heartbeat_path":           "/ekm/bitlocker/clients/{agent_id}/heartbeat",
		"jobs_next_path":           "/ekm/bitlocker/clients/{agent_id}/jobs/next",
		"job_result_path":          "/ekm/bitlocker/clients/{agent_id}/jobs/{job_id}/result",
		"auth_token":               "",
		"tls_skip_verify":          false,
		"heartbeat_interval_sec":   defaultInt(client.HeartbeatIntervalSec, DefaultHeartbeatSec),
		"rotation_cycle_days":      90,
		"auto_provision_tde":       false,
		"bitlocker_mount_point":    defaultString(client.MountPoint, "C:"),
		"bitlocker_protector_type": "recovery_password",
	}
	cfgRaw, _ := json.MarshalIndent(cfg, "", "  ")
	install := `$ErrorActionPreference = "Stop"
param([string]$InstallDir = "C:\ProgramData\Vecta\EKMAgent")
if (-not (Test-Path -Path ".\ekm-agent.exe")) { throw "ekm-agent.exe not found in current directory." }
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Copy-Item ".\ekm-agent.exe" (Join-Path $InstallDir "ekm-agent.exe") -Force
Copy-Item ".\agent-config.json" (Join-Path $InstallDir "agent-config.json") -Force
$svcExe = Join-Path $InstallDir "ekm-agent.exe"
$cfgPath = Join-Path $InstallDir "agent-config.json"
if (Get-Service -Name "VectaBitLockerAgent" -ErrorAction SilentlyContinue) {
  & $svcExe -service stop -config $cfgPath | Out-Null
  & $svcExe -service uninstall -config $cfgPath | Out-Null
}
& $svcExe -service install -config $cfgPath
& $svcExe -service start -config $cfgPath
Write-Host "Vecta BitLocker Agent installed and started."
`
	files := []DeployPackageFile{
		{Path: "agent-config.json", Content: string(cfgRaw), Mode: "0600"},
		{Path: "install-bitlocker-agent.ps1", Content: install, Mode: "0644"},
	}
	pkg := DeployPackage{
		AgentID:            client.ID,
		Name:               client.Name,
		DBEngine:           "bitlocker",
		TargetOS:           "windows",
		CreatedAt:          time.Now().UTC(),
		PKCS11Provider:     "none",
		RegisterPath:       "/ekm/bitlocker/clients/register",
		HeartbeatPath:      "/ekm/bitlocker/clients/" + client.ID + "/heartbeat",
		RotatePath:         "/ekm/bitlocker/clients/" + client.ID + "/operations",
		SupportedDatabases: []string{"bitlocker"},
		RecommendedProfiles: []string{
			"windows-bitlocker-agent",
		},
		Files: files,
	}
	_ = s.publishAudit(ctx, "audit.ekm.bitlocker_deploy_package_generated", tenantID, map[string]interface{}{
		"client_id": client.ID,
		"target_os": "windows",
	})
	return pkg, nil
}

func (s *Service) refreshBitLockerConnectivity(ctx context.Context, client BitLockerClient) (BitLockerClient, error) {
	if client.LastHeartbeatAt.IsZero() {
		return client, nil
	}
	base := defaultInt(client.HeartbeatIntervalSec, DefaultHeartbeatSec)
	timeout := time.Duration(base*3) * time.Second
	if timeout < 45*time.Second {
		timeout = 45 * time.Second
	}
	if timeout > 10*time.Minute {
		timeout = 10 * time.Minute
	}
	if time.Since(client.LastHeartbeatAt.UTC()) > timeout && normalizeBitLockerStatus(client.Status) != AgentStatusDisconnected {
		if err := s.store.MarkBitLockerClientDisconnected(ctx, client.TenantID, client.ID, time.Now().UTC()); err != nil {
			return BitLockerClient{}, err
		}
		client.Status = AgentStatusDisconnected
		client.Health = "down"
		_ = s.publishAudit(ctx, "audit.ekm.bitlocker_client_disconnected", client.TenantID, map[string]interface{}{
			"client_id":          client.ID,
			"last_heartbeat_at":  client.LastHeartbeatAt.UTC().Format(time.RFC3339Nano),
			"disconnect_timeout": int(timeout.Seconds()),
		})
	}
	return client, nil
}

func mustJSON(v interface{}) string {
	raw, err := json.Marshal(v)
	if err != nil || len(raw) == 0 {
		return "{}"
	}
	return string(raw)
}
