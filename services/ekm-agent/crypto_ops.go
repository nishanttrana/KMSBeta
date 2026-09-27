package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	pkgaudit "vecta-kms/pkg/audit"
	"vecta-kms/pkg/keycache"
)

// TryExportKey attempts to fetch key material from KMS and cache it locally.
// If the key is not exportable, it logs and returns — all crypto will be remote.
func (r *AgentRunner) TryExportKey(ctx context.Context, keyID string) error {
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return fmt.Errorf("empty key ID")
	}

	// Check if key is exportable via metadata
	metaURL := joinURL(r.cfg.APIBaseURL, fmt.Sprintf("/ekm/tde/keys/%s", keyID))
	var meta struct {
		ExportAllowed bool   `json:"export_allowed"`
		Algorithm     string `json:"algorithm"`
		Version       int    `json:"version"`
	}
	if err := r.getJSON(ctx, metaURL, &meta); err != nil {
		return fmt.Errorf("fetch key metadata: %w", err)
	}
	if !meta.ExportAllowed {
		r.logger.Printf("key %s is not exportable — crypto operations will proxy to KMS", keyID)
		r.emitAudit(ctx, "key_export_denied", pkgaudit.Event{
			TargetType: "key", TargetID: keyID,
			Details: map[string]interface{}{"reason": "export_not_allowed"},
		})
		return nil
	}

	// Export the key (KMS wraps it; we unwrap locally)
	exportURL := joinURL(r.cfg.APIBaseURL, fmt.Sprintf("/ekm/tde/keys/%s/export", keyID))
	var exportResp struct {
		Material  string `json:"material"` // base64 raw key material
		Algorithm string `json:"algorithm"`
		Version   int    `json:"version"`
	}
	if err := r.postJSON(ctx, exportURL, map[string]interface{}{
		"tenant_id": r.cfg.TenantID,
		"agent_id":  r.cfg.AgentID,
		"purpose":   "local_tde_cache",
	}, &exportResp); err != nil {
		r.emitAudit(ctx, "key_exported", pkgaudit.Event{
			TargetType: "key", TargetID: keyID,
			Result: "failure", ErrorMessage: err.Error(),
		})
		return fmt.Errorf("export key: %w", err)
	}

	material, err := base64.StdEncoding.DecodeString(exportResp.Material)
	if err != nil {
		return fmt.Errorf("decode key material: %w", err)
	}

	r.keyCache.Put(keyID, exportResp.Version, exportResp.Algorithm, material)
	// Zeroize the decoded copy immediately
	for i := range material {
		material[i] = 0
	}

	r.logger.Printf("key %s (v%d, %s) exported and cached locally", keyID, exportResp.Version, exportResp.Algorithm)
	r.emitAudit(ctx, "key_exported", pkgaudit.Event{
		TargetType: "key", TargetID: keyID, RiskScore: 40,
		Details: map[string]interface{}{"version": exportResp.Version, "algorithm": exportResp.Algorithm, "purpose": "local_tde_cache"},
	})
	return nil
}

// Encrypt encrypts plaintext — uses local cache if available, otherwise proxies to KMS.
func (r *AgentRunner) Encrypt(ctx context.Context, keyID string, plaintext []byte) (ciphertext, iv []byte, err error) {
	// Try local cache first
	if entry, ok := r.keyCache.Get(keyID); ok {
		ct, nonce, err := keycache.EncryptAESGCM(entry, plaintext)
		if err == nil {
			r.logger.Printf("encrypt: local cache hit for key %s", keyID)
			return ct, nonce, nil
		}
		r.logger.Printf("encrypt: local cache error, falling back to KMS: %v", err)
	}

	// Remote KMS wrap
	wrapURL := joinURL(r.cfg.APIBaseURL, fmt.Sprintf("/ekm/tde/keys/%s/wrap", keyID))
	var resp struct {
		Ciphertext string `json:"ciphertext"`
		IV         string `json:"iv"`
	}
	payload := map[string]interface{}{
		"tenant_id": r.cfg.TenantID,
		"plaintext": base64.StdEncoding.EncodeToString(plaintext),
	}
	if err := r.postJSON(ctx, wrapURL, payload, &resp); err != nil {
		return nil, nil, fmt.Errorf("kms wrap: %w", err)
	}
	ct, _ := base64.StdEncoding.DecodeString(resp.Ciphertext)
	nonce, _ := base64.StdEncoding.DecodeString(resp.IV)
	return ct, nonce, nil
}

// Decrypt decrypts ciphertext — uses local cache if available, otherwise proxies to KMS.
func (r *AgentRunner) Decrypt(ctx context.Context, keyID string, ciphertext, iv []byte) ([]byte, error) {
	// Try local cache first
	if entry, ok := r.keyCache.Get(keyID); ok {
		pt, err := keycache.DecryptAESGCM(entry, ciphertext, iv)
		if err == nil {
			r.logger.Printf("decrypt: local cache hit for key %s", keyID)
			return pt, nil
		}
		r.logger.Printf("decrypt: local cache error, falling back to KMS: %v", err)
	}

	// Remote KMS unwrap
	unwrapURL := joinURL(r.cfg.APIBaseURL, fmt.Sprintf("/ekm/tde/keys/%s/unwrap", keyID))
	var resp struct {
		Plaintext string `json:"plaintext"`
	}
	payload := map[string]interface{}{
		"tenant_id":  r.cfg.TenantID,
		"ciphertext": base64.StdEncoding.EncodeToString(ciphertext),
		"iv":         base64.StdEncoding.EncodeToString(iv),
	}
	if err := r.postJSON(ctx, unwrapURL, payload, &resp); err != nil {
		return nil, fmt.Errorf("kms unwrap: %w", err)
	}
	pt, _ := base64.StdEncoding.DecodeString(resp.Plaintext)
	return pt, nil
}

// PollAndExecuteJob polls for the next BitLocker job and executes it.
// bitLockerJob is what POST .../jobs/next returns under "job".
type bitLockerJob struct {
	ID         string `json:"id"`
	Operation  string `json:"operation"`
	ParamsJSON string `json:"params_json"`
}

// PollAndExecuteJob claims the next queued BitLocker operation, runs it, and
// reports the result in the shape the EKM service accepts
// (BitLockerJobResultRequest): status succeeded|failed, a structured result,
// and a rotated recovery password as recovery_key so the service escrows it.
func (r *AgentRunner) PollAndExecuteJob(ctx context.Context) {
	nextURL := joinURL(r.cfg.APIBaseURL, replaceAgentIDPath(r.cfg.JobsNextPath, r.cfg.AgentID))
	var next struct {
		Job bitLockerJob `json:"job"`
	}
	// 404 (no pending job) and network errors both mean nothing to run now.
	if err := r.postJSON(ctx, nextURL, map[string]string{"tenant_id": r.cfg.TenantID}, &next); err != nil {
		return
	}
	job := next.Job
	if strings.TrimSpace(job.ID) == "" {
		return
	}
	var params struct {
		MountPoint    string `json:"mount_point"`
		ProtectorType string `json:"protector_type"`
	}
	if strings.TrimSpace(job.ParamsJSON) != "" {
		_ = json.Unmarshal([]byte(job.ParamsJSON), &params)
	}
	mount := firstNonEmpty(params.MountPoint, r.cfg.BitLockerMountPoint)
	protector := firstNonEmpty(params.ProtectorType, r.cfg.BitLockerProtector)
	r.logger.Printf("bitlocker job received: id=%s op=%s mount=%s", job.ID, job.Operation, mount)

	result := map[string]interface{}{"operation": job.Operation, "mount_point": mount}
	protection, recoveryKey := "", ""
	var execErr error
	switch strings.ToLower(strings.TrimSpace(job.Operation)) {
	case "status":
		var st BitLockerStatus
		if st, execErr = GetBitLockerStatus(mount); execErr == nil {
			result["status"] = st
			protection = st.ProtectionStatus
		}
	case "enable":
		var out string
		if out, execErr = EnableBitLocker(mount, protector); execErr == nil {
			result["output"] = out
		}
	case "disable":
		execErr = DisableBitLocker(mount)
	case "suspend":
		execErr = SuspendBitLocker(mount)
	case "resume":
		execErr = ResumeBitLocker(mount)
	case "rotate_recovery":
		recoveryKey, execErr = RotateRecoveryPassword(mount)
	case "tpm_status":
		present, ready, err := GetTPMStatus()
		execErr = err
		result["tpm_present"], result["tpm_ready"] = present, ready
	default:
		execErr = fmt.Errorf("unsupported operation: %s", job.Operation)
	}

	body := map[string]interface{}{
		"tenant_id":          r.cfg.TenantID,
		"status":             "succeeded",
		"result":             result,
		"protection_status":  protection,
		"volume_mount_point": mount,
	}
	if execErr != nil {
		body["status"] = "failed"
		body["error_message"] = execErr.Error()
		r.logger.Printf("bitlocker job %s failed: %v", job.ID, execErr)
	} else if recoveryKey != "" {
		body["recovery_key"] = recoveryKey
	}
	resultPath := strings.ReplaceAll(r.cfg.JobResultPath, "{agent_id}", r.cfg.AgentID)
	resultPath = strings.ReplaceAll(resultPath, "{job_id}", job.ID)
	if err := r.postJSON(ctx, joinURL(r.cfg.APIBaseURL, resultPath), body, nil); err != nil {
		r.logger.Printf("bitlocker job %s result not accepted: %v", job.ID, err)
	}
}
