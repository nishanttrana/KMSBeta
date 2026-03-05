package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

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
		return nil
	}

	// Export the key (KMS wraps it; we unwrap locally)
	exportURL := joinURL(r.cfg.APIBaseURL, fmt.Sprintf("/ekm/tde/keys/%s/export", keyID))
	var exportResp struct {
		Material  string `json:"material"`  // base64 raw key material
		Algorithm string `json:"algorithm"`
		Version   int    `json:"version"`
	}
	if err := r.postJSON(ctx, exportURL, map[string]interface{}{
		"tenant_id": r.cfg.TenantID,
		"agent_id":  r.cfg.AgentID,
		"purpose":   "local_tde_cache",
	}, &exportResp); err != nil {
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
func (r *AgentRunner) PollAndExecuteJob(ctx context.Context) {
	nextURL := joinURL(r.cfg.APIBaseURL, replaceAgentIDPath(r.cfg.JobsNextPath, r.cfg.AgentID))
	var job struct {
		JobID     string `json:"job_id"`
		Operation string `json:"operation"`
		Params    struct {
			MountPoint    string `json:"mount_point"`
			ProtectorType string `json:"protector_type"`
		} `json:"params"`
	}
	if err := r.getJSON(ctx, nextURL, &job); err != nil {
		// No job or network error — expected, not logged as error
		return
	}
	if strings.TrimSpace(job.JobID) == "" {
		return
	}

	r.logger.Printf("bitlocker job received: id=%s op=%s mount=%s", job.JobID, job.Operation, job.Params.MountPoint)

	mount := firstNonEmpty(job.Params.MountPoint, r.cfg.BitLockerMountPoint)
	protector := firstNonEmpty(job.Params.ProtectorType, r.cfg.BitLockerProtector)

	var result string
	var execErr error

	switch strings.ToLower(strings.TrimSpace(job.Operation)) {
	case "status":
		status, err := GetBitLockerStatus(mount)
		execErr = err
		result = mustJSON(status)
	case "enable":
		result, execErr = EnableBitLocker(mount, protector)
	case "disable":
		execErr = DisableBitLocker(mount)
		result = "disabled"
	case "suspend":
		execErr = SuspendBitLocker(mount)
		result = "suspended"
	case "resume":
		execErr = ResumeBitLocker(mount)
		result = "resumed"
	case "rotate_recovery":
		result, execErr = RotateRecoveryPassword(mount)
	case "tpm_status":
		present, ready, err := GetTPMStatus()
		execErr = err
		result = mustJSON(map[string]interface{}{"present": present, "ready": ready})
	default:
		result = "unknown_operation"
		execErr = fmt.Errorf("unsupported operation: %s", job.Operation)
	}

	status := "completed"
	errMsg := ""
	if execErr != nil {
		status = "failed"
		errMsg = execErr.Error()
		r.logger.Printf("bitlocker job %s failed: %v", job.JobID, execErr)
	}

	// Report result
	resultPath := strings.ReplaceAll(r.cfg.JobResultPath, "{agent_id}", r.cfg.AgentID)
	resultPath = strings.ReplaceAll(resultPath, "{job_id}", job.JobID)
	resultURL := joinURL(r.cfg.APIBaseURL, resultPath)
	_ = r.postJSON(ctx, resultURL, map[string]interface{}{
		"job_id": job.JobID,
		"status": status,
		"result": result,
		"error":  errMsg,
	}, nil)
}
