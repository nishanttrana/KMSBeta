package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

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
