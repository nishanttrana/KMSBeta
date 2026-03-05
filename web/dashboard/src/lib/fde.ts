import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export type FDEKeySlot = {
  slot: number;
  status: string;
  type: string;
};

export type FDEStatus = {
  enabled: boolean;
  algorithm: string;
  luks_version: string;
  key_derivation: string;
  device: string;
  unlock_method: string;
  recovery_shares: number;
  recovery_threshold: number;
  key_slots: FDEKeySlot[];
  volume_size_gb: number;
  used_gb: number;
  integrity_last_check?: string;
  integrity_status?: string;
};

export type FDERecoveryShare = {
  index: number;
  label: string;
  verified: boolean;
  last_verified?: string;
};

export type FDERecoveryShareStatus = {
  total: number;
  threshold: number;
  shares: FDERecoveryShare[];
};

export async function getFDEStatus(session: AuthSession): Promise<FDEStatus> {
  return serviceRequest<FDEStatus>(
    session,
    "governance",
    `/governance/system/fde/status?tenant_id=${encodeURIComponent(session.tenantId)}`
  );
}

export async function runFDEIntegrityCheck(
  session: AuthSession
): Promise<{ passed: boolean; mode: string; checked_at: string; errors: string[] }> {
  return serviceRequest(session, "governance", "/governance/system/fde/integrity-check", {
    method: "POST",
    body: JSON.stringify({ tenant_id: session.tenantId }),
  });
}

export async function rotateFDEVolumeKey(
  session: AuthSession
): Promise<{ status: string; job_id: string; started_at: string; estimated_duration_minutes: number }> {
  return serviceRequest(session, "governance", "/governance/system/fde/rotate-key", {
    method: "POST",
    body: JSON.stringify({ tenant_id: session.tenantId, confirm: true, reason: "admin-rotation" }),
  });
}

export async function testFDERecoveryShares(
  session: AuthSession,
  shares: string[]
): Promise<{ valid: boolean; shares_provided: number; threshold_required: number; tested_at: string }> {
  return serviceRequest(session, "governance", "/governance/system/fde/test-recovery", {
    method: "POST",
    body: JSON.stringify({ tenant_id: session.tenantId, shares }),
  });
}

export async function getFDERecoveryShareStatus(session: AuthSession): Promise<FDERecoveryShareStatus> {
  return serviceRequest<FDERecoveryShareStatus>(
    session,
    "governance",
    `/governance/system/fde/recovery-shares?tenant_id=${encodeURIComponent(session.tenantId)}`
  );
}
