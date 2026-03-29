import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export type KeyRiskItem = {
  id: string;
  name: string;
  algorithm: string;
  strength_bits: number;
  status: string;
  exportable: boolean;
  risk_score: number;
  risk_level: string;
  risk_factors: string[];
  ops_count: number;
  last_rotated?: string;
  expires_at?: string;
  created_at: string;
  recommendation: string;
};

export type DataRiskSummary = {
  tenant_id: string;
  overall_score: number;
  overall_level: string;
  critical_count: number;
  high_count: number;
  unrotated_count: number;
  exportable_count: number;
  weak_algo_count: number;
  unused_count: number;
  expiring_count: number;
  risk_by_algorithm: Record<string, number>;
  computed_at: string;
};

export type RemediationItem = {
  priority: number;
  category: string;
  title: string;
  description: string;
  affected_count: number;
  action: string;
  key_ids: string[];
};

function tenantQuery(session: AuthSession): string {
  return `tenant_id=${encodeURIComponent(session.tenantId)}`;
}

export async function getKeyRiskRanking(
  session: AuthSession,
  limit = 50
): Promise<KeyRiskItem[]> {
  const res = await serviceRequest<{ items?: KeyRiskItem[] }>(
    session, "compliance",
    `/compliance/risk/keys?${tenantQuery(session)}&limit=${limit}`
  );
  return Array.isArray(res?.items) ? res.items : [];
}

export async function getDataRiskSummary(session: AuthSession): Promise<DataRiskSummary> {
  const res = await serviceRequest<{ summary?: DataRiskSummary }>(
    session, "compliance", `/compliance/risk/summary?${tenantQuery(session)}`
  );
  return res?.summary ?? {
    tenant_id: session.tenantId,
    overall_score: 0,
    overall_level: "low",
    critical_count: 0,
    high_count: 0,
    unrotated_count: 0,
    exportable_count: 0,
    weak_algo_count: 0,
    unused_count: 0,
    expiring_count: 0,
    risk_by_algorithm: {},
    computed_at: new Date().toISOString(),
  };
}

export async function getRiskRemediation(session: AuthSession): Promise<RemediationItem[]> {
  const res = await serviceRequest<{ items?: RemediationItem[] }>(
    session, "compliance", `/compliance/risk/remediation?${tenantQuery(session)}`
  );
  return Array.isArray(res?.items) ? res.items : [];
}
