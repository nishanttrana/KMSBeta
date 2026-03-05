import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export type BOMComponent = {
  name: string;
  version: string;
  type: string;
  ecosystem?: string;
  supplier?: string;
};

export type SBOMSnapshot = {
  id: string;
  source_hash?: string;
  created_at?: string;
  summary?: Record<string, unknown>;
  document: {
    format: string;
    spec_version: string;
    generated_at?: string;
    appliance?: string;
    components: BOMComponent[];
  };
};

export type CryptoAsset = {
  id: string;
  source: string;
  asset_type: string;
  name: string;
  algorithm: string;
  strength_bits: number;
  status: string;
  pqc_ready?: boolean;
  deprecated?: boolean;
};

export type CBOMSnapshot = {
  id: string;
  tenant_id: string;
  source_hash?: string;
  created_at?: string;
  summary?: Record<string, unknown>;
  document: {
    format: string;
    spec_version: string;
    tenant_id: string;
    generated_at?: string;
    assets: CryptoAsset[];
    algorithm_distribution: Record<string, number>;
    strength_histogram: Record<string, number>;
    deprecated_count: number;
    pqc_ready_count: number;
    total_asset_count: number;
    pqc_readiness_percent: number;
    source_count?: Record<string, number>;
  };
};

export type VulnerabilityMatch = {
  id: string;
  source: string;
  severity: string;
  component: string;
  installed_version: string;
  fixed_version: string;
  summary: string;
  reference: string;
};

export type BOMDiff = {
  from_id: string;
  to_id: string;
  added: Array<Record<string, unknown>>;
  removed: Array<Record<string, unknown>>;
  changed: Array<Record<string, unknown>>;
  metrics: Record<string, unknown>;
  compared_at?: string;
};

export type ExportArtifact = {
  format: string;
  content_type: string;
  encoding: string;
  content: string;
};

type SnapshotResponse<T> = { item: T };
type GenerateResponse<T> = { snapshot: T };
type HistoryResponse<T> = { items: T[] };
type VulnerabilityResponse = { items: VulnerabilityMatch[] };
type SummaryResponse = { summary: Record<string, unknown> };
type ExportResponse = { export: ExportArtifact };
type DiffResponse = { diff: BOMDiff };

function tenantQuery(session: AuthSession): string {
  return `tenant_id=${encodeURIComponent(session.tenantId)}`;
}

export async function generateSBOM(session: AuthSession, trigger = "manual"): Promise<SBOMSnapshot> {
  const out = await serviceRequest<GenerateResponse<SBOMSnapshot>>(session, "sbom", "/sbom/generate", {
    method: "POST",
    body: JSON.stringify({ trigger })
  });
  return out.snapshot;
}

export async function getLatestSBOM(session: AuthSession): Promise<SBOMSnapshot> {
  const out = await serviceRequest<SnapshotResponse<SBOMSnapshot>>(session, "sbom", "/sbom/latest");
  return out.item;
}

export async function listSBOMHistory(session: AuthSession, limit = 20): Promise<SBOMSnapshot[]> {
  const out = await serviceRequest<HistoryResponse<SBOMSnapshot>>(
    session,
    "sbom",
    `/sbom/history?limit=${Math.max(1, Math.trunc(Number(limit || 20)))}`
  );
  return Array.isArray(out?.items) ? out.items : [];
}

export async function listSBOMVulnerabilities(session: AuthSession): Promise<VulnerabilityMatch[]> {
  const out = await serviceRequest<VulnerabilityResponse>(session, "sbom", "/sbom/vulnerabilities");
  return Array.isArray(out?.items) ? out.items : [];
}

export async function exportSBOM(
  session: AuthSession,
  id: string,
  format: "cyclonedx" | "spdx" | "pdf",
  encoding = "json"
): Promise<ExportArtifact> {
  const out = await serviceRequest<ExportResponse>(
    session,
    "sbom",
    `/sbom/${encodeURIComponent(String(id || "").trim())}/export?format=${encodeURIComponent(format)}&encoding=${encodeURIComponent(encoding)}`
  );
  return out.export;
}

export async function generateCBOM(session: AuthSession, trigger = "manual"): Promise<CBOMSnapshot> {
  const out = await serviceRequest<GenerateResponse<CBOMSnapshot>>(session, "sbom", "/cbom/generate", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      trigger
    })
  });
  return out.snapshot;
}

export async function getLatestCBOM(session: AuthSession): Promise<CBOMSnapshot> {
  const out = await serviceRequest<SnapshotResponse<CBOMSnapshot>>(session, "sbom", `/cbom/latest?${tenantQuery(session)}`);
  return out.item;
}

export async function listCBOMHistory(session: AuthSession, limit = 20): Promise<CBOMSnapshot[]> {
  const out = await serviceRequest<HistoryResponse<CBOMSnapshot>>(
    session,
    "sbom",
    `/cbom/history?${tenantQuery(session)}&limit=${Math.max(1, Math.trunc(Number(limit || 20)))}`
  );
  return Array.isArray(out?.items) ? out.items : [];
}

export async function getCBOMSummary(session: AuthSession): Promise<Record<string, unknown>> {
  const out = await serviceRequest<SummaryResponse>(session, "sbom", `/cbom/summary?${tenantQuery(session)}`);
  return out?.summary || {};
}

export async function exportCBOM(
  session: AuthSession,
  id: string,
  format: "cyclonedx" | "pdf" = "cyclonedx"
): Promise<ExportArtifact> {
  const out = await serviceRequest<ExportResponse>(
    session,
    "sbom",
    `/cbom/${encodeURIComponent(String(id || "").trim())}/export?${tenantQuery(session)}&format=${encodeURIComponent(format)}`
  );
  return out.export;
}

export async function diffCBOM(session: AuthSession, fromID: string, toID: string): Promise<BOMDiff> {
  const out = await serviceRequest<DiffResponse>(
    session,
    "sbom",
    `/cbom/diff?${tenantQuery(session)}&from=${encodeURIComponent(String(fromID || "").trim())}&to=${encodeURIComponent(String(toID || "").trim())}`
  );
  return out.diff;
}

export type PQCReadiness = {
  total_assets: number;
  pqc_ready_count: number;
  pqc_readiness_percent: number;
  deprecated_count: number;
  algorithm_distribution: Record<string, number>;
  strength_histogram: Record<string, number>;
};

type PQCReadinessResponse = { pqc_readiness: PQCReadiness };

export async function diffSBOM(session: AuthSession, fromID: string, toID: string): Promise<BOMDiff> {
  const out = await serviceRequest<DiffResponse>(
    session,
    "sbom",
    `/sbom/diff?from=${encodeURIComponent(String(fromID || "").trim())}&to=${encodeURIComponent(String(toID || "").trim())}`
  );
  return out.diff;
}

export async function getCBOMPQCReadiness(session: AuthSession): Promise<PQCReadiness> {
  const out = await serviceRequest<PQCReadinessResponse>(session, "sbom", `/cbom/pqc-readiness?${tenantQuery(session)}`);
  return out.pqc_readiness;
}

export async function getSBOMByID(session: AuthSession, id: string): Promise<SBOMSnapshot> {
  const out = await serviceRequest<SnapshotResponse<SBOMSnapshot>>(
    session,
    "sbom",
    `/sbom/${encodeURIComponent(String(id || "").trim())}`
  );
  return out.item;
}

export async function getCBOMByID(session: AuthSession, id: string): Promise<CBOMSnapshot> {
  const out = await serviceRequest<SnapshotResponse<CBOMSnapshot>>(
    session,
    "sbom",
    `/cbom/${encodeURIComponent(String(id || "").trim())}?${tenantQuery(session)}`
  );
  return out.item;
}
