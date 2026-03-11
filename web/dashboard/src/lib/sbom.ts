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

export type ManualAdvisory = {
  id: string;
  component: string;
  ecosystem?: string;
  introduced_version?: string;
  fixed_version?: string;
  severity: string;
  summary: string;
  reference?: string;
  created_at?: string;
  updated_at?: string;
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
type AdvisoryResponse = { item: ManualAdvisory };
type AdvisoryListResponse = { items: ManualAdvisory[] };
type SummaryResponse = { summary: Record<string, unknown> };
type ExportResponse = { export: ExportArtifact };
type DiffResponse = { diff: BOMDiff };

const SBOM_GENERATE_TIMEOUT_MS = 300_000;
const SBOM_VULNERABILITY_TIMEOUT_MS = 300_000;

function tenantQuery(session: AuthSession): string {
  return `tenant_id=${encodeURIComponent(session.tenantId)}`;
}

export async function generateSBOM(session: AuthSession, trigger = "manual"): Promise<SBOMSnapshot> {
  const out = await serviceRequest<GenerateResponse<SBOMSnapshot>>(session, "sbom", "/sbom/generate", {
    method: "POST",
    body: JSON.stringify({ trigger })
  }, SBOM_GENERATE_TIMEOUT_MS);
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
  const out = await serviceRequest<VulnerabilityResponse>(
    session,
    "sbom",
    "/sbom/vulnerabilities",
    undefined,
    SBOM_VULNERABILITY_TIMEOUT_MS
  );
  return Array.isArray(out?.items) ? out.items : [];
}

export async function listSBOMAdvisories(session: AuthSession): Promise<ManualAdvisory[]> {
  const out = await serviceRequest<AdvisoryListResponse>(session, "sbom", "/sbom/advisories");
  return Array.isArray(out?.items) ? out.items : [];
}

export async function saveSBOMAdvisory(session: AuthSession, advisory: ManualAdvisory): Promise<ManualAdvisory> {
  const out = await serviceRequest<AdvisoryResponse>(session, "sbom", "/sbom/advisories", {
    method: "POST",
    body: JSON.stringify(advisory)
  });
  return out.item;
}

export async function deleteSBOMAdvisory(session: AuthSession, id: string): Promise<void> {
  await serviceRequest(session, "sbom", `/sbom/advisories/${encodeURIComponent(String(id || "").trim())}`, {
    method: "DELETE"
  });
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
  }, SBOM_GENERATE_TIMEOUT_MS);
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
