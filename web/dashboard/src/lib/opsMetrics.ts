import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export type OpType = "encrypt" | "decrypt" | "sign" | "verify" | "wrap" | "unwrap" | "derive" | "generate";

export interface OpsTimeSeries {
  timestamp: string;
  encrypt: number;
  decrypt: number;
  sign: number;
  verify: number;
  wrap: number;
  unwrap: number;
  generate: number;
  total: number;
}

export interface LatencyPercentiles {
  op_type: OpType;
  p50_ms: number;
  p95_ms: number;
  p99_ms: number;
  p999_ms: number;
  max_ms: number;
  sample_count: number;
}

export interface ServiceOpsStats {
  service: string;
  total_ops: number;
  error_count: number;
  error_rate: number;
  avg_latency_ms: number;
  ops_by_type: Partial<Record<OpType, number>>;
}

export interface OpsOverview {
  total_ops_24h: number;
  total_ops_7d: number;
  total_ops_30d: number;
  ops_per_second: number;
  error_rate_24h: number;
  top_algorithm: string;
  top_service: string;
  peak_hour: string;
}

export interface ErrorBreakdown {
  error_code: string;
  description: string;
  count: number;
  last_seen_at: string;
  service: string;
}

export async function getOverview(session: AuthSession): Promise<OpsOverview> {
  const res = await serviceRequest<any>(session, "audit", "/ops-metrics/overview");
  return res.overview ?? res.data ?? res;
}

export async function getTimeSeries(session: AuthSession, window: "1h" | "24h" | "7d" | "30d"): Promise<OpsTimeSeries[]> {
  const res = await serviceRequest<any>(session, "audit", `/ops-metrics/timeseries?window=${window}`);
  return res.items ?? [];
}

export async function getLatencyPercentiles(session: AuthSession): Promise<LatencyPercentiles[]> {
  const res = await serviceRequest<any>(session, "audit", "/ops-metrics/latency");
  return res.items ?? [];
}

export async function getServiceStats(session: AuthSession): Promise<ServiceOpsStats[]> {
  const res = await serviceRequest<any>(session, "audit", "/ops-metrics/by-service");
  return res.items ?? [];
}

export async function getErrorBreakdown(session: AuthSession): Promise<ErrorBreakdown[]> {
  const res = await serviceRequest<any>(session, "audit", "/ops-metrics/errors");
  return res.items ?? [];
}
