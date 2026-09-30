import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

// Operations metrics are built by the audit service from every audit event
// marked as a metered cryptographic operation (pkg/audit.MeteredOp):
// keycore key operations, dataprotect, certificate signing, and
// kernel routes declared Metered.

export type OpsWindow = "1h" | "24h" | "7d" | "30d";

export interface OpsOverview {
  window: string;
  total_ops: number;
  // Values processed: a batch call (tokenize, detokenize) is one op.
  total_values: number;
  total_errors: number;
  error_rate: number;
  avg_latency_ms: number;
  // standalone: one node; cluster: this is the primary and counts every
  // node; node: this is a member and counts only its own operations.
  scope: "standalone" | "cluster" | "node";
  by_node: { node: string; total_ops: number }[];
  // First hour with any recorded operation; earlier operations were not measured.
  recorded_since: string | null;
}

// Percentiles are histogram bucket upper bounds; null means the sample
// fell in the overflow bucket (slower than 1000 ms).
export interface LatencyPercentiles {
  service: string;
  op_type: string;
  avg_ms: number;
  p50_ms: number | null;
  p90_ms: number | null;
  p99_ms: number | null;
  sample_ops: number;
}

export interface ServiceOpsStats {
  service: string;
  total_ops: number;
  total_errors: number;
  error_rate: number;
  avg_latency_ms: number;
}

export interface ErrorBreakdown {
  service: string;
  op_type: string;
  error_count: number;
  total_count: number;
}

export async function getOverview(session: AuthSession, window: OpsWindow): Promise<OpsOverview> {
  const res = await serviceRequest<{ overview: OpsOverview }>(session, "audit", `/ops-metrics/overview?window=${window}`);
  return res.overview;
}

export async function getLatencyPercentiles(session: AuthSession, window: OpsWindow): Promise<LatencyPercentiles[]> {
  const res = await serviceRequest<{ items: LatencyPercentiles[] | null }>(session, "audit", `/ops-metrics/latency?window=${window}`);
  return res.items ?? [];
}

export async function getServiceStats(session: AuthSession, window: OpsWindow): Promise<ServiceOpsStats[]> {
  const res = await serviceRequest<{ items: ServiceOpsStats[] | null }>(session, "audit", `/ops-metrics/by-service?window=${window}`);
  return res.items ?? [];
}

export async function getErrorBreakdown(session: AuthSession, window: OpsWindow): Promise<ErrorBreakdown[]> {
  const res = await serviceRequest<{ items: ErrorBreakdown[] | null }>(session, "audit", `/ops-metrics/errors?window=${window}`);
  return res.items ?? [];
}
