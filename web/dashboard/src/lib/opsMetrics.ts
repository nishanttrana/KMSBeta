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

export async function getOverview(session: AuthSession, window: OpsWindow): Promise<OpsOverview> {
  const res = await serviceRequest<{ overview: OpsOverview }>(session, "audit", `/ops-metrics/overview?window=${window}`);
  return res.overview;
}

// Percentiles are histogram bucket upper bounds; null means the sample fell
// in the overflow bucket (slower than 1000 ms) or there were none.
export interface OpsGroup {
  key: string;
  ops: number;
  errors: number;
  avg_latency_ms: number;
  p50_ms: number | null;
  p90_ms: number | null;
  p99_ms: number | null;
}

// GET /ops-metrics/stats (services/audit/ops_stats.go): the whole window,
// from the hour it starts on, bucketed by pkg/timebucket. Each count has a
// GET /audit/events filter (metered_op, outcome, service, node) listing
// exactly the operations it counts.
export interface OpsStats {
  from: string;
  to: string;
  bucket_seconds: number;
  scope: OpsOverview["scope"];
  recorded_since: string | null;
  total: OpsGroup;
  total_values: number;
  series: { start: string; ops: number; errors: number; avg_latency_ms: number }[];
  by_op: OpsGroup[];
  by_service: OpsGroup[];
  by_node: OpsGroup[];
}

export async function getOpsStats(session: AuthSession, window: { from?: string }): Promise<OpsStats> {
  const q = window.from ? `?from=${encodeURIComponent(window.from)}` : "";
  const res = await serviceRequest<{ stats?: OpsStats }>(session, "audit", `/ops-metrics/stats${q}`);
  const st = res?.stats;
  if (!st || !st.total || !Array.isArray(st.series) || !Array.isArray(st.by_op) || !Array.isArray(st.by_service) || !Array.isArray(st.by_node)) {
    throw new Error("the audit service answered without operations statistics");
  }
  return st;
}
