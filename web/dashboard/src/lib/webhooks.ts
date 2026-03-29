import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export type WebhookEventType =
  | "key.created" | "key.rotated" | "key.deleted" | "key.expiring" | "key.expired"
  | "secret.created" | "secret.rotated" | "secret.deleted"
  | "cert.issued" | "cert.renewed" | "cert.revoked" | "cert.expiring"
  | "access.denied" | "access.anomaly"
  | "ceremony.started" | "ceremony.completed" | "ceremony.aborted"
  | "audit.high_severity"
  | "posture.risk_change"
  | "cluster.node_down" | "cluster.leader_change";

export type WebhookFormat = "json" | "splunk_hec" | "datadog" | "pagerduty" | "slack" | "generic_siem";

export interface Webhook {
  id: string;
  tenant_id: string;
  name: string;
  url: string;
  format: WebhookFormat;
  events: WebhookEventType[];
  secret: string;
  enabled: boolean;
  created_at: string;
  last_delivery_at?: string;
  last_delivery_status?: "success" | "failed";
  failure_count: number;
  headers?: Record<string, string>;
}

export interface WebhookDelivery {
  id: string;
  webhook_id: string;
  event_type: string;
  payload_preview: string;
  status: "success" | "failed" | "retrying";
  http_status?: number;
  delivered_at: string;
  latency_ms: number;
  error?: string;
  attempt: number;
}

export async function listWebhooks(session: AuthSession): Promise<Webhook[]> {
  const res = await serviceRequest<any>(session, "audit", "/webhooks");
  return res.items ?? [];
}

export async function createWebhook(session: AuthSession, data: Partial<Webhook>): Promise<Webhook> {
  return serviceRequest<Webhook>(session, "audit", "/webhooks", { method: "POST", body: JSON.stringify(data) });
}

export async function updateWebhook(session: AuthSession, id: string, data: Partial<Webhook>): Promise<Webhook> {
  return serviceRequest<Webhook>(session, "audit", `/webhooks/${id}`, { method: "PATCH", body: JSON.stringify(data) });
}

export async function deleteWebhook(session: AuthSession, id: string): Promise<void> {
  return serviceRequest<void>(session, "audit", `/webhooks/${id}`, { method: "DELETE" });
}

export async function testWebhook(session: AuthSession, id: string): Promise<{ success: boolean; status: number; latency_ms: number }> {
  return serviceRequest(session, "audit", `/webhooks/${id}/test`, { method: "POST" });
}

export async function listDeliveries(session: AuthSession, webhookId: string): Promise<WebhookDelivery[]> {
  const res = await serviceRequest<any>(session, "audit", `/webhooks/${webhookId}/deliveries`);
  return res.items ?? [];
}
