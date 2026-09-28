import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

// Shapes mirror audit services/audit/webhook.go. The audit service delivers
// every persisted audit event whose action matches a stream's patterns
// through the connection it names; no credential passes through this API.

export type WebhookFormat = "json" | "splunk_hec" | "datadog" | "slack";

// An event stream: matching audit events delivered through a compliance
// connection (Playbooks → Connections), which holds the endpoint and
// credentials sealed. A legacy stream still carries the URL and format an
// earlier release stored, until the migration moves them into a connection.
export interface Webhook {
  id: string;
  tenant_id: string;
  name: string;
  connection_id: string;
  connection_type: string;
  legacy: boolean;
  url?: string;
  format?: WebhookFormat;
  events: string[]; // "*", "audit.key.*" or an exact action such as "audit.key.rotate"
  enabled: boolean;
  created_at: string;
  last_delivery_at?: string;
  last_delivery_status?: "success" | "failure";
  failure_count: number;
}

export interface WebhookDelivery {
  id: string;
  webhook_id: string;
  event_type: string;
  payload_preview: string;
  status: "success" | "failure";
  http_status: number;
  delivered_at: string;
  latency_ms: number;
  error: string;
  attempt: number;
}

export interface WebhookInput {
  name: string;
  connection_id: string;
  events: string[];
  enabled?: boolean;
}

export async function listWebhooks(session: AuthSession): Promise<Webhook[]> {
  const res = await serviceRequest<{ items: Webhook[] }>(session, "audit", "/webhooks");
  return res.items ?? [];
}

export async function createWebhook(session: AuthSession, data: WebhookInput): Promise<Webhook> {
  const res = await serviceRequest<{ webhook: Webhook }>(session, "audit", "/webhooks", { method: "POST", body: JSON.stringify(data) });
  return res.webhook;
}

export async function updateWebhook(session: AuthSession, id: string, data: Partial<WebhookInput>): Promise<Webhook> {
  const res = await serviceRequest<{ webhook: Webhook }>(session, "audit", `/webhooks/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify(data) });
  return res.webhook;
}

export async function deleteWebhook(session: AuthSession, id: string): Promise<void> {
  await serviceRequest(session, "audit", `/webhooks/${encodeURIComponent(id)}`, { method: "DELETE" });
}

export async function testWebhook(session: AuthSession, id: string): Promise<{ success: boolean; status: string; http_status: number; latency_ms: number; error: string }> {
  return serviceRequest(session, "audit", `/webhooks/${encodeURIComponent(id)}/test`, { method: "POST" });
}

export async function listDeliveries(session: AuthSession, webhookId: string): Promise<WebhookDelivery[]> {
  const res = await serviceRequest<{ items: WebhookDelivery[] }>(session, "audit", `/webhooks/${encodeURIComponent(webhookId)}/deliveries`);
  return res.items ?? [];
}
