import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export type UIAuditEvent = {
  action: string;
  target_type: string;
  target_id: string;
  details?: Record<string, unknown>;
};

/**
 * Fire-and-forget UI audit event logger.
 * Never blocks UI operations — silently swallows errors.
 */
export async function logUIAuditEvent(
  session: AuthSession,
  event: UIAuditEvent
): Promise<void> {
  try {
    await serviceRequest(session, "audit", "/audit/events", {
      method: "POST",
      body: JSON.stringify({
        tenant_id: session.tenantId,
        service: "dashboard-ui",
        action: event.action,
        actor_id: session.username || "unknown",
        actor_type: "user",
        target_type: event.target_type,
        target_id: event.target_id,
        source_ip: "dashboard",
        details: event.details || {},
      }),
    });
  } catch {
    // Audit logging must never block UI
  }
}
