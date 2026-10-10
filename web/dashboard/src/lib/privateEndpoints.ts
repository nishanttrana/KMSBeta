import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

// A private address range a root administrator approved for a tenant's
// source connections (git, object storage): compliance
// /compliance/private-endpoints.
export type PrivateEndpoint = { id: string; tenant_id: string; cidr: string; note: string; created_by: string; created_at: string };

function tenantQuery(session: AuthSession): string {
  return `tenant_id=${encodeURIComponent(session.tenantId)}`;
}

// A tenant gets the ranges approved for it; the root tenant every tenant's.
// canApprove: the caller is a root administrator who may approve or withdraw.
export async function listPrivateEndpoints(session: AuthSession): Promise<{ items: PrivateEndpoint[]; canApprove: boolean }> {
  const res = await serviceRequest<{ data?: PrivateEndpoint[]; can_approve?: boolean }>(
    session,
    "compliance",
    `/compliance/private-endpoints?${tenantQuery(session)}`
  );
  return { items: Array.isArray(res?.data) ? res.data : [], canApprove: !!res?.can_approve };
}

export async function approvePrivateEndpoint(session: AuthSession, forTenant: string, cidr: string, note: string): Promise<void> {
  await serviceRequest(session, "compliance", `/compliance/private-endpoints?${tenantQuery(session)}`, {
    method: "POST",
    body: JSON.stringify({ tenant_id: session.tenantId, for_tenant: forTenant, cidr, note }),
  });
}

export async function withdrawPrivateEndpoint(session: AuthSession, id: string): Promise<void> {
  await serviceRequest(session, "compliance", `/compliance/private-endpoints/${encodeURIComponent(id)}?${tenantQuery(session)}`, { method: "DELETE" });
}
