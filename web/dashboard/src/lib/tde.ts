import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export type TDEDatabase = {
  id: string;
  tenant_id: string;
  name: string;
  engine: string;
  host: string;
  port: number;
  db_name: string;
  key_id: string;
  key_algorithm: string;
  status: string;
  rotation_policy: string;
  last_rotated?: string;
  created_at: string;
  updated_at: string;
};

export type TDEStatusSummary = {
  total: number;
  by_engine: Record<string, number>;
  by_status: Record<string, number>;
  keys_provisioned_pct: number;
  rotation_due_soon: number;
};

function tenantQuery(session: AuthSession): string {
  return `tenant_id=${encodeURIComponent(session.tenantId)}`;
}

export async function listTDEDatabases(session: AuthSession): Promise<TDEDatabase[]> {
  const res = await serviceRequest<{ items?: TDEDatabase[] }>(
    session, "kmip", `/tde/databases?${tenantQuery(session)}`
  );
  return Array.isArray(res?.items) ? res.items : [];
}

export async function registerTDEDatabase(
  session: AuthSession,
  payload: {
    name: string;
    engine: string;
    host: string;
    port: number;
    db_name: string;
    rotation_policy?: string;
  }
): Promise<TDEDatabase> {
  const res = await serviceRequest<{ database?: TDEDatabase }>(
    session, "kmip", `/tde/databases?${tenantQuery(session)}`,
    {
      method: "POST",
      body: JSON.stringify({ tenant_id: session.tenantId, ...payload }),
    }
  );
  return res?.database ?? ({} as TDEDatabase);
}

export async function getTDEDatabase(session: AuthSession, id: string): Promise<TDEDatabase> {
  const res = await serviceRequest<{ database?: TDEDatabase }>(
    session, "kmip", `/tde/databases/${encodeURIComponent(id)}?${tenantQuery(session)}`
  );
  return res?.database ?? ({} as TDEDatabase);
}

export async function provisionTDEKey(session: AuthSession, id: string): Promise<TDEDatabase> {
  const res = await serviceRequest<{ database?: TDEDatabase }>(
    session, "kmip",
    `/tde/databases/${encodeURIComponent(id)}/provision?${tenantQuery(session)}`,
    { method: "POST", body: JSON.stringify({ tenant_id: session.tenantId }) }
  );
  return res?.database ?? ({} as TDEDatabase);
}

export async function revokeTDEKey(session: AuthSession, id: string): Promise<TDEDatabase> {
  const res = await serviceRequest<{ database?: TDEDatabase }>(
    session, "kmip",
    `/tde/databases/${encodeURIComponent(id)}/revoke?${tenantQuery(session)}`,
    { method: "POST", body: JSON.stringify({ tenant_id: session.tenantId }) }
  );
  return res?.database ?? ({} as TDEDatabase);
}

export async function getTDEStatus(session: AuthSession): Promise<TDEStatusSummary> {
  const res = await serviceRequest<{ status?: TDEStatusSummary }>(
    session, "kmip", `/tde/status?${tenantQuery(session)}`
  );
  return res?.status ?? {
    total: 0,
    by_engine: {},
    by_status: {},
    keys_provisioned_pct: 0,
    rotation_due_soon: 0,
  };
}
