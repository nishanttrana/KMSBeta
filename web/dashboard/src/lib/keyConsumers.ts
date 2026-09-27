import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

// GET /keys/{id}/consumers: a key's callers from keycore's usage trail
// (node-local, retained window_days) and what rotating or deleting it affects.
export type KeyConsumer = {
  actor_id: string;
  interface: string;
  operations: Record<string, number>;
  total: number;
  first_seen: string;
  last_seen: string;
};

export type KeyImpact = {
  key_status: string;
  current_version: number;
  versions_by_status: Record<string, number>;
  active_callers: number;
  interfaces: string[];
  last_used_at?: string;
  approval_required: boolean;
};

export type KeyConsumers = {
  key_id: string;
  since: string;
  window_days: number;
  node_local: boolean;
  consumers: KeyConsumer[];
  impact: KeyImpact;
};

export async function getKeyConsumers(session: AuthSession, keyID: string): Promise<KeyConsumers> {
  const out = await serviceRequest<{ consumers: KeyConsumers }>(
    session, "keycore",
    `/keys/${encodeURIComponent(keyID)}/consumers?tenant_id=${encodeURIComponent(session.tenantId)}`
  );
  return out.consumers;
}
