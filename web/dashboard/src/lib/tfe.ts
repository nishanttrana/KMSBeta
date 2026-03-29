import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export type TFEAgent = {
  id: string;
  tenant_id: string;
  hostname: string;
  os: string;
  agent_version: string;
  status: string;
  last_seen: string;
  policy_count: number;
  created_at: string;
};

export type TFEPolicy = {
  id: string;
  tenant_id: string;
  agent_id: string;
  path: string;
  recursive: boolean;
  key_id: string;
  algorithm: string;
  include_globs: string[];
  exclude_globs: string[];
  files_encrypted: number;
  status: string;
  created_at: string;
  updated_at: string;
};

export type TFESummary = {
  total_agents: number;
  active_agents: number;
  total_policies: number;
  total_encrypted_files: number;
  by_os: Record<string, number>;
  by_status: Record<string, number>;
};

function tenantQuery(session: AuthSession): string {
  return `tenant_id=${encodeURIComponent(session.tenantId)}`;
}

export async function listTFEAgents(session: AuthSession): Promise<TFEAgent[]> {
  const res = await serviceRequest<{ items?: TFEAgent[] }>(
    session, "tfe", `/tfe/agents?${tenantQuery(session)}`
  );
  return Array.isArray(res?.items) ? res.items : [];
}

export async function listTFEPolicies(
  session: AuthSession,
  agentId?: string
): Promise<TFEPolicy[]> {
  let url = `/tfe/policies?${tenantQuery(session)}`;
  if (agentId) url += `&agent_id=${encodeURIComponent(agentId)}`;
  const res = await serviceRequest<{ items?: TFEPolicy[] }>(session, "tfe", url);
  return Array.isArray(res?.items) ? res.items : [];
}

export async function createTFEPolicy(
  session: AuthSession,
  payload: {
    agent_id: string;
    path: string;
    recursive?: boolean;
    key_id: string;
    algorithm?: string;
    include_globs?: string[];
    exclude_globs?: string[];
  }
): Promise<TFEPolicy> {
  const res = await serviceRequest<{ policy?: TFEPolicy }>(
    session, "tfe", `/tfe/policies?${tenantQuery(session)}`,
    {
      method: "POST",
      body: JSON.stringify({ tenant_id: session.tenantId, ...payload }),
    }
  );
  return res?.policy ?? ({} as TFEPolicy);
}

export async function deleteTFEPolicy(session: AuthSession, id: string): Promise<void> {
  await serviceRequest<void>(
    session, "tfe",
    `/tfe/policies/${encodeURIComponent(id)}?${tenantQuery(session)}`,
    { method: "DELETE" }
  );
}

export async function getTFESummary(session: AuthSession): Promise<TFESummary> {
  const res = await serviceRequest<{ summary?: TFESummary }>(
    session, "tfe", `/tfe/summary?${tenantQuery(session)}`
  );
  return res?.summary ?? {
    total_agents: 0,
    active_agents: 0,
    total_policies: 0,
    total_encrypted_files: 0,
    by_os: {},
    by_status: {},
  };
}
