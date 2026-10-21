import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

// Dynamic database credentials (services/secrets/dbengine.go).

export type DBRole = {
  tenant_id: string;
  name: string;
  connection_id: string;
  engine: string;
  creation_statements: string[];
  revocation_statements: string[];
  default_ttl_seconds: number;
  max_ttl_seconds: number;
  created_by: string;
  created_at: string;
  updated_at: string;
};

export type DBLease = {
  id: string;
  role_name: string;
  username: string;
  state: "active" | "revoked" | "expired" | "revoke_failed" | string;
  created_by: string;
  created_at: string;
  expires_at: string;
  max_expires_at: string;
  ended_at?: string;
  last_error?: string;
};

export type DBRoleInput = Pick<DBRole, "connection_id" | "creation_statements" | "revocation_statements" | "default_ttl_seconds" | "max_ttl_seconds">;

const q = (s: AuthSession) => `tenant_id=${encodeURIComponent(s.tenantId)}`;
const body = (method: string, b: unknown) => ({ method, body: JSON.stringify(b) });

export async function listDBRoles(s: AuthSession): Promise<{ items: { role: DBRole; active_leases: number }[]; defaults: { creation_statements: string[]; revocation_statements: string[] } }> {
  const out = await serviceRequest<{ items?: { role: DBRole; active_leases: number }[]; defaults?: { creation_statements: string[]; revocation_statements: string[] } }>(s, "secrets", `/secrets/database/roles?${q(s)}`);
  if (!Array.isArray(out?.items) || !out?.defaults) throw new Error("secrets returned no role list");
  return { items: out.items, defaults: out.defaults };
}

export async function putDBRole(s: AuthSession, name: string, input: DBRoleInput): Promise<DBRole> {
  const out = await serviceRequest<{ role: DBRole }>(s, "secrets", `/secrets/database/roles/${encodeURIComponent(name)}?${q(s)}`, body("PUT", input));
  return out.role;
}

export async function deleteDBRole(s: AuthSession, name: string): Promise<void> {
  await serviceRequest(s, "secrets", `/secrets/database/roles/${encodeURIComponent(name)}?${q(s)}`, { method: "DELETE" });
}

export async function issueDBCreds(s: AuthSession, name: string, ttlSeconds?: number): Promise<{ lease: DBLease; username: string; password: string }> {
  return serviceRequest(s, "secrets", `/secrets/database/roles/${encodeURIComponent(name)}/creds?${q(s)}`, body("POST", ttlSeconds ? { ttl_seconds: ttlSeconds } : {}));
}

export async function listDBLeases(s: AuthSession): Promise<DBLease[]> {
  const out = await serviceRequest<{ items?: DBLease[] }>(s, "secrets", `/secrets/database/leases?${q(s)}`);
  if (!Array.isArray(out?.items)) throw new Error("secrets returned no lease list");
  return out.items;
}

export async function renewDBLease(s: AuthSession, id: string): Promise<DBLease> {
  const out = await serviceRequest<{ lease: DBLease }>(s, "secrets", `/secrets/database/leases/${encodeURIComponent(id)}/renew?${q(s)}`, body("POST", {}));
  return out.lease;
}

export async function revokeDBLease(s: AuthSession, id: string): Promise<DBLease> {
  const out = await serviceRequest<{ lease: DBLease }>(s, "secrets", `/secrets/database/leases/${encodeURIComponent(id)}/revoke?${q(s)}`, body("POST", {}));
  return out.lease;
}
