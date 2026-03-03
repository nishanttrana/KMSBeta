import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export type SecretItem = {
  id: string;
  tenant_id: string;
  name: string;
  secret_type: string;
  description?: string;
  labels?: Record<string, string>;
  metadata?: Record<string, unknown>;
  status: string;
  lease_ttl_seconds: number;
  expires_at?: string;
  current_version: number;
  created_by?: string;
  created_at?: string;
  updated_at?: string;
};

type ListSecretsResponse = {
  items: SecretItem[];
};

type SecretResponse = {
  secret: SecretItem;
};

type SecretValueResponse = {
  value: string;
  format: string;
  content_type: string;
};

type GenerateSSHResponse = {
  secret: SecretItem;
  public_key: string;
};

type GenerateKeyPairResponse = {
  secret: SecretItem;
  public_key: string;
  key_type: string;
};

export type CreateSecretInput = {
  name: string;
  secret_type: string;
  value: string;
  description?: string;
  labels?: Record<string, string>;
  metadata?: Record<string, unknown>;
  lease_ttl_seconds?: number;
};

export type UpdateSecretInput = {
  name?: string;
  description?: string;
  labels?: Record<string, string>;
  metadata?: Record<string, unknown>;
  lease_ttl_seconds?: number;
  value?: string;
};

export async function listSecrets(
  session: AuthSession,
  options?: { secretType?: string; limit?: number; offset?: number; noCache?: boolean }
): Promise<SecretItem[]> {
  const limit = Math.max(1, Math.min(500, Math.trunc(Number(options?.limit || 200))));
  const offset = Math.max(0, Math.trunc(Number(options?.offset || 0)));
  const secretType = String(options?.secretType || "").trim();
  const q = new URLSearchParams();
  q.set("tenant_id", session.tenantId);
  q.set("limit", String(limit));
  q.set("offset", String(offset));
  if (secretType) {
    q.set("secret_type", secretType);
  }
  if (options?.noCache) {
    q.set("_ts", String(Date.now()));
  }
  const res = await serviceRequest<ListSecretsResponse>(session, "secrets", `/secrets?${q.toString()}`);
  return Array.isArray(res?.items) ? res.items : [];
}

export async function createSecret(session: AuthSession, input: CreateSecretInput): Promise<SecretItem> {
  const payload = await serviceRequest<SecretResponse>(session, "secrets", "/secrets", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      name: input.name,
      secret_type: input.secret_type,
      value: input.value,
      description: input.description || "",
      labels: input.labels || {},
      metadata: input.metadata || {},
      lease_ttl_seconds: Math.trunc(Number(input.lease_ttl_seconds || 0)),
      created_by: session.username || "dashboard"
    })
  });
  return payload.secret;
}

export async function updateSecret(session: AuthSession, secretId: string, input: UpdateSecretInput): Promise<SecretItem> {
  const body: Record<string, unknown> = {
    updated_by: session.username || "dashboard"
  };
  if (typeof input.name === "string") {
    body.name = input.name;
  }
  if (typeof input.description === "string") {
    body.description = input.description;
  }
  if (typeof input.value === "string") {
    body.value = input.value;
  }
  if (input.labels) {
    body.labels = input.labels;
  }
  if (input.metadata) {
    body.metadata = input.metadata;
  }
  if (typeof input.lease_ttl_seconds === "number") {
    body.lease_ttl_seconds = Math.trunc(Number(input.lease_ttl_seconds || 0));
  }
  const payload = await serviceRequest<SecretResponse>(session, "secrets", `/secrets/${encodeURIComponent(secretId)}?tenant_id=${encodeURIComponent(session.tenantId)}`, {
    method: "PUT",
    body: JSON.stringify(body)
  });
  return payload.secret;
}

export async function deleteSecret(session: AuthSession, secretId: string): Promise<void> {
  await serviceRequest(session, "secrets", `/secrets/${encodeURIComponent(secretId)}?tenant_id=${encodeURIComponent(session.tenantId)}`, {
    method: "DELETE"
  });
}

export async function getSecret(session: AuthSession, secretId: string): Promise<SecretItem> {
  const payload = await serviceRequest<SecretResponse>(session, "secrets", `/secrets/${encodeURIComponent(secretId)}?tenant_id=${encodeURIComponent(session.tenantId)}`);
  return payload.secret;
}

export async function getSecretValue(
  session: AuthSession,
  secretId: string,
  format = "raw"
): Promise<SecretValueResponse> {
  return serviceRequest<SecretValueResponse>(
    session,
    "secrets",
    `/secrets/${encodeURIComponent(secretId)}/value?tenant_id=${encodeURIComponent(session.tenantId)}&format=${encodeURIComponent(format)}`
  );
}

export async function generateSSHKeySecret(
  session: AuthSession,
  input: { name: string; description?: string; labels?: Record<string, string>; lease_ttl_seconds?: number }
): Promise<GenerateSSHResponse> {
  return serviceRequest<GenerateSSHResponse>(session, "secrets", "/secrets/generate/ssh_key", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      name: input.name,
      description: input.description || "",
      labels: input.labels || {},
      lease_ttl_seconds: Math.trunc(Number(input.lease_ttl_seconds || 0)),
      created_by: session.username || "dashboard"
    })
  });
}

export type SecretVersionInfo = {
  version: number;
  value_hash: string;
  created_at: string;
};

export type SecretAuditEntry = {
  id: string;
  secret_id: string;
  action: string;
  actor: string;
  detail: string;
  created_at: string;
};

export type VaultStats = {
  total_secrets: number;
  by_type: Record<string, number>;
  total_versions: number;
  expiring_within_30d: number;
  expired: number;
};

export async function getVaultStats(session: AuthSession): Promise<VaultStats> {
  const res = await serviceRequest<{ stats: VaultStats }>(session, "secrets", `/secrets/stats?tenant_id=${encodeURIComponent(session.tenantId)}`);
  return res.stats;
}

export async function listSecretVersions(session: AuthSession, secretId: string): Promise<SecretVersionInfo[]> {
  const res = await serviceRequest<{ versions: SecretVersionInfo[] }>(
    session, "secrets",
    `/secrets/${encodeURIComponent(secretId)}/versions?tenant_id=${encodeURIComponent(session.tenantId)}`
  );
  return Array.isArray(res?.versions) ? res.versions : [];
}

export async function getSecretAuditLog(session: AuthSession, secretId: string, limit = 50): Promise<SecretAuditEntry[]> {
  const res = await serviceRequest<{ entries: SecretAuditEntry[] }>(
    session, "secrets",
    `/secrets/${encodeURIComponent(secretId)}/audit?tenant_id=${encodeURIComponent(session.tenantId)}&limit=${limit}`
  );
  return Array.isArray(res?.entries) ? res.entries : [];
}

export async function rotateSecret(session: AuthSession, secretId: string, newValue: string): Promise<SecretItem> {
  const payload = await serviceRequest<{ secret: SecretItem }>(session, "secrets", `/secrets/${encodeURIComponent(secretId)}/rotate?tenant_id=${encodeURIComponent(session.tenantId)}`, {
    method: "POST",
    body: JSON.stringify({
      value: newValue,
      updated_by: session.username || "dashboard"
    })
  });
  return payload.secret;
}

export async function generateKeyPairSecret(
  session: AuthSession,
  input: {
    name: string;
    key_type: string;
    description?: string;
    labels?: Record<string, string>;
    lease_ttl_seconds?: number;
  }
): Promise<GenerateKeyPairResponse> {
  return serviceRequest<GenerateKeyPairResponse>(session, "secrets", "/secrets/generate/keypair", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      name: input.name,
      key_type: input.key_type,
      description: input.description || "",
      labels: input.labels || {},
      lease_ttl_seconds: Math.trunc(Number(input.lease_ttl_seconds || 0)),
      created_by: session.username || "dashboard"
    })
  });
}
