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
  deleted_at?: string;
  deleted_by?: string;
  // Folder label plus name; access rules match on it.
  path?: string;
  // An access rule limits who may read the value.
  restricted?: boolean;
};

type ListSecretsResponse = {
  items: SecretItem[];
};

type SecretResponse = {
  secret: SecretItem;
};

export type SecretValueResponse = {
  value: string;
  version: number;
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
  options?: { secretType?: string; limit?: number; offset?: number; noCache?: boolean; deleted?: boolean }
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
  if (options?.deleted) {
    q.set("deleted", "true");
  }
  if (options?.noCache) {
    q.set("_ts", String(Date.now()));
  }
  const res = await serviceRequest<ListSecretsResponse>(session, "secrets", `/secrets?${q.toString()}`);
  return Array.isArray(res?.items) ? res.items : [];
}

// Every secret of the tenant the caller may see (active, or deleted and not
// yet destroyed), paged in full: the vault's charts count this list, so it
// is never a sample.
export async function listAllSecrets(session: AuthSession, deleted = false): Promise<SecretItem[]> {
  const PAGE = 500;
  const all: SecretItem[] = [];
  for (;;) {
    const page = await listSecrets(session, { limit: PAGE, offset: all.length, noCache: true, deleted });
    all.push(...page);
    if (page.length < PAGE) return all;
  }
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


// version 0 reads the current version.
export async function getSecretValue(
  session: AuthSession,
  secretId: string,
  format = "raw",
  version = 0
): Promise<SecretValueResponse> {
  return serviceRequest<SecretValueResponse>(
    session,
    "secrets",
    `${secretURL(session, secretId, "/value")}&format=${encodeURIComponent(format)}${version > 0 ? `&version=${version}` : ""}`
  );
}

const secretURL = (session: AuthSession, secretId: string, suffix = "") =>
  `/secrets/${encodeURIComponent(secretId)}${suffix}?tenant_id=${encodeURIComponent(session.tenantId)}`;

const post = (body?: unknown) => ({ method: "POST", body: JSON.stringify(body ?? {}) });

// A deleted secret keeps its versions until it is restored or destroyed.
export async function restoreSecret(session: AuthSession, secretId: string): Promise<void> {
  await serviceRequest(session, "secrets", secretURL(session, secretId, "/restore"), post());
}

export async function destroySecret(session: AuthSession, secretId: string): Promise<void> {
  await serviceRequest(session, "secrets", secretURL(session, secretId, "/destroy"), post());
}

// Makes an earlier version's value current again, as a new version. Refused
// if the secret is no longer at expectedVersion.
export async function rollbackSecret(session: AuthSession, secretId: string, version: number, expectedVersion: number): Promise<SecretItem> {
  const out = await serviceRequest<SecretResponse>(session, "secrets", secretURL(session, secretId, "/rollback"), post({ version, expected_version: expectedVersion }));
  return out.secret;
}

export async function destroySecretVersion(session: AuthSession, secretId: string, version: number): Promise<void> {
  await serviceRequest(session, "secrets", secretURL(session, secretId, `/versions/${version}`), { method: "DELETE" });
}

export const ACCESS_CAPABILITIES = ["read", "value", "write", "delete"] as const;
// "group" is a keycore access group (Key Management, Access groups), by ID.
export const ACCESS_SUBJECT_TYPES = ["role", "group", "user", "client", "workload"] as const;

// A tenant's vault-wide choices (docs/SECURITY/SECRET_ACCESS.md).
export type VaultSettings = {
  default_deny: boolean; // refuse a path no allow rule covers
  max_versions: number; // 0: no cap
  deleted_retention_days: number; // 0: kept until destroyed
  updated_by?: string;
  updated_at?: string;
};

export async function getVaultSettings(session: AuthSession): Promise<VaultSettings> {
  const res = await serviceRequest<{ settings: VaultSettings }>(session, "secrets", `/secrets/settings?tenant_id=${encodeURIComponent(session.tenantId)}`);
  return res.settings;
}

export async function putVaultSettings(session: AuthSession, input: Pick<VaultSettings, "default_deny" | "max_versions" | "deleted_retention_days">): Promise<VaultSettings> {
  const res = await serviceRequest<{ settings: VaultSettings }>(session, "secrets", "/secrets/settings", { method: "PUT", body: JSON.stringify({ tenant_id: session.tenantId, ...input }) });
  return res.settings;
}

export type AccessRule = {
  id: string;
  path: string;
  subject_type: string;
  subject_id: string;
  capabilities: string[];
  effect: "allow" | "deny" | string;
  created_by: string;
  created_at: string;
  // Whether the subject exists where it is defined; "unchecked" when the
  // service that owns it could not be asked.
  subject_status?: "found" | "missing" | "unchecked" | string;
  subject_label?: string;
  subject_missing_since?: string;
};

// A version cap for one secret or one folder, overriding the tenant's.
export type VersionCap = { id: string; path: string; max_versions: number; updated_by?: string; updated_at?: string };

export async function listVersionCaps(session: AuthSession): Promise<VersionCap[]> {
  const res = await serviceRequest<{ items: VersionCap[] }>(session, "secrets", `/secrets/version-caps?tenant_id=${encodeURIComponent(session.tenantId)}`);
  return Array.isArray(res?.items) ? res.items : [];
}

export async function putVersionCap(session: AuthSession, path: string, maxVersions: number): Promise<VersionCap> {
  const res = await serviceRequest<{ cap: VersionCap }>(session, "secrets", "/secrets/version-caps", { method: "PUT", body: JSON.stringify({ tenant_id: session.tenantId, path, max_versions: maxVersions }) });
  return res.cap;
}

// The background prune to the caps in force: it starts when a cap or the
// tenant's setting changes, and the request does not wait for it.
export type PruneStatus = { state: "idle" | "running" | "done" | "failed" | string; secrets_pruned: number; versions_pruned: number; finished_at?: string; error?: string };

export async function getPruneStatus(session: AuthSession): Promise<PruneStatus> {
  const res = await serviceRequest<{ prune: PruneStatus }>(session, "secrets", `/secrets/version-caps/prune?tenant_id=${encodeURIComponent(session.tenantId)}`);
  return res.prune;
}

export async function deleteVersionCap(session: AuthSession, capId: string): Promise<void> {
  await serviceRequest(session, "secrets", `/secrets/version-caps/${encodeURIComponent(capId)}?tenant_id=${encodeURIComponent(session.tenantId)}`, { method: "DELETE" });
}

export type AccessRuleInput = Pick<AccessRule, "path" | "subject_type" | "subject_id" | "capabilities" | "effect">;

// What the rules say about one secret: the rules covering its path, and what
// the signed-in caller may do under them.
export type SecretAccess = {
  path: string; rules: AccessRule[]; caller: Record<string, boolean>; default_deny?: boolean;
  // The version cap that applies (0: none) and its source: a cap's path, or "tenant".
  max_versions?: number; max_versions_from?: string;
};

export async function listAccessRules(session: AuthSession): Promise<AccessRule[]> {
  const res = await serviceRequest<{ items: AccessRule[] }>(session, "secrets", `/secrets/access/rules?tenant_id=${encodeURIComponent(session.tenantId)}`);
  return Array.isArray(res?.items) ? res.items : [];
}

export async function createAccessRule(session: AuthSession, input: AccessRuleInput): Promise<AccessRule> {
  const res = await serviceRequest<{ rule: AccessRule }>(session, "secrets", "/secrets/access/rules", post({ tenant_id: session.tenantId, ...input }));
  return res.rule;
}

// What deleting a rule would open: the capabilities left with no allow rule
// over its path, and how many existing secrets that touches.
export type RuleImpact = { reopens: string[]; secrets_opened: number };

export async function getAccessRuleImpact(session: AuthSession, ruleId: string): Promise<RuleImpact> {
  return serviceRequest<RuleImpact>(session, "secrets", `/secrets/access/rules/${encodeURIComponent(ruleId)}/impact?tenant_id=${encodeURIComponent(session.tenantId)}`);
}

// The service refuses to delete the last allow rule over a path unless
// confirmReopens is set: a path is never reopened as a side effect.
export async function deleteAccessRule(session: AuthSession, ruleId: string, confirmReopens = false): Promise<void> {
  await serviceRequest(session, "secrets", `/secrets/access/rules/${encodeURIComponent(ruleId)}?tenant_id=${encodeURIComponent(session.tenantId)}${confirmReopens ? "&confirm_reopens=true" : ""}`, { method: "DELETE" });
}

export async function getSecretAccess(session: AuthSession, secretId: string): Promise<SecretAccess> {
  return serviceRequest<SecretAccess>(session, "secrets", secretURL(session, secretId, "/access"));
}


export type SecretVersionInfo = {
  version: number;
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

// With expectedVersion the rotate is refused if someone else changed the
// secret since it was loaded.
export async function rotateSecret(session: AuthSession, secretId: string, newValue: string, expectedVersion?: number): Promise<SecretItem> {
  const payload = await serviceRequest<{ secret: SecretItem }>(session, "secrets", `/secrets/${encodeURIComponent(secretId)}/rotate?tenant_id=${encodeURIComponent(session.tenantId)}`, {
    method: "POST",
    body: JSON.stringify({
      value: newValue,
      ...(expectedVersion ? { expected_version: expectedVersion } : {}),
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

