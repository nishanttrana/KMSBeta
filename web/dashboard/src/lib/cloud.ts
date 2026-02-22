import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export type CloudProvider = "aws" | "azure" | "gcp" | "oci" | "salesforce";

export type CloudAccount = {
  id: string;
  tenant_id: string;
  provider: CloudProvider;
  name: string;
  default_region: string;
  status: string;
  created_at?: string;
  updated_at?: string;
};

export type CloudRegionMapping = {
  tenant_id: string;
  provider: CloudProvider;
  vecta_region: string;
  cloud_region: string;
  created_at?: string;
  updated_at?: string;
};

export type CloudKeyBinding = {
  id: string;
  tenant_id: string;
  key_id: string;
  provider: CloudProvider;
  account_id: string;
  cloud_key_id: string;
  cloud_key_ref: string;
  region: string;
  sync_status: string;
  last_synced_at?: string;
  metadata_json?: string;
  created_at?: string;
  updated_at?: string;
};

export type CloudSyncJob = {
  id: string;
  tenant_id: string;
  provider: string;
  account_id: string;
  mode: string;
  status: string;
  summary_json?: string;
  error_message?: string;
  started_at?: string;
  completed_at?: string;
  created_at?: string;
};

export type CloudInventoryItem = {
  cloud_key_id: string;
  cloud_key_ref: string;
  provider: string;
  account_id: string;
  region: string;
  state: string;
  algorithm: string;
  managed_by_vecta: boolean;
};

type ListAccountsResponse = { items?: CloudAccount[] };
type CreateAccountResponse = { account: CloudAccount };
type ListMappingsResponse = { items?: CloudRegionMapping[] };
type MappingResponse = { mapping: CloudRegionMapping };
type ImportResponse = { binding: CloudKeyBinding };
type RotateResponse = { binding: CloudKeyBinding; version_id?: string };
type SyncResponse = { job: CloudSyncJob };
type InventoryResponse = { items?: CloudInventoryItem[] };
type ListBindingsResponse = { items?: CloudKeyBinding[] };
type GetBindingResponse = { binding: CloudKeyBinding };

export type RegisterCloudAccountInput = {
  provider: CloudProvider;
  name: string;
  defaultRegion?: string;
  credentialsJson: string;
};

export type SetCloudRegionMappingInput = {
  provider: CloudProvider;
  vectaRegion: string;
  cloudRegion: string;
};

export type ImportKeyToCloudInput = {
  keyId: string;
  provider?: CloudProvider;
  accountId?: string;
  vectaRegion?: string;
  cloudRegion?: string;
  metadata?: Record<string, unknown>;
};

export type SyncCloudKeysInput = {
  provider?: CloudProvider;
  accountId?: string;
  mode?: string;
};

export function normalizeCloudProvider(value: string): CloudProvider {
  const v = String(value || "").trim().toLowerCase();
  if (v === "aws") return "aws";
  if (v === "azure") return "azure";
  if (v === "gcp") return "gcp";
  if (v === "salesforce") return "salesforce";
  return "oci";
}

export async function listCloudAccounts(session: AuthSession, provider = ""): Promise<CloudAccount[]> {
  const query = provider ? `?provider=${encodeURIComponent(provider)}` : "";
  const payload = await serviceRequest<ListAccountsResponse>(session, "cloud", `/cloud/accounts${query}`);
  return Array.isArray(payload?.items) ? payload.items : [];
}

export async function registerCloudAccount(
  session: AuthSession,
  input: RegisterCloudAccountInput
): Promise<CloudAccount> {
  const payload = await serviceRequest<CreateAccountResponse>(session, "cloud", "/cloud/accounts", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      provider: normalizeCloudProvider(input.provider),
      name: String(input.name || "").trim(),
      default_region: String(input.defaultRegion || "").trim(),
      credentials_json: String(input.credentialsJson || "").trim() || "{}"
    })
  });
  return payload.account;
}

export async function listCloudRegionMappings(session: AuthSession, provider = ""): Promise<CloudRegionMapping[]> {
  const query = provider ? `?provider=${encodeURIComponent(provider)}` : "";
  const payload = await serviceRequest<ListMappingsResponse>(session, "cloud", `/cloud/region-mappings${query}`);
  return Array.isArray(payload?.items) ? payload.items : [];
}

export async function setCloudRegionMapping(
  session: AuthSession,
  input: SetCloudRegionMappingInput
): Promise<CloudRegionMapping> {
  const payload = await serviceRequest<MappingResponse>(session, "cloud", "/cloud/region-mappings", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      provider: normalizeCloudProvider(input.provider),
      vecta_region: String(input.vectaRegion || "").trim(),
      cloud_region: String(input.cloudRegion || "").trim()
    })
  });
  return payload.mapping;
}

export async function importKeyToCloud(session: AuthSession, input: ImportKeyToCloudInput): Promise<CloudKeyBinding> {
  const payload = await serviceRequest<ImportResponse>(session, "cloud", "/cloud/import", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      key_id: String(input.keyId || "").trim(),
      provider: input.provider ? normalizeCloudProvider(input.provider) : "",
      account_id: String(input.accountId || "").trim(),
      vecta_region: String(input.vectaRegion || "").trim(),
      cloud_region: String(input.cloudRegion || "").trim(),
      metadata_json: JSON.stringify(input.metadata || {})
    })
  });
  return payload.binding;
}

export async function rotateCloudBinding(
  session: AuthSession,
  bindingId: string,
  reason = "manual"
): Promise<{ binding: CloudKeyBinding; versionId?: string }> {
  const payload = await serviceRequest<RotateResponse>(session, "cloud", `/cloud/bindings/${encodeURIComponent(bindingId)}/rotate`, {
    method: "POST",
    body: JSON.stringify({
      reason: String(reason || "").trim() || "manual"
    })
  });
  return {
    binding: payload.binding,
    versionId: String(payload.version_id || "").trim() || undefined
  };
}

export async function syncCloudKeys(session: AuthSession, input?: SyncCloudKeysInput): Promise<CloudSyncJob> {
  const payload = await serviceRequest<SyncResponse>(session, "cloud", "/cloud/sync", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      provider: input?.provider ? normalizeCloudProvider(input.provider) : "",
      account_id: String(input?.accountId || "").trim(),
      mode: String(input?.mode || "full").trim() || "full"
    })
  });
  return payload.job;
}

export async function discoverCloudInventory(
  session: AuthSession,
  options?: {
    provider?: CloudProvider;
    accountId?: string;
    cloudRegion?: string;
  }
): Promise<CloudInventoryItem[]> {
  const qp = new URLSearchParams();
  if (options?.provider) qp.set("provider", normalizeCloudProvider(options.provider));
  if (options?.accountId) qp.set("account_id", String(options.accountId || "").trim());
  if (options?.cloudRegion) qp.set("cloud_region", String(options.cloudRegion || "").trim());
  const suffix = qp.toString() ? `?${qp.toString()}` : "";
  const payload = await serviceRequest<InventoryResponse>(session, "cloud", `/cloud/inventory${suffix}`);
  return Array.isArray(payload?.items) ? payload.items : [];
}

export async function listCloudBindings(
  session: AuthSession,
  options?: {
    provider?: CloudProvider;
    accountId?: string;
    keyId?: string;
    limit?: number;
    offset?: number;
  }
): Promise<CloudKeyBinding[]> {
  const qp = new URLSearchParams();
  if (options?.provider) qp.set("provider", normalizeCloudProvider(options.provider));
  if (options?.accountId) qp.set("account_id", String(options.accountId || "").trim());
  if (options?.keyId) qp.set("key_id", String(options.keyId || "").trim());
  if (typeof options?.limit === "number") qp.set("limit", String(Math.max(1, Math.trunc(options.limit))));
  if (typeof options?.offset === "number") qp.set("offset", String(Math.max(0, Math.trunc(options.offset))));
  const suffix = qp.toString() ? `?${qp.toString()}` : "";
  const payload = await serviceRequest<ListBindingsResponse>(session, "cloud", `/cloud/bindings${suffix}`);
  return Array.isArray(payload?.items) ? payload.items : [];
}

export async function getCloudBinding(session: AuthSession, bindingId: string): Promise<CloudKeyBinding> {
  const payload = await serviceRequest<GetBindingResponse>(
    session,
    "cloud",
    `/cloud/bindings/${encodeURIComponent(bindingId)}`
  );
  return payload.binding;
}
