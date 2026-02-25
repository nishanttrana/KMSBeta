import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export type TokenVault = {
  id: string;
  tenant_id: string;
  name: string;
  mode?: "vault" | "vaultless" | string;
  token_type: string;
  format: "random" | "format_preserving" | "deterministic" | "irreversible" | string;
  key_id: string;
  custom_regex?: string;
  created_at?: string;
};

export type MaskingPolicy = {
  id: string;
  tenant_id: string;
  name: string;
  target_type: string;
  field_path: string;
  mask_pattern: string;
  roles_full?: string[];
  roles_partial?: string[];
  roles_redacted?: string[];
  consistent?: boolean;
  key_id?: string;
  created_at?: string;
};

export type RedactionPattern = {
  type: string;
  pattern: string;
  label: string;
};

export type RedactionPolicy = {
  id: string;
  tenant_id: string;
  name: string;
  patterns: RedactionPattern[];
  scope?: string;
  action?: string;
  placeholder?: string;
  applies_to?: string[];
  created_at?: string;
};

type TokenVaultsResponse = { items: TokenVault[] };
type TokenVaultResponse = { vault: TokenVault };
type TokenizeResponse = { items: Array<Record<string, unknown>> };
type FPEResponse = { result: Record<string, unknown> };
type MaskResponse = { masked: Record<string, unknown> };
type MaskPoliciesResponse = { items: MaskingPolicy[] };
type MaskPolicyResponse = { item: MaskingPolicy };
type RedactResponse = { result: Record<string, unknown> };
type RedactionPoliciesResponse = { items: RedactionPolicy[] };
type RedactionPolicyResponse = { item: RedactionPolicy };
type AppResponse = { result: Record<string, unknown> };
type DataProtectionPolicyResponse = { policy: DataProtectionPolicy };

export type DataProtectionPolicy = {
  tenant_id: string;
  allowed_data_algorithms: string[];
  require_aad_for_aead: boolean;
  max_fields_per_operation: number;
  max_document_bytes: number;
  allow_vaultless_tokenization: boolean;
  tokenization_mode_policy: Record<string, string[]>;
  token_format_policy: Record<string, string[]>;
  require_token_ttl: boolean;
  max_token_ttl_hours: number;
  allow_token_renewal: boolean;
  max_token_renewals: number;
  allow_one_time_tokens: boolean;
  detokenize_allowed_purposes: string[];
  detokenize_allowed_workflows: string[];
  require_detokenize_justification: boolean;
  allow_bulk_tokenize: boolean;
  allow_bulk_detokenize: boolean;
  allow_redaction_detect_only: boolean;
  allowed_redaction_detectors: string[];
  allowed_redaction_actions: string[];
  allow_custom_regex_tokens: boolean;
  max_custom_regex_length: number;
  max_custom_regex_groups: number;
  max_token_batch: number;
  max_detokenize_batch: number;
  require_token_context_tags: boolean;
  required_token_context_keys: string[];
  masking_role_policy: Record<string, string>;
  token_metadata_retention_days: number;
  redaction_event_retention_days: number;
  updated_by?: string;
  updated_at?: string;
};

export type CreateTokenVaultInput = {
  name: string;
  token_type: string;
  format: "random" | "format_preserving" | "deterministic" | "irreversible";
  key_id: string;
  custom_regex?: string;
};

export type TokenizeInput = {
  mode?: "vault" | "vaultless";
  vault_id: string;
  key_id?: string;
  token_type?: string;
  format?: "random" | "format_preserving" | "deterministic" | "irreversible" | string;
  custom_regex?: string;
  values: string[];
  ttl_hours?: number;
  one_time_token?: boolean;
  metadata_tags?: Record<string, string>;
};

export type DetokenizeInput = {
  tokens: string[];
  purpose?: string;
  workflow?: string;
  justification?: string;
  metadata_tags?: Record<string, string>;
  renew_ttl_hours?: number;
};

export type FPEInput = {
  key_id: string;
  algorithm?: string;
  radix?: number;
  tweak?: string;
  plaintext?: string;
  ciphertext?: string;
};

export type CreateMaskingPolicyInput = {
  name: string;
  target_type: string;
  field_path: string;
  mask_pattern: string;
  roles_full?: string[];
  roles_partial?: string[];
  roles_redacted?: string[];
  consistent?: boolean;
  key_id?: string;
};

export type ApplyMaskInput = {
  policy_id: string;
  data: Record<string, unknown>;
  role?: string;
  field_path?: string;
  document?: string;
};

export type CreateRedactionPolicyInput = {
  name: string;
  patterns: RedactionPattern[];
  scope?: string;
  action?: "replace_placeholder" | "remove" | "hash" | string;
  placeholder?: string;
  applies_to?: string[];
};

export type RedactInput = {
  policy_id?: string;
  content: string;
  content_type?: string;
  endpoint_name?: string;
};

export type AppFieldInput = {
  document_id?: string;
  document: Record<string, unknown>;
  fields: string[];
  key_id?: string;
  algorithm?: string;
  searchable?: boolean;
  aad?: string;
};

export type EnvelopeInput = {
  key_id: string;
  algorithm?: string;
  plaintext?: string;
  ciphertext?: string;
  iv?: string;
  wrapped_dek?: string;
  wrapped_dek_iv?: string;
  aad?: string;
};

export type SearchableInput = {
  key_id: string;
  plaintext?: string;
  ciphertext?: string;
  aad?: string;
};

export async function listTokenVaults(
  session: AuthSession,
  options?: { limit?: number; offset?: number }
): Promise<TokenVault[]> {
  const q = new URLSearchParams();
  q.set("tenant_id", session.tenantId);
  q.set("limit", String(Math.max(1, Math.min(500, Math.trunc(Number(options?.limit || 200))))));
  q.set("offset", String(Math.max(0, Math.trunc(Number(options?.offset || 0)))));
  const out = await serviceRequest<TokenVaultsResponse>(session, "dataprotect", `/token-vaults?${q.toString()}`);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function createTokenVault(session: AuthSession, input: CreateTokenVaultInput): Promise<TokenVault> {
  const out = await serviceRequest<TokenVaultResponse>(session, "dataprotect", "/token-vaults", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return out.vault;
}

export async function tokenizeValues(session: AuthSession, input: TokenizeInput): Promise<Array<Record<string, unknown>>> {
  const out = await serviceRequest<TokenizeResponse>(session, "dataprotect", "/tokenize", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      mode: input.mode || "vault",
      vault_id: input.vault_id,
      key_id: input.key_id || "",
      token_type: input.token_type || "",
      format: input.format || "",
      custom_regex: input.custom_regex || "",
      values: Array.isArray(input.values) ? input.values : [],
      ttl_hours: Math.max(0, Math.trunc(Number(input.ttl_hours || 0))),
      one_time_token: Boolean(input.one_time_token),
      metadata_tags: input.metadata_tags || {}
    })
  });
  return Array.isArray(out?.items) ? out.items : [];
}

export async function detokenizeValues(session: AuthSession, input: DetokenizeInput): Promise<Array<Record<string, unknown>>> {
  const out = await serviceRequest<TokenizeResponse>(session, "dataprotect", "/detokenize", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      tokens: Array.isArray(input.tokens) ? input.tokens : [],
      purpose: input.purpose || "",
      workflow: input.workflow || "",
      justification: input.justification || "",
      metadata_tags: input.metadata_tags || {},
      renew_ttl_hours: Math.max(0, Math.trunc(Number(input.renew_ttl_hours || 0)))
    })
  });
  return Array.isArray(out?.items) ? out.items : [];
}

export async function fpeEncrypt(session: AuthSession, input: FPEInput): Promise<Record<string, unknown>> {
  const out = await serviceRequest<FPEResponse>(session, "dataprotect", "/fpe/encrypt", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return out?.result || {};
}

export async function fpeDecrypt(session: AuthSession, input: FPEInput): Promise<Record<string, unknown>> {
  const out = await serviceRequest<FPEResponse>(session, "dataprotect", "/fpe/decrypt", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return out?.result || {};
}

export async function listMaskingPolicies(session: AuthSession): Promise<MaskingPolicy[]> {
  const out = await serviceRequest<MaskPoliciesResponse>(session, "dataprotect", `/masking-policies?tenant_id=${encodeURIComponent(session.tenantId)}`);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function createMaskingPolicy(session: AuthSession, input: CreateMaskingPolicyInput): Promise<MaskingPolicy> {
  const out = await serviceRequest<MaskPolicyResponse>(session, "dataprotect", "/masking-policies", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return out.item;
}

export async function applyMask(
  session: AuthSession,
  input: ApplyMaskInput,
  options?: { preview?: boolean }
): Promise<Record<string, unknown>> {
  const path = options?.preview ? "/mask/preview" : "/mask";
  const out = await serviceRequest<MaskResponse>(session, "dataprotect", path, {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return out?.masked || {};
}

export async function listRedactionPolicies(session: AuthSession): Promise<RedactionPolicy[]> {
  const out = await serviceRequest<RedactionPoliciesResponse>(session, "dataprotect", `/redaction-policies?tenant_id=${encodeURIComponent(session.tenantId)}`);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function createRedactionPolicy(session: AuthSession, input: CreateRedactionPolicyInput): Promise<RedactionPolicy> {
  const out = await serviceRequest<RedactionPolicyResponse>(session, "dataprotect", "/redaction-policies", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return out.item;
}

export async function redactContent(
  session: AuthSession,
  input: RedactInput,
  options?: { detectOnly?: boolean }
): Promise<Record<string, unknown>> {
  const path = options?.detectOnly ? "/redact/detect" : "/redact";
  const out = await serviceRequest<RedactResponse>(session, "dataprotect", path, {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return out?.result || {};
}

export async function appEncryptFields(session: AuthSession, input: AppFieldInput): Promise<Record<string, unknown>> {
  const out = await serviceRequest<AppResponse>(session, "dataprotect", "/app/encrypt-fields", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return out?.result || {};
}

export async function appDecryptFields(session: AuthSession, input: AppFieldInput): Promise<Record<string, unknown>> {
  const out = await serviceRequest<AppResponse>(session, "dataprotect", "/app/decrypt-fields", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return out?.result || {};
}

export async function appEnvelopeEncrypt(session: AuthSession, input: EnvelopeInput): Promise<Record<string, unknown>> {
  const out = await serviceRequest<AppResponse>(session, "dataprotect", "/app/envelope-encrypt", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return out?.result || {};
}

export async function appEnvelopeDecrypt(session: AuthSession, input: EnvelopeInput): Promise<Record<string, unknown>> {
  const out = await serviceRequest<AppResponse>(session, "dataprotect", "/app/envelope-decrypt", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return out?.result || {};
}

export async function appSearchableEncrypt(session: AuthSession, input: SearchableInput): Promise<Record<string, unknown>> {
  const out = await serviceRequest<AppResponse>(session, "dataprotect", "/app/searchable-encrypt", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return out?.result || {};
}

export async function appSearchableDecrypt(session: AuthSession, input: SearchableInput): Promise<Record<string, unknown>> {
  const out = await serviceRequest<AppResponse>(session, "dataprotect", "/app/searchable-decrypt", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return out?.result || {};
}

export async function getDataProtectionPolicy(session: AuthSession): Promise<DataProtectionPolicy> {
  const out = await serviceRequest<DataProtectionPolicyResponse>(
    session,
    "dataprotect",
    `/policy?tenant_id=${encodeURIComponent(session.tenantId)}`
  );
  return (out?.policy || {}) as DataProtectionPolicy;
}

export async function updateDataProtectionPolicy(
  session: AuthSession,
  input: Partial<DataProtectionPolicy>
): Promise<DataProtectionPolicy> {
  const out = await serviceRequest<DataProtectionPolicyResponse>(session, "dataprotect", `/policy?tenant_id=${encodeURIComponent(session.tenantId)}`, {
    method: "PUT",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return (out?.policy || {}) as DataProtectionPolicy;
}
