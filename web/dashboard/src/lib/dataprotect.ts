import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export type TokenVault = {
  id: string;
  tenant_id: string;
  name: string;
  mode?: "vault" | "vaultless" | string;
  storage_type?: "internal" | "external" | string;
  external_provider?: "postgres" | "mysql" | "mssql" | "oracle" | "mongodb" | string;
  external_config?: Record<string, string>;
  external_schema_version?: string;
  token_type: string;
  format: "random" | "format_preserving" | "deterministic" | "irreversible" | "custom" | string;
  custom_token_format?: string;
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
type TokenVaultExternalSchemaResponse = { item: TokenVaultExternalSchema };
type FieldEncryptionWrapperResponse = {
  wrapper: FieldEncryptionWrapper;
  auth_profile?: FieldEncryptionAuthProfile;
  certificate?: FieldEncryptionIssuedCertificate;
  warnings?: string[];
};
type FieldEncryptionWrappersResponse = { items: FieldEncryptionWrapper[] };
type FieldEncryptionLeaseResponse = { lease: FieldEncryptionLease };
type FieldEncryptionLeasesResponse = { items: FieldEncryptionLease[] };
type FieldEncryptionReceiptResponse = { receipt: FieldEncryptionUsageReceipt };
type FieldEncryptionRegisterInitResponse = { item: Record<string, unknown> };
type FieldEncryptionSDKDownloadResponse = { artifact: FieldEncryptionSDKArtifact };

export type DataProtectionPolicy = {
  tenant_id: string;
  allowed_data_algorithms: string[];
  algorithm_profile_policy: Record<string, string[]>;
  require_aad_for_aead: boolean;
  required_aad_claims: string[];
  enforce_aad_tenant_binding: boolean;
  allowed_aad_environments: string[];
  max_fields_per_operation: number;
  max_document_bytes: number;
  max_app_crypto_request_bytes: number;
  max_app_crypto_batch_size: number;
  require_symmetric_keys: boolean;
  require_fips_keys: boolean;
  min_key_size_bits: number;
  allowed_encrypt_field_paths: string[];
  allowed_decrypt_field_paths: string[];
  denied_decrypt_field_paths: string[];
  block_wildcard_field_paths: boolean;
  allow_deterministic_encryption: boolean;
  allow_searchable_encryption: boolean;
  allow_range_search: boolean;
  envelope_kek_allowlist: string[];
  max_wrapped_dek_age_minutes: number;
  require_rewrap_on_dek_age_exceeded: boolean;
  allow_vaultless_tokenization: boolean;
  tokenization_mode_policy: Record<string, string[]>;
  token_format_policy: Record<string, string[]>;
  custom_token_formats: Record<string, string>;
  reuse_existing_token_for_same_input: boolean;
  enforce_unique_token_per_vault: boolean;
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
  require_registered_wrapper: boolean;
  local_crypto_allowed: boolean;
  cache_enabled: boolean;
  cache_ttl_sec: number;
  lease_max_ops: number;
  max_cached_keys: number;
  allowed_local_algorithms: string[];
  allowed_key_classes_for_local_export: string[];
  force_remote_ops: string[];
  require_mtls: boolean;
  require_signed_nonce: boolean;
  anti_replay_window_sec: number;
  attested_wrapper_only: boolean;
  revoke_on_policy_change: boolean;
  rekey_on_policy_change: boolean;
  receipt_reconciliation_enabled: boolean;
  receipt_heartbeat_sec: number;
  receipt_missing_grace_sec: number;
  require_tpm_attestation: boolean;
  require_non_exportable_wrapper_keys: boolean;
  attestation_ak_allowlist: string[];
  attestation_allowed_pcrs: Record<string, string[]>;
  updated_by?: string;
  updated_at?: string;
};

export type FieldEncryptionWrapper = {
  tenant_id: string;
  wrapper_id: string;
  app_id: string;
  display_name: string;
  signing_public_key_b64: string;
  encryption_public_key_b64: string;
  transport: string;
  status: string;
  cert_fingerprint?: string;
  metadata?: Record<string, string>;
  approved_by?: string;
  approved_at?: string;
  created_at?: string;
  updated_at?: string;
};

export type FieldEncryptionAuthProfile = {
  mode: string;
  token_type: string;
  token: string;
  expires_at: string;
  scopes: string[];
  issuer: string;
  audience: string;
};

export type FieldEncryptionIssuedCertificate = {
  cert_id?: string;
  cert_pem?: string;
  cert_fingerprint?: string;
  ca_id?: string;
  not_after?: string;
};

export type FieldEncryptionRegistrationResult = {
  wrapper: FieldEncryptionWrapper;
  auth_profile?: FieldEncryptionAuthProfile | undefined;
  certificate?: FieldEncryptionIssuedCertificate | undefined;
  warnings?: string[] | undefined;
};

export type FieldEncryptionLease = {
  tenant_id: string;
  lease_id: string;
  wrapper_id: string;
  key_id: string;
  operation: string;
  lease_package: Record<string, unknown>;
  policy_hash: string;
  revocation_counter: number;
  max_ops: number;
  used_ops: number;
  expires_at: string;
  revoked: boolean;
  revoke_reason?: string;
  issued_at?: string;
  updated_at?: string;
};

export type FieldEncryptionUsageReceipt = {
  tenant_id: string;
  receipt_id: string;
  lease_id: string;
  wrapper_id: string;
  key_id: string;
  operation: string;
  op_count: number;
  nonce: string;
  timestamp: string;
  signature_b64: string;
  payload_hash: string;
  accepted: boolean;
  reject_reason?: string;
  created_at?: string;
};

export type FieldEncryptionSDKArtifact = {
  target_os: "linux" | "windows" | "macos" | string;
  filename: string;
  content_type: string;
  encoding: "base64" | string;
  content: string;
  size_bytes: number;
  sha256: string;
};

export type FieldEncryptionRegisterInitInput = {
  wrapper_id: string;
  app_id: string;
  display_name?: string;
  signing_public_key_b64: string;
  encryption_public_key_b64: string;
  transport?: string;
  metadata?: Record<string, string>;
};

export type FieldEncryptionRegisterCompleteInput = {
  challenge_id: string;
  wrapper_id: string;
  signature_b64: string;
  csr_pem?: string;
  cert_fingerprint?: string;
  governance_approved: boolean;
  approved_by?: string;
  metadata?: Record<string, string>;
  attestation_evidence_b64?: string;
  attestation_signature_b64?: string;
  attestation_public_key_pem?: string;
};

export type FieldEncryptionLeaseInput = {
  wrapper_id: string;
  key_id: string;
  operation: string;
  nonce: string;
  timestamp: string;
  signature_b64: string;
  requested_ttl_sec?: number;
  requested_max_ops?: number;
  wrapper_token?: string;
  client_cert_fingerprint?: string;
};

export type FieldEncryptionReceiptInput = {
  lease_id: string;
  wrapper_id: string;
  key_id: string;
  operation: string;
  op_count: number;
  nonce: string;
  timestamp: string;
  signature_b64: string;
  client_status?: string;
  wrapper_token?: string;
  client_cert_fingerprint?: string;
};

export type CreateTokenVaultInput = {
  name: string;
  token_type: string;
  format: "random" | "format_preserving" | "deterministic" | "irreversible" | "custom";
  custom_token_format?: string;
  key_id: string;
  storage_type?: "internal" | "external";
  external_provider?: "postgres" | "mysql" | "mssql" | "oracle" | "mongodb" | string;
  external_config?: Record<string, string>;
  external_schema_version?: string;
  custom_regex?: string;
};

export type TokenizeInput = {
  mode?: "vault" | "vaultless";
  vault_id: string;
  key_id?: string;
  token_type?: string;
  format?: "random" | "format_preserving" | "deterministic" | "irreversible" | "custom" | string;
  custom_token_format?: string;
  custom_regex?: string;
  values: string[];
  ttl_hours?: number;
  one_time_token?: boolean;
  metadata_tags?: Record<string, string>;
};

export type TokenVaultExternalSchema = {
  provider: "postgres" | "mysql" | "mssql" | "oracle" | "mongodb" | string;
  filename: string;
  content_type: string;
  content: string;
  schema_ver?: string;
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
  dek_created_at?: string;
  aad?: string;
};

export type SearchableInput = {
  key_id: string;
  plaintext?: string;
  ciphertext?: string;
  aad?: string;
  query_type?: "equality" | "range" | string;
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

export async function deleteTokenVault(
  session: AuthSession,
  vaultId: string,
  options?: { governanceApproved?: boolean }
): Promise<void> {
  const q = new URLSearchParams();
  q.set("tenant_id", session.tenantId);
  if (options?.governanceApproved ?? true) {
    q.set("governance_approved", "true");
  }
  await serviceRequest(session, "dataprotect", `/token-vaults/${encodeURIComponent(String(vaultId || "").trim())}?${q.toString()}`, {
    method: "DELETE"
  });
}

export async function downloadTokenVaultExternalSchema(
  session: AuthSession,
  provider: "postgres" | "mysql" | "mssql" | "oracle" | "mongodb" | string
): Promise<TokenVaultExternalSchema> {
  const out = await serviceRequest<TokenVaultExternalSchemaResponse>(
    session,
    "dataprotect",
    `/token-vaults/external-schema?tenant_id=${encodeURIComponent(session.tenantId)}&provider=${encodeURIComponent(String(provider || "").trim())}`
  );
  return out?.item || { provider: String(provider || ""), filename: "", content_type: "text/plain", content: "" };
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
      custom_token_format: input.custom_token_format || "",
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

export async function listFieldEncryptionWrappers(
  session: AuthSession,
  options?: { limit?: number; offset?: number }
): Promise<FieldEncryptionWrapper[]> {
  const q = new URLSearchParams();
  q.set("tenant_id", session.tenantId);
  q.set("limit", String(Math.max(1, Math.min(500, Math.trunc(Number(options?.limit || 200))))));
  q.set("offset", String(Math.max(0, Math.trunc(Number(options?.offset || 0)))));
  const out = await serviceRequest<FieldEncryptionWrappersResponse>(session, "dataprotect", `/field-encryption/wrappers?${q.toString()}`);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function initFieldEncryptionWrapperRegistration(
  session: AuthSession,
  input: FieldEncryptionRegisterInitInput
): Promise<Record<string, unknown>> {
  const out = await serviceRequest<FieldEncryptionRegisterInitResponse>(session, "dataprotect", "/field-encryption/register/init", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return (out?.item || {}) as Record<string, unknown>;
}

export async function completeFieldEncryptionWrapperRegistration(
  session: AuthSession,
  input: FieldEncryptionRegisterCompleteInput
): Promise<FieldEncryptionRegistrationResult> {
  const out = await serviceRequest<FieldEncryptionWrapperResponse>(session, "dataprotect", "/field-encryption/register/complete", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return {
    wrapper: out.wrapper,
    auth_profile: out?.auth_profile,
    certificate: out?.certificate,
    warnings: Array.isArray(out?.warnings) ? out.warnings : []
  };
}

export async function issueFieldEncryptionLease(
  session: AuthSession,
  input: FieldEncryptionLeaseInput
): Promise<FieldEncryptionLease> {
  const wrapperToken = String(input.wrapper_token || "").trim();
  const certFP = String(input.client_cert_fingerprint || "").trim();
  const headers: Record<string, string> = {};
  if (wrapperToken) {
    headers["X-Wrapper-Token"] = wrapperToken;
  }
  if (certFP) {
    headers["X-Wrapper-Cert-Fingerprint"] = certFP;
  }
  const out = await serviceRequest<FieldEncryptionLeaseResponse>(session, "dataprotect", "/field-encryption/leases", {
    method: "POST",
    headers,
    body: JSON.stringify({
      tenant_id: session.tenantId,
      wrapper_id: input.wrapper_id,
      key_id: input.key_id,
      operation: input.operation,
      nonce: input.nonce,
      timestamp: input.timestamp,
      signature_b64: input.signature_b64,
      requested_ttl_sec: input.requested_ttl_sec,
      requested_max_ops: input.requested_max_ops
    })
  });
  return out.lease;
}

export async function listFieldEncryptionLeases(
  session: AuthSession,
  options?: { wrapper_id?: string; limit?: number; offset?: number }
): Promise<FieldEncryptionLease[]> {
  const q = new URLSearchParams();
  q.set("tenant_id", session.tenantId);
  if (options?.wrapper_id) {
    q.set("wrapper_id", String(options.wrapper_id));
  }
  q.set("limit", String(Math.max(1, Math.min(500, Math.trunc(Number(options?.limit || 200))))));
  q.set("offset", String(Math.max(0, Math.trunc(Number(options?.offset || 0)))));
  const out = await serviceRequest<FieldEncryptionLeasesResponse>(session, "dataprotect", `/field-encryption/leases?${q.toString()}`);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function submitFieldEncryptionUsageReceipt(
  session: AuthSession,
  input: FieldEncryptionReceiptInput
): Promise<FieldEncryptionUsageReceipt> {
  const wrapperToken = String(input.wrapper_token || "").trim();
  const certFP = String(input.client_cert_fingerprint || "").trim();
  const headers: Record<string, string> = {};
  if (wrapperToken) {
    headers["X-Wrapper-Token"] = wrapperToken;
  }
  if (certFP) {
    headers["X-Wrapper-Cert-Fingerprint"] = certFP;
  }
  const out = await serviceRequest<FieldEncryptionReceiptResponse>(session, "dataprotect", "/field-encryption/receipts", {
    method: "POST",
    headers,
    body: JSON.stringify({
      tenant_id: session.tenantId,
      lease_id: input.lease_id,
      wrapper_id: input.wrapper_id,
      key_id: input.key_id,
      operation: input.operation,
      op_count: input.op_count,
      nonce: input.nonce,
      timestamp: input.timestamp,
      signature_b64: input.signature_b64,
      client_status: input.client_status
    })
  });
  return out.receipt;
}

export async function revokeFieldEncryptionLease(
  session: AuthSession,
  leaseId: string,
  reason?: string
): Promise<void> {
  await serviceRequest(session, "dataprotect", `/field-encryption/leases/${encodeURIComponent(leaseId)}/revoke?tenant_id=${encodeURIComponent(session.tenantId)}`, {
    method: "POST",
    body: JSON.stringify({
      reason: reason || ""
    })
  });
}

export async function renewFieldEncryptionLease(
  session: AuthSession,
  leaseId: string,
  input: FieldEncryptionLeaseInput
): Promise<FieldEncryptionLease> {
  const wrapperToken = String(input.wrapper_token || "").trim();
  const certFP = String(input.client_cert_fingerprint || "").trim();
  const headers: Record<string, string> = {};
  if (wrapperToken) {
    headers["X-Wrapper-Token"] = wrapperToken;
  }
  if (certFP) {
    headers["X-Wrapper-Cert-Fingerprint"] = certFP;
  }
  const out = await serviceRequest<FieldEncryptionLeaseResponse>(
    session,
    "dataprotect",
    `/field-encryption/leases/${encodeURIComponent(leaseId)}/renew?tenant_id=${encodeURIComponent(session.tenantId)}`,
    {
      method: "POST",
      headers,
      body: JSON.stringify({
        tenant_id: session.tenantId,
        wrapper_id: input.wrapper_id,
        key_id: input.key_id,
        operation: input.operation,
        nonce: input.nonce,
        timestamp: input.timestamp,
        signature_b64: input.signature_b64,
        requested_ttl_sec: input.requested_ttl_sec,
        requested_max_ops: input.requested_max_ops
      })
    }
  );
  return out.lease;
}

export async function downloadFieldEncryptionWrapperSDK(
  session: AuthSession,
  targetOS?: "linux" | "windows" | "macos" | string
): Promise<FieldEncryptionSDKArtifact> {
  const q = new URLSearchParams();
  q.set("tenant_id", session.tenantId);
  if (targetOS && String(targetOS).trim()) {
    q.set("target_os", String(targetOS).trim());
  }
  const out = await serviceRequest<FieldEncryptionSDKDownloadResponse>(
    session,
    "dataprotect",
    `/field-encryption/sdk/download?${q.toString()}`
  );
  return out.artifact;
}
