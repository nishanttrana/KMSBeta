import type { AuthSession } from "./auth";
import { serviceRequestRaw } from "./serviceApi";

export type KeyItem = {
  id: string;
  tenant_id: string;
  name: string;
  algorithm: string;
  key_type: string;
  purpose: string;
  status: string;
  tags?: string[];
  labels?: Record<string, string>;
  export_allowed?: boolean;
  activation_date?: string;
  destroy_date?: string;
  expires_at?: string;
  created_at?: string;
  updated_at?: string;
  ops_total?: number;
  ops_limit?: number;
  ops_limit_window?: string;
  current_version: number;
  kcv: string;
  iv_mode: string;
};

type APIError = {
  error?: {
    message?: string;
  };
};

type APIKeysResponse = {
  items: KeyItem[];
};

type APIKeyVersionItem = {
  id: string;
  version: number;
  status: string;
  kcv: string;
  created_at?: string;
};

type APIKeyVersionsResponse = {
  items: APIKeyVersionItem[];
};

type APITagItem = {
  tenant_id: string;
  name: string;
  color: string;
  is_system: boolean;
  usage_count?: number;
  created_by?: string;
};

export type KeyAccessGrant = {
  subject_type: "user" | "group";
  subject_id: string;
  operations: string[];
  not_before?: string;
  expires_at?: string;
  justification?: string;
  ticket_id?: string;
};

export type KeyAccessPolicy = {
  tenant_id: string;
  key_id: string;
  grants: KeyAccessGrant[];
};

export type KeyAccessGroup = {
  id: string;
  tenant_id: string;
  name: string;
  description?: string;
  created_by?: string;
  member_count?: number;
  created_at?: string;
  updated_at?: string;
};

export type KeyAccessSettings = {
  tenant_id: string;
  deny_by_default: boolean;
  require_approval_for_policy_change: boolean;
  grant_default_ttl_minutes: number;
  grant_max_ttl_minutes: number;
  enforce_signed_requests: boolean;
  replay_window_seconds: number;
  nonce_ttl_seconds: number;
  require_interface_policies: boolean;
  updated_by?: string;
  updated_at?: string;
};

export type KeyInterfaceSubjectPolicy = {
  id: string;
  tenant_id: string;
  interface_name: string;
  subject_type: "user" | "group";
  subject_id: string;
  operations: string[];
  enabled: boolean;
  created_by?: string;
  created_at?: string;
  updated_at?: string;
};

export type KeyInterfacePort = {
  tenant_id: string;
  interface_name: string;
  bind_address: string;
  port: number;
  enabled: boolean;
  description?: string;
  updated_by?: string;
  updated_at?: string;
};

type APITagsResponse = {
  items: APITagItem[];
};

type APIUpsertTagResponse = {
  tag: APITagItem;
};

type APIGetKeyAccessPolicyResponse = {
  policy: KeyAccessPolicy;
};

type APIListAccessGroupsResponse = {
  items: KeyAccessGroup[];
};

type APICreateAccessGroupResponse = {
  group: KeyAccessGroup;
};

type APIGetAccessSettingsResponse = {
  settings: KeyAccessSettings;
};

type APIListInterfacePoliciesResponse = {
  items: KeyInterfaceSubjectPolicy[];
};

type APIUpsertInterfacePolicyResponse = {
  policy: KeyInterfaceSubjectPolicy;
};

type APIListInterfacePortsResponse = {
  items: KeyInterfacePort[];
};

type APIUpsertInterfacePortResponse = {
  item: KeyInterfacePort;
};

type APICreateKeyResponse = {
  key_id: string;
  tenant_id: string;
  kcv: string;
};

type APIFormKeyResponse = APICreateKeyResponse & {
  generated_components?: string[];
};

type APIEncryptResponse = {
  ciphertext: string;
  iv: string;
  version: number;
  key_id: string;
  kcv?: string;
};

type APIDecryptResponse = {
  plaintext: string;
  version: number;
  key_id: string;
};

type APISignResponse = {
  signature: string;
  version: number;
  key_id: string;
};

type APIVerifyResponse = {
  verified: boolean;
  version: number;
  key_id: string;
};

type APIHashResponse = {
  algorithm: string;
  digest: string;
};

type APIRandomResponse = {
  bytes: string;
  length: number;
  source: string;
};

type APIDeriveResponse = {
  key_id: string;
  version: number;
  algorithm: string;
  length_bits: number;
  derived_key: string;
};

type APIKEMResponse = {
  key_id: string;
  version: number;
  algorithm: string;
  shared_secret: string;
  encapsulated_key?: string;
  iv?: string;
};

type APIExportKeyResponse = {
  key_id: string;
  wrapped_material: string;
  material_iv: string;
  wrapped_dek: string;
  kcv: string;
  public_key_plaintext?: string;
  plaintext_encoding?: string;
  component_type?: string;
  wrapping_key_id?: string;
  wrapping_key_kcv?: string;
  export_format?: string;
  request_id?: string;
};

type APIKeyStatusResponse = {
  status: string;
  mode?: string;
  activation_date?: string;
  destroy_at?: string;
  request_id?: string;
};

export type DestroyKeyInput = {
  mode: "scheduled" | "immediate";
  destroy_after_days?: number;
  confirm_name: string;
  justification: string;
  checks: {
    no_active_workloads: boolean;
    backup_completed: boolean;
    irreversible_ack: boolean;
  };
};

export type CreateKeyInput = {
  name: string;
  algorithm: string;
  key_type: string;
  purpose: string;
  tags?: string[];
  labels?: Record<string, string>;
  export_allowed?: boolean;
  activation_mode?: "immediate" | "pre-active" | "scheduled";
  activation_date?: string;
  iv_mode: string;
  created_by: string;
  ops_limit?: number;
  ops_limit_window?: string;
  approval_required?: boolean;
};

export type FormKeyInput = CreateKeyInput & {
  component_mode: "clear-generated" | "clear-user" | "encrypted-user";
  parity?: "none" | "odd" | "even";
  components: Array<{
    material?: string;
    wrapped_material?: string;
    material_iv?: string;
    wrapping_key_id?: string;
  }>;
};

export type ImportKeyInput = {
  name: string;
  algorithm?: string;
  key_type?: string;
  purpose?: string;
  tags?: string[];
  labels?: Record<string, string>;
  export_allowed?: boolean;
  activation_mode?: "immediate" | "pre-active" | "scheduled";
  activation_date?: string;
  iv_mode?: string;
  created_by?: string;
  ops_limit?: number;
  ops_limit_window?: string;
  approval_required?: boolean;
  material: string;
  expected_kcv?: string;
  import_method?: "raw" | "pem" | "jwk" | "tr31" | "pkcs12";
  import_password?: string;
  wrapping_key_id?: string;
  material_iv?: string;
  origin?: string;
};

export type ActivationUpdateInput = {
  mode: "immediate" | "pre-active" | "scheduled";
  activation_date?: string;
};

export type TagItem = {
  tenant_id: string;
  name: string;
  color: string;
  is_system: boolean;
  usage_count?: number;
  created_by?: string;
};

export type KeyVersionItem = {
  id: string;
  version: number;
  status: string;
  kcv: string;
  created_at?: string;
};

export type EncryptResult = {
  ciphertext: string;
  iv: string;
  version: number;
  keyId: string;
  kcv?: string | undefined;
};

export type DecryptResult = {
  plaintext: string;
  plaintextBase64: string;
  version: number;
  keyId: string;
};

export type HashResult = {
  algorithm: string;
  digestBase64: string;
};

export type RandomResult = {
  bytesBase64: string;
  length: number;
  source: string;
};

export type DeriveResult = {
  keyId: string;
  version: number;
  algorithm: string;
  lengthBits: number;
  derivedKeyBase64: string;
};

export type KEMResult = {
  keyId: string;
  version: number;
  algorithm: string;
  sharedSecretBase64: string;
  encapsulatedKeyBase64?: string;
  iv?: string;
};

export type TextEncoding = "utf-8" | "base64" | "hex";

export type ExportKeyInput = {
  wrapping_key_id?: string;
  export_mode?: "wrapped" | "public-plaintext";
};

export type EncryptInputOptions = {
  inputEncoding?: TextEncoding;
  iv?: string;
  ivEncoding?: "base64" | "hex";
  ivMode?: "internal" | "external" | "deterministic";
  aad?: string;
  aadEncoding?: TextEncoding;
  referenceId?: string;
};

export type DecryptInputOptions = {
  inputEncoding?: "base64" | "hex";
  outputEncoding?: TextEncoding;
  aad?: string;
  aadEncoding?: TextEncoding;
};

export type SignInputOptions = {
  inputEncoding?: TextEncoding;
  algorithm?: string;
};

export type VerifyInputOptions = {
  inputEncoding?: TextEncoding;
  algorithm?: string;
};

function encodeUtf8Base64(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let raw = "";
  for (const b of bytes) {
    raw += String.fromCharCode(b);
  }
  return btoa(raw);
}

function decodeUtf8Base64(value: string): string {
  const raw = atob(value);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) {
    bytes[i] = raw.charCodeAt(i);
  }
  return new TextDecoder().decode(bytes);
}

function bytesToBase64(bytes: Uint8Array): string {
  let raw = "";
  for (const b of bytes) {
    raw += String.fromCharCode(b);
  }
  return btoa(raw);
}

function base64ToBytes(value: string): Uint8Array {
  const raw = atob(value);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) {
    out[i] = raw.charCodeAt(i);
  }
  return out;
}

function hexToBytes(value: string): Uint8Array {
  const normalized = value.replace(/[\s-]/g, "").toLowerCase();
  if (!normalized || normalized.length % 2 !== 0 || !/^[0-9a-f]+$/.test(normalized)) {
    throw new Error("Invalid hex input");
  }
  const out = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < normalized.length; i += 2) {
    out[i / 2] = parseInt(normalized.slice(i, i + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function encodeInputToBase64(value: string, encoding: TextEncoding): string {
  const mode = encoding || "utf-8";
  if (mode === "base64") {
    const trimmed = String(value || "").trim();
    if (!trimmed) {
      return "";
    }
    base64ToBytes(trimmed);
    return trimmed;
  }
  if (mode === "hex") {
    return bytesToBase64(hexToBytes(String(value || "")));
  }
  return encodeUtf8Base64(String(value || ""));
}

export function decodeOutputFromBase64(value: string, encoding: TextEncoding): string {
  const mode = encoding || "utf-8";
  if (mode === "base64") {
    return value;
  }
  if (mode === "hex") {
    return bytesToHex(base64ToBytes(value));
  }
  return decodeUtf8Base64(value);
}

async function parseError(response: Response): Promise<string> {
  const fallback = `Request failed (${response.status})`;
  try {
    const payload = (await response.json()) as APIError;
    return payload.error?.message || fallback;
  } catch {
    return fallback;
  }
}

async function apiRequest<T>(session: AuthSession, path: string, init?: RequestInit): Promise<T> {
  const response = await serviceRequestRaw(session, "keycore", path, init, 20_000);
  if (!response.ok) {
    throw new Error(await parseError(response));
  }
  return (await response.json()) as T;
}

export async function listKeys(
  session: AuthSession,
  options?: {
    limit?: number;
    offset?: number;
    includeDeleted?: boolean;
  }
): Promise<KeyItem[]> {
  const limit = Math.max(1, Math.min(5000, Math.trunc(Number(options?.limit || 2000))));
  const offset = Math.max(0, Math.trunc(Number(options?.offset || 0)));
  const includeDeleted = Boolean(options?.includeDeleted);
  const payload = await apiRequest<APIKeysResponse>(
    session,
    `/keys?tenant_id=${encodeURIComponent(session.tenantId)}&limit=${limit}&offset=${offset}&include_deleted=${includeDeleted ? "true" : "false"}`
  );
  return payload.items || [];
}

export type PaginatedKeysResponse = {
  items: KeyItem[];
  next_cursor?: { after_created_at: string; after_id: string };
  has_more: boolean;
};

export async function listKeysPaginated(
  session: AuthSession,
  options?: {
    limit?: number;
    afterCreatedAt?: string;
    afterId?: string;
    includeDeleted?: boolean;
  }
): Promise<PaginatedKeysResponse> {
  const limit = Math.max(1, Math.min(1000, Math.trunc(Number(options?.limit || 100))));
  const includeDeleted = Boolean(options?.includeDeleted);
  let url = `/keys?tenant_id=${encodeURIComponent(session.tenantId)}&limit=${limit}&include_deleted=${includeDeleted ? "true" : "false"}`;
  if (options?.afterCreatedAt && options?.afterId) {
    url += `&after_created_at=${encodeURIComponent(options.afterCreatedAt)}&after_id=${encodeURIComponent(options.afterId)}`;
  }
  const payload = await apiRequest<PaginatedKeysResponse>(session, url);
  const result: PaginatedKeysResponse = {
    items: payload.items || [],
    has_more: Boolean(payload.has_more),
  };
  if (payload.next_cursor) {
    result.next_cursor = payload.next_cursor;
  }
  return result;
}

export async function createKey(session: AuthSession, input: CreateKeyInput): Promise<APICreateKeyResponse> {
  return apiRequest<APICreateKeyResponse>(session, "/keys", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      name: input.name,
      algorithm: input.algorithm,
      key_type: input.key_type,
      purpose: input.purpose,
      tags: Array.isArray(input.tags) ? input.tags : [],
      labels: input.labels || {},
      export_allowed: Boolean(input.export_allowed),
      activation_mode: input.activation_mode || "immediate",
      activation_date: input.activation_date,
      iv_mode: input.iv_mode,
      created_by: input.created_by,
      ops_limit: Number(input.ops_limit || 0),
      ops_limit_window: input.ops_limit_window || "total",
      approval_required: Boolean(input.approval_required)
    })
  });
}

export async function formKey(session: AuthSession, input: FormKeyInput): Promise<APIFormKeyResponse> {
  return apiRequest<APIFormKeyResponse>(session, "/keys/form", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      name: input.name,
      algorithm: input.algorithm,
      key_type: input.key_type,
      purpose: input.purpose,
      tags: Array.isArray(input.tags) ? input.tags : [],
      labels: input.labels || {},
      export_allowed: Boolean(input.export_allowed),
      activation_mode: input.activation_mode || "immediate",
      activation_date: input.activation_date,
      iv_mode: input.iv_mode,
      created_by: input.created_by,
      ops_limit: Math.trunc(Number(input.ops_limit || 0)),
      ops_limit_window: input.ops_limit_window || "total",
      approval_required: Boolean(input.approval_required),
      component_mode: input.component_mode,
      parity: input.parity || "none",
      components: Array.isArray(input.components) ? input.components.map((component) => ({
        material: component.material || "",
        wrapped_material: component.wrapped_material || "",
        material_iv: component.material_iv || "",
        wrapping_key_id: component.wrapping_key_id || ""
      })) : []
    })
  });
}

export async function importKey(session: AuthSession, input: ImportKeyInput): Promise<APICreateKeyResponse> {
  return apiRequest<APICreateKeyResponse>(session, "/keys/import", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      name: input.name,
      algorithm: input.algorithm || "",
      key_type: input.key_type || "",
      purpose: input.purpose || "",
      tags: Array.isArray(input.tags) ? input.tags : [],
      labels: input.labels || {},
      export_allowed: Boolean(input.export_allowed),
      activation_mode: input.activation_mode || "immediate",
      activation_date: input.activation_date,
      iv_mode: input.iv_mode || "internal",
      created_by: input.created_by || session.username || "dashboard-user",
      ops_limit: Math.trunc(Number(input.ops_limit || 0)),
      ops_limit_window: input.ops_limit_window || "total",
      approval_required: Boolean(input.approval_required),
      material: input.material,
      expected_kcv: input.expected_kcv || "",
      import_method: input.import_method || "raw",
      import_password: input.import_password || "",
      wrapping_key_id: input.wrapping_key_id || "",
      material_iv: input.material_iv || "",
      origin: input.origin || ""
    })
  });
}

export async function rotateKey(
  session: AuthSession,
  keyId: string,
  reason = "manual",
  oldVersionAction: "deactivate" | "keep-active" | "destroy" = "deactivate"
): Promise<void> {
  await apiRequest<Record<string, unknown>>(session, `/keys/${encodeURIComponent(keyId)}/rotate?tenant_id=${encodeURIComponent(session.tenantId)}`, {
    method: "POST",
    body: JSON.stringify({ reason, old_version_action: oldVersionAction })
  });
}

export async function listKeyVersions(session: AuthSession, keyId: string): Promise<KeyVersionItem[]> {
  const payload = await apiRequest<APIKeyVersionsResponse>(
    session,
    `/keys/${encodeURIComponent(keyId)}/versions?tenant_id=${encodeURIComponent(session.tenantId)}`
  );
  return Array.isArray(payload.items) ? payload.items : [];
}

export async function encryptData(
  session: AuthSession,
  keyId: string,
  plaintext: string,
  options?: EncryptInputOptions
): Promise<EncryptResult> {
  const inputEncoding = options?.inputEncoding || "utf-8";
  const aadEncoding = options?.aadEncoding || "utf-8";
  let ivPayload = "";
  if (options?.iv) {
    if ((options.ivEncoding || "base64") === "hex") {
      ivPayload = encodeInputToBase64(options.iv, "hex");
    } else {
      ivPayload = String(options.iv || "").trim();
      if (ivPayload) {
        base64ToBytes(ivPayload);
      }
    }
  }
  let aadPayload = "";
  if (typeof options?.aad === "string" && options.aad.length > 0) {
    aadPayload = encodeInputToBase64(options.aad, aadEncoding);
  }
  const payload = await apiRequest<APIEncryptResponse>(session, `/keys/${encodeURIComponent(keyId)}/encrypt`, {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      plaintext: encodeInputToBase64(plaintext, inputEncoding),
      iv: ivPayload,
      iv_mode: options?.ivMode || "",
      aad: aadPayload,
      reference_id: options?.referenceId || ""
    })
  });
  return {
    ciphertext: payload.ciphertext,
    iv: payload.iv,
    version: payload.version,
    keyId: payload.key_id,
    kcv: payload.kcv
  };
}

export async function decryptData(
  session: AuthSession,
  keyId: string,
  ciphertext: string,
  iv: string,
  options?: DecryptInputOptions
): Promise<DecryptResult> {
  const inputEncoding = options?.inputEncoding || "base64";
  const outputEncoding = options?.outputEncoding || "utf-8";
  const aadEncoding = options?.aadEncoding || "utf-8";
  const ciphertextPayload = inputEncoding === "hex" ? encodeInputToBase64(ciphertext, "hex") : String(ciphertext || "").trim();
  const ivPayload = inputEncoding === "hex" ? encodeInputToBase64(iv, "hex") : String(iv || "").trim();
  let aadPayload = "";
  if (typeof options?.aad === "string" && options.aad.length > 0) {
    aadPayload = encodeInputToBase64(options.aad, aadEncoding);
  }
  const payload = await apiRequest<APIDecryptResponse>(session, `/keys/${encodeURIComponent(keyId)}/decrypt`, {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ciphertext: ciphertextPayload,
      iv: ivPayload,
      aad: aadPayload
    })
  });
  return {
    plaintext: decodeOutputFromBase64(payload.plaintext, outputEncoding),
    plaintextBase64: payload.plaintext,
    version: payload.version,
    keyId: payload.key_id
  };
}

export async function signData(
  session: AuthSession,
  keyId: string,
  data: string,
  options?: SignInputOptions
): Promise<APISignResponse> {
  const inputEncoding = options?.inputEncoding || "utf-8";
  return apiRequest<APISignResponse>(session, `/keys/${encodeURIComponent(keyId)}/sign`, {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      data: encodeInputToBase64(data, inputEncoding),
      algorithm: options?.algorithm || "hmac-sha256"
    })
  });
}

export async function verifyData(
  session: AuthSession,
  keyId: string,
  data: string,
  signature: string,
  options?: VerifyInputOptions
): Promise<APIVerifyResponse> {
  const inputEncoding = options?.inputEncoding || "utf-8";
  return apiRequest<APIVerifyResponse>(session, `/keys/${encodeURIComponent(keyId)}/verify`, {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      data: encodeInputToBase64(data, inputEncoding),
      signature: String(signature || "").trim(),
      algorithm: options?.algorithm || "hmac-sha256"
    })
  });
}

export async function hashData(
  session: AuthSession,
  input: string,
  algorithm:
    | "sha-256"
    | "sha-384"
    | "sha-512"
    | "sha3-256"
    | "sha3-384"
    | "sha3-512"
    | "blake2b-256",
  inputEncoding: TextEncoding,
  referenceId = ""
): Promise<HashResult> {
  const payload = await apiRequest<APIHashResponse>(session, "/crypto/hash", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      algorithm,
      input: encodeInputToBase64(input, inputEncoding || "utf-8"),
      reference_id: referenceId
    })
  });
  return {
    algorithm: payload.algorithm,
    digestBase64: payload.digest
  };
}

export async function randomBytes(
  session: AuthSession,
  length: number,
  source: "kms-csprng" | "hsm-trng" | "qkd-seeded-csprng",
  referenceId = ""
): Promise<RandomResult> {
  const payload = await apiRequest<APIRandomResponse>(session, "/crypto/random", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      length: Math.trunc(Number(length || 0)),
      source,
      reference_id: referenceId
    })
  });
  return {
    bytesBase64: payload.bytes,
    length: payload.length,
    source: payload.source
  };
}

export async function deriveKey(
  session: AuthSession,
  keyId: string,
  input: {
    algorithm: "hkdf-sha256" | "hkdf-sha384" | "hkdf-sha512";
    lengthBits: number;
    info?: string;
    salt?: string;
    infoEncoding?: TextEncoding;
    saltEncoding?: TextEncoding;
    referenceId?: string;
  }
): Promise<DeriveResult> {
  const payload = await apiRequest<APIDeriveResponse>(session, `/keys/${encodeURIComponent(keyId)}/derive`, {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      algorithm: input.algorithm,
      length_bits: Math.trunc(Number(input.lengthBits || 0)),
      info: input.info ? encodeInputToBase64(input.info, input.infoEncoding || "utf-8") : "",
      salt: input.salt ? encodeInputToBase64(input.salt, input.saltEncoding || "utf-8") : "",
      reference_id: input.referenceId || ""
    })
  });
  return {
    keyId: payload.key_id,
    version: payload.version,
    algorithm: payload.algorithm,
    lengthBits: payload.length_bits,
    derivedKeyBase64: payload.derived_key
  };
}

export async function kemEncapsulate(
  session: AuthSession,
  keyId: string,
  input?: {
    algorithm?: "ml-kem-768" | "ml-kem-1024";
    referenceId?: string;
  }
): Promise<KEMResult> {
  const payload = await apiRequest<APIKEMResponse>(session, `/keys/${encodeURIComponent(keyId)}/kem/encapsulate`, {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      algorithm: input?.algorithm || "ml-kem-768",
      reference_id: input?.referenceId || ""
    })
  });
  return {
    keyId: payload.key_id,
    version: payload.version,
    algorithm: payload.algorithm,
    sharedSecretBase64: payload.shared_secret,
    encapsulatedKeyBase64: payload.encapsulated_key || "",
    iv: payload.iv || ""
  };
}

export async function kemDecapsulate(
  session: AuthSession,
  keyId: string,
  input: {
    encapsulatedKeyBase64: string;
    inputEncoding?: "base64" | "hex";
    algorithm?: "ml-kem-768" | "ml-kem-1024";
    referenceId?: string;
  }
): Promise<KEMResult> {
  const encoding = input.inputEncoding || "base64";
  const payload = await apiRequest<APIKEMResponse>(session, `/keys/${encodeURIComponent(keyId)}/kem/decapsulate`, {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      algorithm: input.algorithm || "ml-kem-768",
      encapsulated_key:
        encoding === "hex" ? encodeInputToBase64(input.encapsulatedKeyBase64, "hex") : String(input.encapsulatedKeyBase64 || "").trim(),
      reference_id: input.referenceId || ""
    })
  });
  return {
    keyId: payload.key_id,
    version: payload.version,
    algorithm: payload.algorithm,
    sharedSecretBase64: payload.shared_secret,
    encapsulatedKeyBase64: payload.encapsulated_key || "",
    iv: payload.iv || ""
  };
}

export async function exportKey(
  session: AuthSession,
  keyId: string,
  input?: ExportKeyInput
): Promise<APIExportKeyResponse> {
  const mode = input?.export_mode || "wrapped";
  return apiRequest<APIExportKeyResponse>(
    session,
    `/keys/${encodeURIComponent(keyId)}/export?tenant_id=${encodeURIComponent(session.tenantId)}`,
    {
      method: "POST",
      body: JSON.stringify({
        wrapping_key_id: input?.wrapping_key_id || "",
        export_mode: mode
      })
    }
  );
}

export async function destroyKey(
  session: AuthSession,
  keyId: string,
  input?: DestroyKeyInput
): Promise<APIKeyStatusResponse> {
  return apiRequest<APIKeyStatusResponse>(
    session,
    `/keys/${encodeURIComponent(keyId)}/destroy?tenant_id=${encodeURIComponent(session.tenantId)}`,
    {
      method: "POST",
      ...(input ? { body: JSON.stringify(input) } : {})
    }
  );
}

export async function activateKey(session: AuthSession, keyId: string): Promise<APIKeyStatusResponse> {
  return apiRequest<APIKeyStatusResponse>(
    session,
    `/keys/${encodeURIComponent(keyId)}/activate?tenant_id=${encodeURIComponent(session.tenantId)}`,
    { method: "POST" }
  );
}

export async function updateKeyActivation(
  session: AuthSession,
  keyId: string,
  input: ActivationUpdateInput
): Promise<APIKeyStatusResponse> {
  return apiRequest<APIKeyStatusResponse>(
    session,
    `/keys/${encodeURIComponent(keyId)}/activate?tenant_id=${encodeURIComponent(session.tenantId)}`,
    {
      method: "POST",
      body: JSON.stringify({
        mode: input.mode,
        activation_date: input.activation_date
      })
    }
  );
}

export async function deactivateKey(session: AuthSession, keyId: string): Promise<APIKeyStatusResponse> {
  return apiRequest<APIKeyStatusResponse>(
    session,
    `/keys/${encodeURIComponent(keyId)}/deactivate?tenant_id=${encodeURIComponent(session.tenantId)}`,
    { method: "POST" }
  );
}

export async function disableKey(session: AuthSession, keyId: string): Promise<APIKeyStatusResponse> {
  return apiRequest<APIKeyStatusResponse>(
    session,
    `/keys/${encodeURIComponent(keyId)}/disable?tenant_id=${encodeURIComponent(session.tenantId)}`,
    { method: "POST" }
  );
}

export async function setKeyUsageLimit(
  session: AuthSession,
  keyId: string,
  opsLimit: number,
  window: "total" | "daily" | "monthly"
): Promise<void> {
  await apiRequest<Record<string, unknown>>(
    session,
    `/keys/${encodeURIComponent(keyId)}/usage/limit?tenant_id=${encodeURIComponent(session.tenantId)}`,
    {
      method: "PUT",
      body: JSON.stringify({
        ops_limit: Math.trunc(Number(opsLimit || 0)),
        window
      })
    }
  );
}

export async function setKeyExportPolicy(
  session: AuthSession,
  keyId: string,
  exportAllowed: boolean
): Promise<void> {
  await apiRequest<Record<string, unknown>>(
    session,
    `/keys/${encodeURIComponent(keyId)}/export-policy?tenant_id=${encodeURIComponent(session.tenantId)}`,
    {
      method: "PUT",
      body: JSON.stringify({
        export_allowed: Boolean(exportAllowed)
      })
    }
  );
}

export async function getKeyAccessPolicy(
  session: AuthSession,
  keyId: string
): Promise<KeyAccessPolicy> {
  const payload = await apiRequest<APIGetKeyAccessPolicyResponse>(
    session,
    `/keys/${encodeURIComponent(keyId)}/access-policy?tenant_id=${encodeURIComponent(session.tenantId)}`
  );
  return payload.policy || { tenant_id: session.tenantId, key_id: keyId, grants: [] };
}

export async function setKeyAccessPolicy(
  session: AuthSession,
  keyId: string,
  grants: KeyAccessGrant[],
  updatedBy?: string
): Promise<void> {
  await apiRequest<Record<string, unknown>>(
    session,
    `/keys/${encodeURIComponent(keyId)}/access-policy?tenant_id=${encodeURIComponent(session.tenantId)}`,
    {
      method: "PUT",
      body: JSON.stringify({
        grants: Array.isArray(grants) ? grants : [],
        updated_by: String(updatedBy || "").trim()
      })
    }
  );
}

export async function getKeyAccessSettings(session: AuthSession): Promise<KeyAccessSettings> {
  const payload = await apiRequest<APIGetAccessSettingsResponse>(
    session,
    `/access/settings?tenant_id=${encodeURIComponent(session.tenantId)}`
  );
  return payload.settings;
}

export async function updateKeyAccessSettings(
  session: AuthSession,
  input: Partial<KeyAccessSettings>
): Promise<KeyAccessSettings> {
  const payload = await apiRequest<APIGetAccessSettingsResponse>(
    session,
    `/access/settings?tenant_id=${encodeURIComponent(session.tenantId)}`,
    {
      method: "PUT",
      body: JSON.stringify(input || {})
    }
  );
  return payload.settings;
}

export async function listKeyInterfacePolicies(
  session: AuthSession,
  interfaceName = ""
): Promise<KeyInterfaceSubjectPolicy[]> {
  const q = interfaceName ? `&interface=${encodeURIComponent(interfaceName)}` : "";
  const payload = await apiRequest<APIListInterfacePoliciesResponse>(
    session,
    `/access/interface-policies?tenant_id=${encodeURIComponent(session.tenantId)}${q}`
  );
  return Array.isArray(payload.items) ? payload.items : [];
}

export async function upsertKeyInterfacePolicy(
  session: AuthSession,
  input: Partial<KeyInterfaceSubjectPolicy>
): Promise<KeyInterfaceSubjectPolicy> {
  const payload = await apiRequest<APIUpsertInterfacePolicyResponse>(
    session,
    `/access/interface-policies?tenant_id=${encodeURIComponent(session.tenantId)}`,
    {
      method: "POST",
      body: JSON.stringify(input || {})
    }
  );
  return payload.policy;
}

export async function deleteKeyInterfacePolicy(session: AuthSession, id: string): Promise<void> {
  await apiRequest<Record<string, unknown>>(
    session,
    `/access/interface-policies/${encodeURIComponent(id)}?tenant_id=${encodeURIComponent(session.tenantId)}`,
    { method: "DELETE" }
  );
}

export async function listKeyInterfacePorts(session: AuthSession): Promise<KeyInterfacePort[]> {
  const payload = await apiRequest<APIListInterfacePortsResponse>(
    session,
    `/access/interface-ports?tenant_id=${encodeURIComponent(session.tenantId)}`
  );
  return Array.isArray(payload.items) ? payload.items : [];
}

export async function upsertKeyInterfacePort(
  session: AuthSession,
  input: Partial<KeyInterfacePort>
): Promise<KeyInterfacePort> {
  const payload = await apiRequest<APIUpsertInterfacePortResponse>(
    session,
    `/access/interface-ports?tenant_id=${encodeURIComponent(session.tenantId)}`,
    {
      method: "POST",
      body: JSON.stringify(input || {})
    }
  );
  return payload.item;
}

export async function deleteKeyInterfacePort(session: AuthSession, interfaceName: string): Promise<void> {
  await apiRequest<Record<string, unknown>>(
    session,
    `/access/interface-ports/${encodeURIComponent(interfaceName)}?tenant_id=${encodeURIComponent(session.tenantId)}`,
    { method: "DELETE" }
  );
}

export async function listKeyAccessGroups(session: AuthSession): Promise<KeyAccessGroup[]> {
  const payload = await apiRequest<APIListAccessGroupsResponse>(
    session,
    `/access/groups?tenant_id=${encodeURIComponent(session.tenantId)}`
  );
  return Array.isArray(payload.items) ? payload.items : [];
}

export async function createKeyAccessGroup(
  session: AuthSession,
  input: { name: string; description?: string; created_by?: string }
): Promise<KeyAccessGroup> {
  const payload = await apiRequest<APICreateAccessGroupResponse>(
    session,
    `/access/groups?tenant_id=${encodeURIComponent(session.tenantId)}`,
    {
      method: "POST",
      body: JSON.stringify({
        name: String(input?.name || "").trim(),
        description: String(input?.description || "").trim(),
        created_by: String(input?.created_by || "").trim()
      })
    }
  );
  return payload.group;
}

export async function deleteKeyAccessGroup(session: AuthSession, groupId: string): Promise<void> {
  await apiRequest<Record<string, unknown>>(
    session,
    `/access/groups/${encodeURIComponent(groupId)}?tenant_id=${encodeURIComponent(session.tenantId)}`,
    { method: "DELETE" }
  );
}

export async function setKeyAccessGroupMembers(
  session: AuthSession,
  groupId: string,
  userIds: string[]
): Promise<void> {
  await apiRequest<Record<string, unknown>>(
    session,
    `/access/groups/${encodeURIComponent(groupId)}/members?tenant_id=${encodeURIComponent(session.tenantId)}`,
    {
      method: "PUT",
      body: JSON.stringify({
        user_ids: Array.isArray(userIds) ? userIds : []
      })
    }
  );
}

export async function listTags(session: AuthSession): Promise<TagItem[]> {
  const payload = await apiRequest<APITagsResponse>(
    session,
    `/tags?tenant_id=${encodeURIComponent(session.tenantId)}`
  );
  return Array.isArray(payload.items) ? payload.items : [];
}

export async function upsertTag(
  session: AuthSession,
  name: string,
  color: string
): Promise<TagItem> {
  const payload = await apiRequest<APIUpsertTagResponse>(
    session,
    `/tags?tenant_id=${encodeURIComponent(session.tenantId)}`,
    {
      method: "POST",
      body: JSON.stringify({
        name,
        color
      })
    }
  );
  return payload.tag;
}

export async function deleteTag(session: AuthSession, name: string): Promise<void> {
  await apiRequest<Record<string, unknown>>(
    session,
    `/tags/${encodeURIComponent(name)}?tenant_id=${encodeURIComponent(session.tenantId)}`,
    { method: "DELETE" }
  );
}
