import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export type KMIPClientProfile = {
  id: string;
  tenant_id: string;
  name: string;
  ca_id: string;
  username_location: string;
  subject_field_to_modify: string;
  do_not_modify_subject_dn: boolean;
  certificate_duration_days: number;
  role: string;
  metadata_json: string;
  created_at?: string;
  updated_at?: string;
};

export type KMIPClient = {
  id: string;
  tenant_id: string;
  profile_id?: string;
  name: string;
  role: string;
  status: string;
  enrollment_mode: "internal" | "external";
  registration_token: string;
  cert_id?: string;
  cert_subject: string;
  cert_issuer: string;
  cert_serial: string;
  cert_fingerprint_sha256: string;
  cert_not_before?: string;
  cert_not_after?: string;
  certificate_pem?: string;
  ca_bundle_pem?: string;
  metadata_json?: string;
  created_at?: string;
  updated_at?: string;
};

export type CreateKMIPProfileInput = {
  name: string;
  ca_id: string;
  username_location?: string;
  subject_field_to_modify?: string;
  do_not_modify_subject_dn?: boolean;
  certificate_duration_days?: number;
  role?: string;
  metadata_json?: string;
};

export type CreateKMIPClientInput = {
  name: string;
  profile_id?: string;
  role?: string;
  registration_token?: string;
  enrollment_mode: "internal" | "external";
  csr_pem?: string;
  certificate_pem?: string;
  private_key_pem?: string;
  ca_bundle_pem?: string;
  common_name?: string;
  metadata_json?: string;
};

export type CreateKMIPClientResult = {
  client: KMIPClient;
  issued_cert_pem?: string;
  issued_key_pem?: string;
};

export type KMIPCapabilities = {
  library: string;
  library_version: string;
  protocol: string;
  port: string;
  highest_supported_version: string;
  supported_versions: string[];
  operations: string[];
  implemented_operations?: string[];
  unimplemented_operations?: string[];
  object_types: string[];
  implemented_object_types?: string[];
  unimplemented_object_types?: string[];
  auth_modes?: string[];
  interoperability_scope?: string[];
  integration_targets?: string[];
  integration_note?: string;
};

export type KMIPInteropTarget = {
  id: string;
  tenant_id: string;
  name: string;
  vendor: string;
  endpoint: string;
  server_name: string;
  expected_min_version: string;
  test_key_operation: boolean;
  has_ca_pem: boolean;
  has_client_cert_pem: boolean;
  has_client_key_pem: boolean;
  last_status: string;
  last_error: string;
  last_report_json: string;
  last_checked_at?: string;
  created_at?: string;
  updated_at?: string;
};

export type CreateKMIPInteropTargetInput = {
  name: string;
  vendor: string;
  endpoint: string;
  server_name?: string;
  expected_min_version?: string;
  test_key_operation?: boolean;
  ca_pem: string;
  client_cert_pem: string;
  client_key_pem: string;
};

export type KMIPInteropValidationResult = {
  target_id: string;
  vendor: string;
  endpoint: string;
  verified: boolean;
  handshake_ok: boolean;
  discover_versions_ok: boolean;
  query_ok: boolean;
  key_operation_ok: boolean;
  roundtrip_ok: boolean;
  negotiated_version: string;
  discovered_versions: string[];
  latency_ms: number;
  error: string;
  checked_at?: string;
};

type ProfilesResponse = { items: KMIPClientProfile[] };
type ClientsResponse = { items: KMIPClient[] };
type ProfileResponse = { profile: KMIPClientProfile };
type CreateClientResponse = { client: KMIPClient; issued_cert_pem?: string; issued_key_pem?: string };
type CapabilitiesResponse = { capabilities: KMIPCapabilities };
type InteropTargetsResponse = { items: KMIPInteropTarget[] };
type InteropTargetResponse = { target: KMIPInteropTarget };
type InteropValidationResponse = {
  target: KMIPInteropTarget;
  result: KMIPInteropValidationResult;
};

const DEFAULT_KMIP_CAPABILITIES: KMIPCapabilities = {
  library: "github.com/ovh/kmip-go",
  library_version: "v0.7.2",
  protocol: "TTLV over TLS",
  port: "5696",
  highest_supported_version: "3.2",
  supported_versions: ["3.2", "3.1", "3.0", "2.2", "2.1", "2.0", "1.4", "1.3", "1.2", "1.1", "1.0"],
  operations: [],
  implemented_operations: [],
  unimplemented_operations: [],
  object_types: [],
  implemented_object_types: [],
  unimplemented_object_types: [],
  auth_modes: ["mTLS client certificate"],
  interoperability_scope: ["Generic KMIP clients implementing KMIP 1.0-3.2 over TTLV/TLS"],
  integration_targets: [],
  integration_note: "Compatibility is protocol-level and requires client-side KMIP configuration."
};

function tenantQuery(session: AuthSession): string {
  return `tenant_id=${encodeURIComponent(session.tenantId)}`;
}

export async function listKMIPProfiles(session: AuthSession): Promise<KMIPClientProfile[]> {
  const out = await serviceRequest<ProfilesResponse>(session, "kmip", `/kmip/profiles?${tenantQuery(session)}`);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function getKMIPCapabilities(session: AuthSession): Promise<KMIPCapabilities> {
  try {
    const out = await serviceRequest<CapabilitiesResponse>(session, "kmip", `/kmip/capabilities?${tenantQuery(session)}`);
    return {
      ...DEFAULT_KMIP_CAPABILITIES,
      ...(out?.capabilities || {})
    };
  } catch {
    return { ...DEFAULT_KMIP_CAPABILITIES };
  }
}

export async function createKMIPProfile(session: AuthSession, input: CreateKMIPProfileInput): Promise<KMIPClientProfile> {
  const out = await serviceRequest<ProfileResponse>(session, "kmip", "/kmip/profiles", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return out.profile;
}

export async function deleteKMIPProfile(session: AuthSession, profileID: string): Promise<void> {
  const id = encodeURIComponent(String(profileID || "").trim());
  await serviceRequest(session, "kmip", `/kmip/profiles/${id}?${tenantQuery(session)}`, {
    method: "DELETE"
  });
}

export async function listKMIPClients(session: AuthSession): Promise<KMIPClient[]> {
  const out = await serviceRequest<ClientsResponse>(session, "kmip", `/kmip/clients?${tenantQuery(session)}`);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function createKMIPClient(session: AuthSession, input: CreateKMIPClientInput): Promise<CreateKMIPClientResult> {
  const out = await serviceRequest<CreateClientResponse>(session, "kmip", "/kmip/clients", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return {
    client: out.client,
    issued_cert_pem: out.issued_cert_pem || "",
    issued_key_pem: out.issued_key_pem || ""
  };
}

export async function deleteKMIPClient(session: AuthSession, clientID: string): Promise<void> {
  const id = encodeURIComponent(String(clientID || "").trim());
  await serviceRequest(session, "kmip", `/kmip/clients/${id}?${tenantQuery(session)}`, {
    method: "DELETE"
  });
}

export async function listKMIPInteropTargets(session: AuthSession): Promise<KMIPInteropTarget[]> {
  const out = await serviceRequest<InteropTargetsResponse>(session, "kmip", `/kmip/interop/targets?${tenantQuery(session)}`);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function createKMIPInteropTarget(session: AuthSession, input: CreateKMIPInteropTargetInput): Promise<KMIPInteropTarget> {
  const out = await serviceRequest<InteropTargetResponse>(session, "kmip", "/kmip/interop/targets", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      ...input
    })
  });
  return out.target;
}

export async function deleteKMIPInteropTarget(session: AuthSession, targetID: string): Promise<void> {
  const id = encodeURIComponent(String(targetID || "").trim());
  await serviceRequest(session, "kmip", `/kmip/interop/targets/${id}?${tenantQuery(session)}`, {
    method: "DELETE"
  });
}

export async function validateKMIPInteropTarget(session: AuthSession, targetID: string): Promise<InteropValidationResponse> {
  const id = encodeURIComponent(String(targetID || "").trim());
  return serviceRequest<InteropValidationResponse>(session, "kmip", `/kmip/interop/targets/${id}/validate?${tenantQuery(session)}`, {
    method: "POST"
  });
}
