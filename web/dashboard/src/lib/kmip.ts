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
  object_types: string[];
};

type ProfilesResponse = { items: KMIPClientProfile[] };
type ClientsResponse = { items: KMIPClient[] };
type ProfileResponse = { profile: KMIPClientProfile };
type CreateClientResponse = { client: KMIPClient; issued_cert_pem?: string; issued_key_pem?: string };
type CapabilitiesResponse = { capabilities: KMIPCapabilities };

function tenantQuery(session: AuthSession): string {
  return `tenant_id=${encodeURIComponent(session.tenantId)}`;
}

export async function listKMIPProfiles(session: AuthSession): Promise<KMIPClientProfile[]> {
  const out = await serviceRequest<ProfilesResponse>(session, "kmip", `/kmip/profiles?${tenantQuery(session)}`);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function getKMIPCapabilities(session: AuthSession): Promise<KMIPCapabilities> {
  const out = await serviceRequest<CapabilitiesResponse>(session, "kmip", `/kmip/capabilities?${tenantQuery(session)}`);
  return out?.capabilities || {
    library: "github.com/ovh/kmip-go",
    library_version: "v0.7.2",
    protocol: "TTLV over TLS",
    port: "5696",
    highest_supported_version: "",
    supported_versions: [],
    operations: [],
    object_types: []
  };
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
