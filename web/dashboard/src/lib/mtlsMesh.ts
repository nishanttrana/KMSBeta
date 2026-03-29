import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export interface MeshService {
  id: string;
  name: string;
  namespace: string;
  endpoint: string;
  cert_id?: string;
  cert_cn?: string;
  cert_expiry?: string;
  cert_status: "valid" | "expiring" | "expired" | "missing";
  last_renewed_at?: string;
  auto_renew: boolean;
  renew_days_before: number;
  trust_anchors: string[];
  created_at: string;
  mtls_enabled: boolean;
}

export interface MeshCertificate {
  id: string;
  service_id: string;
  service_name: string;
  cn: string;
  san: string[];
  issuer: string;
  not_before: string;
  not_after: string;
  serial: string;
  fingerprint: string;
  key_algorithm: string;
  revoked: boolean;
  created_at: string;
}

export interface TrustAnchor {
  id: string;
  name: string;
  fingerprint: string;
  subject: string;
  not_before: string;
  not_after: string;
  services_count: number;
  created_at: string;
}

export interface MeshTopologyEdge {
  from_service: string;
  to_service: string;
  mtls_verified: boolean;
  last_handshake_at?: string;
}

export async function listServices(session: AuthSession): Promise<MeshService[]> {
  const res = await serviceRequest<any>(session, "certs", "/mesh/services");
  return res.items ?? [];
}

export async function registerService(session: AuthSession, data: Partial<MeshService>): Promise<MeshService> {
  return serviceRequest<MeshService>(session, "certs", "/mesh/services", { method: "POST", body: JSON.stringify(data) });
}

export async function renewServiceCert(session: AuthSession, serviceId: string): Promise<MeshCertificate> {
  return serviceRequest<MeshCertificate>(session, "certs", `/mesh/services/${serviceId}/renew`, { method: "POST" });
}

export async function listCertificates(session: AuthSession): Promise<MeshCertificate[]> {
  const res = await serviceRequest<any>(session, "certs", "/mesh/certificates");
  return res.items ?? [];
}

export async function listTrustAnchors(session: AuthSession): Promise<TrustAnchor[]> {
  const res = await serviceRequest<any>(session, "certs", "/mesh/trust-anchors");
  return res.items ?? [];
}

export async function getTopology(session: AuthSession): Promise<MeshTopologyEdge[]> {
  return serviceRequest<MeshTopologyEdge[]>(session, "certs", "/mesh/topology");
}
