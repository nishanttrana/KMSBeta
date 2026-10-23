import type { AuthSession } from "./auth";
import { serviceRequest, serviceRequestRaw } from "./serviceApi";

// SSH certificate authorities (certs service, 13.49.0-beta;
// docs/CERTIFICATES.md "SSH certificates").

export type SSHCA = {
  id: string;
  name: string;
  algorithm: string;
  key_backend: string;
  public_key: string;
  fingerprint: string;
  cert_types: string[];
  allowed_principals: string[];
  max_validity_seconds: number;
  default_extensions: string[];
  status: string;
  created_by: string;
  created_at: string;
};

export type SSHTrust = { trusted_user_ca_keys: string; known_hosts: string };

export type SSHCertificate = {
  id: string;
  ca_id: string;
  serial: string;
  cert_type: string;
  key_id: string;
  principals: string[];
  key_type: string;
  key_fingerprint: string;
  extensions: string[];
  critical_options: Record<string, string>;
  valid_after: string;
  valid_before: string;
  issued_by: string;
  issued_at: string;
  revoked_at?: string;
  revoked_by?: string;
  revoke_reason?: string;
};

export type CreateSSHCAInput = {
  name: string;
  algorithm: string;
  key_backend: string;
  cert_types: string[];
  allowed_principals: string[];
  max_validity_seconds: number;
  default_extensions: string[];
};

export type SignSSHInput = {
  public_key: string;
  cert_type: string;
  principals: string[];
  valid_seconds: number;
  key_id?: string | undefined;
  extensions?: string[] | undefined;
  force_command?: string | undefined;
  source_address?: string[] | undefined;
};

export const SSH_EXTENSIONS = ["permit-pty", "permit-port-forwarding", "permit-agent-forwarding", "permit-X11-forwarding", "permit-user-rc"];

export const hours = (seconds: number) => (seconds % 3600 === 0 ? `${seconds / 3600} h` : `${Math.round(seconds / 60)} min`);

// lines splits a list typed one per line or comma-separated.
export const lines = (text: string) => text.split(/[\n,]/).map((s) => s.trim()).filter(Boolean);

const q = (session: AuthSession) => `tenant_id=${encodeURIComponent(session.tenantId)}`;

export async function listSSHCAs(session: AuthSession): Promise<SSHCA[]> {
  const out = await serviceRequest<{ items?: SSHCA[] }>(session, "certs", `/certs/ssh/cas?${q(session)}`);
  if (!Array.isArray(out?.items)) throw new Error("certs returned no SSH CA list");
  return out.items;
}

export async function getSSHCA(session: AuthSession, id: string): Promise<{ ca: SSHCA; trust: SSHTrust }> {
  const out = await serviceRequest<{ ssh_ca: SSHCA; trust: SSHTrust }>(session, "certs", `/certs/ssh/cas/${encodeURIComponent(id)}?${q(session)}`);
  return { ca: out.ssh_ca, trust: out.trust };
}

export async function createSSHCA(session: AuthSession, input: CreateSSHCAInput): Promise<SSHCA> {
  const out = await serviceRequest<{ ssh_ca: SSHCA }>(session, "certs", `/certs/ssh/cas?${q(session)}`, { method: "POST", body: JSON.stringify(input) });
  return out.ssh_ca;
}

export async function updateSSHCA(
  session: AuthSession,
  id: string,
  change: { status?: string; allowed_principals?: string[]; max_validity_seconds?: number; cert_types?: string[]; default_extensions?: string[] }
): Promise<SSHCA> {
  const out = await serviceRequest<{ ssh_ca: SSHCA }>(session, "certs", `/certs/ssh/cas/${encodeURIComponent(id)}?${q(session)}`, { method: "PUT", body: JSON.stringify(change) });
  return out.ssh_ca;
}

export async function signSSH(session: AuthSession, caID: string, input: SignSSHInput): Promise<{ certificate: string; record: SSHCertificate }> {
  const out = await serviceRequest<{ certificate: string; ssh_certificate: SSHCertificate }>(session, "certs", `/certs/ssh/cas/${encodeURIComponent(caID)}/sign?${q(session)}`, {
    method: "POST",
    body: JSON.stringify(input)
  });
  return { certificate: out.certificate, record: out.ssh_certificate };
}

export async function listSSHCertificates(session: AuthSession, caID: string): Promise<SSHCertificate[]> {
  const out = await serviceRequest<{ items?: SSHCertificate[] }>(session, "certs", `/certs/ssh/cas/${encodeURIComponent(caID)}/certificates?${q(session)}`);
  if (!Array.isArray(out?.items)) throw new Error("certs returned no SSH certificate list");
  return out.items;
}

export async function revokeSSHCertificate(session: AuthSession, id: string, reason: string): Promise<SSHCertificate> {
  const out = await serviceRequest<{ ssh_certificate: SSHCertificate }>(session, "certs", `/certs/ssh/certificates/${encodeURIComponent(id)}/revoke?${q(session)}`, {
    method: "POST",
    body: JSON.stringify({ reason })
  });
  return out.ssh_certificate;
}

// downloadSSHKRL saves the CA's key revocation list for sshd's RevokedKeys.
export async function downloadSSHKRL(session: AuthSession, ca: SSHCA): Promise<void> {
  const res = await serviceRequestRaw(session, "certs", `/certs/ssh/cas/${encodeURIComponent(ca.id)}/krl?${q(session)}`);
  if (!res.ok) throw new Error(`KRL download failed (${res.status})`);
  const url = URL.createObjectURL(await res.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = `${ca.name.replace(/[^A-Za-z0-9._-]/g, "_")}.krl`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
