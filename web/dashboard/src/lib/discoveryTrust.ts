import type { AuthSession } from "./auth";
import type { CryptoAsset } from "./discovery";
import { serviceRequest } from "./serviceApi";

// Distrusted CAs (services/discovery/distrust.go): the platform's list (the
// CA keys Go refuses) and the tenant's own, each with how many discovered
// certificates run through it, and those certificates.

export type DistrustedCA = {
  spki_sha256: string;
  label: string;
  source: "platform" | "tenant";
  added_by?: string;
  created_at?: string;
  affected: number;
};

export type DistrustFinding = { asset: CryptoAsset; matches: DistrustedCA[] };

const q = (session: AuthSession) => `tenant_id=${encodeURIComponent(session.tenantId)}`;

export async function listDistrustedCAs(session: AuthSession): Promise<DistrustedCA[]> {
  const out = await serviceRequest<{ items?: DistrustedCA[] }>(session, "discovery", `/discovery/distrusted-cas?${q(session)}`);
  if (!Array.isArray(out?.items)) throw new Error("discovery returned no distrusted CA list");
  return out.items;
}

// Exactly the fields the route takes: a CA by its certificate, or by its
// key's SHA-256.
export async function addDistrustedCA(session: AuthSession, input: { label: string; spki_sha256: string; certificate_pem: string }): Promise<DistrustedCA> {
  const out = await serviceRequest<{ distrusted_ca?: DistrustedCA }>(session, "discovery", `/discovery/distrusted-cas?${q(session)}`, {
    method: "POST",
    body: JSON.stringify({ label: input.label.trim(), spki_sha256: input.spki_sha256.trim(), certificate_pem: input.certificate_pem.trim() }),
  });
  if (!out?.distrusted_ca) throw new Error("discovery returned no distrusted CA");
  return out.distrusted_ca;
}

export async function removeDistrustedCA(session: AuthSession, spki: string): Promise<void> {
  await serviceRequest(session, "discovery", `/discovery/distrusted-cas/${encodeURIComponent(spki)}?${q(session)}`, { method: "DELETE" });
}

export type DistrustFindings = { total: number; chain_unrecorded: number; items: DistrustFinding[] };

export async function listDistrustFindings(session: AuthSession, opts: { spki?: string; limit: number; offset: number }): Promise<DistrustFindings> {
  const p = new URLSearchParams({ tenant_id: session.tenantId, limit: String(opts.limit), offset: String(opts.offset) });
  if (opts.spki) p.set("spki", opts.spki);
  const out = await serviceRequest<Partial<DistrustFindings>>(session, "discovery", `/discovery/distrusted?${p.toString()}`);
  if (typeof out?.total !== "number" || !Array.isArray(out.items)) throw new Error("discovery returned no findings");
  return { total: out.total, chain_unrecorded: Number(out.chain_unrecorded || 0), items: out.items };
}
