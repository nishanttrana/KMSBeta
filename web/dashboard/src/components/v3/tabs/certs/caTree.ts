import { type ExpiryPolicy, matchesCertFilter } from "./certFilters";

// A CA's own certificates, counted with the tiles' predicates so a number in
// the hierarchy lists the same rows as the table filter it opens.
export type CAStats = { total: number; active: number; expiring: number; revoked: number };

export type CATree = {
  roots: any[];
  children: Record<string, any[]>;
  issued: Record<string, any[]>;
  stats: Record<string, CAStats>;
};

export function buildCATree(cas: any[], certs: any[], policy: ExpiryPolicy, now: number): CATree {
  const ids = new Set(cas.map((c) => String(c.id)));
  const children: Record<string, any[]> = {};
  const roots: any[] = [];
  for (const ca of cas) {
    const parent = String(ca.parent_ca_id || "").trim();
    if (parent && ids.has(parent)) (children[parent] ||= []).push(ca);
    else roots.push(ca);
  }
  const issued: Record<string, any[]> = {};
  const stats: Record<string, CAStats> = {};
  for (const c of certs) {
    const id = String(c.ca_id || "");
    (issued[id] ||= []).push(c);
    const s = (stats[id] ||= { total: 0, active: 0, expiring: 0, revoked: 0 });
    s.total++;
    if (matchesCertFilter(c, "active", policy, now)) s.active++;
    if (matchesCertFilter(c, "expiring", policy, now)) s.expiring++;
    if (matchesCertFilter(c, "revoked", policy, now)) s.revoked++;
  }
  return { roots, children, issued, stats };
}

export const keyPlace = (backend: unknown) => (backend === "hsm" ? "HSM" : backend === "keycore" ? "keycore" : "software");
