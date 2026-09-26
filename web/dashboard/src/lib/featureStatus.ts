// Preview features: they store configuration but enforce or execute nothing.
// Mirrors pkg/features.Preview (Go); scripts/conformance.sh fails when the two
// lists differ. docs/PREVIEW_FEATURES.md

export type PreviewFeature = { id: string; name: string; limitation: string };

export const PREVIEW_FEATURES: PreviewFeature[] = [
  { id: "keycore.federation", name: "Key federation / multi-KMS failover", limitation: "Providers, mappings and failovers are stored; no key is replicated and no failover happens." },
  { id: "keycore.binding_policy", name: "Key binding policies", limitation: "Stored only; key operations do not evaluate them." },
  { id: "keycore.sharing_grant", name: "Fine-grained key sharing grants", limitation: "Stored only; use key access grants for enforced sharing." },
  { id: "keycore.metadata_profile", name: "Key metadata profiles", limitation: "Stored only; key creation does not apply or validate them." },
  { id: "keycore.escrow_tier", name: "Escrow tiers", limitation: "Stored only; Shamir split/verify and escrow recovery do not use them." },
  { id: "keycore.edge", name: "Edge & IoT agents, leases and receipts", limitation: "Stored only; there is no edge runtime." },
  { id: "keycore.advanced_encryption_modes", name: "Homomorphic / functional encryption modes", limitation: "Registered as controls; no homomorphic or functional encryption is performed. Searchable HMAC tokens are available." },
  { id: "keycore.audit_chain_anchor", name: "External audit-chain anchors", limitation: "Records an external reference in a local hash chain; nothing is anchored externally. Audit tamper evidence comes from the audit service." },
  { id: "backup.scheduler", name: "Backup policies, runs and restore points (Backup tab)", limitation: "Policies are stored but no backup is executed or restored. Real encrypted backups: System Administration > Backups." },
];

export function previewFeature(id: string): PreviewFeature | undefined {
  return PREVIEW_FEATURES.find((f) => f.id === id);
}
